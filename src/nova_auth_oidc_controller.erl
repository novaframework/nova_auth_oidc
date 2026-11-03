-module(nova_auth_oidc_controller).
-moduledoc ~"""
Nova controller for OpenID Connect authentication flows.

Handles login redirect and OAuth callback endpoints. After successful
authentication, the callback moves the client to a new session id
(against session fixation) and stores a mapped actor in it via
`nova_auth_actor`, making it compatible with `nova_auth_security`.

Session renewal uses `nova_session:renew(Req)` when the running Nova
provides it. On older Nova releases the callback deletes the session with
`nova_session:delete/1` and sets a new `session_id` cookie itself: a
256-bit `crypto:strong_rand_bytes/1` id with `Path=/`, `HttpOnly`,
`SameSite=Lax`, and `Secure` on HTTPS requests. The `nova` application's
`session_cookie_opts` map, when set, is merged over those defaults.

## Routes

```erlang
#{prefix => ~"/auth", security => false,
  routes => [
      {~"/:provider/login", fun nova_auth_oidc_controller:login/1,
       #{auth_mod => my_oidc_config}},
      {~"/:provider/callback", fun nova_auth_oidc_controller:callback/1,
       #{auth_mod => my_oidc_config}}
  ]}
```
""".

-export([login/1, callback/1]).

-doc """
Initiate OIDC login by redirecting to the provider's authorization endpoint.

Generates nonce and PKCE verifier, stores them in the session,
and redirects the user to the provider.
""".
-spec login(map()) -> term().
login(#{bindings := #{provider := ProviderBin}} = Req) ->
    AuthMod = auth_mod(Req),
    Provider = binary_to_existing_atom(ProviderBin),
    case nova_auth_oidc:provider_config(AuthMod, Provider) of
        {ok, #{client_id := ClientId, client_secret := ClientSecret} = ProviderCfg} ->
            Nonce = generate_random(32),
            PkceVerifier = generate_random(32),
            RedirectUri = nova_auth_oidc:redirect_uri(AuthMod, Provider),
            GlobalScopes = nova_auth_oidc:config(AuthMod, scopes),
            Scopes = maps:get(scopes, ProviderCfg, GlobalScopes),

            ok = nova_session:set(Req, ~"oidc_nonce", Nonce),
            ok = nova_session:set(Req, ~"oidc_pkce", PkceVerifier),
            ok = nova_session:set(Req, ~"oidc_provider", ProviderBin),

            WorkerName = nova_auth_oidc:provider_worker_name(AuthMod, Provider),
            Opts = #{
                redirect_uri => RedirectUri,
                scopes => Scopes,
                nonce => Nonce,
                pkce_verifier => PkceVerifier
            },
            case oidcc:create_redirect_url(WorkerName, ClientId, ClientSecret, Opts) of
                {ok, AuthUrl} ->
                    {redirect, AuthUrl};
                {error, Reason} ->
                    handle_failure(AuthMod, Reason)
            end;
        {error, not_found} ->
            {status, 404, #{}, ~"Unknown provider"}
    end.

-doc """
Handle the OAuth callback after the user authenticates with the provider.

Exchanges the authorization code for tokens, retrieves user info,
applies claims mapping, renews the session, stores the actor in the new
session, and redirects to the configured success URL.
""".
-spec callback(map()) -> term().
callback(#{bindings := #{provider := ProviderBin}} = Req) ->
    AuthMod = auth_mod(Req),
    Provider = binary_to_existing_atom(ProviderBin),
    QsList = cowboy_req:parse_qs(Req),
    case proplists:get_value(~"code", QsList) of
        undefined ->
            ErrorDesc = proplists:get_value(~"error_description", QsList, ~"no code"),
            handle_failure(AuthMod, {missing_code, ErrorDesc});
        Code ->
            handle_code(Req, AuthMod, Provider, Code)
    end.

%%----------------------------------------------------------------------
%% Internal
%%----------------------------------------------------------------------

handle_code(Req, AuthMod, Provider, Code) ->
    case nova_auth_oidc:provider_config(AuthMod, Provider) of
        {ok, #{client_id := ClientId, client_secret := ClientSecret}} ->
            {ok, Nonce} = nova_session:get(Req, ~"oidc_nonce"),
            PkceVerifier =
                case nova_session:get(Req, ~"oidc_pkce") of
                    {ok, V} -> V;
                    _ -> none
                end,
            RedirectUri = nova_auth_oidc:redirect_uri(AuthMod, Provider),
            WorkerName = nova_auth_oidc:provider_worker_name(AuthMod, Provider),

            TokenOpts = #{
                redirect_uri => RedirectUri,
                nonce => Nonce,
                pkce_verifier => PkceVerifier
            },

            case retrieve_token_and_userinfo(WorkerName, ClientId, ClientSecret, Code, TokenOpts) of
                {ok, _Token, Userinfo} ->
                    Actor = build_actor(AuthMod, Provider, Userinfo),
                    {ok, Req1} = renew_session(Req),
                    ok = nova_auth_actor:store(Req1, Actor),
                    case nova_auth_oidc:config(AuthMod, on_success) of
                        {redirect, Url} -> {redirect, Url, Req1};
                        _ -> {redirect, ~"/", Req1}
                    end;
                {error, Reason} ->
                    handle_failure(AuthMod, Reason)
            end;
        {error, not_found} ->
            {status, 404, #{}, ~"Unknown provider"}
    end.

build_actor(AuthMod, Provider, Userinfo) ->
    Mapping = nova_auth_oidc:config(AuthMod, claims_mapping),
    Base = #{provider => Provider},
    case Mapping of
        M when map_size(M) =:= 0 ->
            %% No mapping configured — use sub as id, pass through all claims
            Id = maps:get(~"sub", Userinfo, maps:get(~"email", Userinfo, undefined)),
            Base#{id => Id, claims => Userinfo};
        _ ->
            nova_auth_claims:map(Mapping, Userinfo, Base)
    end.

retrieve_token_and_userinfo(WorkerName, ClientId, ClientSecret, Code, TokenOpts) ->
    case oidcc:retrieve_token(Code, WorkerName, ClientId, ClientSecret, TokenOpts) of
        {ok, Token} ->
            case oidcc:retrieve_userinfo(Token, WorkerName, ClientId, ClientSecret, #{}) of
                {ok, Userinfo} ->
                    {ok, Token, Userinfo};
                {error, _} ->
                    {ok, Token, #{}}
            end;
        {error, Reason} ->
            {error, Reason}
    end.

handle_failure(AuthMod, Reason) ->
    logger:error(~"nova_auth_oidc authentication failed: ~p", [Reason]),
    case nova_auth_oidc:config(AuthMod, on_failure) of
        {status, Code} -> {status, Code};
        {redirect, Url} -> {redirect, Url};
        _ -> {status, 401}
    end.

renew_session(Req) ->
    _ = code:ensure_loaded(nova_session),
    case erlang:function_exported(nova_session, renew, 1) of
        true -> nova_session_renew(Req);
        false -> renew_session_fallback(Req)
    end.

%% Called through a variable: older Nova releases have no renew/1, and a
%% literal remote call would fail xref there.
nova_session_renew(Req) ->
    Mod = nova_session,
    Mod:renew(Req).

renew_session_fallback(Req0) ->
    {ok, Req1} = nova_session:delete(Req0),
    SessionId = generate_random(32),
    Req2 = cowboy_req:set_resp_cookie(~"session_id", SessionId, Req1, cookie_opts(Req1)),
    {ok, Req2#{nova_session_id => SessionId}}.

cookie_opts(Req) ->
    Defaults = #{
        path => ~"/",
        http_only => true,
        same_site => lax,
        secure => cowboy_req:scheme(Req) =:= ~"https"
    },
    case application:get_env(nova, session_cookie_opts) of
        {ok, Opts} when is_map(Opts) -> maps:merge(Defaults, Opts);
        _ -> Defaults
    end.

auth_mod(Req) ->
    maps:get(auth_mod, Req).

generate_random(Bytes) ->
    base64:encode(crypto:strong_rand_bytes(Bytes), #{mode => urlsafe, padding => false}).
