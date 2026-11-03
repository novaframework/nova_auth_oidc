-module(nova_auth_oidc_controller).
-moduledoc ~"""
Nova controller for OpenID Connect authentication flows.

Handles login redirect and OAuth callback endpoints. After successful
authentication, the callback moves the client to a new session id
(against session fixation) and stores a mapped actor in it via
`nova_auth_actor`, making it compatible with `nova_auth_security`.
Renewal is `nova_auth_actor:renew/1`.

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

-include_lib("kernel/include/logger.hrl").

-export([login/1, callback/1]).

-doc """
Initiate OIDC login by redirecting to the provider's authorization endpoint.

Generates state, nonce and PKCE verifier, stores them in the session,
and redirects the user to the provider. An unknown `:provider` gets a 404.
If the authorization URL cannot be built (provider unreachable,
discovery not loaded, bad provider config) the reply is a 502; that is a
server-side fault, so `on_failure` is not used and cannot loop back here.

Each login overwrites the session's state, nonce and PKCE verifier, so
when a user starts a second login (another tab) before finishing the
first, the first tab's callback fails with `on_failure`.
""".
-spec login(map()) -> term().
login(#{bindings := #{provider := ProviderBin}} = Req) ->
    AuthMod = auth_mod(Req),
    case lookup_provider(AuthMod, ProviderBin) of
        {ok, Provider, #{client_id := ClientId, client_secret := ClientSecret} = ProviderCfg} ->
            State = generate_random(32),
            Nonce = generate_random(32),
            PkceVerifier = generate_random(32),
            RedirectUri = nova_auth_oidc:redirect_uri(AuthMod, Provider),
            GlobalScopes = nova_auth_oidc:config(AuthMod, scopes),
            Scopes = maps:get(scopes, ProviderCfg, GlobalScopes),

            ok = nova_session:set(Req, ~"oidc_state", State),
            ok = nova_session:set(Req, ~"oidc_nonce", Nonce),
            ok = nova_session:set(Req, ~"oidc_pkce", PkceVerifier),
            ok = nova_session:set(Req, ~"oidc_provider", ProviderBin),

            WorkerName = nova_auth_oidc:provider_worker_name(AuthMod, Provider),
            Opts = #{
                redirect_uri => RedirectUri,
                scopes => Scopes,
                state => State,
                nonce => Nonce,
                pkce_verifier => PkceVerifier
            },
            case oidcc:create_redirect_url(WorkerName, ClientId, ClientSecret, Opts) of
                {ok, AuthUrl} ->
                    {redirect, AuthUrl};
                {error, Reason} ->
                    ?LOG_WARNING(#{
                        msg => ~"nova_auth_oidc could not build the authorization URL",
                        provider => Provider,
                        reason => reason_tag(Reason)
                    }),
                    {status, 502}
            end;
        {error, not_found} ->
            unknown_provider()
    end.

-doc """
Handle the OAuth callback after the user authenticates with the provider.

Checks that the callback belongs to a login this session started: the
`state` query parameter must match the one stored by `login/1`, and the
session must hold the nonce and the same provider. Then it exchanges the
authorization code for tokens, retrieves user info, applies claims
mapping, renews the session, stores the actor in the new session, and
redirects to the configured success URL.

An unknown `:provider` gets a 404. A callback that cannot be tied to the
session (no or wrong `state`, no nonce, other provider), that the provider
rejects, or whose user info cannot be retrieved is an authentication
failure and gets the configured `on_failure` response (401 by default).
The login's state, nonce and PKCE verifier are single-use: they are
deleted as soon as the `state` matches, before the code exchange, so a
replayed or concurrent callback with the same `state` fails.
""".
-spec callback(map()) -> term().
callback(#{bindings := #{provider := ProviderBin}} = Req) ->
    AuthMod = auth_mod(Req),
    case lookup_provider(AuthMod, ProviderBin) of
        {ok, Provider, ProviderCfg} ->
            QsList = cowboy_req:parse_qs(Req),
            case check_login_session(Req, ProviderBin, QsList) of
                {ok, Nonce, PkceVerifier} ->
                    ok = consume_login_session(Req),
                    case proplists:get_value(~"code", QsList) of
                        Code when is_binary(Code) ->
                            handle_code(
                                Req, AuthMod, Provider, ProviderCfg, Code, Nonce, PkceVerifier
                            );
                        _ ->
                            ErrorDesc = proplists:get_value(
                                ~"error_description", QsList, ~"no code"
                            ),
                            fail_callback(Req, AuthMod, {missing_code, ErrorDesc})
                    end;
                {error, Reason} ->
                    fail_callback(Req, AuthMod, Reason)
            end;
        {error, not_found} ->
            unknown_provider()
    end.

%%----------------------------------------------------------------------
%% Internal
%%----------------------------------------------------------------------

lookup_provider(AuthMod, ProviderBin) ->
    Providers = nova_auth_oidc:config(AuthMod, providers),
    case [P || P <- maps:keys(Providers), is_atom(P), atom_to_binary(P) =:= ProviderBin] of
        [Provider] -> {ok, Provider, maps:get(Provider, Providers)};
        [] -> {error, not_found}
    end.

unknown_provider() ->
    {status, 404, #{}, ~"Unknown provider"}.

check_login_session(Req, ProviderBin, QsList) ->
    Stored = [session_value(Req, Key) || Key <- [~"oidc_state", ~"oidc_nonce", ~"oidc_provider"]],
    case {Stored, proplists:get_value(~"state", QsList)} of
        {[{ok, State}, {ok, Nonce}, {ok, ProviderBin}], Given} ->
            case same_secret(State, Given) of
                true -> {ok, Nonce, pkce_verifier(Req)};
                false -> {error, state_mismatch}
            end;
        {[{ok, _}, {ok, _}, {ok, _}], _} ->
            {error, provider_mismatch};
        _ ->
            {error, no_login_in_session}
    end.

session_value(Req, Key) ->
    case nova_session:get(Req, Key) of
        {ok, Value} when is_binary(Value) -> {ok, Value};
        _ -> error
    end.

pkce_verifier(Req) ->
    case session_value(Req, ~"oidc_pkce") of
        {ok, Verifier} -> Verifier;
        error -> none
    end.

same_secret(Expected, Given) when
    is_binary(Expected), is_binary(Given), byte_size(Expected) =:= byte_size(Given)
->
    crypto:hash_equals(Expected, Given);
same_secret(_Expected, _Given) ->
    false.

fail_callback(Req, AuthMod, Reason) ->
    ok = consume_login_session(Req),
    handle_failure(AuthMod, Reason).

consume_login_session(Req) ->
    _ = [nova_session:delete(Req, Key) || Key <- login_session_keys()],
    ok.

login_session_keys() ->
    [~"oidc_state", ~"oidc_nonce", ~"oidc_pkce", ~"oidc_provider"].

handle_code(Req, AuthMod, Provider, ProviderCfg, Code, Nonce, PkceVerifier) ->
    #{client_id := ClientId, client_secret := ClientSecret} = ProviderCfg,
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
            case nova_auth_actor:sign_in(Req, Actor) of
                {ok, Req1} ->
                    case nova_auth_oidc:config(AuthMod, on_success) of
                        {redirect, Url} -> {redirect, Url, Req1};
                        _ -> {redirect, ~"/", Req1}
                    end;
                {error, Reason} ->
                    fail_callback(Req, AuthMod, {session, Reason})
            end;
        {error, Reason} ->
            fail_callback(Req, AuthMod, Reason)
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
                {error, Reason} ->
                    {error, {userinfo, Reason}}
            end;
        {error, Reason} ->
            {error, Reason}
    end.

handle_failure(AuthMod, Reason) ->
    ?LOG_WARNING(#{msg => ~"nova_auth_oidc authentication failed", reason => reason_tag(Reason)}),
    nova_auth_oidc:config(AuthMod, on_failure).

%% oidcc reasons can carry tokens or claims (e.g. {none_alg_used, Token}),
%% so only the tag is logged.
reason_tag(Reason) when is_atom(Reason) ->
    Reason;
reason_tag(Reason) when is_tuple(Reason), tuple_size(Reason) > 0, is_atom(element(1, Reason)) ->
    element(1, Reason);
reason_tag(_Reason) ->
    unknown.

auth_mod(Req) ->
    maps:get(auth_mod, Req).

generate_random(Bytes) ->
    base64:encode(crypto:strong_rand_bytes(Bytes), #{mode => urlsafe, padding => false}).
