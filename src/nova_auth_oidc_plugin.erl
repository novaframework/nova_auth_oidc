-module(nova_auth_oidc_plugin).
-moduledoc ~"""
Nova plugin that protects routes by checking for an authenticated actor
in the session. Uses `nova_auth_actor` for session storage, making it
compatible with any auth strategy.

## Usage

```erlang
#{prefix => ~"/protected",
  plugins => [{pre_request, [{nova_auth_oidc_plugin, #{
      auth_mod => my_oidc_config,
      provider => authentik,
      on_unauthorized => {redirect, ~"/auth/authentik/login"}
  }}]}],
  routes => [...]}
```

## Options

- `auth_mod` -- OIDC config module (used to build login redirect URL)
- `provider` -- provider atom for redirect URL construction
- `on_unauthorized` -- action when no actor session exists:
  - `{redirect, Url}` -- redirect to login
  - `{status, Code}` -- return HTTP status (e.g., 401)
""".

-behaviour(nova_plugin).

-export([pre_request/4, post_request/4, plugin_info/0]).

-spec pre_request(map(), term(), map(), term()) -> term().
pre_request(Req, _Env, Options, State) ->
    case nova_auth_actor:fetch(Req) of
        {ok, Actor} ->
            {ok, Req#{auth_data => Actor}, State};
        {error, not_found} ->
            OnUnauth = resolve_unauthorized(Options),
            case OnUnauth of
                {redirect, Url} ->
                    {break, {redirect, Url}, Req, State};
                {status, Code} ->
                    {break, {status, Code}, Req, State}
            end
    end.

-spec post_request(map(), term(), map(), term()) -> term().
post_request(Req, _Env, _Options, State) ->
    {ok, Req, State}.

-spec plugin_info() -> map().
plugin_info() ->
    #{
        title => ~"Nova Auth OIDC Plugin",
        version => ~"0.1.0",
        url => ~"https://github.com/Taure/nova_auth_oidc",
        authors => [~"Nova Team"],
        description => ~"Protects routes by requiring OIDC authentication",
        options => [
            {auth_mod, ~"OIDC config module"},
            {provider, ~"Provider atom for redirect URL"},
            {on_unauthorized, ~"Action: {redirect, Url} | {status, Code}"}
        ]
    }.

%%----------------------------------------------------------------------
%% Internal
%%----------------------------------------------------------------------

resolve_unauthorized(#{on_unauthorized := Action}) ->
    Action;
resolve_unauthorized(#{auth_mod := AuthMod, provider := Provider}) ->
    Prefix = nova_auth_oidc:config(AuthMod, auth_path_prefix),
    ProviderBin = atom_to_binary(Provider),
    {redirect, <<Prefix/binary, "/", ProviderBin/binary, "/login">>};
resolve_unauthorized(_) ->
    {status, 401}.
