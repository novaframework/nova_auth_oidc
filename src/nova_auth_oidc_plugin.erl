-module(nova_auth_oidc_plugin).
-moduledoc ~"""
Nova plugin that protects routes by checking for an authenticated actor
in the session. Uses `nova_auth_actor` for session storage, making it
compatible with any auth strategy.

## Usage

```erlang
#{prefix => ~"/protected",
  plugins => [{pre_request, nova_auth_oidc_plugin, #{
      auth_mod => my_oidc_config,
      provider => authentik,
      on_unauthorized => {redirect, ~"/auth/authentik/login"}
  }}],
  routes => [...]}
```

On a Nova that has the `pre_security/4` plugin callback the session is checked
there, ahead of the security callback of the route group. On an earlier Nova
it is checked in `pre_request/4`. A request without an actor is answered by
the plugin and goes no further.

## Options

- `auth_mod` -- OIDC config module (used to build login redirect URL)
- `provider` -- provider atom for redirect URL construction
- `on_unauthorized` -- action when no actor session exists:
  - `{redirect, Url}` -- redirect to login
  - `{status, Code}` -- return HTTP status (e.g., 401)
""".

-behaviour(nova_plugin).

-export([pre_security/4, pre_request/4, post_request/4, plugin_info/0]).

-define(CHECKED, nova_auth_oidc_plugin_checked).

-spec pre_security(cowboy_req:req(), term(), map(), term()) ->
    {ok, cowboy_req:req(), term()} | {stop, cowboy_req:req(), term()}.
pre_security(Req, _Env, Options, State) ->
    case require_actor(Req, Options) of
        {ok, Req1} -> {ok, Req1#{?CHECKED => true}, State};
        {stop, Req1} -> {stop, Req1, State}
    end.

-spec pre_request(cowboy_req:req(), term(), map(), term()) ->
    {ok, cowboy_req:req(), term()} | {stop, cowboy_req:req(), term()}.
pre_request(#{?CHECKED := true} = Req, _Env, _Options, State) ->
    {ok, Req, State};
pre_request(Req, _Env, Options, State) ->
    case require_actor(Req, Options) of
        {ok, Req1} -> {ok, Req1, State};
        {stop, Req1} -> {stop, Req1, State}
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

-spec require_actor(cowboy_req:req(), map()) -> {ok, cowboy_req:req()} | {stop, cowboy_req:req()}.
require_actor(Req, Options) ->
    case nova_auth_actor:fetch(Req) of
        {ok, Actor} ->
            {ok, Req#{auth_data => Actor}};
        {error, not_found} ->
            {stop, refuse(resolve_unauthorized(Options), Req)}
    end.

-spec refuse({redirect, iodata()} | {status, cowboy:http_status()}, cowboy_req:req()) ->
    cowboy_req:req().
refuse({redirect, Url}, Req) ->
    cowboy_req:reply(302, #{~"location" => Url}, Req);
refuse({status, Code}, Req) ->
    cowboy_req:reply(Code, Req).

resolve_unauthorized(#{on_unauthorized := Action}) ->
    Action;
resolve_unauthorized(#{auth_mod := AuthMod, provider := Provider}) ->
    Prefix = nova_auth_oidc:config(AuthMod, auth_path_prefix),
    ProviderBin = atom_to_binary(Provider),
    {redirect, <<Prefix/binary, "/", ProviderBin/binary, "/login">>};
resolve_unauthorized(_) ->
    {status, 401}.
