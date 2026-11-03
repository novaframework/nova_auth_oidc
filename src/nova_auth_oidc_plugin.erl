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

Without `on_unauthorized`, the plugin redirects to the provider's login
route when `auth_mod` and `provider` are set, and replies 401 otherwise.
The reply ends the request (`{stop, Reply, Req, State}`), so no later
plugin or controller runs.
""".

-behaviour(nova_plugin).

-export([pre_request/4, post_request/4, plugin_info/0]).

-type reply() :: {reply, integer(), #{binary() => binary()}, binary()}.

-spec pre_request(cowboy_req:req(), term(), map(), term()) ->
    {ok, cowboy_req:req(), term()} | {stop, reply(), cowboy_req:req(), term()}.
pre_request(Req, _Env, Options, State) ->
    case nova_auth_actor:fetch(Req) of
        {ok, Actor} ->
            {ok, Req#{auth_data => Actor}, State};
        {error, not_found} ->
            {stop, unauthorized_reply(resolve_unauthorized(Options)), Req, State}
    end.

-spec post_request(cowboy_req:req(), term(), map(), term()) -> {ok, cowboy_req:req(), term()}.
post_request(Req, _Env, _Options, State) ->
    {ok, Req, State}.

-spec plugin_info() -> map().
plugin_info() ->
    #{
        title => ~"Nova Auth OIDC Plugin",
        version => app_vsn(),
        url => ~"https://github.com/novaframework/nova_auth_oidc",
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

unauthorized_reply({redirect, Url}) ->
    {reply, 302, #{~"location" => unicode:characters_to_binary(Url)}, ~""};
unauthorized_reply({status, Code}) ->
    {reply, Code, #{}, ~""}.

app_vsn() ->
    case application:get_key(nova_auth_oidc, vsn) of
        {ok, Vsn} when is_list(Vsn) -> iolist_to_binary(io_lib:format("~ts", [Vsn]));
        _ -> ~"unknown"
    end.
