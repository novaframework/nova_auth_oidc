-module(nova_auth_oidc_plugin_SUITE).
-behaviour(ct_suite).
-include_lib("stdlib/include/assert.hrl").

-export([all/0, init_per_suite/1, end_per_suite/1]).
-export([
    actor_passes_through/1,
    anonymous_redirect_stops_with_302/1,
    anonymous_redirect_to_provider_login/1,
    anonymous_status_stops_with_code/1,
    anonymous_without_options_is_401/1,
    plugin_info_version_is_app_vsn/1
]).

all() ->
    [
        actor_passes_through,
        anonymous_redirect_stops_with_302,
        anonymous_redirect_to_provider_login,
        anonymous_status_stops_with_code,
        anonymous_without_options_is_401,
        plugin_info_version_is_app_vsn
    ].

init_per_suite(Config) ->
    ok = test_session_backend:start(),
    ok = application:set_env(nova, session_manager, test_session_backend),
    Config.

end_per_suite(_Config) ->
    ok = application:unset_env(nova, session_manager),
    test_session_backend:stop().

plugin_info_version_is_app_vsn(_Config) ->
    _ = application:load(nova_auth_oidc),
    {ok, Vsn} = application:get_key(nova_auth_oidc, vsn),
    ?assertEqual(
        iolist_to_binary(io_lib:format("~ts", [Vsn])),
        maps:get(version, nova_auth_oidc_plugin:plugin_info())
    ).

actor_passes_through(_Config) ->
    Req = req(~"plugin-actor"),
    Actor = #{id => ~"user-1", provider => authentik},
    ok = nova_auth_actor:store(Req, Actor),
    ?assertMatch(
        {ok, #{auth_data := Actor}, state}, nova_auth_oidc_plugin:pre_request(Req, #{}, #{}, state)
    ).

anonymous_redirect_stops_with_302(_Config) ->
    Options = #{on_unauthorized => {redirect, "/login"}},
    Req = req(~"plugin-anon-1"),
    ?assertEqual(
        {stop, {reply, 302, #{~"location" => ~"/login"}, ~""}, Req, state},
        nova_auth_oidc_plugin:pre_request(Req, #{}, Options, state)
    ).

anonymous_redirect_to_provider_login(_Config) ->
    Options = #{auth_mod => test_oidc_config, provider => authentik},
    Req = req(~"plugin-anon-2"),
    ?assertEqual(
        {stop, {reply, 302, #{~"location" => ~"/auth/authentik/login"}, ~""}, Req, state},
        nova_auth_oidc_plugin:pre_request(Req, #{}, Options, state)
    ).

anonymous_status_stops_with_code(_Config) ->
    Req = req(~"plugin-anon-3"),
    ?assertEqual(
        {stop, {reply, 403, #{}, ~""}, Req, state},
        nova_auth_oidc_plugin:pre_request(Req, #{}, #{on_unauthorized => {status, 403}}, state)
    ).

anonymous_without_options_is_401(_Config) ->
    Req = req(~"plugin-anon-4"),
    ?assertEqual(
        {stop, {reply, 401, #{}, ~""}, Req, state},
        nova_auth_oidc_plugin:pre_request(Req, #{}, #{}, state)
    ).

req(SessionId) ->
    #{nova_session_id => SessionId, headers => #{}}.
