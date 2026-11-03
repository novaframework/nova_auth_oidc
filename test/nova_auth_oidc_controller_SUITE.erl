-module(nova_auth_oidc_controller_SUITE).
-behaviour(ct_suite).
-include_lib("stdlib/include/assert.hrl").

-export([all/0, init_per_suite/1, end_per_suite/1, init_per_testcase/2, end_per_testcase/2]).
-export([
    callback_renews_session/1,
    callback_planted_session_stays_anonymous/1,
    callback_sets_flagged_cookie/1
]).

-define(OLD_ID, ~"planted-session-id").

all() ->
    [
        callback_renews_session,
        callback_planted_session_stays_anonymous,
        callback_sets_flagged_cookie
    ].

init_per_suite(Config) ->
    ok = test_session_backend:start(),
    ok = application:set_env(nova, session_manager, test_session_backend),
    Config.

end_per_suite(_Config) ->
    ok = application:unset_env(nova, session_manager),
    test_session_backend:stop().

init_per_testcase(_Case, Config) ->
    ok = meck:new(oidcc, [no_link]),
    ok = meck:expect(oidcc, retrieve_token, fun(_, _, _, _, _) -> {ok, token} end),
    ok = meck:expect(oidcc, retrieve_userinfo, fun(_, _, _, _, _) ->
        {ok, #{~"sub" => ~"user-1", ~"email" => ~"user@example.com"}}
    end),
    OldReq = req(),
    ok = nova_session:set(OldReq, ~"oidc_nonce", ~"nonce"),
    ok = nova_session:set(OldReq, ~"oidc_pkce", ~"verifier"),
    ok = nova_session:set(OldReq, ~"oidc_provider", ~"authentik"),
    Config.

end_per_testcase(_Case, _Config) ->
    _ = test_session_backend:delete_value(?OLD_ID),
    meck:unload(oidcc).

callback_renews_session(_Config) ->
    {~"/", #{nova_session_id := NewId} = Req1} = callback(req()),
    ?assertNotEqual(?OLD_ID, NewId),
    ?assertEqual([], test_session_backend:keys(?OLD_ID)),
    ?assertMatch(
        {ok, #{id := ~"user-1", provider := authentik, email := ~"user@example.com"}},
        nova_auth_actor:fetch(Req1)
    ).

callback_planted_session_stays_anonymous(_Config) ->
    {_, _} = callback(req()),
    ?assertEqual({error, not_found}, nova_auth_actor:fetch(req())).

callback_sets_flagged_cookie(_Config) ->
    case nova_has_renew() of
        true ->
            {skip, ~"nova_session:renew/1 writes the cookie in nova_stream_h"};
        false ->
            {_, #{nova_session_id := NewId} = Req1} = callback(req()),
            Cookie = set_cookie(Req1),
            ?assertMatch(<<"session_id=", _/binary>>, Cookie),
            [<<"session_id=", Value/binary>> | _] = binary:split(Cookie, ~";"),
            ?assertEqual(NewId, Value),
            [
                ?assertNotEqual(nomatch, string:find(Cookie, Flag))
             || Flag <- [~"; Path=/", ~"; HttpOnly", ~"; SameSite=Lax", ~"; Secure"]
            ]
    end.

callback(Req) ->
    case nova_auth_oidc_controller:callback(Req) of
        {redirect, Path, #{} = Req1} -> {Path, Req1}
    end.

%% cowboy_req keeps response cookies as untyped iodata.
-spec set_cookie(dynamic()) -> binary().
set_cookie(#{resp_cookies := #{~"session_id" := Cookie}}) ->
    iolist_to_binary(Cookie).

req() ->
    #{
        bindings => #{provider => ~"authentik"},
        auth_mod => test_oidc_config,
        qs => ~"code=auth-code&state=s",
        nova_session_id => ?OLD_ID,
        scheme => ~"https",
        headers => #{},
        resp_cookies => #{}
    }.

nova_has_renew() ->
    _ = code:ensure_loaded(nova_session),
    erlang:function_exported(nova_session, renew, 1).
