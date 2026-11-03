-module(nova_auth_oidc_controller_SUITE).
-behaviour(ct_suite).
-include_lib("stdlib/include/assert.hrl").

-export([all/0, init_per_suite/1, end_per_suite/1, init_per_testcase/2, end_per_testcase/2]).
-export([
    callback_renews_session/1,
    callback_planted_session_stays_anonymous/1,
    login_unknown_provider_is_404/1,
    callback_unknown_provider_is_404/1,
    login_stores_state_and_sends_it/1,
    callback_without_login_is_401/1,
    callback_missing_state_is_401/1,
    callback_wrong_state_is_401_and_single_use/1,
    callback_other_provider_is_401/1,
    callback_provider_error_is_401_and_single_use/1
]).

-define(OLD_ID, ~"planted-session-id").
-define(STATE, ~"expected-state-value").
-define(UNKNOWN_PROVIDER, ~"nova_auth_oidc_controller_SUITE_no_such_provider").

all() ->
    [
        callback_renews_session,
        callback_planted_session_stays_anonymous,
        login_unknown_provider_is_404,
        callback_unknown_provider_is_404,
        login_stores_state_and_sends_it,
        callback_without_login_is_401,
        callback_missing_state_is_401,
        callback_wrong_state_is_401_and_single_use,
        callback_other_provider_is_401,
        callback_provider_error_is_401_and_single_use
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
    ok = meck:expect(oidcc, create_redirect_url, fun(_, _, _, _) ->
        {ok, ~"https://auth.example.com/authorize"}
    end),
    OldReq = req(),
    ok = nova_session:set(OldReq, ~"oidc_state", ?STATE),
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

login_unknown_provider_is_404(_Config) ->
    Req = (req())#{bindings => #{provider => ?UNKNOWN_PROVIDER}},
    ?assertMatch({status, 404, _, _}, nova_auth_oidc_controller:login(Req)),
    ?assertError(badarg, binary_to_existing_atom(?UNKNOWN_PROVIDER)).

callback_unknown_provider_is_404(_Config) ->
    Req = (req())#{bindings => #{provider => ?UNKNOWN_PROVIDER}},
    ?assertMatch({status, 404, _, _}, nova_auth_oidc_controller:callback(Req)),
    ?assertError(badarg, binary_to_existing_atom(?UNKNOWN_PROVIDER)),
    ?assertNot(meck:called(oidcc, retrieve_token, '_')).

login_stores_state_and_sends_it(_Config) ->
    Req = (req())#{nova_session_id => ~"fresh-login-session"},
    ?assertEqual(
        {redirect, ~"https://auth.example.com/authorize"}, nova_auth_oidc_controller:login(Req)
    ),
    {ok, State} = nova_session:get(Req, ~"oidc_state"),
    ?assert(is_binary(State) andalso byte_size(State) >= 43),
    [{_, {oidcc, create_redirect_url, [_, _, _, Opts]}, _}] = meck:history(oidcc),
    ?assertMatch(#{state := State, nonce := _, pkce_verifier := _}, Opts).

callback_without_login_is_401(_Config) ->
    Req = (req())#{nova_session_id => ~"no-login-session"},
    ?assertEqual({status, 401}, nova_auth_oidc_controller:callback(Req)),
    ?assertNot(meck:called(oidcc, retrieve_token, '_')).

callback_missing_state_is_401(_Config) ->
    Req = (req())#{qs => ~"code=auth-code"},
    ?assertEqual({status, 401}, nova_auth_oidc_controller:callback(Req)),
    ?assertNot(meck:called(oidcc, retrieve_token, '_')).

callback_wrong_state_is_401_and_single_use(_Config) ->
    Req = (req())#{qs => ~"code=auth-code&state=attacker-chosen-val"},
    ?assertEqual({status, 401}, nova_auth_oidc_controller:callback(Req)),
    ?assertNot(meck:called(oidcc, retrieve_token, '_')),
    ?assertEqual([], test_session_backend:keys(?OLD_ID)),
    ?assertEqual({status, 401}, nova_auth_oidc_controller:callback(req())).

callback_other_provider_is_401(_Config) ->
    Req = (req())#{bindings => #{provider => ~"google"}},
    ?assertEqual({status, 401}, nova_auth_oidc_controller:callback(Req)),
    ?assertNot(meck:called(oidcc, retrieve_token, '_')).

callback_provider_error_is_401_and_single_use(_Config) ->
    ok = meck:expect(oidcc, retrieve_token, fun(_, _, _, _, _) -> {error, nonce_mismatch} end),
    ?assertEqual({status, 401}, nova_auth_oidc_controller:callback(req())),
    ?assertEqual([], test_session_backend:keys(?OLD_ID)),
    ?assertEqual({error, not_found}, nova_auth_actor:fetch(req())).

callback(Req) ->
    case nova_auth_oidc_controller:callback(Req) of
        {redirect, Path, #{} = Req1} -> {Path, Req1}
    end.

req() ->
    #{
        bindings => #{provider => ~"authentik"},
        auth_mod => test_oidc_config,
        qs => <<"code=auth-code&state=", ?STATE/binary>>,
        nova_session_id => ?OLD_ID,
        scheme => ~"https",
        headers => #{},
        resp_cookies => #{}
    }.
