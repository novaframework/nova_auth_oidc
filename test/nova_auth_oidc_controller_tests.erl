-module(nova_auth_oidc_controller_tests).
-include_lib("eunit/include/eunit.hrl").

-define(SESSION_ID, ~"session-of-the-login").

callback_test_() ->
    {foreach, fun start/0, fun stop/1, [
        fun callback_signs_the_actor_in_on_the_returned_request/0,
        fun callback_reads_nonce_and_pkce_before_it_signs_in/0,
        fun callback_leaves_no_login_state_behind/0,
        fun callback_moves_to_a_new_session/0
    ]}.

start() ->
    ok = test_oidc_session_backend:start(),
    ok = meck:new(oidcc, [no_link]),
    ok = meck:expect(oidcc, retrieve_token, fun(_Code, _Worker, _Id, _Secret, _Opts) ->
        {ok, token}
    end),
    ok = meck:expect(oidcc, retrieve_userinfo, fun(token, _Worker, _Id, _Secret, _Opts) ->
        {ok, #{~"sub" => ~"user-1", ~"email" => ~"user@example.com"}}
    end),
    ok = nova_session:set(login_request(), ~"oidc_nonce", ~"the-nonce"),
    ok = nova_session:set(login_request(), ~"oidc_pkce", ~"the-verifier"),
    ok = nova_session:set(login_request(), ~"oidc_provider", ~"authentik").

stop(_) ->
    ok = meck:unload(oidcc),
    _ = persistent_term:erase({nova_auth_oidc, test_oidc_config}),
    test_oidc_session_backend:stop().

callback_signs_the_actor_in_on_the_returned_request() ->
    {redirect, ~"/", SignedIn} = nova_auth_oidc_controller:callback(login_request()),
    ?assertMatch(
        {ok, #{id := ~"user-1", email := ~"user@example.com", provider := authentik}},
        nova_auth_actor:fetch(SignedIn)
    ).

callback_reads_nonce_and_pkce_before_it_signs_in() ->
    {redirect, ~"/", _SignedIn} = nova_auth_oidc_controller:callback(login_request()),
    [TokenOpts] = [
        Opts
     || {_Pid, {oidcc, retrieve_token, [_Code, _Worker, _Id, _Secret, Opts]}, _Result} <-
            meck:history(oidcc)
    ],
    ?assertMatch(#{nonce := ~"the-nonce", pkce_verifier := ~"the-verifier"}, TokenOpts).

callback_leaves_no_login_state_behind() ->
    {redirect, ~"/", SignedIn} = nova_auth_oidc_controller:callback(login_request()),
    [
        ?assertEqual(
            {Request, Key, {error, not_found}}, {Request, Key, nova_session:get(Request, Key)}
        )
     || Request <- [login_request(), SignedIn],
        Key <- [~"oidc_nonce", ~"oidc_pkce", ~"oidc_provider"]
    ].

callback_moves_to_a_new_session() ->
    case nova_has_sign_in() of
        true ->
            {redirect, ~"/", SignedIn} = nova_auth_oidc_controller:callback(login_request()),
            ?assertNotEqual(?SESSION_ID, maps:get(nova_session_id, SignedIn)),
            ?assertEqual({error, not_found}, nova_auth_actor:fetch(login_request()));
        false ->
            ok
    end.

login_request() ->
    #{
        bindings => #{provider => ~"authentik"},
        auth_mod => test_oidc_config,
        qs => ~"code=the-code&state=the-state",
        nova_session_id => ?SESSION_ID
    }.

nova_has_sign_in() ->
    _ = code:ensure_loaded(nova_session),
    erlang:function_exported(nova_session, sign_in, 3).
