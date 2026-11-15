-module(nova_auth_oidc_plugin_tests).
-include_lib("eunit/include/eunit.hrl").

-define(ACTOR, #{id => ~"user-1", provider => authentik}).
-define(REFUSE_WITH_401, #{on_unauthorized => {status, 401}}).

plugin_test_() ->
    {foreach, fun test_oidc_session_backend:start/0, fun(_) -> test_oidc_session_backend:stop() end,
        [
            fun pre_security_lets_a_signed_in_actor_through/0,
            fun pre_security_answers_with_the_status/0,
            fun pre_security_answers_with_the_redirect/0,
            fun pre_request_passes_through_after_pre_security/0,
            fun pre_request_lets_a_signed_in_actor_through/0,
            fun pre_request_answers_with_the_status/0,
            fun pre_request_answers_with_the_redirect/0
        ]}.

pre_security_lets_a_signed_in_actor_through() ->
    {ok, SignedIn} = nova_auth_actor:sign_in(request(), ?ACTOR),
    {ok, Checked, plugin_state} =
        nova_auth_oidc_plugin:pre_security(SignedIn, #{}, ?REFUSE_WITH_401, plugin_state),
    ?assertEqual(?ACTOR, maps:get(auth_data, Checked)).

pre_security_answers_with_the_status() ->
    ?assertMatch(
        {stop, #{has_sent_resp := true}, plugin_state},
        nova_auth_oidc_plugin:pre_security(request(), #{}, ?REFUSE_WITH_401, plugin_state)
    ),
    ?assertMatch({401, _Headers}, sent_response()).

pre_security_answers_with_the_redirect() ->
    Options = #{on_unauthorized => {redirect, ~"/auth/authentik/login"}},
    ?assertMatch(
        {stop, #{has_sent_resp := true}, plugin_state},
        nova_auth_oidc_plugin:pre_security(request(), #{}, Options, plugin_state)
    ),
    ?assertMatch({302, #{~"location" := ~"/auth/authentik/login"}}, sent_response()).

pre_request_passes_through_after_pre_security() ->
    {ok, SignedIn} = nova_auth_actor:sign_in(request(), ?ACTOR),
    {ok, Checked, plugin_state} =
        nova_auth_oidc_plugin:pre_security(SignedIn, #{}, ?REFUSE_WITH_401, plugin_state),
    {ok, _SignedOut} = nova_auth_actor:delete(Checked),
    ?assertEqual(
        {ok, Checked, plugin_state},
        nova_auth_oidc_plugin:pre_request(Checked, #{}, ?REFUSE_WITH_401, plugin_state)
    ).

pre_request_lets_a_signed_in_actor_through() ->
    {ok, SignedIn} = nova_auth_actor:sign_in(request(), ?ACTOR),
    {ok, Checked, plugin_state} =
        nova_auth_oidc_plugin:pre_request(SignedIn, #{}, ?REFUSE_WITH_401, plugin_state),
    ?assertEqual(?ACTOR, maps:get(auth_data, Checked)).

pre_request_answers_with_the_status() ->
    ?assertMatch(
        {stop, #{has_sent_resp := true}, plugin_state},
        nova_auth_oidc_plugin:pre_request(request(), #{}, ?REFUSE_WITH_401, plugin_state)
    ),
    ?assertMatch({401, _Headers}, sent_response()).

pre_request_answers_with_the_redirect() ->
    Options = #{auth_mod => test_oidc_config, provider => authentik},
    ?assertMatch(
        {stop, #{has_sent_resp := true}, plugin_state},
        nova_auth_oidc_plugin:pre_request(request(), #{}, Options, plugin_state)
    ),
    ?assertMatch({302, #{~"location" := ~"/auth/authentik/login"}}, sent_response()).

request() ->
    #{
        pid => self(),
        streamid => 1,
        method => ~"GET",
        headers => #{},
        nova_session_id => ~"session-of-the-request"
    }.

sent_response() ->
    receive
        {{Pid, 1}, {response, Status, Headers, _Body}} when Pid =:= self() -> {Status, Headers}
    after 1000 -> no_response
    end.
