-module(nova_auth_oidc_jwt_tests).
-include_lib("eunit/include/eunit.hrl").

%% Standard-claim validation: exp -> iss -> aud. Provider config comes from
%% test_oidc_config (authentik: issuer https://auth.example.com/application/o/myapp,
%% client_id test-client-id).

-define(ISS, ~"https://auth.example.com/application/o/myapp").
-define(AUD, ~"test-client-id").

valid_claims_pass_test() ->
    ?assertEqual(ok, validate(base())).

expired_rejected_test() ->
    ?assertEqual({error, token_expired}, validate((base())#{~"exp" => past()})).

missing_exp_rejected_test() ->
    ?assertEqual({error, missing_exp}, validate(maps:remove(~"exp", base()))).

wrong_issuer_rejected_test() ->
    ?assertEqual(
        {error, invalid_issuer}, validate((base())#{~"iss" => ~"https://evil.example.com"})
    ).

missing_issuer_rejected_test() ->
    ?assertEqual({error, invalid_issuer}, validate(maps:remove(~"iss", base()))).

wrong_audience_rejected_test() ->
    ?assertEqual({error, invalid_audience}, validate((base())#{~"aud" => ~"someone-else"})).

audience_list_pass_test() ->
    ?assertEqual(ok, validate((base())#{~"aud" => [~"other", ?AUD]})).

validate(Claims) ->
    nova_auth_oidc_jwt:validate_claims(test_oidc_config, authentik, Claims).

base() ->
    #{~"exp" => future(), ~"iss" => ?ISS, ~"aud" => ?AUD, ~"sub" => ~"user-1"}.

future() -> erlang:system_time(second) + 3600.
past() -> erlang:system_time(second) - 3600.
