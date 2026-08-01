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

%% End-to-end signature verification: validate_token/3's real
%% get_jwks -> verify_signature -> validate_claims -> build_actor path,
%% against genuinely-signed tokens. Previously untested at any layer -
%% the only coverage was validate_claims/3 in isolation above, which is
%% exactly why jose_jwt:verify/2 shipped with a function_clause crash on
%% any real, correctly-signed token: get_jwks/1 always returns a
%% #jose_jwk{keys = {jose_jwk_set, _}} (a provider can rotate keys, so
%% it's always a set, even with a single key), and jose_jwt:verify/2 has
%% no clause matching a set - only oidcc_jwt_util:verify_signature/3
%% (what validate_token/3 now calls) folds over one.

setup() ->
    meck:new(oidcc_provider_configuration_worker, [passthrough, non_strict]),
    ok.

cleanup(_) ->
    meck:unload(oidcc_provider_configuration_worker).

validate_token_test_() ->
    {foreach, fun setup/0, fun cleanup/1, [
        {"a genuinely RS256-signed token from a single-key JWKS set validates",
            fun signed_token_validates/0},
        {"a genuinely signed token from a multi-key JWKS set still validates",
            fun signed_token_from_multi_key_set_validates/0},
        {"an alg:none token is rejected, not treated as valid", fun alg_none_rejected/0},
        {"a token signed by a key that isn't in the JWKS is rejected",
            fun wrong_key_signature_rejected/0}
    ]}.

signed_token_validates() ->
    Priv = rsa_key(),
    mock_jwks(jwks_of([Priv])),
    Token = sign_rs256(Priv, claims()),
    ?assertMatch(
        {ok, #{id := ~"user-1"}},
        nova_auth_oidc_jwt:validate_token(test_oidc_config, authentik, Token)
    ).

signed_token_from_multi_key_set_validates() ->
    Priv1 = rsa_key(),
    Priv2 = rsa_key(),
    mock_jwks(jwks_of([Priv1, Priv2])),
    Token = sign_rs256(Priv1, claims()),
    ?assertMatch(
        {ok, _},
        nova_auth_oidc_jwt:validate_token(test_oidc_config, authentik, Token)
    ).

alg_none_rejected() ->
    Priv = rsa_key(),
    mock_jwks(jwks_of([Priv])),
    Token = none_alg_token(claims()),
    ?assertMatch(
        {error, _},
        nova_auth_oidc_jwt:validate_token(test_oidc_config, authentik, Token)
    ).

wrong_key_signature_rejected() ->
    Priv = rsa_key(),
    OtherPriv = rsa_key(),
    mock_jwks(jwks_of([Priv])),
    Token = sign_rs256(OtherPriv, claims()),
    ?assertMatch(
        {error, _},
        nova_auth_oidc_jwt:validate_token(test_oidc_config, authentik, Token)
    ).

%% ---- signature-test helpers ----

mock_jwks(Jwks) ->
    meck:expect(oidcc_provider_configuration_worker, get_jwks, fun(_) -> Jwks end).

rsa_key() ->
    jose_jwk:generate_key({rsa, 2048}).

jwks_of(PrivKeys) ->
    PubMaps = [element(2, jose_jwk:to_map(jose_jwk:to_public(K))) || K <- PrivKeys],
    jose_jwk:from_map(#{~"keys" => PubMaps}).

sign_rs256(PrivKey, Claims) ->
    Jwt = jose_jwt:from(Claims),
    {_, Signed} = jose_jwt:sign(PrivKey, #{~"alg" => ~"RS256"}, Jwt),
    {_, Compact} = jose_jws:compact(Signed),
    Compact.

%% jose refuses to sign an alg:none token itself (jose_jwa:unsecured_signing()
%% gates it, off by default) - build the raw compact form directly, matching
%% how an attacker actually constructs this forgery.
none_alg_token(Claims) ->
    Header = b64url(iolist_to_binary(json:encode(#{~"alg" => ~"none", ~"typ" => ~"JWT"}))),
    Payload = b64url(iolist_to_binary(json:encode(Claims))),
    <<Header/binary, ".", Payload/binary, ".">>.

b64url(Bin) ->
    NoPad = binary:replace(base64:encode(Bin), <<"=">>, <<"">>, [global]),
    binary:replace(binary:replace(NoPad, <<"+">>, <<"-">>, [global]), <<"/">>, <<"_">>, [global]).

claims() ->
    #{~"iss" => ?ISS, ~"aud" => ?AUD, ~"sub" => ~"user-1", ~"exp" => future()}.
