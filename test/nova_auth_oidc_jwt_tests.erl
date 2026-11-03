-module(nova_auth_oidc_jwt_tests).
-include_lib("eunit/include/eunit.hrl").

%% Standard-claim validation: exp -> sub -> iss -> aud -> azp. Provider
%% config comes from test_oidc_config (authentik: issuer
%% https://auth.example.com/application/o/myapp, client_id test-client-id).

-define(ISS, ~"https://auth.example.com/application/o/myapp").
-define(AUD, ~"test-client-id").

%% oidcc before 3.9.0 accepts a JWE ID token without a nested signature
%% (CVE-2026-75759, GHSA-533g-4vf3-xwrj); jose before 1.11.13 has known CVEs.
dependency_floors_test() ->
    ?assert(vsn_at_least(oidcc, [3, 9, 0])),
    ?assert(vsn_at_least(jose, [1, 11, 13])).

vsn_at_least(App, Floor) ->
    _ = application:load(App),
    {ok, Vsn} = application:get_key(App, vsn),
    VsnBin = iolist_to_binary(io_lib:format("~s", [Vsn])),
    [binary_to_integer(Part) || Part <- binary:split(VsnBin, ~".", [global])] >= Floor.

valid_claims_pass_test() ->
    ?assertEqual(ok, validate(base())).

expired_rejected_test() ->
    ?assertEqual({error, token_expired}, validate((base())#{~"exp" => past()})).

missing_exp_rejected_test() ->
    ?assertEqual({error, missing_exp}, validate(maps:remove(~"exp", base()))).

%% Erlang term order puts binaries/lists above every number, so a naive
%% `Exp =< Now` would treat a non-numeric exp as "not expired" - this
%% must be its own rejection, not silently accepted.
non_numeric_exp_rejected_test() ->
    ?assertEqual({error, invalid_exp}, validate((base())#{~"exp" => ~"not-a-number"})).

missing_sub_rejected_test() ->
    %% nova_auth:actor()'s `id` is mandatory and comes straight from `sub`
    %% with no fallback - a token without one must fail validation, not
    %% produce an actor with no identity.
    ?assertEqual({error, missing_sub}, validate(maps:remove(~"sub", base()))).

empty_sub_rejected_test() ->
    ?assertEqual({error, missing_sub}, validate((base())#{~"sub" => ~""})).

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

%% OIDC Core 3.1.3.7: azp, when present, must equal our client_id - aud
%% alone isn't proof the token was issued for us on a shared IdP where
%% another client could list us as an additional audience.
azp_matching_client_id_accepted_test() ->
    ?assertEqual(ok, validate((base())#{~"azp" => ?AUD})).

azp_absent_accepted_test() ->
    ?assertEqual(ok, validate(base())).

azp_mismatch_rejected_test() ->
    ?assertEqual(
        {error, invalid_azp},
        validate((base())#{~"aud" => [~"other-client", ?AUD], ~"azp" => ~"other-client"})
    ).

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
    %% No non_strict: this suite's entire job is pinning the contract
    %% against the REAL oidcc_provider_configuration_worker module - the
    %% bug being fixed was a dependency API mismatch, and non_strict
    %% would let a renamed/removed get_jwks/1 pass silently instead of
    %% failing the meck:expect below.
    meck:new(oidcc_provider_configuration_worker, [passthrough]),
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
            fun wrong_key_signature_rejected/0},
        {"an RSA public key replayed as an HMAC secret (alg confusion) is rejected",
            fun hmac_alg_confusion_rejected/0},
        {"a signature-valid token with an expired exp is still rejected by validate_token/3",
            fun signature_valid_but_expired_claims_rejected/0}
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
    ?assertEqual(
        {error, invalid_signature},
        nova_auth_oidc_jwt:validate_token(test_oidc_config, authentik, Token)
    ).

wrong_key_signature_rejected() ->
    Priv = rsa_key(),
    OtherPriv = rsa_key(),
    mock_jwks(jwks_of([Priv])),
    Token = sign_rs256(OtherPriv, claims()),
    ?assertEqual(
        {error, invalid_signature},
        nova_auth_oidc_jwt:validate_token(test_oidc_config, authentik, Token)
    ).

%% ?ALLOWED_ALGORITHMS excludes HS* precisely to close this off: an RSA
%% public key IS public (published at the provider's JWKS endpoint), so
%% if HMAC were allowed, an attacker could sign their own token with it
%% as the HMAC secret and have it accepted as if the IdP had signed it.
%% This attempt is rejected regardless (jose's own key-type matching
%% also refuses to treat an RSA-family JWK as HMAC-compatible), so this
%% pins the end-to-end property - a forged HS256 token using the public
%% key is never accepted - rather than isolating the allowlist as the
%% sole cause; adding ~"HS256" to ?ALLOWED_ALGORITHMS does not turn this
%% specific test red, confirmed by trying it.
hmac_alg_confusion_rejected() ->
    Priv = rsa_key(),
    mock_jwks(jwks_of([Priv])),
    PubPem = element(2, jose_jwk:to_pem(jose_jwk:to_public(Priv))),
    HmacJwk = jose_jwk:from_oct(PubPem),
    Jwt = jose_jwt:from(claims()),
    {_, Signed} = jose_jwt:sign(HmacJwk, #{~"alg" => ~"HS256"}, Jwt),
    {_, Token} = jose_jws:compact(Signed),
    ?assertEqual(
        {error, invalid_signature},
        nova_auth_oidc_jwt:validate_token(test_oidc_config, authentik, Token)
    ).

%% validate_claims/3 above is tested in isolation - this proves the two
%% stages are actually wired together through validate_token/3: a
%% cryptographically valid signature must not short-circuit claims
%% validation.
signature_valid_but_expired_claims_rejected() ->
    Priv = rsa_key(),
    mock_jwks(jwks_of([Priv])),
    Token = sign_rs256(Priv, (claims())#{~"exp" => past()}),
    ?assertEqual(
        {error, token_expired},
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
