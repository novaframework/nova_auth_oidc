-module(nova_auth_oidc_jwt_tests).
-include_lib("eunit/include/eunit.hrl").
-include_lib("oidcc/include/oidcc_provider_configuration.hrl").

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
    meck:expect(oidcc_provider_configuration_worker, get_provider_configuration, fun(_) ->
        #oidcc_provider_configuration{
            issuer = ?ISS,
            authorization_endpoint = ?ISS,
            response_types_supported = [~"code"],
            subject_types_supported = [public],
            id_token_signing_alg_values_supported = [~"RS256"]
        }
    end),
    ok = nova_auth_oidc_jwt:init_refresh_table(),
    ok.

cleanup(_) ->
    true = ets:delete(nova_auth_oidc_jwks_refresh),
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
            fun signature_valid_but_expired_claims_rejected/0},
        {"a token without iat is rejected", fun missing_iat_rejected/0},
        {"a token whose nbf is in the future is rejected", fun not_yet_valid_rejected/0},
        {"a non-numeric exp in a signed token is rejected, not a crash",
            fun non_numeric_exp_in_signed_token_rejected/0},
        {"an unknown kid refetches the JWKS and validates against the new key",
            fun unknown_kid_refreshes_jwks/0},
        {"unknown-kid refetches are limited per provider",
            fun unknown_kid_refresh_is_rate_limited/0},
        {"concurrent unknown-kid tokens refetch the JWKS once",
            {timeout, 60, fun concurrent_unknown_kids_refresh_once/0}},
        {"malformed tokens are invalid_signature, not a crash", fun malformed_tokens_rejected/0},
        {"a malformed bearer token gets a 401", fun malformed_bearer_is_unauthorized/0}
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

missing_iat_rejected() ->
    Priv = rsa_key(),
    mock_jwks(jwks_of([Priv])),
    Token = sign_rs256(Priv, maps:remove(~"iat", claims())),
    ?assertEqual(
        {error, missing_iat},
        nova_auth_oidc_jwt:validate_token(test_oidc_config, authentik, Token)
    ).

not_yet_valid_rejected() ->
    Priv = rsa_key(),
    mock_jwks(jwks_of([Priv])),
    Token = sign_rs256(Priv, (claims())#{~"nbf" => future()}),
    ?assertEqual(
        {error, token_not_yet_valid},
        nova_auth_oidc_jwt:validate_token(test_oidc_config, authentik, Token)
    ).

non_numeric_exp_in_signed_token_rejected() ->
    Priv = rsa_key(),
    mock_jwks(jwks_of([Priv])),
    Token = sign_rs256(Priv, (claims())#{~"exp" => ~"tomorrow"}),
    ?assertEqual(
        {error, invalid_claims},
        nova_auth_oidc_jwt:validate_token(test_oidc_config, authentik, Token)
    ).

unknown_kid_refreshes_jwks() ->
    Old = with_kid(rsa_key(), ~"old-key"),
    New = with_kid(rsa_key(), ~"new-key"),
    mock_rotation(jwks_of([Old]), jwks_of([Old, New])),
    Token = sign_rs256(New, claims()),
    ?assertMatch(
        {ok, #{id := ~"user-1"}},
        nova_auth_oidc_jwt:validate_token(test_oidc_config, authentik, Token)
    ),
    ?assertEqual(
        1, meck:num_calls(oidcc_provider_configuration_worker, refresh_jwks_for_unknown_kid, '_')
    ).

unknown_kid_refresh_is_rate_limited() ->
    Known = with_kid(rsa_key(), ~"known-key"),
    mock_rotation(jwks_of([Known]), jwks_of([Known])),
    Tokens = [
        sign_rs256(with_kid(rsa_key(), Kid), claims())
     || Kid <- [~"made-up-1", ~"made-up-2"]
    ],
    [
        ?assertEqual(
            {error, invalid_signature},
            nova_auth_oidc_jwt:validate_token(test_oidc_config, authentik, Token)
        )
     || Token <- Tokens
    ],
    ?assertEqual(
        1, meck:num_calls(oidcc_provider_configuration_worker, refresh_jwks_for_unknown_kid, '_')
    ).

concurrent_unknown_kids_refresh_once() ->
    Known = with_kid(rsa_key(), ~"known-key"),
    mock_jwks(jwks_of([Known])),
    meck:expect(oidcc_provider_configuration_worker, refresh_jwks_for_unknown_kid, fun(_, _) ->
        ok
    end),
    Token = sign_rs256(with_kid(rsa_key(), ~"made-up"), claims()),
    Refetches = [unknown_kid_burst(Token, 2000) || _ <- lists:seq(1, 10)],
    ?assertEqual(lists:duplicate(10, 1), Refetches).

unknown_kid_burst(Token, N) ->
    true = ets:delete_all_objects(nova_auth_oidc_jwks_refresh),
    meck:reset(oidcc_provider_configuration_worker),
    Self = self(),
    Go = make_ref(),
    Pids = [
        spawn_link(fun() ->
            receive
                Go -> ok
            end,
            Self ! {self(), nova_auth_oidc_jwt:validate_token(test_oidc_config, authentik, Token)}
        end)
     || _ <- lists:seq(1, N)
    ],
    _ = [Pid ! Go || Pid <- Pids],
    Results = [
        receive
            {Pid, Result} -> Result
        after 30000 -> error(timeout)
        end
     || Pid <- Pids
    ],
    ?assertEqual([{error, invalid_signature}], lists:usort(Results)),
    meck:num_calls(oidcc_provider_configuration_worker, refresh_jwks_for_unknown_kid, '_').

malformed_tokens_rejected() ->
    mock_jwks(jwks_of([rsa_key()])),
    Payload = b64url(iolist_to_binary(json:encode(claims()))),
    Tokens = [
        ~"a.b.c",
        ~"a.b.c.d.e",
        ~"!!!.!!!.!!!",
        <<(b64url(~"not json"))/binary, ".", Payload/binary, ".abc">>,
        <<
            (b64url(iolist_to_binary(json:encode(#{~"alg" => 1}))))/binary,
            ".",
            Payload/binary,
            ".abc"
        >>
    ],
    ?assertEqual(
        [{Token, {error, invalid_signature}} || Token <- Tokens],
        [{Token, validate_raising(Token)} || Token <- Tokens]
    ).

malformed_bearer_is_unauthorized() ->
    mock_jwks(jwks_of([rsa_key()])),
    Req = #{
        ref => test,
        pid => self(),
        streamid => 1,
        peer => {{127, 0, 0, 1}, 40000},
        sock => {{127, 0, 0, 1}, 8080},
        cert => undefined,
        method => ~"GET",
        version => 'HTTP/1.1',
        scheme => ~"http",
        host => ~"localhost",
        port => 8080,
        path => ~"/api",
        qs => ~"",
        headers => #{~"authorization" => ~"Bearer !!!.!!!.!!!"},
        has_body => false,
        body_length => 0
    },
    ?assertMatch({false, 401, _, _}, nova_auth_oidc_security:require_bearer(test_oidc_config, Req)).

validate_raising(Token) ->
    try
        nova_auth_oidc_jwt:validate_token(test_oidc_config, authentik, Token)
    catch
        Class:Reason -> {raised, Class, Reason}
    end.

%% ---- signature-test helpers ----

mock_rotation(Before, After) ->
    Key = {?MODULE, rotated},
    put(Key, false),
    meck:expect(oidcc_provider_configuration_worker, get_jwks, fun(_) ->
        case get(Key) of
            true -> After;
            false -> Before
        end
    end),
    meck:expect(oidcc_provider_configuration_worker, refresh_jwks_for_unknown_kid, fun(_, _) ->
        put(Key, true),
        ok
    end).

with_kid(PrivKey, Kid) ->
    jose_jwk:merge(PrivKey, #{~"kid" => Kid}).

mock_jwks(Jwks) ->
    meck:expect(oidcc_provider_configuration_worker, get_jwks, fun(_) -> Jwks end).

rsa_key() ->
    jose_jwk:generate_key({rsa, 2048}).

jwks_of(PrivKeys) ->
    PubMaps = [element(2, jose_jwk:to_map(jose_jwk:to_public(K))) || K <- PrivKeys],
    jose_jwk:from_map(#{~"keys" => PubMaps}).

sign_rs256(PrivKey, Claims) ->
    Jwt = jose_jwt:from(Claims),
    Header =
        case jose_jwk:to_map(PrivKey) of
            {_, #{~"kid" := Kid}} -> #{~"alg" => ~"RS256", ~"kid" => Kid};
            _ -> #{~"alg" => ~"RS256"}
        end,
    {_, Signed} = jose_jwt:sign(PrivKey, Header, Jwt),
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
    #{
        ~"iss" => ?ISS,
        ~"aud" => ?AUD,
        ~"sub" => ~"user-1",
        ~"exp" => future(),
        ~"iat" => erlang:system_time(second)
    }.
