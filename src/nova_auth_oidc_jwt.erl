-module(nova_auth_oidc_jwt).
-moduledoc ~"""
JWT bearer token validation for API protection. Validates JWTs issued by
a configured OIDC provider using the provider's JWKS (fetched and cached
by `oidcc_provider_configuration_worker`).

## Usage

```erlang
%% In a Nova security callback
case nova_auth_oidc_jwt:validate_bearer(my_oidc_config, Req) of
    {ok, Actor} -> {true, Actor};
    {error, _} -> {false, 401, #{}, ~"unauthorized"}
end
```
""".

-include_lib("jose/include/jose_jwt.hrl").
-include_lib("kernel/include/logger.hrl").

-export([validate_bearer/2, validate_bearer/3, validate_token/3]).
%% Exported for tests: standard-claim validation (exp/iss/aud) in isolation.
-export([validate_claims/3]).

%% signature_error_class/1's catch-all is unreachable against
%% oidcc_jwt_util:verify_signature/3's CURRENT error() type, and dialyzer
%% proves it - deliberately kept anyway, since this classifier is what
%% makes an external dependency's error terms safe to log, with no
%% try/catch of its own to fall back on inside this module. See the
%% function for the full reasoning.
-dialyzer({nowarn_function, signature_error_class/1}).

%% ID tokens are always asymmetrically signed (the private key never
%% leaves the IdP) - RSA and ECDSA cover every major provider (Google,
%% Apple, Microsoft, Discord all sign with RS256). HMAC variants are
%% deliberately excluded: if this list included an HS* algorithm, a
%% raw RSA public key (which IS public, published at the provider's
%% JWKS endpoint) could be replayed as an HMAC secret to forge a token
%% ("alg confusion") - see oidcc_jwt_util's own default and the RFC
%% 8725 discussion of this class of vulnerability.
-define(ALLOWED_ALGORITHMS, [
    ~"RS256",
    ~"RS384",
    ~"RS512",
    ~"ES256",
    ~"ES384",
    ~"ES512"
]).

-doc """
Validate a JWT bearer token from the request's Authorization header.
Uses the first configured provider for validation.
""".
-spec validate_bearer(module(), cowboy_req:req()) ->
    {ok, nova_auth:actor()} | {error, term()}.
validate_bearer(AuthMod, Req) ->
    #{providers := Providers} = nova_auth_oidc:config(AuthMod),
    case maps:next(maps:iterator(Providers)) of
        {Provider, _, _} ->
            validate_bearer(AuthMod, Provider, Req);
        none ->
            {error, no_providers}
    end.

-doc "Validate a JWT bearer token using a specific provider.".
-spec validate_bearer(module(), atom(), cowboy_req:req()) ->
    {ok, nova_auth:actor()} | {error, term()}.
validate_bearer(AuthMod, Provider, Req) ->
    case cowboy_req:header(~"authorization", Req) of
        <<"Bearer ", Token/binary>> ->
            validate_token(AuthMod, Provider, Token);
        _ ->
            {error, missing_bearer}
    end.

-doc """
Validate a raw JWT binary against the provider's JWKS.

Steps:
1. Get provider configuration and JWKS from the worker
2. Decode and verify the JWT signature
3. Validate standard claims (exp, iss, aud)
4. Apply claims mapping
5. Return the actor map
""".
-spec validate_token(module(), atom(), binary()) ->
    {ok, nova_auth:actor()} | {error, term()}.
validate_token(AuthMod, Provider, Token) ->
    WorkerName = nova_auth_oidc:provider_worker_name(AuthMod, Provider),
    case get_jwks(WorkerName) of
        {ok, Jwks} ->
            %% get_jwks/1 always returns a #jose_jwk{keys = {jose_jwk_set,
            %% _}} (a provider can rotate keys, so it's always a set, even
            %% with one key) - jose_jwt:verify/2 has no clause for a key
            %% set, it only matches a single #jose_jwk{} with a concrete
            %% kty, so it always raised function_clause here. oidcc's own
            %% verify_signature/3 folds over the set, matches by `kid` when
            %% present, and enforces the algorithm allowlist itself (also
            %% closing off alg:none and cross-algorithm confusion).
            case oidcc_jwt_util:verify_signature(Token, ?ALLOWED_ALGORITHMS, Jwks) of
                {ok, {#jose_jwt{fields = Claims}, _Jws, _Jwk}} ->
                    case validate_claims(AuthMod, Provider, Claims) of
                        ok ->
                            Actor = build_actor(AuthMod, Provider, Claims),
                            {ok, Actor};
                        {error, _} = Err ->
                            Err
                    end;
                {error, Reason} ->
                    %% oidcc_jwt_util's error terms are its own internal
                    %% vocabulary (no_matching_key, {no_matching_key_with_kid,
                    %% Kid}, {none_alg_used, Jwt, Jws} - the latter two
                    %% carrying decoded token/JWS records, i.e. attacker-
                    %% supplied claims, straight into a Reason a consumer
                    %% might log verbatim). Normalize at this boundary so
                    %% this module's own public error contract
                    %% (invalid_signature, unchanged since before this fix)
                    %% doesn't silently change shape whenever oidcc's
                    %% internal vocabulary does, and so nothing attacker-
                    %% controlled crosses it.
                    ?LOG_DEBUG(#{
                        msg => ~"jwt signature verification failed",
                        reason_class => signature_error_class(Reason)
                    }),
                    {error, invalid_signature}
            end;
        {error, _} = Err ->
            Err
    end.

%%----------------------------------------------------------------------
%% Internal
%%----------------------------------------------------------------------

get_jwks(WorkerName) ->
    try
        {ok, oidcc_provider_configuration_worker:get_jwks(WorkerName)}
    catch
        _:_ -> {error, provider_not_available}
    end.

%% Classify oidcc_jwt_util:verify_signature/3's error term into a bare
%% atom for logging - two of its variants ({none_alg_used, Jwt, Jws})
%% carry decoded token/JWS records, i.e. attacker-supplied claims;
%% logging Reason verbatim would put those in the log.
signature_error_class({no_matching_key_with_kid, _Kid}) -> no_matching_key_with_kid;
signature_error_class({none_alg_used, _Jwt, _Jws}) -> none_alg_used;
signature_error_class(Reason) when is_atom(Reason) -> Reason;
%% Dialyzer proves this is unreachable against oidcc_jwt_util's CURRENT
%% error() type - deliberately kept anyway. validate_token/3 has no
%% try/catch of its own in this module (unlike a caller such as
%% asobi_oauth_controller, which wraps the whole call), so if a future
%% oidcc version added an error variant this function doesn't recognize,
%% removing this clause would mean THIS classifier - the thing meant to
%% make an external dependency's behavior safe to log - is what crashes
%% validate_token/3 uncaught. That is the exact bug class this whole fix
%% exists to close, one level deeper. See the -dialyzer attribute at the
%% top of this module.
signature_error_class(_Other) -> unknown.

validate_claims(AuthMod, Provider, Claims) ->
    Now = erlang:system_time(second),
    case maps:get(~"exp", Claims, undefined) of
        Exp when is_number(Exp), Exp > Now ->
            validate_subject(AuthMod, Provider, Claims);
        undefined ->
            {error, missing_exp};
        Exp when is_number(Exp) ->
            {error, token_expired};
        _ ->
            %% A non-numeric exp (a string, a list, ...) sorts above every
            %% number in Erlang term order, so `Exp =< Now` would have
            %% treated it as "not expired" - reject the shape outright
            %% rather than silently accept a claim that isn't a timestamp.
            {error, invalid_exp}
    end.

%% sub identifies the end user. nova_auth:actor()'s `id` field is
%% mandatory, and build_actor/3's default claims mapping reads it
%% straight from this claim with no fallback - a token without one would
%% otherwise produce an actor with no identity at all, rather than
%% failing validation up front.
validate_subject(AuthMod, Provider, Claims) ->
    case maps:get(~"sub", Claims, undefined) of
        Sub when is_binary(Sub), Sub =/= ~"" ->
            validate_issuer(AuthMod, Provider, Claims);
        _ ->
            {error, missing_sub}
    end.

%% The token's `iss` must match the provider's configured issuer. Without this,
%% a validly-signed token from any issuer the JWKS resolves could be accepted.
validate_issuer(AuthMod, Provider, Claims) ->
    {ok, #{issuer := ExpectedIss}} = nova_auth_oidc:provider_config(AuthMod, Provider),
    case maps:get(~"iss", Claims, undefined) of
        ExpectedIss -> validate_audience(AuthMod, Provider, Claims);
        _ -> {error, invalid_issuer}
    end.

validate_audience(AuthMod, Provider, Claims) ->
    {ok, #{client_id := ExpectedAud}} = nova_auth_oidc:provider_config(AuthMod, Provider),
    Aud = maps:get(~"aud", Claims, undefined),
    case Aud of
        ExpectedAud ->
            validate_azp(ExpectedAud, Claims);
        AudList when is_list(AudList) ->
            case lists:member(ExpectedAud, AudList) of
                true -> validate_azp(ExpectedAud, Claims);
                false -> {error, invalid_audience}
            end;
        _ ->
            {error, invalid_audience}
    end.

%% OIDC Core 3.1.3.7: when a token carries azp (authorized party), it
%% must equal our client_id. Without this, on an IdP shared with other
%% registered clients, a token minted for a DIFFERENT client that also
%% happens to list our client_id in `aud` would pass the audience check
%% above - a confused-deputy risk. A token with no azp at all has
%% nothing to check here (not every IdP sets it for single-audience
%% tokens), so this only rejects a token that names a different party.
validate_azp(ExpectedAud, Claims) ->
    case maps:get(~"azp", Claims, undefined) of
        undefined -> ok;
        ExpectedAud -> ok;
        _ -> {error, invalid_azp}
    end.

build_actor(AuthMod, Provider, Claims) ->
    Mapping = nova_auth_oidc:config(AuthMod, claims_mapping),
    Base = #{provider => Provider},
    case Mapping of
        M when map_size(M) =:= 0 ->
            Id = maps:get(~"sub", Claims, undefined),
            Base#{id => Id, claims => Claims};
        _ ->
            nova_auth_claims:map(Mapping, Claims, Base)
    end.
