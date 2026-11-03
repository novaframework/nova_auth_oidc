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

-include_lib("jose/include/jose_jwk.hrl").
-include_lib("oidcc/include/oidcc_provider_configuration.hrl").
-include_lib("kernel/include/logger.hrl").

-export([validate_bearer/2, validate_bearer/3, validate_token/3]).
-export([init_refresh_table/0]).
%% Exported for tests: standard-claim validation (exp/iss/aud) in isolation.
-export([validate_claims/3]).

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

-define(REFRESH_TABLE, nova_auth_oidc_jwks_refresh).
-define(REFRESH_INTERVAL_MS, 10_000).

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
1. Build an `oidcc` client context from the provider worker's discovery
   document and JWKS
2. Verify the signature (RS*/ES* only) and the standard claims with
   `oidcc_token:validate_jwt/3`: `iss` is the provider's issuer, `aud` holds
   the client_id, `exp` is in the future, `nbf` (if present) is in the past,
   and `iss`, `sub`, `aud`, `exp` and `iat` are present
3. Check the configured issuer, a non-empty `sub`, and `azp`: it must
   equal the client_id when present, and is required when `aud` lists more
   than one audience
4. Apply claims mapping and return the actor map

A token whose `kid` is not in the cached JWKS makes the worker refetch the
JWKS once, so a key the provider just rotated in is accepted. Refetches for
unknown kids are limited to one per provider every 10 seconds, so tokens
with made-up kids cannot make every request fetch the JWKS.
""".
-spec validate_token(module(), atom(), binary()) ->
    {ok, nova_auth:actor()} | {error, term()}.
validate_token(AuthMod, Provider, Token) ->
    WorkerName = nova_auth_oidc:provider_worker_name(AuthMod, Provider),
    {ok, #{client_id := ClientId}} = nova_auth_oidc:provider_config(AuthMod, Provider),
    case client_context(WorkerName, ClientId) of
        {ok, ClientContext} ->
            Opts = #{
                signing_algs => ?ALLOWED_ALGORITHMS,
                refresh_jwks => fun(_Jwks, Kid) -> refresh_jwks(WorkerName, Kid) end
            },
            case validate_jwt(Token, ClientContext, Opts) of
                {ok, Claims} ->
                    case validate_claims(AuthMod, Provider, Claims) of
                        ok -> {ok, build_actor(AuthMod, Provider, Claims)};
                        {error, _} = Err -> Err
                    end;
                {error, Reason} ->
                    ?LOG_DEBUG(#{
                        msg => ~"jwt validation failed",
                        reason_class => error_class(Reason)
                    }),
                    {error, public_error(Reason)}
            end;
        {error, _} = Err ->
            Err
    end.

-doc false.
-spec init_refresh_table() -> ok.
init_refresh_table() ->
    _ = ets:new(?REFRESH_TABLE, [named_table, public, set]),
    ok.

%%----------------------------------------------------------------------
%% Internal
%%----------------------------------------------------------------------

client_context(WorkerName, ClientId) ->
    try
        {
            oidcc_provider_configuration_worker:get_provider_configuration(WorkerName),
            oidcc_provider_configuration_worker:get_jwks(WorkerName)
        }
    of
        {#oidcc_provider_configuration{} = Configuration, #jose_jwk{} = Jwks} ->
            %% Bearer tokens are verified with the provider's public keys
            %% only; an unauthenticated context keeps the client secret out
            %% of the key set.
            {ok, oidcc_client_context:from_manual(Configuration, Jwks, ClientId, unauthenticated)};
        _ ->
            {error, provider_not_available}
    catch
        _:_ -> {error, provider_not_available}
    end.

%% oidcc compares exp and nbf arithmetically and raises on a non-numeric
%% value, which only a token the provider itself signed can carry. jose
%% raises on input that does not parse as a JWS at all.
validate_jwt(Token, ClientContext, Opts) ->
    try
        oidcc_token:validate_jwt(Token, ClientContext, Opts)
    catch
        error:badarith -> {error, invalid_claims};
        error:_ -> {error, malformed_token}
    end.

refresh_jwks(WorkerName, Kid) ->
    case refresh_allowed(WorkerName) of
        true ->
            try
                ok = oidcc_provider_configuration_worker:refresh_jwks_for_unknown_kid(
                    WorkerName, Kid
                ),
                oidcc_provider_configuration_worker:get_jwks(WorkerName)
            of
                #jose_jwk{} = Jwks -> {ok, Jwks};
                _ -> {error, provider_not_available}
            catch
                _:_ -> {error, provider_not_available}
            end;
        false ->
            {error, jwks_refresh_limited}
    end.

%% Claim the slot atomically: of concurrent callers only the one whose
%% insert_new or select_replace writes the row gets to refetch.
refresh_allowed(WorkerName) ->
    Now = erlang:monotonic_time(millisecond),
    Due = [
        {{WorkerName, '$1'}, [{'=<', '$1', Now - ?REFRESH_INTERVAL_MS}], [{{WorkerName, Now}}]}
    ],
    try
        ets:insert_new(?REFRESH_TABLE, {WorkerName, Now}) orelse
            ets:select_replace(?REFRESH_TABLE, Due) =:= 1
    catch
        error:badarg -> false
    end.

%% oidcc's error terms can carry the token's claims, so callers get a fixed
%% atom and the log gets only the tag.
public_error(token_expired) -> token_expired;
public_error(token_not_yet_valid) -> token_not_yet_valid;
public_error(invalid_claims) -> invalid_claims;
public_error({missing_claim, ~"exp", _}) -> missing_exp;
public_error({missing_claim, ~"iat", _}) -> missing_iat;
public_error({missing_claim, ~"sub", _}) -> missing_sub;
public_error({missing_claim, ~"iss", _}) -> invalid_issuer;
public_error({missing_claim, ~"aud", _}) -> invalid_audience;
public_error({missing_claim, {~"iss", _}, _}) -> invalid_issuer;
public_error({missing_claim, {~"aud", _}, _}) -> invalid_audience;
public_error(_Reason) -> invalid_signature.

error_class(Reason) when is_atom(Reason) -> Reason;
error_class(Reason) when is_tuple(Reason), tuple_size(Reason) > 0, is_atom(element(1, Reason)) ->
    element(1, Reason);
error_class(_Reason) ->
    unknown.

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
        [ExpectedAud] ->
            validate_azp(ExpectedAud, Claims);
        AudList when is_list(AudList) ->
            case lists:member(ExpectedAud, AudList) of
                true -> require_azp(ExpectedAud, Claims);
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

%% A token with several audiences was issued for one of them; OIDC Core
%% 3.1.3.7 has azp name which, and only our own client_id is accepted.
require_azp(ExpectedAud, Claims) ->
    case maps:get(~"azp", Claims, undefined) of
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
