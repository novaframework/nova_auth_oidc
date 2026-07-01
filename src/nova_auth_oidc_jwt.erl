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

-export([validate_bearer/2, validate_bearer/3, validate_token/3]).
%% Exported for tests: standard-claim validation (exp/iss/aud) in isolation.
-export([validate_claims/3]).

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
            case jose_jwt:verify(Jwks, Token) of
                {true, Jwt, _Jws} ->
                    Claims = Jwt#jose_jwt.fields,
                    case validate_claims(AuthMod, Provider, Claims) of
                        ok ->
                            Actor = build_actor(AuthMod, Provider, Claims),
                            {ok, Actor};
                        {error, _} = Err ->
                            Err
                    end;
                {false, _, _} ->
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

validate_claims(AuthMod, Provider, Claims) ->
    Now = erlang:system_time(second),
    case maps:get(~"exp", Claims, undefined) of
        undefined ->
            {error, missing_exp};
        Exp when Exp =< Now ->
            {error, token_expired};
        _ ->
            validate_issuer(AuthMod, Provider, Claims)
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
            ok;
        AudList when is_list(AudList) ->
            case lists:member(ExpectedAud, AudList) of
                true -> ok;
                false -> {error, invalid_audience}
            end;
        _ ->
            {error, invalid_audience}
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
