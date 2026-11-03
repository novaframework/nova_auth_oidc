-module(nova_auth_oidc_introspect).
-moduledoc ~"""
Token introspection (RFC 7662). Checks if an access token is active
at the provider (e.g., not revoked or expired).

## Usage

```erlang
case nova_auth_oidc_introspect:introspect(my_oidc_config, authentik, AccessToken) of
    {ok, #{active := true}} -> ok;
    {ok, #{active := false}} -> revoked;
    {error, Reason} -> handle_error(Reason)
end
```
""".

-export([introspect/3]).

-doc """
Introspect an access token at the provider's introspection endpoint.

Returns `{error, unsupported_oidcc_introspection}` if oidcc returns an
introspection record of a shape this module does not know (an oidcc
release that changed the record).
""".
-spec introspect(module(), atom(), binary()) ->
    {ok, map()} | {error, term()}.
introspect(AuthMod, Provider, AccessToken) ->
    WorkerName = nova_auth_oidc:provider_worker_name(AuthMod, Provider),
    {ok, #{client_id := ClientId, client_secret := ClientSecret}} =
        nova_auth_oidc:provider_config(AuthMod, Provider),
    case oidcc:introspect_token(AccessToken, WorkerName, ClientId, ClientSecret, #{}) of
        {ok, Introspection} ->
            introspection_to_map(Introspection);
        {error, _} = Err ->
            Err
    end.

%%----------------------------------------------------------------------
%% Internal
%%----------------------------------------------------------------------

%% Matched as a list: oidcc_token_introspection.hrl types `extra` as
%% `#{binary() := term()}`, which eqwalizer rejects in every module that
%% includes it, and a list keeps the shape check for a future oidcc record.
%% nova_auth_oidc_introspect_tests pins the field order.
introspection_to_map(Introspection) ->
    fields_to_map(tuple_to_list(Introspection)).

fields_to_map([
    oidcc_token_introspection,
    Active,
    ClientId,
    Exp,
    Scope,
    Username,
    TokenType,
    _Iat,
    _Nbf,
    _Sub,
    _Aud,
    Iss,
    _Jti,
    Extra
]) ->
    {ok, #{
        active => Active,
        client_id => ClientId,
        exp => Exp,
        scope => Scope,
        username => Username,
        token_type => TokenType,
        iss => Iss,
        extra => Extra
    }};
fields_to_map(_Other) ->
    {error, unsupported_oidcc_introspection}.
