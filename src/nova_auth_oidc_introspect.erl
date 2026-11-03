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

-include_lib("oidcc/include/oidcc_token_introspection.hrl").

-export([introspect/3]).

-doc "Introspect an access token at the provider's introspection endpoint.".
-spec introspect(module(), atom(), binary()) ->
    {ok, map()} | {error, term()}.
introspect(AuthMod, Provider, AccessToken) ->
    WorkerName = nova_auth_oidc:provider_worker_name(AuthMod, Provider),
    {ok, #{client_id := ClientId, client_secret := ClientSecret}} =
        nova_auth_oidc:provider_config(AuthMod, Provider),
    case oidcc:introspect_token(AccessToken, WorkerName, ClientId, ClientSecret, #{}) of
        {ok, Introspection} ->
            {ok, introspection_to_map(Introspection)};
        {error, _} = Err ->
            Err
    end.

%%----------------------------------------------------------------------
%% Internal
%%----------------------------------------------------------------------

introspection_to_map(#oidcc_token_introspection{} = I) ->
    #{
        active => I#oidcc_token_introspection.active,
        client_id => I#oidcc_token_introspection.client_id,
        exp => I#oidcc_token_introspection.exp,
        scope => I#oidcc_token_introspection.scope,
        username => I#oidcc_token_introspection.username,
        token_type => I#oidcc_token_introspection.token_type,
        iss => I#oidcc_token_introspection.iss,
        extra => I#oidcc_token_introspection.extra
    }.
