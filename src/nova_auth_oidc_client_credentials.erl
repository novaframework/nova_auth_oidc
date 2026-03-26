-module(nova_auth_oidc_client_credentials).
-moduledoc ~"""
Client credentials flow for machine-to-machine authentication.
Obtains and caches access tokens using the OAuth2 client credentials grant.

## Usage

```erlang
{ok, AccessToken} = nova_auth_oidc_client_credentials:get_token(my_oidc_config, authentik),
%% Use AccessToken to call another service
```
""".

-include_lib("oidcc/include/oidcc_token.hrl").

-export([get_token/2, get_token/3, refresh/2]).

-doc "Get a (possibly cached) M2M access token for the given provider.".
-spec get_token(module(), atom()) -> {ok, binary()} | {error, term()}.
get_token(AuthMod, Provider) ->
    get_token(AuthMod, Provider, []).

-doc "Get a M2M access token with specific scopes.".
-spec get_token(module(), atom(), [binary()]) -> {ok, binary()} | {error, term()}.
get_token(AuthMod, Provider, Scopes) ->
    CacheKey = {nova_auth_oidc_cc, AuthMod, Provider},
    Now = erlang:system_time(second),
    case persistent_term:get(CacheKey, undefined) of
        #{token := Token, expires_at := ExpiresAt} when ExpiresAt > Now + 30 ->
            {ok, Token};
        _ ->
            fetch_and_cache(AuthMod, Provider, Scopes, CacheKey)
    end.

-doc "Force refresh the cached M2M token.".
-spec refresh(module(), atom()) -> {ok, binary()} | {error, term()}.
refresh(AuthMod, Provider) ->
    CacheKey = {nova_auth_oidc_cc, AuthMod, Provider},
    persistent_term:erase(CacheKey),
    get_token(AuthMod, Provider).

%%----------------------------------------------------------------------
%% Internal
%%----------------------------------------------------------------------

fetch_and_cache(AuthMod, Provider, Scopes, CacheKey) ->
    WorkerName = nova_auth_oidc:provider_worker_name(AuthMod, Provider),
    {ok, #{client_id := ClientId, client_secret := ClientSecret}} =
        nova_auth_oidc:provider_config(AuthMod, Provider),
    Opts =
        case Scopes of
            [] -> #{};
            _ -> #{scope => Scopes}
        end,
    case oidcc:client_credentials_token(WorkerName, ClientId, ClientSecret, Opts) of
        {ok, Token} ->
            AccessToken = extract_access_token(Token),
            ExpiresIn = extract_expires_in(Token),
            Now = erlang:system_time(second),
            persistent_term:put(CacheKey, #{
                token => AccessToken,
                expires_at => Now + ExpiresIn
            }),
            {ok, AccessToken};
        {error, _} = Err ->
            Err
    end.

extract_access_token(#oidcc_token{access = #oidcc_token_access{token = AccessToken}}) ->
    AccessToken.

extract_expires_in(#oidcc_token{access = #oidcc_token_access{expires = undefined}}) ->
    3600;
extract_expires_in(#oidcc_token{access = #oidcc_token_access{expires = Expires}}) ->
    Expires.
