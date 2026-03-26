# Client Credentials

`nova_auth_oidc_client_credentials` implements the OAuth2 client credentials
grant for machine-to-machine (M2M) authentication. Tokens are cached in
`persistent_term` and automatically refreshed when expired.

## Usage

```erlang
%% Get a cached or fresh access token
{ok, AccessToken} = nova_auth_oidc_client_credentials:get_token(my_oidc_config, authentik).

%% Use it to call another service
Headers = [{~"authorization", <<~"Bearer ", AccessToken/binary>>}],
httpc:request(get, {"https://api.example.com/data", Headers}, [], []).
```

## With Specific Scopes

```erlang
{ok, Token} = nova_auth_oidc_client_credentials:get_token(
    my_oidc_config, authentik, [~"read:users", ~"write:users"]
).
```

## Force Refresh

If a token is rejected (e.g., revoked server-side), force a refresh:

```erlang
{ok, FreshToken} = nova_auth_oidc_client_credentials:refresh(my_oidc_config, authentik).
```

## How Caching Works

1. First call fetches a token from the provider via `oidcc:client_credentials_token/4`
2. Token and expiry are cached in `persistent_term`
3. Subsequent calls return the cached token if it hasn't expired (with 30s buffer)
4. Expired tokens are automatically refreshed on the next call
5. Cache key: `{nova_auth_oidc_cc, AuthMod, Provider}`

## Token Introspection

To check if a received token is still active (not revoked):

```erlang
case nova_auth_oidc_introspect:introspect(my_oidc_config, authentik, ReceivedToken) of
    {ok, #{active := true, username := Username}} ->
        handle_request(Username);
    {ok, #{active := false}} ->
        {status, 401};
    {error, Reason} ->
        logger:error(~"Introspection failed: ~p", [Reason]),
        {status, 500}
end.
```

The introspection response includes:

| Field | Type | Description |
|-------|------|-------------|
| `active` | `boolean()` | Whether the token is active |
| `client_id` | `binary()` | Client that requested the token |
| `exp` | `pos_integer() \| undefined` | Expiration timestamp |
| `scope` | `[binary()]` | Granted scopes |
| `username` | `binary() \| undefined` | Resource owner username |
| `token_type` | `binary() \| undefined` | Token type (e.g., `Bearer`) |
| `iss` | `binary() \| undefined` | Token issuer |
| `extra` | `map()` | Additional provider-specific fields |

## Provider Setup: Authentik

For client credentials in Authentik:

1. Create a new OAuth2 Provider with "Machine-to-machine" flow
2. Under "Advanced protocol settings", enable the `client_credentials` grant type
3. Assign the provider to an Application
4. The client ID and secret from the provider config are used automatically

## Error Handling

```erlang
case nova_auth_oidc_client_credentials:get_token(my_oidc_config, authentik) of
    {ok, Token} ->
        use_token(Token);
    {error, {grant_type_not_supported, client_credentials}} ->
        %% Provider doesn't support client credentials
        logger:error(~"Provider does not support client_credentials grant");
    {error, Reason} ->
        logger:error(~"Failed to get M2M token: ~p", [Reason])
end.
```
