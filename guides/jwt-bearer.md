# JWT Bearer Validation

`nova_auth_oidc_jwt` validates JWTs from the `Authorization: Bearer <token>`
header using the OIDC provider's JWKS. This is useful for protecting API routes
that receive tokens directly from Authentik or other providers.

## Route Protection

Use `nova_auth_oidc_security:require_bearer/1` to protect API routes:

```erlang
#{prefix => ~"/api",
  security => nova_auth_oidc_security:require_bearer(my_oidc_config),
  routes => [
      {~"/resources", fun my_resource_controller:index/1, #{methods => [get]}}
  ]}
```

The security callback extracts the Bearer token, validates it against the
provider's JWKS, checks claims, applies the claims mapping, and passes the
resulting actor as `auth_data`.

## Mixed Session + Bearer

Use `nova_auth_oidc_security:require_any/1` for routes that accept both
browser sessions and API tokens:

```erlang
#{prefix => ~"/api",
  security => nova_auth_oidc_security:require_any(my_oidc_config),
  routes => [...]}
```

This tries session auth first (via `nova_auth_actor:fetch/1`), then falls
back to JWT bearer validation.

## How Validation Works

1. Extract `Authorization: Bearer <token>` header
2. Get the JWKS from the provider's cached configuration worker
3. Verify the JWT signature using `jose_jwt:verify/2`
4. Validate `exp` (not expired) and `aud` (matches client_id)
5. Apply `claims_mapping` from config to build the actor
6. Return `{ok, Actor}` or `{error, Reason}`

## Direct API Usage

You can validate tokens programmatically:

```erlang
%% Validate from request
case nova_auth_oidc_jwt:validate_bearer(my_oidc_config, Req) of
    {ok, Actor} -> handle_authenticated(Actor);
    {error, Reason} -> handle_error(Reason)
end.

%% Validate a specific provider
case nova_auth_oidc_jwt:validate_bearer(my_oidc_config, authentik, Req) of
    {ok, Actor} -> ok;
    {error, _} -> unauthorized
end.

%% Validate a raw token string
case nova_auth_oidc_jwt:validate_token(my_oidc_config, authentik, TokenBinary) of
    {ok, Actor} -> ok;
    {error, _} -> unauthorized
end.
```

## Error Types

| Error | Description |
|-------|-------------|
| `missing_bearer` | No `Authorization: Bearer` header |
| `no_providers` | No providers configured |
| `provider_not_available` | Provider worker not running |
| `invalid_signature` | JWT signature verification failed |
| `missing_exp` | JWT has no `exp` claim |
| `token_expired` | JWT `exp` is in the past |
| `invalid_audience` | JWT `aud` doesn't match client_id |

## JWKS Caching

The JWKS is fetched and cached by the `oidcc_provider_configuration_worker`
(the same worker used for OIDC login flows). Keys are refreshed automatically
when the provider rotates them.
