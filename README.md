# nova_auth_oidc

OpenID Connect authentication for [Nova](https://github.com/novaframework/nova) web applications.

Provides OIDC login flows, JWT bearer validation, token introspection, and
client credentials (M2M) -- all integrated with [nova_auth](https://github.com/Taure/nova_auth)'s
unified actor session.

## Features

- **Multi-provider OIDC** -- Authentik, Google, GitHub, Keycloak, etc.
- **JWT bearer validation** -- protect API routes with provider-issued JWTs
- **Token introspection** -- check revocation status (RFC 7662)
- **Client credentials** -- machine-to-machine tokens with caching
- **Claims mapping** -- transform provider claims to actor maps via [nova_auth_claims](https://github.com/Taure/nova_auth)
- **Nova integration** -- security callbacks, plugins, route protection

## Quick Start

```erlang
%% 1. Define your OIDC config
-module(my_oidc_config).
-behaviour(nova_auth_oidc).
-export([config/0]).

config() ->
    #{providers => #{
          authentik => #{
              issuer => ~"https://auth.example.com/application/o/myapp",
              client_id => os:getenv("AUTHENTIK_CLIENT_ID"),
              client_secret => os:getenv("AUTHENTIK_CLIENT_SECRET")
          }
      },
      base_url => ~"https://myapp.example.com",
      claims_mapping => #{
          ~"sub" => id, ~"email" => email, ~"groups" => roles
      }}.

%% 2. Start providers in your app's start/2
start(_Type, _Args) ->
    nova_auth_oidc:ensure_providers(my_oidc_config),
    my_sup:start_link().

%% 3. Add routes
routes(_Env) ->
    [#{prefix => ~"/auth", security => false,
       routes => [
           {~"/:provider/login", fun nova_auth_oidc_controller:login/1,
            #{auth_mod => my_oidc_config}},
           {~"/:provider/callback", fun nova_auth_oidc_controller:callback/1,
            #{auth_mod => my_oidc_config}}
       ]},
     #{prefix => ~"/dashboard",
       security => nova_auth_security:require_authenticated(),
       routes => [...]},
     #{prefix => ~"/api",
       security => nova_auth_oidc_security:require_bearer(my_oidc_config),
       routes => [...]}].
```

## Modules

| Module | Description |
|--------|-------------|
| `nova_auth_oidc` | Behaviour-based config, provider worker management |
| `nova_auth_oidc_controller` | Login redirect and OAuth callback endpoints |
| `nova_auth_oidc_plugin` | Route protection plugin (session-based) |
| `nova_auth_oidc_jwt` | JWT bearer token validation via provider JWKS |
| `nova_auth_oidc_security` | Security callbacks: `require_bearer/1`, `require_any/1` |
| `nova_auth_oidc_introspect` | Token introspection (RFC 7662) |
| `nova_auth_oidc_client_credentials` | Client credentials flow with caching |

## How It Works

1. User visits `/auth/authentik/login`
2. Controller generates nonce + PKCE, stores in session, redirects to provider
3. User authenticates at Authentik
4. Authentik redirects to `/auth/authentik/callback?code=...`
5. Controller exchanges code for tokens via `oidcc`
6. Controller retrieves userinfo from provider
7. Claims are mapped to an actor via `nova_auth_claims`
8. Actor is stored in session via `nova_auth_actor`
9. User is redirected to the success URL

From this point, `nova_auth_security:require_authenticated()` works for all
protected routes.

## Guides

- [Getting Started](guides/getting-started.md) -- Installation and first setup
- [Configuration](guides/configuration.md) -- Full config reference
- [JWT Bearer](guides/jwt-bearer.md) -- Protecting API routes with JWTs
- [Claims Mapping](guides/claims-mapping.md) -- Transforming provider claims
- [Client Credentials](guides/client-credentials.md) -- Machine-to-machine auth

## Dependencies

- [nova_auth](https://github.com/Taure/nova_auth) -- unified actor session, claims mapping, policies
- [oidcc](https://github.com/erlef/oidcc) -- ERLEF OpenID Connect Certified client
- [nova](https://github.com/novaframework/nova) -- web framework

## Requirements

- Erlang/OTP 28+

## License

MIT
