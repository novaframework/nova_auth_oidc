# nova_auth_oidc

OpenID Connect authentication for [Nova](https://github.com/novaframework/nova) web applications.

Provides OIDC login flows, JWT bearer validation, token introspection, and
client credentials (M2M) — all integrated with [nova_auth](https://github.com/Taure/nova_auth)'s
unified actor session.

## Features

- **Multi-provider OIDC** — Authentik, Google, GitHub, Keycloak, etc.
- **JWT bearer validation** — protect API routes with provider-issued JWTs
- **Token introspection** — check revocation status (RFC 7662)
- **Client credentials** — machine-to-machine tokens with caching
- **Claims mapping** — transform provider claims to actor maps
- **Nova integration** — security callbacks, plugins, route protection

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

## Dependencies

- [nova_auth](https://github.com/Taure/nova_auth) — unified actor session
- [oidcc](https://github.com/erlef/oidcc) — ERLEF OpenID Connect Certified client
- [nova](https://github.com/novaframework/nova) — web framework

## License

MIT
