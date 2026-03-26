# Getting Started

## Installation

Add `nova_auth_oidc` to your `rebar.config` dependencies:

```erlang
{deps, [
    {nova_auth_oidc, {git, "https://github.com/Taure/nova_auth_oidc.git", {branch, "main"}}}
]}.
```

This pulls in `nova_auth` and `oidcc` as transitive dependencies.

## Configuration

Create a module implementing the `nova_auth_oidc` behaviour:

```erlang
-module(my_oidc_config).
-behaviour(nova_auth_oidc).
-export([config/0]).

config() ->
    #{
        providers => #{
            authentik => #{
                issuer => ~"https://auth.example.com/application/o/myapp",
                client_id => os:getenv("AUTHENTIK_CLIENT_ID"),
                client_secret => os:getenv("AUTHENTIK_CLIENT_SECRET")
            }
        },
        base_url => ~"https://myapp.example.com",
        claims_mapping => #{
            ~"sub" => id,
            ~"email" => email,
            ~"name" => display_name,
            ~"groups" => roles
        }
    }.
```

## Start Providers

In your application's `start/2`, start the OIDC provider workers:

```erlang
-module(my_app).
-behaviour(application).
-export([start/2, stop/1]).

start(_Type, _Args) ->
    nova_auth_oidc:ensure_providers(my_oidc_config),
    my_sup:start_link().

stop(_State) ->
    ok.
```

Each provider gets an `oidcc_provider_configuration_worker` that fetches
and caches the discovery document and JWKS from the provider.

## Routes

Add login and callback routes to your Nova router:

```erlang
routes(_Env) ->
    [
        %% Auth routes (must be public)
        #{prefix => ~"/auth",
          security => false,
          routes => [
              {~"/:provider/login", fun nova_auth_oidc_controller:login/1,
               #{auth_mod => my_oidc_config}},
              {~"/:provider/callback", fun nova_auth_oidc_controller:callback/1,
               #{auth_mod => my_oidc_config}}
          ]},

        %% Protected web routes (session-based)
        #{prefix => ~"/dashboard",
          security => nova_auth_security:require_authenticated(),
          routes => [
              {~"/", fun my_dashboard_controller:index/1, #{methods => [get]}}
          ]},

        %% Protected API routes (JWT bearer)
        #{prefix => ~"/api",
          security => nova_auth_oidc_security:require_bearer(my_oidc_config),
          routes => [
              {~"/resources", fun my_resource_controller:index/1, #{methods => [get]}}
          ]}
    ].
```

The `:provider` path parameter selects which provider to use. With the config
above, the login URL is `/auth/authentik/login`.

## Access Actor in Controllers

After authentication, the actor is available in the request map:

```erlang
index(#{auth_data := Actor} = _Req) ->
    #{id := Id, email := Email} = Actor,
    {json, #{id => Id, email => Email}}.
```

## Provider Setup: Authentik

1. Create an OAuth2/OpenID Provider in Authentik admin
2. Set the redirect URI to `https://myapp.example.com/auth/authentik/callback`
3. Copy the Client ID and Client Secret to your environment variables
4. The issuer URL is `https://your-authentik.example.com/application/o/<slug>`

## Provider Setup: Google

1. Create OAuth 2.0 credentials in Google Cloud Console
2. Set the redirect URI to `https://myapp.example.com/auth/google/callback`
3. The issuer is `https://accounts.google.com`

## Multiple Providers

Add more providers to the config map:

```erlang
config() ->
    #{
        providers => #{
            authentik => #{
                issuer => ~"https://auth.example.com/application/o/myapp",
                client_id => os:getenv("AUTHENTIK_CLIENT_ID"),
                client_secret => os:getenv("AUTHENTIK_CLIENT_SECRET")
            },
            google => #{
                issuer => ~"https://accounts.google.com",
                client_id => os:getenv("GOOGLE_CLIENT_ID"),
                client_secret => os:getenv("GOOGLE_CLIENT_SECRET"),
                scopes => [~"openid", ~"email"]  %% per-provider scope override
            }
        },
        ...
    }.
```

Login URLs: `/auth/authentik/login`, `/auth/google/login`.
