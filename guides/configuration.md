# Configuration

All configuration is provided through the `config/0` callback in your module
implementing `-behaviour(nova_auth_oidc)`. The returned map is merged with
defaults and cached in `persistent_term`.

## Config Keys

| Key | Type | Default | Description |
|-----|------|---------|-------------|
| `providers` | `#{atom() => provider_config()}` | *required* | Map of provider name to config |
| `base_url` | `binary()` | `~"http://localhost:8080"` | Application base URL for callback URIs |
| `auth_path_prefix` | `binary()` | `~"/auth"` | URL prefix for auth routes |
| `scopes` | `[binary()]` | `[~"openid", ~"profile", ~"email"]` | Default OIDC scopes |
| `on_success` | `{redirect, binary()}` | `{redirect, ~"/"}` | Action after successful auth |
| `on_failure` | `{status, 100..599} \| {redirect, binary()}` | `{status, 401}` | Action on a failed callback |
| `claims_mapping` | `#{binary() => atom()} \| {module(), atom()}` | `#{}` | How to map claims to actor |
| `provider_configuration_opts` | `oidcc_provider_configuration:opts()` | `#{}` | Options for every provider's discovery/JWKS fetch - see below |

`on_failure` is checked when the config is first loaded: any other value
raises `{invalid_on_failure, Value}` from `nova_auth_oidc:config/1`. It only
applies to the callback. If the login step cannot build the provider's
authorization URL (for example the provider is unreachable), the login
answers 502 instead.

## Provider discovery/JWKS trust options

On OTP 28+, the discovery/JWKS fetch already verifies TLS against the OS
trust store by default. `provider_configuration_opts` lets you pin explicit
options instead - most commonly a private CA bundle:

```erlang
provider_configuration_opts => #{
    request_opts => #{
        ssl => [
            {verify, verify_peer},
            {cacerts, public_key:cacerts_get()},
            {depth, 4},
            {customize_hostname_check, [
                {match_fun, public_key:pkix_verify_hostname_match_fun(https)}
            ]}
        ]
    }
}
```

**Treat this key as a trust anchor, not just a TLS knob.** Besides
`request_opts`, it also accepts `quirks` (`allow_unsafe_http`,
`document_overrides`, `issuer_regex`), which can downgrade discovery to
plaintext HTTP or override the discovery document's `jwks_uri`. Build it
from static code, never from operator- or env-supplied data.

Applies to every provider `ensure_providers/1` starts; there is no
per-provider override. An unknown key here raises an error at
`ensure_providers/1` rather than silently failing to apply.

## Provider Config

Each provider entry requires:

| Key | Type | Required | Description |
|-----|------|----------|-------------|
| `issuer` | `binary()` | yes | OIDC issuer URL (used for discovery) |
| `client_id` | `binary()` | yes | OAuth2 client ID |
| `client_secret` | `binary()` | yes | OAuth2 client secret |
| `scopes` | `[binary()]` | no | Override default scopes for this provider |
| `extra_params` | `#{binary() => binary()}` | no | Extra query parameters for authorization |

## Full Example

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
        auth_path_prefix => ~"/auth",
        scopes => [~"openid", ~"profile", ~"email"],
        on_success => {redirect, ~"/dashboard"},
        on_failure => {redirect, ~"/login?error=auth_failed"},
        claims_mapping => #{
            ~"sub" => id,
            ~"email" => email,
            ~"name" => display_name,
            ~"groups" => roles
        }
    }.
```

## Session Keys

During the OIDC flow, temporary state is stored in the Nova session:

| Key | Lifetime | Contents |
|-----|----------|----------|
| `oidc_state` | Login to callback | OAuth `state`, compared with the callback's `state` parameter |
| `oidc_nonce` | Login to callback | Cryptographic nonce |
| `oidc_pkce` | Login to callback | PKCE code verifier |
| `oidc_provider` | Login to callback | Provider name |
| `nova_auth_actor` | After callback | Mapped actor (permanent session) |

The temporary keys are single-use: the callback deletes them as soon as the
`state` matches, before it exchanges the code, and a successful callback
then replaces the whole session (see session renewal in the README). A
failed callback deletes them too.
A callback without a matching `state`, without a stored nonce, or for a
different provider than the login started with is an authentication
failure and gets `on_failure`. An unknown `:provider` in the login or
callback path gets a 404.

A failure to retrieve user info after the code exchange is an
authentication failure as well and gets `on_failure`; the callback does not
sign in an actor without claims.

A session holds one login at a time. Starting a login in a second tab
overwrites the first tab's state and nonce, so the first tab's callback
then fails with `on_failure`.

## Session cookie and `response_mode`

The callback must arrive with the session cookie, since the state and
nonce live in the session. Nova's default `SameSite=Lax` cookie is sent on
the top-level GET redirect used by the default `response_mode=query`. It is
not sent on a cross-site POST, so `response_mode=form_post` does not work
with a Lax cookie: every callback fails with `on_failure`.

The callback does not yet check the RFC 9207 `iss` response parameter.
Configure one client per provider, with distinct redirect URIs, which is
what the per-provider callback path gives you.

## Provider Worker Names

Each provider gets a worker process registered as
`nova_auth_oidc_<module>_<provider>`. For example, with module `my_oidc_config`
and provider `authentik`, the worker is `nova_auth_oidc_my_oidc_config_authentik`.

You can retrieve the name programmatically:

```erlang
Name = nova_auth_oidc:provider_worker_name(my_oidc_config, authentik).
```

## Cache Invalidation

Configuration is cached in `persistent_term`. To force a refresh:

```erlang
nova_auth_oidc:invalidate_cache(my_oidc_config).
```
