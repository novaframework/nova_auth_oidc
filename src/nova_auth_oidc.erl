-module(nova_auth_oidc).
-moduledoc ~"""
Behaviour for OIDC authentication configuration. Implementing modules
define OIDC providers, scopes, and callbacks. Configuration is cached
in persistent_term for fast repeated access.

## Example

```erlang
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
          ~"sub" => id,
          ~"email" => email,
          ~"groups" => roles
      }}.
```
""".

-export([
    config/1,
    config/2,
    invalidate_cache/1,
    provider_config/2,
    provider_worker_name/2,
    redirect_uri/2,
    ensure_providers/1
]).

-type provider_config() :: #{
    issuer := binary(),
    client_id := binary(),
    client_secret := binary(),
    scopes => [binary()],
    extra_params => #{binary() => binary()}
}.

-export_type([provider_config/0]).

-callback config() ->
    #{
        providers := #{atom() => provider_config()},
        base_url => binary(),
        auth_path_prefix => binary(),
        scopes => [binary()],
        on_success => {redirect, binary()},
        on_failure => {status, integer()} | {redirect, binary()},
        claims_mapping => #{binary() => atom()} | {module(), atom()}
    }.

-doc "Return the merged OIDC configuration for `Mod`, caching in persistent_term.".
-spec config(module()) -> map().
config(Mod) ->
    case persistent_term:get({nova_auth_oidc, Mod}, undefined) of
        undefined ->
            Cfg = Mod:config(),
            Defaults = #{
                base_url => ~"http://localhost:8080",
                auth_path_prefix => ~"/auth",
                scopes => [~"openid", ~"profile", ~"email"],
                on_success => {redirect, ~"/"},
                on_failure => {status, 401},
                claims_mapping => #{}
            },
            Merged = maps:merge(Defaults, Cfg),
            persistent_term:put({nova_auth_oidc, Mod}, Merged),
            Merged;
        Cfg ->
            Cfg
    end.

-doc "Return a single config value for `Key` from the OIDC module `Mod`.".
-spec config(module(), atom()) -> term().
config(Mod, Key) ->
    maps:get(Key, config(Mod)).

-doc "Evict the cached configuration for `Mod` from persistent_term.".
-spec invalidate_cache(module()) -> boolean().
invalidate_cache(Mod) ->
    persistent_term:erase({nova_auth_oidc, Mod}).

-doc "Return configuration for a specific provider.".
-spec provider_config(module(), atom()) -> {ok, provider_config()} | {error, not_found}.
provider_config(Mod, Provider) ->
    #{providers := Providers} = config(Mod),
    case maps:find(Provider, Providers) of
        {ok, _} = Ok -> Ok;
        error -> {error, not_found}
    end.

-doc "Return the registered name for a provider's configuration worker.".
-spec provider_worker_name(module(), atom()) -> atom().
provider_worker_name(Mod, Provider) ->
    list_to_atom(
        "nova_auth_oidc_" ++ atom_to_list(Mod) ++ "_" ++ atom_to_list(Provider)
    ).

-doc "Build the callback redirect URI for a provider.".
-spec redirect_uri(module(), atom()) -> binary().
redirect_uri(Mod, Provider) ->
    Cfg = config(Mod),
    BaseUrl = maps:get(base_url, Cfg),
    Prefix = maps:get(auth_path_prefix, Cfg),
    ProviderBin = atom_to_binary(Provider),
    <<BaseUrl/binary, Prefix/binary, "/", ProviderBin/binary, "/callback">>.

-doc """
Start all provider configuration workers for the given auth module.
Call this from your application's `start/2`. Idempotent.
""".
-spec ensure_providers(module()) -> ok.
ensure_providers(Mod) ->
    #{providers := Providers} = config(Mod),
    maps:foreach(
        fun(Name, #{issuer := Issuer}) ->
            WorkerName = provider_worker_name(Mod, Name),
            case whereis(WorkerName) of
                undefined ->
                    {ok, _} = nova_auth_oidc_sup:start_provider(WorkerName, Issuer),
                    ok;
                _Pid ->
                    ok
            end
        end,
        Providers
    ).
