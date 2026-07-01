-module(nova_auth_oidc_SUITE).
-behaviour(ct_suite).
-include_lib("stdlib/include/assert.hrl").

-export([all/0, groups/0, init_per_suite/1, end_per_suite/1]).
-export([
    config_returns_defaults/1,
    config_merges_user_values/1,
    config_caches_in_persistent_term/1,
    config_key_lookup/1,
    invalidate_cache_clears/1,
    provider_config_found/1,
    provider_config_not_found/1,
    provider_worker_name_format/1,
    redirect_uri_builds_correctly/1
]).

all() ->
    [{group, config_tests}].

groups() ->
    [
        {config_tests, [], [
            config_returns_defaults,
            config_merges_user_values,
            config_caches_in_persistent_term,
            config_key_lookup,
            invalidate_cache_clears,
            provider_config_found,
            provider_config_not_found,
            provider_worker_name_format,
            redirect_uri_builds_correctly
        ]}
    ].

init_per_suite(Config) ->
    Config.

end_per_suite(_Config) ->
    _ =
        (try
            persistent_term:erase({nova_auth_oidc, test_oidc_config})
        catch
            _:_ -> ok
        end),
    ok.

config_returns_defaults(_Config) ->
    clear_cache(),
    Cfg = nova_auth_oidc:config(test_oidc_config),
    ?assertEqual([~"openid", ~"profile", ~"email"], maps:get(scopes, Cfg)),
    ?assertEqual({redirect, ~"/"}, maps:get(on_success, Cfg)),
    ?assertEqual({status, 401}, maps:get(on_failure, Cfg)).

config_merges_user_values(_Config) ->
    clear_cache(),
    Cfg = nova_auth_oidc:config(test_oidc_config),
    ?assertEqual(~"https://myapp.example.com", maps:get(base_url, Cfg)),
    ?assertEqual(~"/auth", maps:get(auth_path_prefix, Cfg)),
    ?assert(maps:is_key(authentik, maps:get(providers, Cfg))),
    ?assert(maps:is_key(google, maps:get(providers, Cfg))).

config_caches_in_persistent_term(_Config) ->
    clear_cache(),
    Cfg1 = nova_auth_oidc:config(test_oidc_config),
    Cfg2 = nova_auth_oidc:config(test_oidc_config),
    ?assertEqual(Cfg1, Cfg2),
    ?assertNotEqual(undefined, persistent_term:get({nova_auth_oidc, test_oidc_config}, undefined)).

config_key_lookup(_Config) ->
    clear_cache(),
    ?assertEqual(~"https://myapp.example.com", nova_auth_oidc:config(test_oidc_config, base_url)).

invalidate_cache_clears(_Config) ->
    clear_cache(),
    _ = nova_auth_oidc:config(test_oidc_config),
    nova_auth_oidc:invalidate_cache(test_oidc_config),
    ?assertEqual(undefined, persistent_term:get({nova_auth_oidc, test_oidc_config}, undefined)).

provider_config_found(_Config) ->
    clear_cache(),
    {ok, Cfg} = nova_auth_oidc:provider_config(test_oidc_config, authentik),
    ?assertEqual(~"test-client-id", maps:get(client_id, Cfg)),
    ?assertEqual(~"https://auth.example.com/application/o/myapp", maps:get(issuer, Cfg)).

provider_config_not_found(_Config) ->
    clear_cache(),
    ?assertEqual({error, not_found}, nova_auth_oidc:provider_config(test_oidc_config, nonexistent)).

provider_worker_name_format(_Config) ->
    Name = nova_auth_oidc:provider_worker_name(test_oidc_config, authentik),
    ?assertEqual(nova_auth_oidc_test_oidc_config_authentik, Name).

redirect_uri_builds_correctly(_Config) ->
    clear_cache(),
    Uri = nova_auth_oidc:redirect_uri(test_oidc_config, authentik),
    ?assertEqual(~"https://myapp.example.com/auth/authentik/callback", Uri).

%%----------------------------------------------------------------------
%% Internal
%%----------------------------------------------------------------------

clear_cache() ->
    _ =
        (try
            persistent_term:erase({nova_auth_oidc, test_oidc_config})
        catch
            _:_ -> ok
        end).
