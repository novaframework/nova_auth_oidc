-module(nova_auth_oidc_sup_tests).
-include_lib("eunit/include/eunit.hrl").

build_worker_opts_sets_issuer_and_name_test() ->
    Opts = nova_auth_oidc_sup:build_worker_opts(my_worker, ~"https://issuer.example.com", #{}),
    ?assertEqual(~"https://issuer.example.com", maps:get(issuer, Opts)),
    ?assertEqual({local, my_worker}, maps:get(name, Opts)).

build_worker_opts_threads_extra_opts_test() ->
    %% [{verify, verify_peer}] alone isn't a connectable ssl option list
    %% either (cacerts is also required) - this is deliberately just the
    %% shape-threading check, not a "copy this" example. See
    %% guides/configuration.md for a real, connectable option list.
    Extra = #{provider_configuration_opts => #{request_opts => #{ssl => [{verify, verify_peer}]}}},
    Opts = nova_auth_oidc_sup:build_worker_opts(my_worker, ~"https://issuer.example.com", Extra),
    ?assertEqual(
        #{request_opts => #{ssl => [{verify, verify_peer}]}},
        maps:get(provider_configuration_opts, Opts)
    ).

build_worker_opts_defaults_exponential_backoff_test() ->
    %% oidcc's own default backoff_type is `stop` - paired with this
    %% supervisor's `restart => permanent`, a repeatedly-failing discovery
    %% fetch (unreachable issuer, mismatched CA bundle) would otherwise
    %% crash-loop the whole application in milliseconds. See H1 in the
    %% asobi#220 PR review.
    Opts = nova_auth_oidc_sup:build_worker_opts(my_worker, ~"https://issuer.example.com", #{}),
    ?assertEqual(exponential, maps:get(backoff_type, Opts)),
    ?assert(maps:get(backoff_min, Opts) > 0),
    ?assert(maps:get(backoff_max, Opts) > maps:get(backoff_min, Opts)).

build_worker_opts_caller_backoff_overrides_default_test() ->
    Extra = #{backoff_type => stop},
    Opts = nova_auth_oidc_sup:build_worker_opts(my_worker, ~"https://issuer.example.com", Extra),
    ?assertEqual(stop, maps:get(backoff_type, Opts)).

%% asobi#220: the whole point of threading ExtraOpts through is caller-
%% supplied TLS/backoff tuning, never a way to hijack which provider a
%% worker is registered as. issuer/name must win regardless of what a
%% caller passes in ExtraOpts.
build_worker_opts_extra_opts_cannot_override_issuer_or_name_test() ->
    Extra = #{issuer => ~"https://evil.example.com", name => {local, someone_else}},
    Opts = nova_auth_oidc_sup:build_worker_opts(my_worker, ~"https://issuer.example.com", Extra),
    ?assertEqual(~"https://issuer.example.com", maps:get(issuer, Opts)),
    ?assertEqual({local, my_worker}, maps:get(name, Opts)).
