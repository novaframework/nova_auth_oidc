-module(nova_auth_oidc_sup_tests).
-include_lib("eunit/include/eunit.hrl").

build_worker_opts_sets_issuer_and_name_test() ->
    Opts = nova_auth_oidc_sup:build_worker_opts(my_worker, ~"https://issuer.example.com", #{}),
    ?assertEqual(~"https://issuer.example.com", maps:get(issuer, Opts)),
    ?assertEqual({local, my_worker}, maps:get(name, Opts)).

build_worker_opts_threads_extra_opts_test() ->
    Extra = #{provider_configuration_opts => #{request_opts => #{ssl => [verify_peer]}}},
    Opts = nova_auth_oidc_sup:build_worker_opts(my_worker, ~"https://issuer.example.com", Extra),
    ?assertEqual(
        #{request_opts => #{ssl => [verify_peer]}},
        maps:get(provider_configuration_opts, Opts)
    ).

%% asobi#220: the whole point of threading ExtraOpts through is caller-
%% supplied TLS/backoff tuning, never a way to hijack which provider a
%% worker is registered as. issuer/name must win regardless of what a
%% caller passes in ExtraOpts.
build_worker_opts_extra_opts_cannot_override_issuer_or_name_test() ->
    Extra = #{issuer => ~"https://evil.example.com", name => {local, someone_else}},
    Opts = nova_auth_oidc_sup:build_worker_opts(my_worker, ~"https://issuer.example.com", Extra),
    ?assertEqual(~"https://issuer.example.com", maps:get(issuer, Opts)),
    ?assertEqual({local, my_worker}, maps:get(name, Opts)).
