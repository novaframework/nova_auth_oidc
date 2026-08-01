-module(nova_auth_oidc_ensure_providers_tests).
-include_lib("eunit/include/eunit.hrl").

%% asobi#220 M2: config/1 returning provider_configuration_opts is tested
%% (nova_auth_oidc_SUITE), and build_worker_opts/3 threading it is tested
%% (nova_auth_oidc_sup_tests) - but nothing proved ensure_providers/1
%% actually connects the two. A rename on one side or a dropped maps:get
%% on the other would leave every other test green while silently
%% disabling a caller's trust pinning. Mock the one seam function
%% (start_provider/3) to observe exactly what ensure_providers/1 passes,
%% without needing a real network call.

setup() ->
    clear_cache(),
    meck:new(nova_auth_oidc_sup, [passthrough]),
    ok.

cleanup(_) ->
    meck:unload(nova_auth_oidc_sup),
    clear_cache().

ensure_providers_seam_test_() ->
    {setup, fun setup/0, fun cleanup/1, fun() ->
        Self = self(),
        meck:expect(nova_auth_oidc_sup, start_provider, fun(Name, Issuer, ExtraOpts) ->
            Self ! {start_provider_called, Name, Issuer, ExtraOpts},
            {ok, self()}
        end),

        Cfg = nova_auth_oidc:config(test_oidc_config_tls),
        ExpectedPco = maps:get(provider_configuration_opts, Cfg),
        ?assertNotEqual(#{}, ExpectedPco),

        ok = nova_auth_oidc:ensure_providers(test_oidc_config_tls),

        receive
            {start_provider_called, _Name, _Issuer, ExtraOpts} ->
                ?assertEqual(
                    ExpectedPco,
                    maps:get(provider_configuration_opts, ExtraOpts)
                )
        after 1000 ->
            error(start_provider_never_called)
        end
    end}.

clear_cache() ->
    _ =
        (try
            persistent_term:erase({nova_auth_oidc, test_oidc_config_tls})
        catch
            _:_ -> ok
        end).
