-module(test_oidc_config_bad_pco).
-behaviour(nova_auth_oidc).

-export([config/0]).

%% asobi#220: a typo'd provider_configuration_opts key must fail loud at
%% ensure_providers/1, not silently skip applying trust pinning.
config() ->
    #{
        providers => #{
            authentik => #{
                issuer => ~"https://auth.example.com/application/o/myapp",
                client_id => ~"test-client-id",
                client_secret => ~"test-client-secret"
            }
        },
        base_url => ~"https://myapp.example.com",
        provider_configuration_opts => #{
            ssl => [{verify, verify_peer}]
        }
    }.
