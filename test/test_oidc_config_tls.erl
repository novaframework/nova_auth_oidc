-module(test_oidc_config_tls).
-behaviour(nova_auth_oidc).

-export([config/0]).

%% asobi#220: a caller supplying explicit discovery/JWKS TLS options via
%% provider_configuration_opts, distinct from test_oidc_config (which
%% leaves it at the default #{}).
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
            request_opts => #{ssl => [verify_peer]}
        }
    }.
