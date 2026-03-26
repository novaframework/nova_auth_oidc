-module(test_oidc_config).
-behaviour(nova_auth_oidc).

-export([config/0]).

config() ->
    #{
        providers => #{
            authentik => #{
                issuer => ~"https://auth.example.com/application/o/myapp",
                client_id => ~"test-client-id",
                client_secret => ~"test-client-secret"
            },
            google => #{
                issuer => ~"https://accounts.google.com",
                client_id => ~"google-client-id",
                client_secret => ~"google-client-secret",
                scopes => [~"openid", ~"email"]
            }
        },
        base_url => ~"https://myapp.example.com",
        auth_path_prefix => ~"/auth",
        claims_mapping => #{
            ~"sub" => id,
            ~"email" => email,
            ~"groups" => roles
        }
    }.
