-module(test_oidc_config_bad_failure).
-behaviour(nova_auth_oidc).

-export([config/0]).

config() ->
    #{
        providers => #{},
        on_failure => {status, ~"401"}
    }.
