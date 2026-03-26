-module(nova_auth_oidc_sup).
-moduledoc ~"""
Supervisor for OIDC provider configuration workers. Each provider gets its
own `oidcc_provider_configuration_worker` child that fetches and caches
the provider's discovery document and JWKS.
""".
-behaviour(supervisor).

-export([start_link/0, start_provider/2]).
-export([init/1]).

-doc false.
start_link() ->
    supervisor:start_link({local, ?MODULE}, ?MODULE, []).

-doc "Start a provider configuration worker as a child of this supervisor.".
-spec start_provider(atom(), binary()) -> {ok, pid()} | {error, term()}.
start_provider(Name, Issuer) ->
    ChildSpec = #{
        id => Name,
        start =>
            {oidcc_provider_configuration_worker, start_link, [
                #{issuer => Issuer, name => {local, Name}}
            ]},
        restart => permanent,
        shutdown => 5000
    },
    supervisor:start_child(?MODULE, ChildSpec).

-doc false.
init([]) ->
    {ok, {#{strategy => one_for_one, intensity => 10, period => 60}, []}}.
