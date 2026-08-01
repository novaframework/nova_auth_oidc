-module(nova_auth_oidc_sup).
-moduledoc ~"""
Supervisor for OIDC provider configuration workers. Each provider gets its
own `oidcc_provider_configuration_worker` child that fetches and caches
the provider's discovery document and JWKS.
""".
-behaviour(supervisor).

-export([start_link/0, start_provider/2, start_provider/3]).
-ifdef(TEST).
-export([build_worker_opts/3]).
-endif.
-export([init/1]).

%% Everything oidcc_provider_configuration_worker:opts/0 accepts EXCEPT
%% `issuer`/`name` - this supervisor owns those two identity fields (they
%% come from start_provider/2,3's own arguments), so a caller-supplied
%% ExtraOpts is deliberately typed to exclude them rather than reusing
%% opts/0 wholesale, which would wrongly require callers to pass an
%% `issuer` they don't have yet.
-type extra_worker_opts() :: #{
    provider_configuration_opts => oidcc_provider_configuration:opts(),
    backoff_min => oidcc_backoff:min(),
    backoff_max => oidcc_backoff:max(),
    backoff_type => oidcc_backoff:type()
}.

-export_type([extra_worker_opts/0]).

%% oidcc's own default backoff_type is `stop` - combined with `restart =>
%% permanent` below, a discovery fetch that keeps failing (unreachable
%% issuer, or a caller-supplied CA bundle that doesn't match, entirely
%% possible now that ExtraOpts can carry one) restarts the worker
%% immediately with zero delay between attempts, blows through this
%% supervisor's restart intensity in milliseconds, and takes the whole
%% nova_auth_oidc application down with it. Exponential backoff is the
%% floor for "an IdP blip doesn't crash-loop the consuming node"; a
%% caller-supplied backoff_* in ExtraOpts still wins over these.
-define(DEFAULT_BACKOFF, #{
    backoff_min => 1_000,
    backoff_max => 30_000,
    backoff_type => exponential
}).

-doc false.
start_link() ->
    supervisor:start_link({local, ?MODULE}, ?MODULE, []).

-doc "Start a provider configuration worker as a child of this supervisor.".
-spec start_provider(atom(), binary()) -> supervisor:startchild_ret().
start_provider(Name, Issuer) ->
    start_provider(Name, Issuer, #{}).

-doc """
Start a provider configuration worker, threading extra
`oidcc_provider_configuration_worker` options alongside the required
`issuer`/`name` - most notably `provider_configuration_opts => #{request_opts
=> #{ssl => [...]}}` to pin the discovery/JWKS fetch to an explicit CA bundle
instead of the OS trust store. See `nova_auth_oidc`'s moduledoc for why this
key must be treated as a trust anchor, not just a TLS knob.

`ExtraOpts` cannot override `issuer` or `name`: this supervisor owns those two
identity fields, so they are applied after merging in `ExtraOpts`.

Prefer `certfile`/`keyfile` paths over inline key material (`{key, ...}`,
`{password, ...}`) in the `ssl` option list: `ExtraOpts` is echoed verbatim
in this supervisor's crash/restart SASL reports, so inline secrets end up in
logs and crash dumps every time the worker restarts.
""".
-spec start_provider(atom(), binary(), extra_worker_opts()) -> supervisor:startchild_ret().
start_provider(Name, Issuer, ExtraOpts) ->
    Opts = build_worker_opts(Name, Issuer, ExtraOpts),
    ChildSpec = #{
        id => Name,
        start => {oidcc_provider_configuration_worker, start_link, [Opts]},
        restart => permanent,
        shutdown => 5000
    },
    supervisor:start_child(?MODULE, ChildSpec).

-spec build_worker_opts(atom(), binary(), extra_worker_opts()) ->
    oidcc_provider_configuration_worker:opts().
build_worker_opts(Name, Issuer, ExtraOpts) ->
    maps:merge(
        maps:merge(?DEFAULT_BACKOFF, ExtraOpts),
        #{issuer => Issuer, name => {local, Name}}
    ).

-doc false.
init([]) ->
    {ok, {#{strategy => one_for_one, intensity => 10, period => 60}, []}}.
