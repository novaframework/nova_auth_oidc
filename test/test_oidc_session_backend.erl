-module(test_oidc_session_backend).
-behaviour(nova_session).

-export([start/0, stop/0]).
-export([get_value/2, set_value/3, delete_value/1, delete_value/2]).

start() ->
    _ = ets:new(?MODULE, [named_table, public, set]),
    application:set_env(nova, session_manager, ?MODULE).

stop() ->
    application:unset_env(nova, session_manager),
    true = ets:delete(?MODULE),
    ok.

get_value(SessionId, Key) ->
    case ets:lookup(?MODULE, {SessionId, Key}) of
        [{_, Value}] -> {ok, Value};
        [] -> {error, not_found}
    end.

set_value(SessionId, Key, Value) ->
    true = ets:insert(?MODULE, {{SessionId, Key}, Value}),
    ok.

delete_value(SessionId) ->
    true = ets:match_delete(?MODULE, {{SessionId, '_'}, '_'}),
    ok.

delete_value(SessionId, Key) ->
    true = ets:delete(?MODULE, {SessionId, Key}),
    ok.
