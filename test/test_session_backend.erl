-module(test_session_backend).
-behaviour(nova_session).

-export([start/0, stop/0, keys/1]).
-export([get_value/2, set_value/3, delete_value/1, delete_value/2]).

-define(TABLE, ?MODULE).

start() ->
    Parent = self(),
    Pid = spawn(fun() ->
        ets:new(?TABLE, [named_table, public, set]),
        Parent ! {?MODULE, ready},
        receive
            stop -> ok
        end
    end),
    register(test_session_backend_owner, Pid),
    receive
        {?MODULE, ready} -> ok
    end.

stop() ->
    test_session_backend_owner ! stop,
    ok.

keys(SessionId) ->
    [Key || {{Sid, Key}, _} <- ets:tab2list(?TABLE), Sid =:= SessionId].

get_value(SessionId, Key) ->
    case ets:lookup(?TABLE, {SessionId, Key}) of
        [{_, Value}] -> {ok, Value};
        [] -> {error, not_found}
    end.

set_value(SessionId, Key, Value) ->
    true = ets:insert(?TABLE, {{SessionId, Key}, Value}),
    ok.

delete_value(SessionId) ->
    true = ets:match_delete(?TABLE, {{SessionId, '_'}, '_'}),
    ok.

delete_value(SessionId, Key) ->
    true = ets:delete(?TABLE, {SessionId, Key}),
    ok.
