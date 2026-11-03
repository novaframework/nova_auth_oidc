-module(test_failing_session_backend).
-behaviour(nova_session).

-export([get_value/2, set_value/3, delete_value/1, delete_value/2]).

get_value(SessionId, Key) ->
    test_session_backend:get_value(SessionId, Key).

set_value(_SessionId, ~"nova_auth_actor", _Value) ->
    {error, backend_down};
set_value(SessionId, Key, Value) ->
    test_session_backend:set_value(SessionId, Key, Value).

delete_value(SessionId) ->
    test_session_backend:delete_value(SessionId).

delete_value(SessionId, Key) ->
    test_session_backend:delete_value(SessionId, Key).
