-module(test_log_capture).

-export([start/0, stop/0, events/0]).
-export([log/2]).

start() ->
    ok = logger:add_handler(?MODULE, ?MODULE, #{config => #{pid => self()}}).

stop() ->
    _ = logger:remove_handler(?MODULE),
    ok.

events() ->
    receive
        {?MODULE, Event} -> [Event | events()]
    after 100 ->
        []
    end.

log(Event, #{config := #{pid := Pid}}) ->
    Pid ! {?MODULE, Event},
    ok.
