-module(libsnarl).

-export([start/0, discovered/0]).

-export([user_get/1, user_add/1]).

discovered() ->
    mdns_client:discovered(<<"_snarl._zeromq._tcp">>).

start() ->
    application:start(zmq_mdns_client),
    application:start(libsnarl).

user_get(User) ->
    send({user, get, User}).

user_add(User) ->
    send({user, add, User}).


send(Msg) ->
    libsnarl_server:send(Msg).
