-module(libsnarl).

-export([
	 start/0, 
	 servers/0
	]).


-export([
	 auth/2,
	 allowed/2
	]).

-export([
	 user_list/0,
	 user_get/1,
	 user_add/1,
	 user_delete/1,
	 user_grant/2,
	 user_revoke/2,
	 user_passwd/2,
	 user_join/2,
	 user_leave/2
	]).

-export([
	 group_list/0,
	 group_get/1,
	 group_add/1,
	 group_delete/1,
	 group_grant/2,
	 group_revoke/2
	]).

%%%===================================================================
%%% Generatl Functions
%%%===================================================================

start() ->
    application:start(zmq_mdns_client),
    application:start(libsnarl).

servers() ->
    libsnarl_server:servers().

auth(User, Pass) ->
    send({user, auth, User, Pass}).

allowed(User, Permission) ->
    send({user, allowed, User, Permission}).

%%%===================================================================
%%% User Functions
%%%===================================================================

user_list() ->
    send({user, list}).

user_get(User) ->
    send({user, get, User}).

user_add(User) ->
    send({user, add, User}).

user_delete(User) ->
    send({user, delete, User}).

user_grant(User, Permission) ->
    send({user, grant, User, Permission}).

user_revoke(User, Permission) ->
    send({user, revoke, User, Permission}).

user_passwd(User, Pass) ->
    send({user, passwd, User, Pass}).

user_join(User, Group) ->
    send({user, join, User, Group}).

user_leave(User, Group) ->
    send({user, leave, User, Group}).

%%%===================================================================
%%% Group Functions
%%%===================================================================

group_list() ->
    send({group, list}).

group_get(Group) ->
    send({group, get, Group}).

group_add(Group) ->
    send({group, add, Group}).

group_delete(Group) ->
    send({group, delete, Group}).

group_grant(Group, Permission) ->
    send({group, grant, Group, Permission}).

group_revoke(Group, Permission) ->
    send({group, revoke, Group, Permission}).


%%%===================================================================
%%% Internal Functions
%%%===================================================================

send(Msg) ->
    libsnarl_server:send(Msg).
