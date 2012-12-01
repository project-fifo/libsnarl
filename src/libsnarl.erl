-module(libsnarl).

-export([
	 start/0,
	 servers/0
	]).

-export([
	 auth/2,
	 allowed/2,
	 test/2
	]).

-export([
	 user_list/0,
	 user_cache/1,
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

%%--------------------------------------------------------------------
%% @private
%% @doc Starts the service.
%% @spec start() -> ok
%% @end
%%--------------------------------------------------------------------

-spec start() -> ok.
start() ->
    application:start(libsnarlmatch),
    application:start(mdns_client_lib),
    application:start(libsnarl).

%%--------------------------------------------------------------------
%% @doc Tests cached permissions.
%% @spec test([term()], [[term()]]) -> true | false
%% @end
%%--------------------------------------------------------------------

-spec test(fifo:permission(), [fifo:permission()]) -> true | false.

test(Permission, Permissions) ->
    libsnarlmatch:test_perms(Permission, Permissions).
%%--------------------------------------------------------------------
%% @doc Gets a list of servers
%% @spec servers() -> [term()]
%% @end
%%--------------------------------------------------------------------

-spec servers() -> [term()].

servers() ->
    libsnarl_server:servers().

%%--------------------------------------------------------------------
%% @doc Authenticates a user and returns a token that can be used for
%%  the session.
%% @spec auth(User::binary(), Pass::binary()) ->
%%		     {ok, Token::{token, binary()}} |
%%		     {error, not_found}
%% @end
%%--------------------------------------------------------------------

-spec auth(User::binary(), Pass::binary()) ->
		  {ok, not_found | {token, binary()}} |
		  {error, no_servers}.

auth(User, Pass) ->
    send({user, auth, User, Pass}).

%%--------------------------------------------------------------------
%% @doc Checks if the user has the given permission.
%% @spec allowed(User::binary(),
%%                Permission::[atom()|binary()|string()]) ->
%%                 {error, not_found|no_servers} | term()
%% @end
%%--------------------------------------------------------------------

-spec allowed(User::binary() | {token, binary()},
	      Permission::fifo:permission()) ->
		     {error, no_servers} |
		     not_found |
		     true |
		     false.

allowed(User, Permission) ->
    send({user, allowed, User, Permission}).

%%%===================================================================
%%% User Functions
%%%===================================================================

%%--------------------------------------------------------------------
%% @doc Retrievs a list of all user id's.
%% @spec user_list() ->
%%                 [term()]
%% @end
%%--------------------------------------------------------------------

-spec user_list() -> {error, timeout} |
		     {ok, [term()]}.
user_list() ->
    send({user, list}).

%%--------------------------------------------------------------------
%% @doc Retrieves user data from the server.
%% @spec user_get(User::binary()) ->
%%                 {error, not_found|no_servers} | term()
%% @end
%%--------------------------------------------------------------------

-spec user_get(User::binary()) ->
		       {error, no_servers} |
		       {ok, not_found | term()}.
user_get(User) ->
    send({user, get, User}).

%%--------------------------------------------------------------------
%% @doc Retrieves all user permissions to later test.
%% @spec user_get(User::binary()) ->
%%                 {error, not_found|no_servers} | term()
%% @end
%%--------------------------------------------------------------------

-spec user_cache(User::binary()) ->
			{error, no_servers} |
			not_found |
			{ok, [fifo:permission()]}.
user_cache(User) ->
    send({user, cache, User}).

%%--------------------------------------------------------------------
%% @doc Adds a new user.
%% @spec user_add(User::binary()) ->
%%                 {error, doublicate} | ok
%% @end
%%--------------------------------------------------------------------

-spec user_add(User::binary()) ->
		      {error, no_servers} |
		      doublicate |
		      ok.
user_add(User) ->
    send({user, add, User}).

%%--------------------------------------------------------------------
%% @doc Deletes a user.
%% @spec user_delete(User::binary()) ->
%%                    {error, not_found|no_servers} | ok
%% @end
%%--------------------------------------------------------------------

-spec user_delete(User::binary()) ->
			 {error, no_servers} |
			 not_found |
			 ok.
user_delete(User) ->
    send({user, delete, User}).

%%--------------------------------------------------------------------
%% @doc Grants a right of a user.
%% @spec user_grant(User::binary(),
%%                  Permission::[atom()|binary()|string()]) ->
%%                  {error, not_found|no_servers} | ok
%% @end
%%--------------------------------------------------------------------

-spec user_grant(User::binary(),
		 Permission::fifo:permission()) ->
			{error, no_servers} |
			not_found |
			ok.
user_grant(User, Permission) ->
    send({user, grant, User, Permission}).

%%--------------------------------------------------------------------
%% @doc Revokes a right of a user.
%% @spec user_revoke(User::binary(),
%%                   Permission::[atom()|binary()|string()]) ->
%%                   {error, not_found|no_servers} | ok
%% @end
%%--------------------------------------------------------------------

-spec user_revoke(User::binary(),
		  Permission::fifo:permission()) ->
			 {error, no_servers} |
			 not_found |
			 ok.

user_revoke(User, Permission) ->
    send({user, revoke, User, Permission}).

%%--------------------------------------------------------------------
%% @doc Changes the Password of a user.
%% @spec user_passwd(User::binary(), Pass::binary()) ->
%%		     ok |
%%		     {error, not_found|no_servers}
%% @end
%%--------------------------------------------------------------------

-spec user_passwd(User::binary(), Pass::binary()) ->
			 {error, no_servers} |
			 not_found |
			 ok.

user_passwd(User, Pass) ->
    send({user, passwd, User, Pass}).

%%--------------------------------------------------------------------
%% @doc Adds a user to a group.
%% @spec user_join(User::binary(), Group::binary()) ->
%%		       ok |
%%		       {error, not_found|no_servers}
%% @end
%%--------------------------------------------------------------------

-spec user_join(User::binary(), Group::binary()) ->
			 {error, no_servers} |
			 not_found |
			 ok.
user_join(User, Group) ->
    send({user, join, User, Group}).

%%--------------------------------------------------------------------
%% @doc Removes a user from a group.
%% @spec user_leave(User::binary(), Group::binary()) ->
%%			ok |
%%			{error, not_found|no_servers}
%% @end
%%--------------------------------------------------------------------

-spec user_leave(User::binary(), Group::binary()) ->
			 {error, no_servers} |
			 not_found |
			 ok.
user_leave(User, Group) ->
    send({user, leave, User, Group}).

%%%===================================================================
%%% Group Functions
%%%===================================================================

%%--------------------------------------------------------------------
%% @doc Retrievs a list of all group id's.
%% @spec group_list() ->
%%                 [term()]
%% @end
%%--------------------------------------------------------------------

-spec group_list() -> {error, not_found} |
		      not_found |
		      {ok, [binary()]}.
group_list() ->
    send({group, list}).

%%--------------------------------------------------------------------
%% @doc Retrieves group data from the server.
%% @spec group_get(Group::binary()) ->
%%                 {error, not_found|no_servers} | term()
%% @end
%%--------------------------------------------------------------------

-spec group_get(Group::binary()) ->
		       {error, no_servers} |
		       not_found |
		       {ok, term()}.
group_get(Group) ->
    send({group, get, Group}).

%%--------------------------------------------------------------------
%% @doc Adds a new group.
%% @spec group_add(Group::binary()) ->
%%                 {error, doublicate} | ok
%% @end
%%--------------------------------------------------------------------

-spec group_add(Group::binary()) ->
		       {error, no_servers} |
		       doublicate |
		       ok.
group_add(Group) ->
    send({group, add, Group}).

%%--------------------------------------------------------------------
%% @doc Deletes a group.
%% @spec group_delete(Group::binary()) ->
%%                    {error, not_found|no_servers} | ok
%% @end
%%--------------------------------------------------------------------

-spec group_delete(Group::binary()) ->
			  {error, no_servers} |
			  not_found |
			  ok.
group_delete(Group) ->
    send({group, delete, Group}).

%%--------------------------------------------------------------------
%% @doc Grants a right of a group.
%% @spec group_grant(Group::binary(),
%%                   Permission::[atom()|binary()|string()]) ->
%%                   {error, not_found|no_servers} | ok
%% @end
%%--------------------------------------------------------------------

-spec group_grant(Group::binary(),
		  Permission::fifo:permission()) ->
			 {error, no_servers} |
			 not_found |
			 ok.
group_grant(Group, Permission) ->
    send({group, grant, Group, Permission}).

%%--------------------------------------------------------------------
%% @doc Revokes a right of a group.
%% @spec group_revoke(Group::binary(),
%%                    Permission::[atom()|binary()|string()]) ->
%%                    {error, not_found|no_servers} | ok
%% @end
%%--------------------------------------------------------------------

-spec group_revoke(Group::binary(),
                   Permission::fifo:permission()) ->
			  {error, no_servers} |
			  not_found |
			  ok.
group_revoke(Group, Permission) ->
    send({group, revoke, Group, Permission}).

%%%===================================================================
%%% Internal Functions
%%%===================================================================

%%--------------------------------------------------------------------
%% @private
%% @doc Sends a message.
%% @spec send(Msg::term()) -> {ok, Reply::term()} | {error, no_server}
%% @end
%%--------------------------------------------------------------------

-spec send(Msg::fifo:smarl_message()) ->
		  ok |
		  not_found |
		  doublicate |
		  {ok, Reply::term()} |
		  {error, no_server}.
send(Msg) ->
    case libsnarl_server:call(Msg) of
	{reply, Reply} ->
	    Reply;
	E ->
	    E
    end.
