-module(libsnarl).

-export([
         start/0,
         servers/0
        ]).

-export([
         auth/2,
         allowed/2,
         test/2,
         version/0
        ]).

-export([
         token_delete/1
        ]).

-export([
         user_lookup/1,
         user_list/0,
         user_cache/1,
         user_get/1,
         user_add/1,
         user_delete/1,
         user_grant/2,
         user_revoke/2,
         user_passwd/2,
         user_join/2,
         user_leave/2,
         user_set/2,
         user_set/3
        ]).

-export([
         group_list/0,
         group_get/1,
         group_add/1,
         group_delete/1,
         group_grant/2,
         group_revoke/2,
         group_set/2,
         group_set/3
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
-spec start() ->
                   ok.
start() ->
    application:start(libsnarlmatch),
    application:start(mdns_client_lib),
    application:start(libsnarl).

%%--------------------------------------------------------------------
%% @doc Tests cached permissions.
%% @spec test([term()], [[term()]]) -> true | false
%% @end
%%--------------------------------------------------------------------
-spec test(fifo:permission(), [fifo:permission()]) ->
                  true | false.
test(Permission, Permissions) ->
    libsnarlmatch:test_perms(Permission, Permissions).

%%--------------------------------------------------------------------
%% @doc Gets a list of servers
%% @spec servers() -> [term()]
%% @end
%%--------------------------------------------------------------------
-spec servers() ->
                     [term()].
servers() ->
    libsnarl_server:servers().

%%--------------------------------------------------------------------
%% @private
%% @doc Fetches version
%% @spec version() -> binary
%% @end
%%--------------------------------------------------------------------
-spec version() -> binary() |
                   {error, no_servers}.
version() ->
    ServerVersion = send(version),
    ServerVersion.

%%--------------------------------------------------------------------
%% @doc Authenticates a user and returns a token that can be used for
%%  the session.
%% @spec auth(User::binary(), Pass::binary()) ->
%%           {ok, Token::{token, binary()}} |
%%           {error, not_found}
%% @end
%%--------------------------------------------------------------------
-spec auth(User::fifo:user_id(), Pass::binary()) ->
                  not_found |
                  {ok, {token, fifo:user_id()}} |
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
-spec allowed(User::fifo:user_id() | {token, binary()},
              Permission::fifo:permission()) ->
                     {error, no_servers} |
                     not_found |
                     true |
                     false.
allowed(User, Permission) ->
    send({user, allowed, User, Permission}).

%%%===================================================================
%%% Token Functions
%%%===================================================================

%%--------------------------------------------------------------------
%% @doc Deletes a user.
%% @spec token_delete(Token::binary()) ->
%%                    {error, not_found|no_servers} | ok
%% @end
%%--------------------------------------------------------------------

-spec token_delete(Token::fifo:uuid()) ->
                          {error, no_servers} |
                          not_found |
                          ok.
token_delete(Token) ->
    send({token, delete, Token}).

%%%===================================================================
%%% User Functions
%%%===================================================================

%%--------------------------------------------------------------------
%% @doc Sets a attribute for the user.
%% @end
%%--------------------------------------------------------------------
-spec user_set(User::fifo:user_id(),
               Attribute::fifo:key(),
               Value::fifo:value()) ->
                      ok | not_found |
                      {'error','no_servers'}.
user_set(User, Attribute, Value) when
      is_binary(User) ->
    send({user, set, User, Attribute, Value}).

%%--------------------------------------------------------------------
%% @doc Sets multiple attributes for the user.
%% @end
%%--------------------------------------------------------------------
-spec user_set(User::fifo:uuid(),
               Attributes::fifo:attr_list()) ->
                      ok | not_found |
                      {'error','no_servers'}.
user_set(User, Attributes) when
      is_binary(User) ->
    send({user, set, User, Attributes}).

%%--------------------------------------------------------------------
%% @doc Retrievs a list of all user id's.
%% @spec user_list() ->
%%                 [term()]
%% @end
%%--------------------------------------------------------------------
-spec user_list() ->
                       {error, timeout} |
                       {ok, [fifo:user_id()]}.
user_list() ->
    send({user, list}).

%%--------------------------------------------------------------------
%% @doc Retrieves user data from the server.
%% @spec user_get(User::binary()) ->
%%                 {error, not_found|no_servers} | term()
%% @end
%%--------------------------------------------------------------------
-spec user_get(User::fifo:user_id()) ->
                      not_found |
                      {error, no_servers} |
                      {ok, fifo:user()}.
user_get(User) ->
    send({user, get, User}).

%%--------------------------------------------------------------------
%% @doc Retrieves user data from the server.
%% @spec user_get(User::binary()) ->
%%                 {error, not_found|no_servers} | term()
%% @end
%%--------------------------------------------------------------------
-spec user_lookup(User::fifo:user_id()) ->
                         not_found |
                         {error, no_servers} |
                         {ok, fifo:user()}.
user_lookup(User) ->
    send({user, lookup, User}).

%%--------------------------------------------------------------------
%% @doc Retrieves all user permissions to later test.
%% @spec user_get(User::binary()) ->
%%                 {error, not_found|no_servers} | term()
%% @end
%%--------------------------------------------------------------------
-spec user_cache(User::fifo:user_id()) ->
                        {error, no_servers} |
                        not_found |
                        {ok, [fifo:permission()]}.
user_cache(User) ->
    send({user, cache, User}).

%%--------------------------------------------------------------------
%% @doc Adds a new user.
%% @spec user_add(User::binary()) ->
%%                 {error, duplicate} | ok
%% @end
%%--------------------------------------------------------------------
-spec user_add(UserName::binary()) ->
                      {error, no_servers} |
                      duplicate |
                      {ok, UUID::fifo:user_id()}.
user_add(UserName) ->
    send({user, add, UserName}).

%%--------------------------------------------------------------------
%% @doc Deletes a user.
%% @spec user_delete(User::binary()) ->
%%                    {error, not_found|no_servers} | ok
%% @end
%%--------------------------------------------------------------------
-spec user_delete(User::fifo:user_id()) ->
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

-spec user_grant(User::fifo:user_id(),
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
-spec user_revoke(User::fifo:user_id(),
                  Permission::fifo:permission()) ->
                         {error, no_servers} |
                         not_found |
                         ok.
user_revoke(User, Permission) ->
    send({user, revoke, User, Permission}).

%%--------------------------------------------------------------------
%% @doc Changes the Password of a user.
%% @spec user_passwd(User::binary(), Pass::binary()) ->
%%           ok |
%%           {error, not_found|no_servers}
%% @end
%%--------------------------------------------------------------------
-spec user_passwd(User::fifo:user_id(), Pass::binary()) ->
                         {error, no_servers} |
                         not_found |
                         ok.
user_passwd(User, Pass) ->
    send({user, passwd, User, Pass}).

%%--------------------------------------------------------------------
%% @doc Adds a user to a group.
%% @spec user_join(User::binary(), Group::binary()) ->
%%             ok |
%%             {error, not_found|no_servers}
%% @end
%%--------------------------------------------------------------------

-spec user_join(User::fifo:user_id(), Group::fifo:group_id()) ->
                       {error, no_servers} |
                       not_found |
                       ok.
user_join(User, Group) ->
    send({user, join, User, Group}).

%%--------------------------------------------------------------------
%% @doc Removes a user from a group.
%% @spec user_leave(User::binary(), Group::binary()) ->
%%          ok |
%%          {error, not_found|no_servers}
%% @end
%%--------------------------------------------------------------------
-spec user_leave(User::fifo:user_id(), Group::fifo:group_id()) ->
                        {error, no_servers} |
                        not_found |
                        ok.
user_leave(User, Group) ->
    send({user, leave, User, Group}).

%%%===================================================================
%%% Group Functions
%%%===================================================================

%%--------------------------------------------------------------------
%% @doc Sets an attribute on the group.
%% @end
%%--------------------------------------------------------------------
-spec group_set(Group::fifo:group_id(),
                Attribute::fifo:key(),
                Value::fifo:value()) -> ok | not_found |
                                 {'error','no_servers'}.
group_set(Group, Attribute, Value) when
      is_binary(Group) ->
    send({group, set, Group, Attribute, Value}).

%%--------------------------------------------------------------------
%% @doc Sets multiple attributes on the group.
%% @end
%%--------------------------------------------------------------------
-spec group_set(Group::fifo:group_id(),
                Attributes::fifo:attr_list()) ->
                       ok | not_found |
                       {'error','no_servers'}.
group_set(Group, Attributes) when
      is_binary(Group) ->
    send({group, set, Group, Attributes}).

%%--------------------------------------------------------------------
%% @doc Retrievs a list of all group id's.
%% @spec group_list() ->
%%                 [term()]
%% @end
%%--------------------------------------------------------------------
-spec group_list() ->
                        {error, no_servers} |
                        {ok, [fifo:group_id()]}.
group_list() ->
    send({group, list}).

%%--------------------------------------------------------------------
%% @doc Retrieves group data from the server.
%% @spec group_get(Group::binary()) ->
%%                 {error, not_found|no_servers} | term()
%% @end
%%--------------------------------------------------------------------
-spec group_get(Group::fifo:group_id()) ->
                       not_found |
                       {error, no_servers} |
                       {ok, fifo:group()}.
group_get(Group) ->
    send({group, get, Group}).

%%--------------------------------------------------------------------
%% @doc Adds a new group.
%% @spec group_add(Group::binary()) ->
%%                 {error, duplicate} | ok
%% @end
%%--------------------------------------------------------------------
-spec group_add(Group::fifo:group_id()) ->
                       {error, no_servers} |
                       duplicate |
                       ok.
group_add(Group) ->
    send({group, add, Group}).

%%--------------------------------------------------------------------
%% @doc Deletes a group.
%% @spec group_delete(Group::binary()) ->
%%                    {error, not_found|no_servers} | ok
%% @end
%%--------------------------------------------------------------------
-spec group_delete(Group::fifo:group_id()) ->
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
-spec group_grant(Group::fifo:group_id(),
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
-spec group_revoke(Group::fifo:group_id(),
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

-spec send(Msg::fifo:snarl_message()) ->
                  atom() |
                  {ok, Reply::term()} |
                  {error, no_server}.
send(Msg) ->
    case libsnarl_server:call(Msg) of
        {reply, Reply} ->
            Reply;
        E ->
            E
    end.
