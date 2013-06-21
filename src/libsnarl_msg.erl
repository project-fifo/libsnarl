-module(libsnarl_msg).

-export([
         auth/2,
         allowed/2
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
         user_revoke_prefix/2,
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
         group_revoke_prefix/2,
         group_set/2,
         group_set/3
        ]).

-define(User, <<User:36/binary>>).
-define(Group, <<Group:36/binary>>).
-define(Token, {token, <<_:36/binary>>} = Token).


%%%===================================================================
%%% Generatl Functions
%%%===================================================================

-spec auth(Login::binary(), Pass::binary()) ->
                  {user, auth, Login::binary(), Pass::binary()}.
auth(Login, Pass) when
      is_binary(Login),
      is_binary(Pass)->
    {user, auth, Login, Pass}.

-spec allowed(User::fifo:user_token_id(),
              Permission::fifo:permission()) ->
                     {user, allowed,
                      User::fifo:user_token_id(),
                      Permission::fifo:permission()}.

allowed(?Token, Permission)
  when is_list(Permission) ->
    {user, allowed, {token, Token}, Permission};

allowed(?User, Permission)
  when is_list(Permission) ->
    {user, allowed, User, Permission}.

%%%===================================================================
%%% Token Functions
%%%===================================================================

-spec token_delete(Token::fifo:token()) ->
    {token, delete, Token::fifo:token()}.
token_delete(<<Token:36/binary>>) ->
    {token, delete, Token}.

%%%===================================================================
%%% User Functions
%%%===================================================================

%%--------------------------------------------------------------------
%% @doc Sets a attribute for the user.
%% @end
%%--------------------------------------------------------------------
-spec user_set(User::fifo:user_id(),
               Attribute::fifo:keys(),
               Value::fifo:value()) ->
                      {user, set, User::fifo:user_id(),
                       Attribute::fifo:keys(),
                       Value::fifo:value()}.
user_set(?User, Attribute, Value) ->
    {user, set, User, Attribute, Value}.

%%--------------------------------------------------------------------
%% @doc Sets multiple attributes for the user.
%% @end
%%--------------------------------------------------------------------
-spec user_set(User::fifo:user_id(),
               Attributes::fifo:attr_list()) ->
                      {user, set,
                       User::fifo:uuid(),
                       Attributes::fifo:attr_list()}.
user_set(?User, Attributes) ->
    {user, set, User, Attributes}.

%%--------------------------------------------------------------------
%% @doc Retrievs a list of all user id's.
%% @spec user_list() ->
%%                 [term()]
%% @end
%%--------------------------------------------------------------------
-spec user_list() ->
                       {user, list}.
user_list() ->
    {user, list}.

%%--------------------------------------------------------------------
%% @doc Retrieves user data from the server.
%% @end
%%--------------------------------------------------------------------
-spec user_get(User::fifo:user_token_id()) ->
                      {user, get, User::fifo:user_token_id()}.
user_get(?Token) ->
    {user, get, Token};

user_get(?User) ->
    {user, get, User}.


%%--------------------------------------------------------------------
%% @doc Retrieves user data from the server.
%% @end
%%--------------------------------------------------------------------
-spec user_lookup(Login::binary()) ->
                         {user, lookup, Login::binary()}.
user_lookup(Login) when is_binary(Login) ->
    {user, lookup, Login}.

%%--------------------------------------------------------------------
%% @doc Retrieves all user permissions to later test.
%% @end
%%--------------------------------------------------------------------
-spec user_cache(User::fifo:user_token_id()) ->
                        {user, cache, User::fifo:user_token_id()}.
user_cache(?Token) ->
    {user, cache, Token};
user_cache(?User) ->
    {user, cache, User}.

%%--------------------------------------------------------------------
%% @doc Adds a new user.
%% @end
%%--------------------------------------------------------------------
-spec user_add(UserName::binary()) ->
                      {user, add, UserName::binary()}.
user_add(UserName) ->
    {user, add, UserName}.

%%--------------------------------------------------------------------
%% @doc Deletes a user.
%% @end
%%--------------------------------------------------------------------
-spec user_delete(User::fifo:user_id()) ->
                         {user, delete, User::fifo:user_id()}.
user_delete(User) ->
    {user, delete, User}.

%%--------------------------------------------------------------------
%% @doc Grants a right of a user.
%% @end
%%--------------------------------------------------------------------

-spec user_grant(User::fifo:user_id(),
                 Permission::fifo:permission()) ->
                        {user, grant,
                         User::fifo:user_id(),
                         Permission::fifo:permission()}.
user_grant(User, Permission) ->
    {user, grant, User, Permission}.

%%--------------------------------------------------------------------
%% @doc Revokes a right of a user.
%% @end
%%--------------------------------------------------------------------
-spec user_revoke(User::fifo:user_id(),
                  Permission::fifo:permission()) ->
                        {user, revoke,
                         User::fifo:user_id(),
                         Permission::fifo:permission()}.
user_revoke(User, Permission) ->
    {user, revoke, User, Permission}.

%%--------------------------------------------------------------------
%% @doc Revokes all right with a certain prefix from a user.
%% @end
%%--------------------------------------------------------------------
-spec user_revoke_prefix(User::fifo:user_id(),
                         Prefix::fifo:permission()) ->
                        {user, revoke_prefix,
                         User::fifo:user_id(),
                         Permission::fifo:permission()}.
user_revoke_prefix(?User, Prefix) when is_list(Prefix)->
    {user, revoke_prefix, User, Prefix}.

%%--------------------------------------------------------------------
%% @doc Changes the Password of a user.
%% @spec user_passwd(User::binary(), Pass::binary()) ->
%%           ok |
%%           {error, not_found|no_servers}
%% @end
%%--------------------------------------------------------------------
-spec user_passwd(User::fifo:user_id(), Pass::binary()) ->
                         {user, passwd, User::fifo:user_id(), Pass::binary()}.
user_passwd(?User, Pass) when is_binary(Pass) ->
    {user, passwd, User, Pass}.

%%--------------------------------------------------------------------
%% @doc Adds a user to a group.
%% @spec user_join(User::binary(), Group::binary()) ->
%%             ok |
%%             {error, not_found|no_servers}
%% @end
%%--------------------------------------------------------------------

-spec user_join(User::fifo:user_id(), Group::fifo:group_id()) ->
                       {user, join, User::fifo:user_id(), Group::fifo:group_id()}.
user_join(?User, ?Group) ->
    {user, join, User, Group}.

%%--------------------------------------------------------------------
%% @doc Removes a user from a group.
%% @spec user_leave(User::binary(), Group::binary()) ->
%%          ok |
%%          {error, not_found|no_servers}
%% @end
%%--------------------------------------------------------------------
-spec user_leave(User::fifo:user_id(), Group::fifo:group_id()) ->
                        {user, leave,
                         User::fifo:user_id(),
                         Group::fifo:group_id()}.
user_leave(?User,?Group) ->
    {user, leave, User, Group}.

%%%===================================================================
%%% Group Functions
%%%===================================================================

%%--------------------------------------------------------------------
%% @doc Sets an attribute on the group.
%% @end
%%--------------------------------------------------------------------
-spec group_set(Group::fifo:group_id(),
                Attribute::fifo:keys(),
                Value::fifo:value()) ->
                       {group, set,
                        Group::fifo:group_id(),
                        Attribute::fifo:keys(),
                        Value::fifo:value()}.

group_set(?Group, Attribute, Value)  ->
    {group, set, Group, Attribute, Value}.

%%--------------------------------------------------------------------
%% @doc Sets multiple attributes on the group.
%% @end
%%--------------------------------------------------------------------
-spec group_set(Group::fifo:group_id(),
                Attributes::fifo:attr_list()) ->
                       {group, set,
                        Group::fifo:group_id(),
                        Attributes::fifo:attr_list()}.
group_set(?Group, Attributes) when
      is_list(Attributes) ->
    {group, set, Group, Attributes}.

%%--------------------------------------------------------------------
%% @doc Retrievs a list of all group id's.
%% @end
%%--------------------------------------------------------------------
-spec group_list() ->
    {group, list}.
group_list() ->
    {group, list}.

%%--------------------------------------------------------------------
%% @doc Retrieves group data from the server.
%% @end
%%--------------------------------------------------------------------
-spec group_get(Group::fifo:group_id()) ->
                       {group, get, Group::fifo:group_id()}.
group_get(?Group) ->
    {group, get, Group}.

%%--------------------------------------------------------------------
%% @doc Adds a new group.
%% @end
%%--------------------------------------------------------------------
-spec group_add(GroupName::binary()) ->
                       {group, add, GroupName::binary()}.
group_add(GroupName) when is_binary(GroupName)->
    {group, add, GroupName}.

%%--------------------------------------------------------------------
%% @doc Deletes a group.
%% @end
%%--------------------------------------------------------------------
-spec group_delete(Group::fifo:group_id()) ->
                          {group, delete, Group::fifo:group_id()}.
group_delete(?Group) ->
    {group, delete, Group}.

%%--------------------------------------------------------------------
%% @doc Grants a right of a group.
%% @end
%%--------------------------------------------------------------------
-spec group_grant(Group::fifo:group_id(),
                  Permission::fifo:permission()) ->
                         {group, grant,
                          Group::fifo:group_id(),
                          Permission::fifo:permission()}.

group_grant(?Group, Permission) when is_list(Permission) ->
    {group, grant, Group, Permission}.

%%--------------------------------------------------------------------
%% @doc Revokes a right of a group.
%% @end
%%--------------------------------------------------------------------
-spec group_revoke(Group::fifo:group_id(),
                   Permission::fifo:permission()) ->
                          {group, revoke,
                           Group::fifo:group_id(),
                           Permission::fifo:permission()}.
group_revoke(?Group, Permission) when is_list(Permission) ->
    {group, revoke, Group, Permission}.

%%--------------------------------------------------------------------
%% @doc Revokes all rights matching a prefix from a group.
%% @end
%%--------------------------------------------------------------------
-spec group_revoke_prefix(Group::fifo:group_id(),
                          Prefix::fifo:permission()) ->
                          {group, revoke_prefix,
                           Group::fifo:group_id(),
                           Permission::fifo:permission()}.
group_revoke_prefix(?Group, Prefix) when is_list(Prefix) ->
    {group, revoke_prefix, Group, Prefix}.

%%%===================================================================
%%% Internal Functions
%%%===================================================================
