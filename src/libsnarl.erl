-module(libsnarl).

-export([
         servers/0,
         start/0
        ]).

-export([
         allowed/2,
         auth/2,
         test/2,
         version/0,
         keystr_to_id/1
        ]).

-export([
         token_delete/1
        ]).

-export([
         user_add/1,
         user_cache/1,
         user_delete/1,
         user_get/1,
         user_grant/2,
         user_join/2,
         user_key_find/1,
         user_key_add/3,
         user_key_revoke/2,
         user_keys/1,
         user_leave/2,
         user_list/0,
         user_lookup/1,
         user_passwd/2,
         user_revoke/2,
         user_revoke_prefix/2,
         user_set/2,
         user_set/3
        ]).

-export([
         group_add/1,
         group_delete/1,
         group_get/1,
         group_grant/2,
         group_list/0,
         group_revoke/2,
         group_revoke_prefix/2,
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


keystr_to_id(S) ->
    << <<D:8>> || {ok, [D], []} <- [io_lib:fread("~16u", P) || P <- re:split(S, ":", [{return, list}])]>>.

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
-spec version() -> {ok, binary()} |
                   {error, no_servers}.
version() ->
    ServerVersion = send(version),
    ServerVersion.

%%--------------------------------------------------------------------
%% @doc Authenticates a user and returns a token that can be used for
%%  the session.
%% @end
%%--------------------------------------------------------------------
-spec auth(User::fifo:user_id(), Pass::binary()) ->
                  not_found |
                  {ok, {token, fifo:user_id()}} |
                  {error, no_servers}.
auth(User, Pass) ->
    send(libsnarl_msg:auth(User, Pass)).

%%--------------------------------------------------------------------
%% @doc Checks if the user has the given permission.
%% @end
%%--------------------------------------------------------------------
-spec allowed(User::fifo:user_token_id() | {token, binary()},
              Permission::fifo:permission()) ->
                     {error, no_servers} |
                     not_found |
                     true |
                     false.
allowed(User, Permission) ->
    send(libsnarl_msg:allowed(User, Permission)).

%%%===================================================================
%%% Token Functions
%%%===================================================================

%%--------------------------------------------------------------------
%% @doc Deletes a user.
%% @spec token_delete(Token::binary()) ->
%%                    {error, not_found|no_servers} | ok
%% @end
%%--------------------------------------------------------------------

-spec token_delete(Token::fifo:token()) ->
                          {error, no_servers} |
                          not_found |
                          ok.
token_delete(Token) ->
    send(libsnarl_msg:token_delete(Token)).

%%%===================================================================
%%% User Functions
%%%===================================================================

%%--------------------------------------------------------------------
%% @doc Sets a attribute for the user.
%% @end
%%--------------------------------------------------------------------
-spec user_set(User::fifo:user_id(),
               Attribute::fifo:keys(),
               Value::fifo:value() | delete) ->
                      ok | not_found |
                      {'error','no_servers'}.
user_set(User, Attribute, Value) ->
    send(libsnarl_msg:user_set(User, Attribute, Value)).

%%--------------------------------------------------------------------
%% @doc Sets multiple attributes for the user.
%% @end
%%--------------------------------------------------------------------
-spec user_set(User::fifo:uuid(),
               Attributes::fifo:attr_list()) ->
                      ok | not_found |
                      {'error','no_servers'}.
user_set(User, Attributes) ->
    send(libsnarl_msg:user_set(User, Attributes)).

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
    send(libsnarl_msg:user_list()).

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
    send(libsnarl_msg:user_get(User)).

%%--------------------------------------------------------------------
%% @doc Retrieves user data from the server.
%% @spec user_lookup(User::binary()) ->
%%                 {error, not_found|no_servers} | term()
%% @end
%%--------------------------------------------------------------------
-spec user_lookup(User::fifo:user_id()) ->
                         not_found |
                         {error, no_servers} |
                         {ok, fifo:user()}.
user_lookup(User) ->
    send(libsnarl_msg:user_lookup(User)).

%%--------------------------------------------------------------------
%% @doc Retrieves all user permissions to later test.
%% @spec user_cache(User::binary()) ->
%%                 {error, not_found|no_servers} | term()
%% @end
%%--------------------------------------------------------------------
-spec user_cache(User::fifo:user_id()) ->
                        {error, no_servers} |
                        not_found |
                        {ok, [fifo:permission()]}.
user_cache(User) ->
    send(libsnarl_msg:user_cache(User)).

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
    send(libsnarl_msg:user_add(UserName)).

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
    send(libsnarl_msg:user_delete(User)).

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
    send(libsnarl_msg:user_grant(User, Permission)).

%%--------------------------------------------------------------------
%% @doc Revokes a right of a user.
%% @spec user_revoke(User::binary(),
%%                   Permission::fifo:permission()) ->
%%                   {error, not_found|no_servers} | ok
%% @end
%%--------------------------------------------------------------------
-spec user_revoke(User::fifo:user_id(),
                  Permission::fifo:permission()) ->
                         {error, no_servers} |
                         not_found |
                         ok.
user_revoke(User, Permission) ->
    send(libsnarl_msg:user_revoke(User, Permission)).

%%--------------------------------------------------------------------
%% @doc Revokes all right with a certain prefix from a user.
%% @spec user_revoke(User::binary(),
%%                   Prefix::fifo:permission()) ->
%%                   {error, not_found|no_servers} | ok
%% @end
%%--------------------------------------------------------------------
-spec user_revoke_prefix(User::fifo:user_id(),
                         Prefix::fifo:permission()) ->
                                {error, no_servers} |
                                not_found |
                                ok.
user_revoke_prefix(User, Prefix) ->
    send(libsnarl_msg:user_revoke_prefix(User, Prefix)).

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
    send(libsnarl_msg:user_passwd(User, Pass)).

%%--------------------------------------------------------------------
%% @doc Adds a user to a group.
%% @end
%%--------------------------------------------------------------------
-spec user_join(User::fifo:user_id(), Group::fifo:group_id()) ->
                       {error, no_servers} |
                       not_found |
                       ok.
user_join(User, Group) ->
    send(libsnarl_msg:user_join(User, Group)).

-spec user_key_find(KeyID::binary()) ->
                           {error, no_servers} |
                           not_found |
                           {ok, UUID::fifo:user_id()}.
user_key_find(KeyID) ->
    send(libsnarl_msg:user_key_find(KeyID)).

%%--------------------------------------------------------------------
%% @doc Adds a key to the users SSH keys.
%% @end
%%--------------------------------------------------------------------
-spec user_key_add(User::fifo:user_id(), KeyID::binary(), Key::binary()) ->
                       {error, no_servers} |
                       not_found |
                       ok.
user_key_add(User, KeyID, Key) ->
    send(libsnarl_msg:user_key_add(User, KeyID, Key)).

%%--------------------------------------------------------------------
%% @doc Removes a key from the users SSH keys.
%% @end
%%--------------------------------------------------------------------
-spec user_key_revoke(User::fifo:user_id(), KeyID::binary()) ->
                       {error, no_servers} |
                       not_found |
                       ok.
user_key_revoke(User, KeyID) ->
    send(libsnarl_msg:user_key_revoke(User, KeyID)).

%%--------------------------------------------------------------------
%% @doc Returns a list of all SSH keys for a user.
%% @end
%%--------------------------------------------------------------------
-spec user_keys(User::fifo:user_id()) ->
                       {error, no_servers} |
                       not_found |
                       {ok, [{KeyID::binary(), Key::binary()}]}.
user_keys(User) ->
    send(libsnarl_msg:user_keys(User)).
%%--------------------------------------------------------------------
%% @doc Removes a user from a group.
%% @spec user_leave(User::binary()(Group::binary()) ->
%%          ok |
%%          {error, not_found|no_servers}
%% @end
%%--------------------------------------------------------------------
-spec user_leave(User::fifo:user_id(), Group::fifo:group_id()) ->
                        {error, no_servers} |
                        not_found |
                        ok.
user_leave(User, Group) ->
    send(libsnarl_msg:user_leave(User, Group)).

%%%===================================================================
%%% Group Functions
%%%===================================================================

%%--------------------------------------------------------------------
%% @doc Sets an attribute on the group.
%% @end
%%--------------------------------------------------------------------
-spec group_set(Group::fifo:group_id(),
                Attribute::fifo:keys(),
                Value::fifo:value() | delete) -> ok | not_found |
                                                 {'error','no_servers'}.
group_set(Group, Attribute, Value) when
      is_binary(Group) ->
    send(libsnarl_msg:group_set(Group, Attribute, Value)).

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
    send(libsnarl_msg:group_set(Group, Attributes)).

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
    send(libsnarl_msg:group_list()).

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
    send(libsnarl_msg:group_get(Group)).

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
    send(libsnarl_msg:group_add(Group)).

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
    send(libsnarl_msg:group_delete(Group)).

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
    send(libsnarl_msg:group_grant(Group, Permission)).

%%--------------------------------------------------------------------
%% @doc Revokes a right of a group.
%% @spec group_revoke(Group::binary(),
%%                    Permission::fifo:permission()) ->
%%                    {error, not_found|no_servers} | ok
%% @end
%%--------------------------------------------------------------------
-spec group_revoke(Group::fifo:group_id(),
                   Permission::fifo:permission()) ->
                          {error, no_servers} |
                          not_found |
                          ok.
group_revoke(Group, Permission) ->
    send(libsnarl_msg:group_revoke(Group, Permission)).

%%--------------------------------------------------------------------
%% @doc Revokes all rights matching a prefix from a group.
%% @spec group_revoke(Group::binary(),
%%                    Prefix::fifo:permission()) ->
%%                    {error, not_found|no_servers} | ok
%% @end
%%--------------------------------------------------------------------
-spec group_revoke_prefix(Group::fifo:group_id(),
                          Prefix::fifo:permission()) ->
                                 {error, no_servers} |
                                 not_found |
                                 ok.
group_revoke_prefix(Group, Prefix) ->
    send(libsnarl_msg:group_revoke(Group, Prefix)).

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
