-module(ls_user).

-export([
         add/1, add/2,
         cache/1,
         delete/1,
         get/1,
         grant/2,
         join/2,
         key_find/1,
         key_add/3,
         key_revoke/2,
         keys/1,
         yubikey_add/2,
         yubikey_remove/2,
         yubikeys/1,
         leave/2,
         list/0,
         list/2,
         lookup/1,
         passwd/2,
         revoke/2,
         revoke_prefix/2,
         set/2,
         set/3,
         active_org/1,
         orgs/1,
         join_org/2,
         leave_org/2,
         select_org/2
        ]).

-ignore_xref([
              add/1,
              cache/1,
              delete/1,
              get/1,
              grant/2,
              join/2,
              key_find/1,
              key_add/3,
              key_revoke/2,
              keys/1,
              yubikey_add/2,
              yubikey_remove/2,
              yubikeys/1,
              leave/2,
              list/0,
              list/2,
              lookup/1,
              passwd/2,
              revoke/2,
              revoke_prefix/2,
              set/2,
              set/3,
              active_org/1,
              orgs/1,
              join_org/2,
              leave_org/2,
              select_org/2
             ]).

%%%===================================================================
%%% User Functions
%%%===================================================================

%%--------------------------------------------------------------------
%% @doc Sets a attribute for the user.
%% @end
%%--------------------------------------------------------------------
-spec set(User::fifo:id(),
               Attribute::fifo:keys(),
               Value::fifo:value() | delete) ->
                      ok | not_found |
                      {'error','no_servers'}.
set(User, Attribute, Value) ->
    send(libsnarl_msg:user_set(r(), User, Attribute, Value)).

%%--------------------------------------------------------------------
%% @doc Sets multiple attributes for the user.
%% @end
%%--------------------------------------------------------------------
-spec set(User::fifo:uuid(),
               Attributes::fifo:attr_list()) ->
                      ok | not_found |
                      {'error','no_servers'}.
set(User, Attributes) ->
    send(libsnarl_msg:user_set(r(), User, Attributes)).

%%--------------------------------------------------------------------
%% @doc Retrievs a list of all user id's.
%% @spec list() ->
%%                 [term()]
%% @end
%%--------------------------------------------------------------------
-spec list() ->
                       {error, timeout} |
                       {ok, [fifo:id()]}.
list() ->
    send(libsnarl_msg:user_list(r())).

%%--------------------------------------------------------------------
%% @doc Retrievs a filtered list for users.
%% @end
%%--------------------------------------------------------------------
-spec list(Reqs::[fifo:matcher()], boolean()) ->
                       {error, timeout} |
                       {ok, [fifo:id()]}.
list(Reqs, Full) ->
    send(libsnarl_msg:user_list(r(), Reqs, Full)).

%%--------------------------------------------------------------------
%% @doc Retrieves user data from the server.
%% @spec get(User::binary()) ->
%%                 {error, not_found|no_servers} | term()
%% @end
%%--------------------------------------------------------------------
-spec get(User::fifo:id()) ->
                      not_found |
                      {error, no_servers} |
                      {ok, fifo:user()}.
get(User) ->
    send(libsnarl_msg:user_get(r(), User)).

%%--------------------------------------------------------------------
%% @doc Retrieves user data from the server.
%% @spec lookup(User::binary()) ->
%%                 {error, not_found|no_servers} | term()
%% @end
%%--------------------------------------------------------------------
-spec lookup(User::fifo:id()) ->
                         not_found |
                         {error, no_servers} |
                         {ok, fifo:user()}.
lookup(User) ->
    send(libsnarl_msg:user_lookup(r(), User)).

%%--------------------------------------------------------------------
%% @doc Retrieves all user permissions to later test.
%% @spec cache(User::binary()) ->
%%                 {error, not_found|no_servers} | term()
%% @end
%%--------------------------------------------------------------------
-spec cache(User::fifo:id()) ->
                        {error, no_servers} |
                        not_found |
                        {ok, [fifo:permission()]}.
cache(User) ->
    send(libsnarl_msg:user_cache(r(), User)).

%%--------------------------------------------------------------------
%% @doc Adds a new user.
%% @spec add(User::binary()) ->
%%                 {error, duplicate} | ok
%% @end
%%--------------------------------------------------------------------
-spec add(UserName::binary()) ->
                      {error, no_servers} |
                      duplicate |
                      {ok, UUID::fifo:id()}.
add(UserName) ->
    send(libsnarl_msg:user_add(r(), UserName)).


%%--------------------------------------------------------------------
%% @doc Adds a new user from perspective of a creator, triggering
%%      Org events in the process
%% @end
%%--------------------------------------------------------------------
-spec add(Creator::fifo:id(),
               UserName::binary()) ->
                      {error, no_servers} |
                      duplicate |
                      {ok, UUID::fifo:id()}.
add(Creator, UserName) ->
    send(libsnarl_msg:user_add(r(), Creator, UserName)).

%%--------------------------------------------------------------------
%% @doc Deletes a user.
%% @spec delete(User::binary()) ->
%%                    {error, not_found|no_servers} | ok
%% @end
%%--------------------------------------------------------------------
-spec delete(User::fifo:id()) ->
                         {error, no_servers} |
                         not_found |
                         ok.
delete(User) ->
    send(libsnarl_msg:user_delete(r(), User)).

%%--------------------------------------------------------------------
%% @doc Grants a right of a user.
%% @spec grant(User::binary(),
%%                  Permission::[atom()|binary()|string()]) ->
%%                  {error, not_found|no_servers} | ok
%% @end
%%--------------------------------------------------------------------

-spec grant(User::fifo:id(),
                 Permission::fifo:permission()) ->
                        {error, no_servers} |
                        not_found |
                        ok.
grant(User, Permission) ->
    send(libsnarl_msg:user_grant(r(), User, Permission)).

%%--------------------------------------------------------------------
%% @doc Revokes a right of a user.
%% @spec revoke(User::binary(),
%%                   Permission::fifo:permission()) ->
%%                   {error, not_found|no_servers} | ok
%% @end
%%--------------------------------------------------------------------
-spec revoke(User::fifo:id(),
                  Permission::fifo:permission()) ->
                         {error, no_servers} |
                         not_found |
                         ok.
revoke(User, Permission) ->
    send(libsnarl_msg:user_revoke(r(), User, Permission)).

%%--------------------------------------------------------------------
%% @doc Revokes all right with a certain prefix from a user.
%% @spec revoke(User::binary(),
%%                   Prefix::fifo:permission()) ->
%%                   {error, not_found|no_servers} | ok
%% @end
%%--------------------------------------------------------------------
-spec revoke_prefix(User::fifo:id(),
                         Prefix::fifo:permission()) ->
                                {error, no_servers} |
                                not_found |
                                ok.
revoke_prefix(User, Prefix) ->
    send(libsnarl_msg:user_revoke_prefix(r(), User, Prefix)).

%%--------------------------------------------------------------------
%% @doc Changes the Password of a user.
%% @spec passwd(User::binary(), Pass::binary()) ->
%%           ok |
%%           {error, not_found|no_servers}
%% @end
%%--------------------------------------------------------------------
-spec passwd(User::fifo:id(), Pass::binary()) ->
                         {error, no_servers} |
                         not_found |
                         ok.
passwd(User, Pass) ->
    send(libsnarl_msg:user_passwd(User, Pass)).

%%--------------------------------------------------------------------
%% @doc Adds a user to a role.
%% @end
%%--------------------------------------------------------------------
-spec join(User::fifo:id(), Role::fifo:role_id()) ->
                       {error, no_servers} |
                       not_found |
                       ok.
join(User, Role) ->
    send(libsnarl_msg:user_join(r(), User, Role)).

-spec key_find(KeyID::binary()) ->
                           {error, no_servers} |
                           not_found |
                           {ok, UUID::fifo:id()}.
key_find(KeyID) ->
    send(libsnarl_msg:user_key_find(r(), KeyID)).

%%--------------------------------------------------------------------
%% @doc Adds a key to the users SSH keys.
%% @end
%%--------------------------------------------------------------------
-spec key_add(User::fifo:id(), KeyID::binary(), Key::binary()) ->
                          {error, no_servers} |
                          not_found |
                          ok.
key_add(User, KeyID, Key) ->
    send(libsnarl_msg:user_key_add(r(), User, KeyID, Key)).

%%--------------------------------------------------------------------
%% @doc Removes a key from the users SSH keys.
%% @end
%%--------------------------------------------------------------------
-spec key_revoke(User::fifo:id(), KeyID::binary()) ->
                             {error, no_servers} |
                             not_found |
                             ok.
key_revoke(User, KeyID) ->
    send(libsnarl_msg:user_key_revoke(r(), User, KeyID)).

%%--------------------------------------------------------------------
%% @doc Returns a list of all SSH keys for a user.
%% @end
%%--------------------------------------------------------------------
-spec keys(User::fifo:id()) ->
                       {error, no_servers} |
                       not_found |
                       {ok, [{KeyID::binary(), Key::binary()}]}.
keys(User) ->
    send(libsnarl_msg:user_keys(r(), User)).


%%--------------------------------------------------------------------
%% @doc Adds a key to the users SSH keys.
%% @end
%%--------------------------------------------------------------------
-spec yubikey_add(User::fifo:id(), OTP::binary()) ->
                              {error, no_servers} |
                              not_found |
                              ok.
yubikey_add(User, OTP) ->
    send(libsnarl_msg:user_yubikey_add(r(), User, OTP)).

%%--------------------------------------------------------------------
%% @doc Removes a key from the users SSH keys.
%% @end
%%--------------------------------------------------------------------
-spec yubikey_remove(User::fifo:id(), KeyID::binary()) ->
                             {error, no_servers} |
                             not_found |
                             ok.
yubikey_remove(User, KeyID) ->
    send(libsnarl_msg:user_yubikey_remove(r(), User, KeyID)).

%%--------------------------------------------------------------------
%% @doc Returns a list of all SSH keys for a user.
%% @end
%%--------------------------------------------------------------------
-spec yubikeys(User::fifo:id()) ->
                           {error, no_servers} |
                           not_found |
                           {ok, [KeyID::binary()]}.
yubikeys(User) ->
    send(libsnarl_msg:user_yubikeys(r(), User)).

%%--------------------------------------------------------------------
%% @doc Removes a user from a role.
%% @spec leave(User::binary()(Role::binary()) ->
%%          ok |
%%          {error, not_found|no_servers}
%% @end
%%--------------------------------------------------------------------
-spec leave(User::fifo:id(), Role::fifo:role_id()) ->
                        {error, no_servers} |
                        not_found |
                        ok.
leave(User, Role) ->
    send(libsnarl_msg:user_leave(r(), User, Role)).

%%--------------------------------------------------------------------
%% @doc Lets a user join the org.
%% @end
%%--------------------------------------------------------------------
-spec join_org(User::fifo:id(), Org::fifo:org_id()) ->
                           {error, no_servers} |
                           not_found |
                           ok.
join_org(User, Org) ->
    send(libsnarl_msg:user_join_org(r(), User, Org)).

%%--------------------------------------------------------------------
%% @doc Lets a user leave the org.
%% @end
%%--------------------------------------------------------------------
-spec leave_org(User::fifo:id(), Org::fifo:org_id()) ->
                            {error, no_servers} |
                            not_found |
                            ok.
leave_org(User, Org) ->
    send(libsnarl_msg:user_leave_org(r(), User, Org)).

%%--------------------------------------------------------------------
%% @doc Sets a org as active for a user.
%% @end
%%--------------------------------------------------------------------
-spec select_org(User::fifo:id(), Org::fifo:org_id()) ->
                             {error, no_servers} |
                             not_found |
                             ok.
select_org(User, Org) ->
    send(libsnarl_msg:user_select_org(r(), User, Org)).

%%--------------------------------------------------------------------
%% @doc Fetches the active org.
%% @end
%%--------------------------------------------------------------------
-spec active_org(User::fifo:id()) ->
                             {error, no_servers} |
                             not_found |
                             {ok, Org::fifo:org_id() | binary()}.
active_org(User) ->
    send(libsnarl_msg:user_active_org(r(), User)).

%%--------------------------------------------------------------------
%% @doc Fetches all orgs.
%% @end
%%--------------------------------------------------------------------
-spec orgs(User::fifo:id()) ->
                       {error, no_servers} |
                       not_found |
                       {ok, [Org::fifo:org_id() | binary()]}.
orgs(User) ->
    send(libsnarl_msg:user_orgs(r(), User)).

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

r() ->
    application:get_env(libsnarl, realm, <<"default">>).