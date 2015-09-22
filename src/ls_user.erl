-module(ls_user).

-export([
         add/1, add/2,
         cache/1,
         delete/1,
         get/1,
         make_token/1,
         grant/2,
         join/2,
         key_find/1,
         key_add/3,
         key_revoke/2,
         yubikey_add/2,
         yubikey_check/2,
         yubikey_remove/2,
         leave/2,
         list/0,
         list/2,
         lookup/1,
         passwd/2,
         revoke/2,
         revoke_prefix/2,
         join_org/2,
         leave_org/2,
         select_org/2,
         set_metadata/2,
         api_token/3,
         revoke_token/2
        ]).

-ignore_xref([
              add/1,
              cache/1,
              delete/1,
              get/1,
              make_token/1,
              grant/2,
              join/2,
              key_find/1,
              key_add/3,
              key_revoke/2,
              yubikey_add/2,
              yubikey_check/2,
              yubikey_remove/2,
              leave/2,
              list/0,
              list/2,
              lookup/1,
              passwd/2,
              revoke/2,
              revoke_prefix/2,
              join_org/2,
              leave_org/2,
              select_org/2,
              set_metadata/2,
              api_token/3,
              revoke_token/2
             ]).

%%%===================================================================
%%% User Functions
%%%===================================================================

-spec set_metadata(User::fifo:user_id(), Attrs::fifo:attr_list()) ->
                          {error, no_servers} |
                          ok.
set_metadata(User, Attrs) ->
    send(libsnarl_msg:user_set_metadata(r(), User, Attrs)).

%%--------------------------------------------------------------------
%% @doc Retrievs a list of all user id's.
%% @spec list() ->
%%                 [term()]
%% @end
%%--------------------------------------------------------------------
-spec list() ->
                  {error, timeout} |
                  {ok, [fifo:user_id()]}.
list() ->
    send(libsnarl_msg:user_list(r())).

%%--------------------------------------------------------------------
%% @doc Retrievs a filtered list for users.
%% @end
%%--------------------------------------------------------------------
-spec list(Reqs::[fifo:matcher()], boolean()) ->
                  {error, timeout} |
                  {ok, [{integer(), fifo:user_id()}]} |
                  {ok, [{integer(), fifo:user()}]}.

list(Reqs, Full) ->
    send(libsnarl_msg:user_list(r(), Reqs, Full)).

%%--------------------------------------------------------------------
%% @doc Retrieves user data from the server.
%% @spec get(User::binary()) ->
%%                 {error, not_found|no_servers} | term()
%% @end
%%--------------------------------------------------------------------
-spec get(User::fifo:user_id()) ->
                 not_found |
                 {error, no_servers} |
                 {ok, fifo:user()}.
get(User) ->
    send(libsnarl_msg:user_get(r(), User)).

%%--------------------------------------------------------------------
%% @doc Creates a token for a user.
%% @end
%%--------------------------------------------------------------------
-spec make_token(User::fifo:user_id()) ->
                        not_found |
                        {ok, fifo:token()}.
make_token(User) ->
    send(libsnarl_msg:user_make_token(r(), User)).

%%--------------------------------------------------------------------
%% @doc Retrieves user data from the server.
%% @spec lookup(User::binary()) ->
%%                 {error, not_found|no_servers} | term()
%% @end
%%--------------------------------------------------------------------
-spec lookup(User::fifo:user_id()) ->
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
-spec cache(User::fifo:user_id()) ->
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
                 {ok, UUID::fifo:user_id()}.
add(UserName) ->
    send(libsnarl_msg:user_add(r(), UserName)).


%%--------------------------------------------------------------------
%% @doc Adds a new user from perspective of a creator, triggering
%%      Org events in the process
%% @end
%%--------------------------------------------------------------------
-spec add(Creator::fifo:user_id(),
          UserName::binary()) ->
                 {error, no_servers} |
                 duplicate |
                 {ok, UUID::fifo:user_id()}.
add(Creator, UserName) ->
    send(libsnarl_msg:user_add(r(), Creator, UserName)).

%%--------------------------------------------------------------------
%% @doc Deletes a user.
%% @spec delete(User::binary()) ->
%%                    {error, not_found|no_servers} | ok
%% @end
%%--------------------------------------------------------------------
-spec delete(User::fifo:user_id()) ->
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

-spec grant(User::fifo:user_id(),
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
-spec revoke(User::fifo:user_id(),
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
-spec revoke_prefix(User::fifo:user_id(),
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
-spec passwd(User::fifo:user_id(), Pass::binary()) ->
                    {error, no_servers} |
                    not_found |
                    ok.
passwd(User, Pass) ->
    send(libsnarl_msg:user_passwd(r(), User, Pass)).

%%--------------------------------------------------------------------
%% @doc Adds a user to a role.
%% @end
%%--------------------------------------------------------------------
-spec join(User::fifo:user_id(), Role::fifo:role_id()) ->
                  {error, no_servers} |
                  not_found |
                  ok.
join(User, Role) ->
    send(libsnarl_msg:user_join(r(), User, Role)).

-spec key_find(KeyID::binary()) ->
                      {error, no_servers} |
                      not_found |
                      {ok, UUID::fifo:user_id()}.
key_find(KeyID) ->
    send(libsnarl_msg:user_key_find(r(), KeyID)).

%%--------------------------------------------------------------------
%% @doc Adds a key to the users SSH keys.
%% @end
%%--------------------------------------------------------------------
-spec key_add(User::fifo:user_id(), KeyID::binary(), Key::binary()) ->
                     {error, no_servers} |
                     duplicate |
                     not_found |
                     ok.
key_add(User, KeyID, Key) ->
    send(libsnarl_msg:user_key_add(r(), User, KeyID, Key)).

%%--------------------------------------------------------------------
%% @doc Removes a key from the users SSH keys.
%% @end
%%--------------------------------------------------------------------
-spec key_revoke(User::fifo:user_id(), KeyID::binary()) ->
                        {error, no_servers} |
                        not_found |
                        ok.
key_revoke(User, KeyID) ->
    send(libsnarl_msg:user_key_revoke(r(), User, KeyID)).

%%--------------------------------------------------------------------
%% @doc Adds a key to the users SSH keys.
%% @end
%%--------------------------------------------------------------------
-spec yubikey_add(User::fifo:user_id(), OTP::binary()) ->
                         {error, no_servers} |
                         not_found |
                         ok.
yubikey_add(User, OTP) ->
    send(libsnarl_msg:user_yubikey_add(r(), User, OTP)).

%%--------------------------------------------------------------------
%% @doc Checks a Yubikey OTP.
%% @end
%%--------------------------------------------------------------------
-spec yubikey_check(User::fifo:user_id(), OTP::binary()) ->
                           {error, no_servers} |
                           not_found |
                           {otp_required, yubikey, UUID :: fifo:user_id()} |
                           {ok, UUID :: fifo:user_id()}.
yubikey_check(User, OTP) ->
    send(libsnarl_msg:user_yubikey_check(r(), User, OTP)).

%%--------------------------------------------------------------------
%% @doc Removes a key from the users SSH keys.
%% @end
%%--------------------------------------------------------------------
-spec yubikey_remove(User::fifo:user_id(), KeyID::binary()) ->
                            {error, no_servers} |
                            not_found |
                            ok.
yubikey_remove(User, KeyID) ->
    send(libsnarl_msg:user_yubikey_remove(r(), User, KeyID)).


%%--------------------------------------------------------------------
%% @doc Removes a user from a role.
%% @spec leave(User::binary()(Role::binary()) ->
%%          ok |
%%          {error, not_found|no_servers}
%% @end
%%--------------------------------------------------------------------
-spec leave(User::fifo:user_id(), Role::fifo:role_id()) ->
                   {error, no_servers} |
                   not_found |
                   ok.
leave(User, Role) ->
    send(libsnarl_msg:user_leave(r(), User, Role)).

%%--------------------------------------------------------------------
%% @doc Lets a user join the org.
%% @end
%%--------------------------------------------------------------------
-spec join_org(User::fifo:user_id(), Org::fifo:org_id()) ->
                      {error, no_servers} |
                      not_found |
                      ok.
join_org(User, Org) ->
    send(libsnarl_msg:user_join_org(r(), User, Org)).

%%--------------------------------------------------------------------
%% @doc Lets a user leave the org.
%% @end
%%--------------------------------------------------------------------
-spec leave_org(User::fifo:user_id(), Org::fifo:org_id()) ->
                       {error, no_servers} |
                       not_found |
                       ok.
leave_org(User, Org) ->
    send(libsnarl_msg:user_leave_org(r(), User, Org)).

%%--------------------------------------------------------------------
%% @doc Sets a org as active for a user.
%% @end
%%--------------------------------------------------------------------
-spec select_org(User::fifo:user_id(), Org::fifo:org_id()) ->
                        {error, no_servers} |
                        not_found |
                        ok.
select_org(User, Org) ->
    send(libsnarl_msg:user_select_org(r(), User, Org)).

%%--------------------------------------------------------------------
%% @doc Generates an API token for a user.
%% @end
%%--------------------------------------------------------------------
-spec api_token(User::fifo:user_id(), Scope::[binary()], Comment::binary()) ->
                       {error, no_servers} |
                       {error, bad_scope} |
                       not_found |
                       {ok, {TokenID::binary(), Token::binary()}}.
api_token(User, Scope, Comment) ->

    send(libsnarl_msg:user_api_token(r(), User, Scope, Comment)).

%%--------------------------------------------------------------------
%% @doc Revokes a token from  a user from a TokenID
%% @end
%%--------------------------------------------------------------------
-spec revoke_token(User::fifo:user_id(), TokenID::binary()) ->
                          {error, no_servers} |
                          not_found |
                          ok.
revoke_token(User, TokenID) ->
    send(libsnarl_msg:user_revoke_token(r(), User, TokenID)).

%%%===================================================================
%%% Internal Functions
%%%===================================================================

%%--------------------------------------------------------------------
%% @private
%% @doc Sends a message.
%% @spec send(Msg::term()) -> {ok, Reply::term()} | {error, no_server}
%% @end
%%--------------------------------------------------------------------

-spec send(Msg::fifo:snarl_user_message()) ->
                  duplicate |
                  ok |
                  not_found |
                  {ok, Reply::term()} |
                  {error, no_server} |
                  {error, Reason::term()}.
send(Msg) ->
    case libsnarl_server:call(Msg) of
        {reply, Reply} ->
            Reply;
        E ->
            E
    end.

r() ->
    application:get_env(libsnarl, realm, <<"default">>).
