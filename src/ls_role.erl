-module(ls_role).


-export([
         add/1,
         delete/1,
         get/1,
         grant/2,
         list/0,
         list/2,
         revoke/2,
         revoke_prefix/2,
         set/2,
         set/3
        ]).

%%%===================================================================
%%% Ignore
%%%===================================================================

-ignore_xref([
              add/1,
              delete/1,
              get/1,
              grant/2,
              list/0,
              list/2,
              revoke/2,
              revoke_prefix/2,
              set/2,
              set/3
             ]).

%%%===================================================================
%%% Role Functions
%%%===================================================================

%%--------------------------------------------------------------------
%% @doc Sets an attribute on the role.
%% @end
%%--------------------------------------------------------------------
-spec set(Role::fifo:role_id(),
                Attribute::fifo:keys(),
                Value::fifo:value() | delete) -> ok | not_found |
                                                 {'error','no_servers'}.
set(Role, Attribute, Value) when
      is_binary(Role) ->
    send(libsnarl_msg:role_set(r(), Role, Attribute, Value)).

%%--------------------------------------------------------------------
%% @doc Sets multiple attributes on the role.
%% @end
%%--------------------------------------------------------------------
-spec set(Role::fifo:role_id(),
                Attributes::fifo:attr_list()) ->
                       ok | not_found |
                       {'error','no_servers'}.
set(Role, Attributes) when
      is_binary(Role) ->
    send(libsnarl_msg:role_set(r(), Role, Attributes)).

%%--------------------------------------------------------------------
%% @doc Retrievs a list of all role id's.
%% @spec list() ->
%%                 [term()]
%% @end
%%--------------------------------------------------------------------
-spec list() ->
                        {error, no_servers} |
                        {ok, [fifo:role_id()]}.
list() ->
    send(libsnarl_msg:role_list(r())).

%%--------------------------------------------------------------------
%% @doc Retrievs a filtered list for roles.
%% @end
%%--------------------------------------------------------------------
-spec list(Reqs::[fifo:matcher()], boolean()) ->
                        {error, timeout} |
                        {ok, [fifo:role_id()]}.
list(Reqs, Full) ->
    send(libsnarl_msg:role_list(r(), Reqs, Full)).

%%--------------------------------------------------------------------
%% @doc Retrieves role data from the server.
%% @spec get(Role::binary()) ->
%%                 {error, not_found|no_servers} | term()
%% @end
%%--------------------------------------------------------------------
-spec get(Role::fifo:role_id()) ->
                       not_found |
                       {error, no_servers} |
                       {ok, fifo:role()}.
get(Role) ->
    send(libsnarl_msg:role_get(r(), Role)).

%%--------------------------------------------------------------------
%% @doc Adds a new role.
%% @spec add(Role::binary()) ->
%%                 {error, duplicate} | ok
%% @end
%%--------------------------------------------------------------------
-spec add(Role::fifo:role_id()) ->
                       {error, no_servers} |
                       duplicate |
                       ok.
add(Role) ->
    send(libsnarl_msg:role_add(r(), Role)).

%%--------------------------------------------------------------------
%% @doc Deletes a role.
%% @spec delete(Role::binary()) ->
%%                    {error, not_found|no_servers} | ok
%% @end
%%--------------------------------------------------------------------
-spec delete(Role::fifo:role_id()) ->
                          {error, no_servers} |
                          not_found |
                          ok.
delete(Role) ->
    send(libsnarl_msg:role_delete(r(), Role)).

%%--------------------------------------------------------------------
%% @doc Grants a right of a role.
%% @spec grant(Role::binary(),
%%                   Permission::[atom()|binary()|string()]) ->
%%                   {error, not_found|no_servers} | ok
%% @end
%%--------------------------------------------------------------------
-spec grant(Role::fifo:role_id(),
                  Permission::fifo:permission()) ->
                         {error, no_servers} |
                         not_found |
                         ok.
grant(Role, Permission) ->
    send(libsnarl_msg:role_grant(r(), Role, Permission)).

%%--------------------------------------------------------------------
%% @doc Revokes a right of a role.
%% @spec revoke(Role::binary(),
%%                    Permission::fifo:permission()) ->
%%                    {error, not_found|no_servers} | ok
%% @end
%%--------------------------------------------------------------------
-spec revoke(Role::fifo:role_id(),
                   Permission::fifo:permission()) ->
                          {error, no_servers} |
                          not_found |
                          ok.
revoke(Role, Permission) ->
    send(libsnarl_msg:role_revoke(r(), Role, Permission)).

%%--------------------------------------------------------------------
%% @doc Revokes all rights matching a prefix from a role.
%% @spec revoke(Role::binary(),
%%                    Prefix::fifo:permission()) ->
%%                    {error, not_found|no_servers} | ok
%% @end
%%--------------------------------------------------------------------
-spec revoke_prefix(Role::fifo:role_id(),
                          Prefix::fifo:permission()) ->
                                 {error, no_servers} |
                                 not_found |
                                 ok.
revoke_prefix(Role, Prefix) ->
    send(libsnarl_msg:role_revoke_prefix(r(), Role, Prefix)).

%%%===================================================================
%%% Internal Functions
%%%===================================================================

%%--------------------------------------------------------------------
%% @private
%% @doc Sends a message.
%% @spec send(Msg::term()) -> {ok, Reply::term()} | {error, no_server}
%% @end
%%--------------------------------------------------------------------

-spec send(Msg::fifo:snarl_role_message()) ->
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
