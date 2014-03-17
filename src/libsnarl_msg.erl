-module(libsnarl_msg).

-export([
         allowed/2,
         auth/2,
         auth/3
        ]).

-export([
         token_delete/1
        ]).

-export([
         user_add/1, user_add/2,
         user_cache/1,
         user_delete/1,
         user_get/1,
         user_grant/2,
         user_join/2,
         user_key_find/1,
         user_key_add/3,
         user_key_revoke/2,
         user_keys/1,
         user_yubikey_add/2,
         user_yubikey_remove/2,
         user_yubikeys/1,
         user_leave/2,
         user_list/0,
         user_list/2,
         user_lookup/1,
         user_passwd/2,
         user_revoke/2,
         user_revoke_prefix/2,
         user_set/2,
         user_set/3,
         user_active_org/1,
         user_orgs/1,
         user_join_org/2,
         user_leave_org/2,
         user_select_org/2
        ]).

-export([
         group_add/1,
         group_delete/1,
         group_get/1,
         group_grant/2,
         group_list/0,
         group_list/2,
         group_revoke/2,
         group_revoke_prefix/2,
         group_set/2,
         group_set/3
        ]).

-export([
         org_add/1,
         org_delete/1,
         org_get/1,
         org_add_trigger/2,
         org_list/0,
         org_list/2,
         org_remove_trigger/2,
         org_execute_trigger/3,
         org_set/2,
         org_set/3
        ]).

-define(User, <<User:36/binary>>).
-define(Group, <<Group:36/binary>>).
-define(Org, <<Org:36/binary>>).
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

-spec auth(Login::binary(), Pass::binary(), OTP::binary()|basic) ->
                  {user, auth, Login::binary(), Pass::binary(),
                   OTP::binary() | basic}.
auth(Login, Pass, basic) when
      is_binary(Login),
      is_binary(Pass) ->
    {user, auth, Login, Pass, basic};
auth(Login, Pass, OTP) when
      is_binary(Login),
      is_binary(Pass),
      is_binary(OTP) ->
    {user, auth, Login, Pass, OTP}.

-spec allowed(User::fifo:user_token_id(),
              Permission::fifo:permission()) ->
                     {user, allowed,
                      User::fifo:user_token_id(),
                      Permission::fifo:permission()}.

allowed(?Token, Permission)
  when is_list(Permission) ->
    {user, allowed, Token, Permission};

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
               Value::fifo:value()  | delete) ->
                      {user, set, User::fifo:user_id(),
                       Attribute::fifo:keys(),
                       Value::fifo:value()  | delete}.
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
%% @doc Retrievs a list of all user id's.
%% @spec user_list() ->
%%                 [term()]
%% @end
%%--------------------------------------------------------------------
-spec user_list(Reqs::[fifo:matcher()], boolean()) ->
                       {user, list, Reqs::[fifo:matcher()], boolean()}.
user_list(Reqs, Full) ->
    {user, list, Reqs, Full}.

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

-spec user_add(UserName::binary()) ->
                      {user, add, UserName::binary()}.
user_add(UserName) ->
    {user, add, UserName}.

-spec user_add(Creator::fifo:user_id(),
               UserName::binary()) ->
                      {user, add, Creator::fifo:user_id(), UserName::binary()}.
user_add(Creator, UserName) ->
    {user, add, Creator, UserName}.

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
%% @end
%%--------------------------------------------------------------------

-spec user_join(User::fifo:user_id(), Group::fifo:group_id()) ->
                       {user, join, User::fifo:user_id(), Group::fifo:group_id()}.
user_join(?User, ?Group) ->
    {user, join, User, Group}.

-spec user_leave(User::fifo:user_id(), Group::fifo:group_id()) ->
                        {user, leave,
                         User::fifo:user_id(),
                         Group::fifo:group_id()}.

user_leave(?User,?Group) ->
    {user, leave, User, Group}.

-spec user_key_find(KeyID::binary()) ->
                           {user, keys, find, KeyID::binary()}.

user_key_find(<<KeyID:16/binary>>) ->
    {user, keys, find, KeyID}.


-spec user_key_add(User::fifo:user_id(), KeyID::binary(), Key::binary()) ->
                          {user, keys, add, User::fifo:user_id(), KeyID::binary(), Key::binary()}.
user_key_add(?User, KeyID, Key)
  when is_binary(KeyID),
       is_binary(Key) ->
    {user, keys, add, User, KeyID, Key}.

-spec user_key_revoke(User::fifo:user_id(), KeyID::binary()) ->
                             {user, keys, revoke, User::fifo:user_id(), KeyID::binary()}.
user_key_revoke(?User, KeyID)
  when is_binary(KeyID) ->
    {user, keys, revoke, User, KeyID}.

-spec user_keys(User::fifo:user_id()) ->
                       {user, keys, get, User::fifo:user_id()}.
user_keys(?User) ->
    {user, keys, get, User}.

-spec user_yubikey_add(User::fifo:user_id(), KeyID::binary()) ->
                              {user, yubikeys, add, User::fifo:user_id(), KeyID::binary()}.
user_yubikey_add(?User, KeyID)
  when is_binary(KeyID) ->
    {user, yubikeys, add, User, KeyID}.

-spec user_yubikey_remove(User::fifo:user_id(), KeyID::binary()) ->
                             {user, yubikeys, remove, User::fifo:user_id(), KeyID::binary()}.
user_yubikey_remove(?User, KeyID)
  when is_binary(KeyID) ->
    {user, yubikeys, remove, User, KeyID}.

-spec user_yubikeys(User::fifo:user_id()) ->
                           {user, yubikeys, get, User::fifo:user_id()}.
user_yubikeys(?User) ->
    {user, yubikeys, get, User}.

-spec user_join_org(User::fifo:user_id(), Org::fifo:org_id()) ->
                           {user, org, join,
                            User::fifo:user_id(),
                            Org::fifo:org_id()}.
user_join_org(?User, ?Org) ->
    {user, org, join, User, Org}.

-spec user_orgs(User::fifo:user_id()) ->
                       {user, org, get,
                        User::fifo:user_id()}.
user_orgs(?User) ->
    {user, org, get, User}.

-spec user_active_org(User::fifo:user_id()) ->
                             {user, org, active,
                              User::fifo:user_id()}.
user_active_org(?User) ->
    {user, org, active, User}.

-spec user_leave_org(User::fifo:user_id(), Org::fifo:org_id()) ->
                            {user, org, leave,
                             User::fifo:user_id(),
                             Org::fifo:org_id()}.
user_leave_org(?User, ?Org) ->
    {user, org, leave, User, Org}.

-spec user_select_org(User::fifo:user_id(), Org::fifo:org_id()) ->
                             {user, org, select,
                              User::fifo:user_id(),
                              Org::fifo:org_id()}.
user_select_org(?User, ?Org) ->
    {user, org, select, User, Org}.


%%%===================================================================
%%% Group Functions
%%%===================================================================

%%--------------------------------------------------------------------
%% @doc Sets an attribute on the group.
%% @end
%%--------------------------------------------------------------------
-spec group_set(Group::fifo:group_id(),
                Attribute::fifo:keys(),
                Value::fifo:value() | delete) ->
                       {group, set,
                        Group::fifo:group_id(),
                        Attribute::fifo:keys(),
                        Value::fifo:value() | delete}.

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
%% @doc Retrievs a list of all user id's.
%% @spec group_list() ->
%%                 [term()]
%% @end
%%--------------------------------------------------------------------
-spec group_list(Reqs::[fifo:matcher()], boolean()) ->
                       {group, list, Reqs::[fifo:matcher()], boolean()}.
group_list(Reqs, Full) ->
    {group, list, Reqs, Full}.

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
%%% Org Functions
%%%===================================================================

%%--------------------------------------------------------------------
%% @doc Sets an attribute on the org.
%% @end
%%--------------------------------------------------------------------
-spec org_set(Org::fifo:org_id(),
              Attribute::fifo:keys(),
              Value::fifo:value() | delete) ->
                     {org, set,
                      Org::fifo:org_id(),
                      Attribute::fifo:keys(),
                      Value::fifo:value() | delete}.

org_set(?Org, Attribute, Value)  ->
    {org, set, Org, Attribute, Value}.

%%--------------------------------------------------------------------
%% @doc Sets multiple attributes on the org.
%% @end
%%--------------------------------------------------------------------
-spec org_set(Org::fifo:org_id(),
              Attributes::fifo:attr_list()) ->
                     {org, set,
                      Org::fifo:org_id(),
                      Attributes::fifo:attr_list()}.
org_set(?Org, Attributes) when
      is_list(Attributes) ->
    {org, set, Org, Attributes}.

%%--------------------------------------------------------------------
%% @doc Retrievs a list of all org id's.
%% @end
%%--------------------------------------------------------------------
-spec org_list() ->
                      {org, list}.
org_list() ->
    {org, list}.

-spec org_list(Reqs::[fifo:matcher()], boolean()) ->
                       {org, list, Reqs::[fifo:matcher()], boolean()}.
org_list(Reqs, Full) ->
    {org, list, Reqs, Full}.

%%--------------------------------------------------------------------
%% @doc Retrieves org data from the server.
%% @end
%%--------------------------------------------------------------------
-spec org_get(Org::fifo:org_id()) ->
                     {org, get, Org::fifo:org_id()}.
org_get(?Org) ->
    {org, get, Org}.

%%--------------------------------------------------------------------
%% @doc Adds a new org.
%% @end
%%--------------------------------------------------------------------
-spec org_add(OrgName::binary()) ->
                     {org, add, OrgName::binary()}.
org_add(OrgName) when is_binary(OrgName)->
    {org, add, OrgName}.

%%--------------------------------------------------------------------
%% @doc Deletes a org.
%% @end
%%--------------------------------------------------------------------
-spec org_delete(Org::fifo:org_id()) ->
                        {org, delete, Org::fifo:org_id()}.
org_delete(?Org) ->
    {org, delete, Org}.

%%--------------------------------------------------------------------
%% @doc adds a trigger.
%% @end
%%--------------------------------------------------------------------
-spec org_add_trigger(Org::fifo:org_id(),
                      Trigger::fifo:trigger()) ->
                             {org, trigger, add,
                              Org::fifo:org_id(),
                              Trigger::fifo:trigger()}.

org_add_trigger(?Org, Trigger) ->
    {org, trigger, add, Org, Trigger}.

%%--------------------------------------------------------------------
%% @doc Removes a trigger.
%% @end
%%--------------------------------------------------------------------
-spec org_remove_trigger(Org::fifo:org_id(),
                         Trigger::fifo:trigger()) ->
                                {org, trigger, remove,
                                 Org::fifo:org_id(),
                                 Trigger::fifo:trigger()}.

org_remove_trigger(?Org, Trigger) ->
    {org, trigger, remove, Org, Trigger}.

%%--------------------------------------------------------------------
%% @doc Executes a trigger.
%% @end
%%--------------------------------------------------------------------
-spec org_execute_trigger(Org::fifo:org_id(),
                          Event::fifo:event(),
                          Payload::term()) ->
                                 {org, trigger, execute,
                                  Org::fifo:org_id(),
                                  Trigger::fifo:trigger(),
                                  Payload::term()}.

org_execute_trigger(?Org, Event, Payload) ->
    {org, trigger, execute, Org, Event, Payload}.

%%%===================================================================
%%% Internal Functions
%%%===================================================================
