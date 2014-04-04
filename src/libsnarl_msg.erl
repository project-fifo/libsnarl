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
         role_add/1,
         role_delete/1,
         role_get/1,
         role_grant/2,
         role_list/0,
         role_list/2,
         role_revoke/2,
         role_revoke_prefix/2,
         role_set/2,
         role_set/3
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
-define(Role, <<Role:36/binary>>).
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
%% @doc Adds a user to a role.
%% @end
%%--------------------------------------------------------------------

-spec user_join(User::fifo:user_id(), Role::fifo:role_id()) ->
                       {user, join, User::fifo:user_id(), Role::fifo:role_id()}.
user_join(?User, ?Role) ->
    {user, join, User, Role}.

-spec user_leave(User::fifo:user_id(), Role::fifo:role_id()) ->
                        {user, leave,
                         User::fifo:user_id(),
                         Role::fifo:role_id()}.

user_leave(?User,?Role) ->
    {user, leave, User, Role}.

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
%%% Role Functions
%%%===================================================================

%%--------------------------------------------------------------------
%% @doc Sets an attribute on the role.
%% @end
%%--------------------------------------------------------------------
-spec role_set(Role::fifo:role_id(),
                Attribute::fifo:keys(),
                Value::fifo:value() | delete) ->
                       {role, set,
                        Role::fifo:role_id(),
                        Attribute::fifo:keys(),
                        Value::fifo:value() | delete}.

role_set(?Role, Attribute, Value)  ->
    {role, set, Role, Attribute, Value}.

%%--------------------------------------------------------------------
%% @doc Sets multiple attributes on the role.
%% @end
%%--------------------------------------------------------------------
-spec role_set(Role::fifo:role_id(),
                Attributes::fifo:attr_list()) ->
                       {role, set,
                        Role::fifo:role_id(),
                        Attributes::fifo:attr_list()}.
role_set(?Role, Attributes) when
      is_list(Attributes) ->
    {role, set, Role, Attributes}.

%%--------------------------------------------------------------------
%% @doc Retrievs a list of all role id's.
%% @end
%%--------------------------------------------------------------------
-spec role_list() ->
                        {role, list}.
role_list() ->
    {role, list}.

%%--------------------------------------------------------------------
%% @doc Retrievs a list of all user id's.
%% @spec role_list() ->
%%                 [term()]
%% @end
%%--------------------------------------------------------------------
-spec role_list(Reqs::[fifo:matcher()], boolean()) ->
                       {role, list, Reqs::[fifo:matcher()], boolean()}.
role_list(Reqs, Full) ->
    {role, list, Reqs, Full}.

%%--------------------------------------------------------------------
%% @doc Retrieves role data from the server.
%% @end
%%--------------------------------------------------------------------
-spec role_get(Role::fifo:role_id()) ->
                       {role, get, Role::fifo:role_id()}.
role_get(?Role) ->
    {role, get, Role}.

%%--------------------------------------------------------------------
%% @doc Adds a new role.
%% @end
%%--------------------------------------------------------------------
-spec role_add(RoleName::binary()) ->
                       {role, add, RoleName::binary()}.
role_add(RoleName) when is_binary(RoleName)->
    {role, add, RoleName}.

%%--------------------------------------------------------------------
%% @doc Deletes a role.
%% @end
%%--------------------------------------------------------------------
-spec role_delete(Role::fifo:role_id()) ->
                          {role, delete, Role::fifo:role_id()}.
role_delete(?Role) ->
    {role, delete, Role}.

%%--------------------------------------------------------------------
%% @doc Grants a right of a role.
%% @end
%%--------------------------------------------------------------------
-spec role_grant(Role::fifo:role_id(),
                  Permission::fifo:permission()) ->
                         {role, grant,
                          Role::fifo:role_id(),
                          Permission::fifo:permission()}.

role_grant(?Role, Permission) when is_list(Permission) ->
    {role, grant, Role, Permission}.

%%--------------------------------------------------------------------
%% @doc Revokes a right of a role.
%% @end
%%--------------------------------------------------------------------
-spec role_revoke(Role::fifo:role_id(),
                   Permission::fifo:permission()) ->
                          {role, revoke,
                           Role::fifo:role_id(),
                           Permission::fifo:permission()}.
role_revoke(?Role, Permission) when is_list(Permission) ->
    {role, revoke, Role, Permission}.

%%--------------------------------------------------------------------
%% @doc Revokes all rights matching a prefix from a role.
%% @end
%%--------------------------------------------------------------------
-spec role_revoke_prefix(Role::fifo:role_id(),
                          Prefix::fifo:permission()) ->
                                 {role, revoke_prefix,
                                  Role::fifo:role_id(),
                                  Permission::fifo:permission()}.
role_revoke_prefix(?Role, Prefix) when is_list(Prefix) ->
    {role, revoke_prefix, Role, Prefix}.


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
