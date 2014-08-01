-module(libsnarl_msg).

-export([
         allowed/3,
         auth/3,
         auth/4
        ]).

-export([
         token_delete/2
        ]).

-export([
         user_add/2, user_add/3,
         user_cache/2,
         user_delete/2,
         user_get/2,
         user_grant/3,
         user_join/3,
         user_key_find/2,
         user_key_add/4,
         user_key_revoke/3,
         user_keys/2,
         user_yubikey_add/3,
         user_yubikey_remove/3,
         user_yubikeys/2,
         user_leave/3,
         user_list/1,
         user_list/3,
         user_lookup/2,
         user_passwd/3,
         user_revoke/3,
         user_revoke_prefix/3,
         user_set/3,
         user_set/4,
         user_active_org/2,
         user_orgs/2,
         user_join_org/3,
         user_leave_org/3,
         user_select_org/3
        ]).

-export([
         role_add/2,
         role_delete/2,
         role_get/2,
         role_grant/3,
         role_list/1,
         role_list/3,
         role_revoke/3,
         role_revoke_prefix/3,
         role_set/3,
         role_set/4
        ]).

-export([
         org_add/2,
         org_delete/2,
         org_get/2,
         org_add_trigger/3,
         org_list/1,
         org_list/3,
         org_remove_trigger/3,
         org_execute_trigger/4,
         org_set/3,
         org_set/4
        ]).

-define(User, <<User:36/binary>>).
-define(Role, <<Role:36/binary>>).
-define(Org, <<Org:36/binary>>).
-define(Token, {token, <<_:36/binary>>} = Token).


%%%===================================================================
%%% Generatl Functions
%%%===================================================================

-spec auth(Realm::binary(), Login::binary(), Pass::binary()) ->
                  {user, auth, Login::binary(), Pass::binary()}.
auth(Realm, Login, Pass) when
      is_binary(Login),
      is_binary(Pass)->
    {user, auth, Realm, Login, Pass}.

-spec auth(Realm::binary(), Login::binary(), Pass::binary(), OTP::binary()|basic) ->
                  {user, auth, Login::binary(), Pass::binary(),
                   OTP::binary() | basic}.
auth(Realm, Login, Pass, basic) when
      is_binary(Login),
      is_binary(Pass) ->
    {user, auth, Realm, Login, Pass, basic};
auth(Realm, Login, Pass, OTP) when
      is_binary(Login),
      is_binary(Pass),
      is_binary(OTP) ->
    {user, auth, Realm, Login, Pass, OTP}.

-spec allowed(Realm::binary(),
              User::fifo:user_token_id(),
              Permission::fifo:permission()) ->
                     {user, allowed,
                      User::fifo:user_token_id(),
                      Permission::fifo:permission()}.

allowed(Realm, ?Token, Permission)
  when is_list(Permission) ->
    {user, allowed, Realm, Token, Permission};

allowed(Realm, ?User, Permission)
  when is_list(Permission) ->
    {user, allowed, Realm, User, Permission}.

%%%===================================================================
%%% Token Functions
%%%===================================================================

-spec token_delete(Realm::binary(), Token::fifo:token()) ->
                          {token, delete, Token::fifo:token()}.
token_delete(Realm, <<Token:36/binary>>) ->
    {token, delete, Realm, Token}.

%%%===================================================================
%%% User Functions
%%%===================================================================

%%--------------------------------------------------------------------
%% @doc Sets a attribute for the user.
%% @end
%%--------------------------------------------------------------------
-spec user_set(Realm::binary(),
               User::fifo:user_id(),
               Attribute::fifo:keys(),
               Value::fifo:value()  | delete) ->
                      {user, set, User::fifo:user_id(),
                       Attribute::fifo:keys(),
                       Value::fifo:value()  | delete}.
user_set(Realm, ?User, Attribute, Value) ->
    {user, set, Realm, User, Attribute, Value}.

%%--------------------------------------------------------------------
%% @doc Sets multiple attributes for the user.
%% @end
%%--------------------------------------------------------------------
-spec user_set(Realm::binary(), User::fifo:user_id(),
               Attributes::fifo:attr_list()) ->
                      {user, set,
                       User::fifo:uuid(),
                       Attributes::fifo:attr_list()}.
user_set(Realm, ?User, Attributes) ->
    {user, set, Realm, User, Attributes}.

%%--------------------------------------------------------------------
%% @doc Retrievs a list of all user id's.
%% @spec user_list() ->
%%                 [term()]
%% @end
%%--------------------------------------------------------------------
-spec user_list(Realm::binary()) ->
                       {user, list}.
user_list(Realm) ->
    {user, list, Realm}.

%%--------------------------------------------------------------------
%% @doc Retrievs a list of all user id's.
%% @spec user_list() ->
%%                 [term()]
%% @end
%%--------------------------------------------------------------------
-spec user_list(Realm::binary(), Reqs::[fifo:matcher()], boolean()) ->
                       {user, list, Reqs::[fifo:matcher()], boolean()}.
user_list(Realm, Reqs, Full) ->
    {user, list, Realm, Reqs, Full}.

%%--------------------------------------------------------------------
%% @doc Retrieves user data from the server.
%% @end
%%--------------------------------------------------------------------
-spec user_get(Realm::binary(), User::fifo:user_token_id()) ->
                      {user, get, User::fifo:user_token_id()}.
user_get(Realm, ?Token) ->
    {user, get, Realm, Token};

user_get(Realm, ?User) ->
    {user, get, Realm, User}.


%%--------------------------------------------------------------------
%% @doc Retrieves user data from the server.
%% @end
%%--------------------------------------------------------------------
-spec user_lookup(Realm::binary(), Login::binary()) ->
                         {user, lookup, Login::binary()}.
user_lookup(Realm, Login) when is_binary(Login) ->
    {user, lookup, Realm, Login}.

%%--------------------------------------------------------------------
%% @doc Retrieves all user permissions to later test.
%% @end
%%--------------------------------------------------------------------
-spec user_cache(Realm::binary(), User::fifo:user_token_id()) ->
                        {user, cache, User::fifo:user_token_id()}.
user_cache(Realm, ?Token) ->
    {user, cache, Realm, Token};
user_cache(Realm, ?User) ->
    {user, cache, Realm, User}.

-spec user_add(Realm::binary(), UserName::binary()) ->
                      {user, add, UserName::binary()}.
user_add(Realm, UserName) ->
    {user, add, Realm, UserName}.

-spec user_add(Realm::binary(), Creator::fifo:user_id(),
               UserName::binary()) ->
                      {user, add, Creator::fifo:user_id(), UserName::binary()}.
user_add(Realm, Creator, UserName) ->
    {user, add, Realm, Creator, UserName}.

%%--------------------------------------------------------------------
%% @doc Deletes a user.
%% @end
%%--------------------------------------------------------------------
-spec user_delete(Realm::binary(), User::fifo:user_id()) ->
                         {user, delete, User::fifo:user_id()}.
user_delete(Realm, User) ->
    {user, delete, Realm, User}.

%%--------------------------------------------------------------------
%% @doc Grants a right of a user.
%% @end
%%--------------------------------------------------------------------

-spec user_grant(Realm::binary(), User::fifo:user_id(),
                 Permission::fifo:permission()) ->
                        {user, grant,
                         User::fifo:user_id(),
                         Permission::fifo:permission()}.
user_grant(Realm, User, Permission) ->
    {user, grant, Realm, User, Permission}.

%%--------------------------------------------------------------------
%% @doc Revokes a right of a user.
%% @end
%%--------------------------------------------------------------------
-spec user_revoke(Realm::binary(), User::fifo:user_id(),
                  Permission::fifo:permission()) ->
                         {user, revoke,
                          User::fifo:user_id(),
                          Permission::fifo:permission()}.
user_revoke(Realm, User, Permission) ->
    {user, revoke, Realm, User, Permission}.

%%--------------------------------------------------------------------
%% @doc Revokes all right with a certain prefix from a user.
%% @end
%%--------------------------------------------------------------------
-spec user_revoke_prefix(Realm::binary(), User::fifo:user_id(),
                         Prefix::fifo:permission()) ->
                                {user, revoke_prefix,
                                 User::fifo:user_id(),
                                 Permission::fifo:permission()}.
user_revoke_prefix(Realm, ?User, Prefix) when is_list(Prefix)->
    {user, revoke_prefix, Realm, User, Prefix}.

%%--------------------------------------------------------------------
%% @doc Changes the Password of a user.
%% @spec user_passwd(User::binary(), Pass::binary()) ->
%%           ok |
%%           {error, not_found|no_servers}
%% @end
%%--------------------------------------------------------------------
-spec user_passwd(Realm::binary(), User::fifo:user_id(), Pass::binary()) ->
                         {user, passwd, User::fifo:user_id(), Pass::binary()}.
user_passwd(Realm, ?User, Pass) when is_binary(Pass) ->
    {user, passwd, Realm, User, Pass}.

%%--------------------------------------------------------------------
%% @doc Adds a user to a role.
%% @end
%%--------------------------------------------------------------------

-spec user_join(Realm::binary(), User::fifo:user_id(), Role::fifo:role_id()) ->
                       {user, join, User::fifo:user_id(), Role::fifo:role_id()}.
user_join(Realm, ?User, ?Role) ->
    {user, join, Realm, User, Role}.

-spec user_leave(Realm::binary(), User::fifo:user_id(), Role::fifo:role_id()) ->
                        {user, leave,
                         User::fifo:user_id(),
                         Role::fifo:role_id()}.

user_leave(Realm, ?User, ?Role) ->
    {user, leave, Realm, User, Role}.

-spec user_key_find(Realm::binary(), KeyID::binary()) ->
                           {user, keys, find, KeyID::binary()}.

user_key_find(Realm, <<KeyID:16/binary>>) ->
    {user, keys, find, Realm, KeyID}.


-spec user_key_add(Realm::binary(), User::fifo:user_id(), KeyID::binary(), Key::binary()) ->
                          {user, keys, add, User::fifo:user_id(), KeyID::binary(), Key::binary()}.
user_key_add(Realm, ?User, KeyID, Key)
  when is_binary(KeyID),
       is_binary(Key) ->
    {user, keys, add, Realm, User, KeyID, Key}.

-spec user_key_revoke(Realm::binary(), User::fifo:user_id(), KeyID::binary()) ->
                             {user, keys, revoke, User::fifo:user_id(), KeyID::binary()}.
user_key_revoke(Realm, ?User, KeyID)
  when is_binary(KeyID) ->
    {user, keys, revoke, Realm, User, KeyID}.

-spec user_keys(Realm::binary(), User::fifo:user_id()) ->
                       {user, keys, get, User::fifo:user_id()}.
user_keys(Realm, ?User) ->
    {user, keys, get, Realm, User}.

-spec user_yubikey_add(Realm::binary(), User::fifo:user_id(), KeyID::binary()) ->
                              {user, yubikeys, add, User::fifo:user_id(), KeyID::binary()}.
user_yubikey_add(Realm, ?User, KeyID)
  when is_binary(KeyID) ->
    {user, yubikeys, add, Realm, User, KeyID}.

-spec user_yubikey_remove(Realm::binary(), User::fifo:user_id(), KeyID::binary()) ->
                                 {user, yubikeys, remove, User::fifo:user_id(), KeyID::binary()}.
user_yubikey_remove(Realm, ?User, KeyID)
  when is_binary(KeyID) ->
    {user, yubikeys, remove, Realm, User, KeyID}.

-spec user_yubikeys(Realm::binary(), User::fifo:user_id()) ->
                           {user, yubikeys, get, User::fifo:user_id()}.
user_yubikeys(Realm, ?User) ->
    {user, yubikeys, get, Realm, User}.

-spec user_join_org(Realm::binary(), User::fifo:user_id(), Org::fifo:org_id()) ->
                           {user, org, join,
                            User::fifo:user_id(),
                            Org::fifo:org_id()}.
user_join_org(Realm, ?User, ?Org) ->
    {user, org, join, Realm, User, Org}.

-spec user_orgs(Realm::binary(), User::fifo:user_id()) ->
                       {user, org, get,
                        User::fifo:user_id()}.
user_orgs(Realm, ?User) ->
    {user, org, get, Realm, User}.

-spec user_active_org(Realm::binary(), User::fifo:user_id()) ->
                             {user, org, active,
                              User::fifo:user_id()}.
user_active_org(Realm, ?User) ->
    {user, org, active, Realm, User}.

-spec user_leave_org(Realm::binary(), User::fifo:user_id(), Org::fifo:org_id()) ->
                            {user, org, leave,
                             User::fifo:user_id(),
                             Org::fifo:org_id()}.
user_leave_org(Realm, ?User, ?Org) ->
    {user, org, leave, Realm, User, Org}.

-spec user_select_org(Realm::binary(), User::fifo:user_id(), Org::fifo:org_id()) ->
                             {user, org, select,
                              User::fifo:user_id(),
                              Org::fifo:org_id()}.
user_select_org(Realm, ?User, ?Org) ->
    {user, org, select, Realm, User, Org}.


%%%===================================================================
%%% Role Functions
%%%===================================================================

%%--------------------------------------------------------------------
%% @doc Sets an attribute on the role.
%% @end
%%--------------------------------------------------------------------
-spec role_set(Realm::binary(), Role::fifo:role_id(),
               Attribute::fifo:keys(),
               Value::fifo:value() | delete) ->
                      {role, set,
                       Role::fifo:role_id(),
                       Attribute::fifo:keys(),
                       Value::fifo:value() | delete}.

role_set(Realm, ?Role, Attribute, Value)  ->
    {role, set, Realm, Role, Attribute, Value}.

%%--------------------------------------------------------------------
%% @doc Sets multiple attributes on the role.
%% @end
%%--------------------------------------------------------------------
-spec role_set(Realm::binary(), Role::fifo:role_id(),
               Attributes::fifo:attr_list()) ->
                      {role, set,
                       Role::fifo:role_id(),
                       Attributes::fifo:attr_list()}.
role_set(Realm, ?Role, Attributes) when
      is_list(Attributes) ->
    {role, set, Realm, Role, Attributes}.

%%--------------------------------------------------------------------
%% @doc Retrievs a list of all role id's.
%% @end
%%--------------------------------------------------------------------
-spec role_list(Realm::binary()) ->
                       {role, list}.
role_list(Realm) ->
    {role, list, Realm}.

%%--------------------------------------------------------------------
%% @doc Retrievs a list of all user id's.
%% @spec role_list() ->
%%                 [term()]
%% @end
%%--------------------------------------------------------------------
-spec role_list(Realm::binary(), Reqs::[fifo:matcher()], boolean()) ->
                       {role, list, Reqs::[fifo:matcher()], boolean()}.
role_list(Realm, Reqs, Full) ->
    {role, list, Realm, Reqs, Full}.

%%--------------------------------------------------------------------
%% @doc Retrieves role data from the server.
%% @end
%%--------------------------------------------------------------------
-spec role_get(Realm::binary(), Role::fifo:role_id()) ->
                      {role, get, Role::fifo:role_id()}.
role_get(Realm, ?Role) ->
    {role, get, Realm, Role}.

%%--------------------------------------------------------------------
%% @doc Adds a new role.
%% @end
%%--------------------------------------------------------------------
-spec role_add(Realm::binary(), RoleName::binary()) ->
                      {role, add, RoleName::binary()}.
role_add(Realm, RoleName) when is_binary(RoleName)->
    {role, add, Realm, RoleName}.

%%--------------------------------------------------------------------
%% @doc Deletes a role.
%% @end
%%--------------------------------------------------------------------
-spec role_delete(Realm::binary(), Role::fifo:role_id()) ->
                         {role, delete, Role::fifo:role_id()}.
role_delete(Realm, ?Role) ->
    {role, delete, Realm, Role}.

%%--------------------------------------------------------------------
%% @doc Grants a right of a role.
%% @end
%%--------------------------------------------------------------------
-spec role_grant(Realm::binary(), Role::fifo:role_id(),
                 Permission::fifo:permission()) ->
                        {role, grant,
                         Role::fifo:role_id(),
                         Permission::fifo:permission()}.

role_grant(Realm, ?Role, Permission) when is_list(Permission) ->
    {role, grant, Realm, Role, Permission}.

%%--------------------------------------------------------------------
%% @doc Revokes a right of a role.
%% @end
%%--------------------------------------------------------------------
-spec role_revoke(Realm::binary(), Role::fifo:role_id(),
                  Permission::fifo:permission()) ->
                         {role, revoke,
                          Role::fifo:role_id(),
                          Permission::fifo:permission()}.
role_revoke(Realm, ?Role, Permission) when is_list(Permission) ->
    {role, revoke, Realm, Role, Permission}.

%%--------------------------------------------------------------------
%% @doc Revokes all rights matching a prefix from a role.
%% @end
%%--------------------------------------------------------------------
-spec role_revoke_prefix(Realm::binary(), Role::fifo:role_id(),
                         Prefix::fifo:permission()) ->
                                {role, revoke_prefix,
                                 Role::fifo:role_id(),
                                 Permission::fifo:permission()}.
role_revoke_prefix(Realm, ?Role, Prefix) when is_list(Prefix) ->
    {role, revoke_prefix, Realm, Role, Prefix}.


%%%===================================================================
%%% Org Functions
%%%===================================================================

%%--------------------------------------------------------------------
%% @doc Sets an attribute on the org.
%% @end
%%--------------------------------------------------------------------
-spec org_set(Realm::binary(), Org::fifo:org_id(),
              Attribute::fifo:keys(),
              Value::fifo:value() | delete) ->
                     {org, set,
                      Org::fifo:org_id(),
                      Attribute::fifo:keys(),
                      Value::fifo:value() | delete}.

org_set(Realm, ?Org, Attribute, Value)  ->
    {org, set, Realm, Org, Attribute, Value}.

%%--------------------------------------------------------------------
%% @doc Sets multiple attributes on the org.
%% @end
%%--------------------------------------------------------------------
-spec org_set(Realm::binary(), Org::fifo:org_id(),
              Attributes::fifo:attr_list()) ->
                     {org, set,
                      Org::fifo:org_id(),
                      Attributes::fifo:attr_list()}.
org_set(Realm, ?Org, Attributes) when
      is_list(Attributes) ->
    {org, set, Realm, Org, Attributes}.

%%--------------------------------------------------------------------
%% @doc Retrievs a list of all org id's.
%% @end
%%--------------------------------------------------------------------
-spec org_list(Realm::binary()) ->
                      {org, list}.
org_list(Realm) ->
    {org, list, Realm}.

-spec org_list(Realm::binary(), Reqs::[fifo:matcher()], boolean()) ->
                      {org, list, Reqs::[fifo:matcher()], boolean()}.
org_list(Realm, Reqs, Full) ->
    {org, list, Realm, Reqs, Full}.

%%--------------------------------------------------------------------
%% @doc Retrieves org data from the server.
%% @end
%%--------------------------------------------------------------------
-spec org_get(Realm::binary(), Org::fifo:org_id()) ->
                     {org, get, Org::fifo:org_id()}.
org_get(Realm, ?Org) ->
    {org, get, Realm, Org}.

%%--------------------------------------------------------------------
%% @doc Adds a new org.
%% @end
%%--------------------------------------------------------------------
-spec org_add(Realm::binary(), OrgName::binary()) ->
                     {org, add, OrgName::binary()}.
org_add(Realm, OrgName) when is_binary(OrgName)->
    {org, add, Realm, OrgName}.

%%--------------------------------------------------------------------
%% @doc Deletes a org.
%% @end
%%--------------------------------------------------------------------
-spec org_delete(Realm::binary(), Org::fifo:org_id()) ->
                        {org, delete, Org::fifo:org_id()}.
org_delete(Realm, ?Org) ->
    {org, delete, Realm, Org}.

%%--------------------------------------------------------------------
%% @doc adds a trigger.
%% @end
%%--------------------------------------------------------------------
-spec org_add_trigger(Realm::binary(), Org::fifo:org_id(),
                      Trigger::fifo:trigger()) ->
                             {org, trigger, add,
                              Org::fifo:org_id(),
                              Trigger::fifo:trigger()}.

org_add_trigger(Realm, ?Org, Trigger) ->
    {org, trigger, add, Realm, Org, Trigger}.

%%--------------------------------------------------------------------
%% @doc Removes a trigger.
%% @end
%%--------------------------------------------------------------------
-spec org_remove_trigger(Realm::binary(), Org::fifo:org_id(),
                         Trigger::fifo:trigger()) ->
                                {org, trigger, remove,
                                 Org::fifo:org_id(),
                                 Trigger::fifo:trigger()}.

org_remove_trigger(Realm, ?Org, Trigger) ->
    {org, trigger, remove, Realm, Org, Trigger}.

%%--------------------------------------------------------------------
%% @doc Executes a trigger.
%% @end
%%--------------------------------------------------------------------
-spec org_execute_trigger(Realm::binary(), Org::fifo:org_id(),
                          Event::fifo:event(),
                          Payload::term()) ->
                                 {org, trigger, execute,
                                  Org::fifo:org_id(),
                                  Trigger::fifo:trigger(),
                                  Payload::term()}.

org_execute_trigger(Realm, ?Org, Event, Payload) ->
    {org, trigger, execute, Realm, Org, Event, Payload}.

%%%===================================================================
%%% Internal Functions
%%%===================================================================
