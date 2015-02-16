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
         user_make_token/2,
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
         user_active_org/2,
         user_orgs/2,
         user_join_org/3,
         user_leave_org/3,
         user_select_org/3,
         user_set_metadata/3
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
         role_set_metadata/3
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
         org_resource_action/6,
         org_set_metadata/3
        ]).

-export([authorize_password/3]).
-export([authorize_password/4]).
-export([authorize_password/5]).
-export([authorize_client_credentials/3]).
-export([authorize_code_grant/4]).
-export([authorize_code_request/5]).
-export([issue_code/2]).
-export([issue_token/2]).
-export([issue_token_and_refresh/2]).
-export([verify_access_token/2]).
-export([verify_access_code/2]).
-export([verify_access_code/3]).
-export([refresh_access_token/4]).


-define(User, <<User:36/binary>>).
-define(Role, <<Role:36/binary>>).
-define(Org, <<Org:36/binary>>).
-define(Token, {token, <<_:36/binary>>} = Token).


%%%===================================================================
%%% Generatl Functions
%%%===================================================================

-spec auth(Realm::binary(), Login::binary(), Pass::binary()) ->
                  {user, auth, Realm::binary(), Login::binary(), Pass::binary()}.
auth(Realm, Login, Pass) when
      is_binary(Realm),
      is_binary(Login),
      is_binary(Pass)->
    {user, auth, Realm, Login, Pass}.

-spec auth(Realm::binary(), Login::binary(), Pass::binary(), OTP::binary()|basic) ->
                  {user, auth, Realm::binary(), Login::binary(), Pass::binary(),
                   OTP::binary() | basic}.
auth(Realm, Login, Pass, basic) when
      is_binary(Realm),
      is_binary(Login),
      is_binary(Pass) ->
    {user, auth, Realm, Login, Pass, basic};

auth(Realm, Login, Pass, OTP) when
      is_binary(Realm),
      is_binary(Login),
      is_binary(Pass),
      is_binary(OTP) ->
    {user, auth, Realm, Login, Pass, OTP}.

-spec allowed(Realm::binary(),
              User::fifo:user_token_id(),
              Permission::fifo:permission()) ->
                     {user, allowed, Realm::binary(),
                      User::fifo:user_token_id(),
                      Permission::fifo:permission()}.

allowed(Realm, ?Token, Permission) when
      is_binary(Realm),
      is_list(Permission) ->
    {user, allowed, Realm, Token, Permission};

allowed(Realm, ?User, Permission)
  when is_list(Permission) ->
    {user, allowed, Realm, User, Permission}.

%%%===================================================================
%%% Token Functions
%%%===================================================================

-spec token_delete(Realm::binary(), Token::fifo:token()) ->
                          {token, delete, Realm::binary(), Token::fifo:token()}.
token_delete(Realm, <<Token:36/binary>>) when
      is_binary(Realm) ->
    {token, delete, Realm, Token}.

%%%===================================================================
%%% User Functions
%%%===================================================================

-spec user_set_metadata(Ream::binary(), User::fifo:user_id(),
                        Attrs::fifo:attr_list()) ->
                               {user, set_metadata, Realm::binary(),
                                User::fifo:user_id(), Attrs::fifo:attr_list()}.

user_set_metadata(Realm, User, Attrs) when
      is_binary(Realm),
      is_binary(User),
      is_list(Attrs) ->
    {user, set_metadata, Realm, User, Attrs}.
%%--------------------------------------------------------------------
%% @doc Retrievs a list of all user id's.
%% @spec user_list() ->
%%                 [term()]
%% @end
%%--------------------------------------------------------------------
-spec user_list(Realm::binary()) ->
                       {user, list, Realm::binary()}.
user_list(Realm) when
      is_binary(Realm) ->
    {user, list, Realm}.

%%--------------------------------------------------------------------
%% @doc Retrievs a list of all user id's.
%% @spec user_list() ->
%%                 [term()]
%% @end
%%--------------------------------------------------------------------
-spec user_list(Realm::binary(), Reqs::[fifo:matcher()], boolean()) ->
                       {user, list, Realm::binary(), Reqs::[fifo:matcher()], boolean()}.
user_list(Realm, Reqs, Full) when
      is_binary(Realm) ->
    {user, list, Realm, Reqs, Full}.


%%--------------------------------------------------------------------
%% @doc Retrieves user data from the server.
%% @end
%%--------------------------------------------------------------------
-spec user_get(Realm::binary(), User::fifo:user_token_id()) ->
                      {user, get, Realm::binary(), User::fifo:user_token_id()}.
user_get(Realm, ?Token) when
      is_binary(Realm) ->
    {user, get, Realm, Token};

user_get(Realm, ?User) when
      is_binary(Realm) ->
    {user, get, Realm, User}.

%%--------------------------------------------------------------------
%% @doc Creates a token for a user.
%% @end
%%--------------------------------------------------------------------
-spec user_make_token(Realm::binary(), User::fifo:user_id()) ->
                      {user, token, Realm::binary(), User::fifo:user_id()}.

user_make_token(Realm, ?User) when
      is_binary(Realm) ->
    {user, token, Realm, User}.


%%--------------------------------------------------------------------
%% @doc Retrieves user data from the server.
%% @end
%%--------------------------------------------------------------------
-spec user_lookup(Realm::binary(), Login::binary()) ->
                         {user, lookup, Realm::binary(), Login::binary()}.
user_lookup(Realm, Login) when
      is_binary(Realm),
      is_binary(Login) ->
    {user, lookup, Realm, Login}.

%%--------------------------------------------------------------------
%% @doc Retrieves all user permissions to later test.
%% @end
%%--------------------------------------------------------------------
-spec user_cache(Realm::binary(), User::fifo:user_token_id()) ->
                        {user, cache, Realm::binary(), User::fifo:user_token_id()}.
user_cache(Realm, ?Token) when
      is_binary(Realm) ->
    {user, cache, Realm, Token};
user_cache(Realm, ?User) when
      is_binary(Realm) ->
    {user, cache, Realm, User}.

-spec user_add(Realm::binary(), UserName::binary()) ->
                      {user, add, Realm::binary(), UserName::binary()}.
user_add(Realm, UserName) when
      is_binary(Realm),
      is_binary(UserName) ->
    {user, add, Realm, UserName}.

-spec user_add(Realm::binary(), Creator::fifo:user_id(),
               UserName::binary()) ->
                      {user, add, Realm::binary(), Creator::fifo:user_id(), UserName::binary()}.
user_add(Realm, Creator, UserName) when
      is_binary(Realm),
      is_binary(Creator),
      is_binary(UserName) ->
    {user, add, Realm, Creator, UserName}.

%%--------------------------------------------------------------------
%% @doc Deletes a user.
%% @end
%%--------------------------------------------------------------------
-spec user_delete(Realm::binary(), User::fifo:user_id()) ->
                         {user, delete, Realm::binary(), User::fifo:user_id()}.
user_delete(Realm, User) when
      is_binary(Realm),
      is_binary(User) ->
    {user, delete, Realm, User}.

%%--------------------------------------------------------------------
%% @doc Grants a right of a user.
%% @end
%%--------------------------------------------------------------------

-spec user_grant(Realm::binary(), User::fifo:user_id(),
                 Permission::fifo:permission()) ->
                        {user, grant, Realm::binary(),
                         User::fifo:user_id(),
                         Permission::fifo:permission()}.
user_grant(Realm, User, Permission) when
      is_binary(Realm),
      is_binary(User) ->
    {user, grant, Realm, User, Permission}.

%%--------------------------------------------------------------------
%% @doc Revokes a right of a user.
%% @end
%%--------------------------------------------------------------------
-spec user_revoke(Realm::binary(), User::fifo:user_id(),
                  Permission::fifo:permission()) ->
                         {user, revoke, Realm::binary(),
                          User::fifo:user_id(),
                          Permission::fifo:permission()}.
user_revoke(Realm, User, Permission) when
      is_binary(Realm),
      is_binary(User) ->
    {user, revoke, Realm, User, Permission}.

%%--------------------------------------------------------------------
%% @doc Revokes all right with a certain prefix from a user.
%% @end
%%--------------------------------------------------------------------
-spec user_revoke_prefix(Realm::binary(), User::fifo:user_id(),
                         Prefix::fifo:permission()) ->
                                {user, revoke_prefix, Realm::binary(),
                                 User::fifo:user_id(),
                                 Permission::fifo:permission()}.
user_revoke_prefix(Realm, ?User, Prefix) when
      is_binary(Realm),
      is_list(Prefix) ->
    {user, revoke_prefix, Realm, User, Prefix}.

%%--------------------------------------------------------------------
%% @doc Changes the Password of a user.
%% @spec user_passwd(User::binary(), Pass::binary()) ->
%%           ok |
%%           {error, not_found|no_servers}
%% @end
%%--------------------------------------------------------------------
-spec user_passwd(Realm::binary(), User::fifo:user_id(), Pass::binary()) ->
                         {user, passwd, Realm::binary(), User::fifo:user_id(), Pass::binary()}.
user_passwd(Realm, ?User, Pass) when
      is_binary(Realm),
      is_binary(Pass) ->
    {user, passwd, Realm, User, Pass}.

%%--------------------------------------------------------------------
%% @doc Adds a user to a role.
%% @end
%%--------------------------------------------------------------------

-spec user_join(Realm::binary(), User::fifo:user_id(), Role::fifo:role_id()) ->
                       {user, join, Realm::binary(), User::fifo:user_id(), Role::fifo:role_id()}.
user_join(Realm, ?User, ?Role) when
      is_binary(Realm) ->
    {user, join, Realm, User, Role}.

-spec user_leave(Realm::binary(), User::fifo:user_id(), Role::fifo:role_id()) ->
                        {user, leave, Realm::binary(),
                         User::fifo:user_id(),
                         Role::fifo:role_id()}.

user_leave(Realm, ?User, ?Role) when
      is_binary(Realm) ->
    {user, leave, Realm, User, Role}.

-spec user_key_find(Realm::binary(), KeyID::binary()) ->
                           {user, keys, find, Realm::binary(), KeyID::binary()}.

user_key_find(Realm, <<KeyID:16/binary>>) when
      is_binary(Realm) ->
    {user, keys, find, Realm, KeyID}.


-spec user_key_add(Realm::binary(), User::fifo:user_id(), KeyID::binary(), Key::binary()) ->
                          {user, keys, add, Realm::binary(), User::fifo:user_id(), KeyID::binary(), Key::binary()}.
user_key_add(Realm, ?User, KeyID, Key)when
      is_binary(Realm),
      is_binary(KeyID),
      is_binary(Key) ->
    {user, keys, add, Realm, User, KeyID, Key}.

-spec user_key_revoke(Realm::binary(), User::fifo:user_id(), KeyID::binary()) ->
                             {user, keys, revoke, Realm::binary(), User::fifo:user_id(), KeyID::binary()}.
user_key_revoke(Realm, ?User, KeyID)when
      is_binary(Realm),
      is_binary(KeyID) ->
    {user, keys, revoke, Realm, User, KeyID}.

-spec user_keys(Realm::binary(), User::fifo:user_id()) ->
                       {user, keys, get, Realm::binary(), User::fifo:user_id()}.
user_keys(Realm, ?User) when
      is_binary(Realm) ->
    {user, keys, get, Realm, User}.

-spec user_yubikey_add(Realm::binary(), User::fifo:user_id(), KeyID::binary()) ->
                              {user, yubikeys, add, Realm::binary(), User::fifo:user_id(), KeyID::binary()}.
user_yubikey_add(Realm, ?User, KeyID)when
      is_binary(Realm),
      is_binary(KeyID) ->
    {user, yubikeys, add, Realm, User, KeyID}.

-spec user_yubikey_remove(Realm::binary(), User::fifo:user_id(), KeyID::binary()) ->
                                 {user, yubikeys, remove, Realm::binary(), User::fifo:user_id(), KeyID::binary()}.
user_yubikey_remove(Realm, ?User, KeyID) when
      is_binary(Realm),
      is_binary(KeyID) ->
    {user, yubikeys, remove, Realm, User, KeyID}.

-spec user_yubikeys(Realm::binary(), User::fifo:user_id()) ->
                           {user, yubikeys, get, Realm::binary(), User::fifo:user_id()}.
user_yubikeys(Realm, ?User) when
      is_binary(Realm) ->
    {user, yubikeys, get, Realm, User}.

-spec user_join_org(Realm::binary(), User::fifo:user_id(), Org::fifo:org_id()) ->
                           {user, org, join, Realm::binary(),
                            User::fifo:user_id(),
                            Org::fifo:org_id()}.
user_join_org(Realm, ?User, ?Org) when
      is_binary(Realm) ->
    {user, org, join, Realm, User, Org}.

-spec user_orgs(Realm::binary(), User::fifo:user_id()) ->
                       {user, org, get, Realm::binary(),
                        User::fifo:user_id()}.
user_orgs(Realm, ?User) when
      is_binary(Realm) ->
    {user, org, get, Realm, User}.

-spec user_active_org(Realm::binary(), User::fifo:user_id()) ->
                             {user, org, active, Realm::binary(),
                              User::fifo:user_id()}.
user_active_org(Realm, ?User) when
      is_binary(Realm) ->
    {user, org, active, Realm, User}.

-spec user_leave_org(Realm::binary(), User::fifo:user_id(), Org::fifo:org_id()) ->
                            {user, org, leave, Realm::binary(),
                             User::fifo:user_id(),
                             Org::fifo:org_id()}.
user_leave_org(Realm, ?User, ?Org) when
      is_binary(Realm) ->
    {user, org, leave, Realm, User, Org}.

-spec user_select_org(Realm::binary(), User::fifo:user_id(), Org::fifo:org_id()) ->
                             {user, org, select, Realm::binary(),
                              User::fifo:user_id(),
                              Org::fifo:org_id()}.
user_select_org(Realm, ?User, ?Org) when
      is_binary(Realm) ->
    {user, org, select, Realm, User, Org}.


%%%===================================================================
%%% Role Functions
%%%===================================================================

-spec role_set_metadata(Ream::binary(), Role::fifo:role_id(),
                        Attrs::fifo:attr_list()) ->
                               {role, set_metadata, Realm::binary(),
                                Role::fifo:role_id(), Attrs::fifo:attr_list()}.

role_set_metadata(Realm, Role, Attrs) when
      is_binary(Realm),
      is_binary(Role),
      is_list(Attrs) ->
    {role, set_metadata, Realm, Role, Attrs}.

%%--------------------------------------------------------------------
%% @doc Retrievs a list of all role id's.
%% @end
%%--------------------------------------------------------------------
-spec role_list(Realm::binary()) ->
                       {role, list, Realm::binary()}.
role_list(Realm) when
      is_binary(Realm) ->
    {role, list, Realm}.

%%--------------------------------------------------------------------
%% @doc Retrievs a list of all user id's.
%% @spec role_list() ->
%%                 [term()]
%% @end
%%--------------------------------------------------------------------
-spec role_list(Realm::binary(), Reqs::[fifo:matcher()], boolean()) ->
                       {role, list, Realm::binary(),
                        Reqs::[fifo:matcher()],
                        boolean()}.
role_list(Realm, Reqs, Full) when
      is_binary(Realm) ->
    {role, list, Realm, Reqs, Full}.

%%--------------------------------------------------------------------
%% @doc Retrieves role data from the server.
%% @end
%%--------------------------------------------------------------------
-spec role_get(Realm::binary(), Role::fifo:role_id()) ->
                      {role, get, Realm::binary(), Role::fifo:role_id()}.
role_get(Realm, ?Role) when
      is_binary(Realm) ->
    {role, get, Realm, Role}.

%%--------------------------------------------------------------------
%% @doc Adds a new role.
%% @end
%%--------------------------------------------------------------------
-spec role_add(Realm::binary(), RoleName::binary()) ->
                      {role, add, Realm::binary(), RoleName::binary()}.
role_add(Realm, RoleName) when
      is_binary(Realm),
      is_binary(RoleName) ->
    {role, add, Realm, RoleName}.

%%--------------------------------------------------------------------
%% @doc Deletes a role.
%% @end
%%--------------------------------------------------------------------
-spec role_delete(Realm::binary(), Role::fifo:role_id()) ->
                         {role, delete, Realm::binary(), Role::fifo:role_id()}.
role_delete(Realm, ?Role) when
      is_binary(Realm) ->
    {role, delete, Realm, Role}.

%%--------------------------------------------------------------------
%% @doc Grants a right of a role.
%% @end
%%--------------------------------------------------------------------
-spec role_grant(Realm::binary(), Role::fifo:role_id(),
                 Permission::fifo:permission()) ->
                        {role, grant, Realm::binary(),
                         Role::fifo:role_id(),
                         Permission::fifo:permission()}.

role_grant(Realm, ?Role, Permission) when
      is_binary(Realm),
      is_list(Permission) ->
    {role, grant, Realm, Role, Permission}.

%%--------------------------------------------------------------------
%% @doc Revokes a right of a role.
%% @end
%%--------------------------------------------------------------------
-spec role_revoke(Realm::binary(), Role::fifo:role_id(),
                  Permission::fifo:permission()) ->
                         {role, revoke, Realm::binary(),
                          Role::fifo:role_id(),
                          Permission::fifo:permission()}.
role_revoke(Realm, ?Role, Permission) when
      is_binary(Realm),
      is_list(Permission) ->
    {role, revoke, Realm, Role, Permission}.

%%--------------------------------------------------------------------
%% @doc Revokes all rights matching a prefix from a role.
%% @end
%%--------------------------------------------------------------------
-spec role_revoke_prefix(Realm::binary(), Role::fifo:role_id(),
                         Prefix::fifo:permission()) ->
                                {role, revoke_prefix, Realm::binary(),
                                 Role::fifo:role_id(),
                                 Permission::fifo:permission()}.
role_revoke_prefix(Realm, ?Role, Prefix) when
      is_binary(Realm),
      is_list(Prefix) ->
    {role, revoke_prefix, Realm, Role, Prefix}.


%%%===================================================================
%%% Org Functions
%%%===================================================================

-spec org_set_metadata(Ream::binary(), Org::fifo:org_id(),
                        Attrs::fifo:attr_list()) ->
                               {org, set_metadata, Realm::binary(),
                                Org::fifo:org_id(), Attrs::fifo:attr_list()}.

org_set_metadata(Realm, Org, Attrs) when
      is_binary(Realm),
      is_binary(Org),
      is_list(Attrs) ->
    {org, set_metadata, Realm, Org, Attrs}.

%%--------------------------------------------------------------------
%% @doc Retrievs a list of all org id's.
%% @end
%%--------------------------------------------------------------------
-spec org_list(Realm::binary()) ->
                      {org, list, Realm::binary()}.
org_list(Realm) when
      is_binary(Realm) ->
    {org, list, Realm}.

-spec org_list(Realm::binary(), Reqs::[fifo:matcher()], boolean()) ->
                      {org, list, Realm::binary(), Reqs::[fifo:matcher()],
                       boolean()}.
org_list(Realm, Reqs, Full) when
      is_binary(Realm) ->
    {org, list, Realm, Reqs, Full}.

%%--------------------------------------------------------------------
%% @doc Retrieves org data from the server.
%% @end
%%--------------------------------------------------------------------
-spec org_get(Realm::binary(), Org::fifo:org_id()) ->
                     {org, get, Realm::binary(), Org::fifo:org_id()}.
org_get(Realm, ?Org) when
      is_binary(Realm) ->
    {org, get, Realm, Org}.

%%--------------------------------------------------------------------
%% @doc Adds a new org.
%% @end
%%--------------------------------------------------------------------
-spec org_add(Realm::binary(), OrgName::binary()) ->
                     {org, add, Realm::binary(), OrgName::binary()}.
org_add(Realm, OrgName) when
      is_binary(Realm),
      is_binary(OrgName) ->
    {org, add, Realm, OrgName}.

%%--------------------------------------------------------------------
%% @doc Deletes a org.
%% @end
%%--------------------------------------------------------------------
-spec org_delete(Realm::binary(), Org::fifo:org_id()) ->
                        {org, delete, Realm::binary(), Org::fifo:org_id()}.
org_delete(Realm, ?Org) when
      is_binary(Realm) ->
    {org, delete, Realm, Org}.

%%--------------------------------------------------------------------
%% @doc adds a trigger.
%% @end
%%--------------------------------------------------------------------
-spec org_add_trigger(Realm::binary(), Org::fifo:org_id(),
                      Trigger::fifo:trigger()) ->
                             {org, trigger, add, Realm::binary(),
                              Org::fifo:org_id(),
                              Trigger::fifo:trigger()}.

org_add_trigger(Realm, ?Org, Trigger) when
      is_binary(Realm) ->
    {org, trigger, add, Realm, Org, Trigger}.

%%--------------------------------------------------------------------
%% @doc Removes a trigger.
%% @end
%%--------------------------------------------------------------------
-spec org_remove_trigger(Realm::binary(), Org::fifo:org_id(),
                         Trigger::fifo:trigger()) ->
                                {org, trigger, remove, Realm::binary(),
                                 Org::fifo:org_id(),
                                 Trigger::fifo:trigger()}.

org_remove_trigger(Realm, ?Org, Trigger) when
      is_binary(Realm) ->
    {org, trigger, remove, Realm, Org, Trigger}.

%%--------------------------------------------------------------------
%% @doc Executes a trigger.
%% @end
%%--------------------------------------------------------------------
-spec org_execute_trigger(Realm::binary(), Org::fifo:org_id(),
                          Event::fifo:event(),
                          Payload::term()) ->
                                 {org, trigger, execute, Realm::binary(),
                                  Org::fifo:org_id(),
                                  Trigger::fifo:trigger(),
                                  Payload::term()}.

org_execute_trigger(Realm, ?Org, Event, Payload) when
      is_binary(Realm) ->
    {org, trigger, execute, Realm, Org, Event, Payload}.

-spec org_resource_action(Realm::binary(), Org::fifo:org_id(), Resource::binary(),
                      TimeStamp::pos_integer(), Action::atom(),
                      Opts::proplists:proplist()) ->
                             {org, resource_action, Realm::binary(),
                              Org::fifo:org_id(), Resource::binary(),
                              TimeStamp::pos_integer(), Action::atom(),
                              Opts::proplists:proplist()}.

org_resource_action(Realm, ?Org, Resource, TimeStamp, Action, Opts) ->
    {org, resource_action, Realm, Org, Resource, TimeStamp, Action, Opts}.

%%%===================================================================
%%% OAuth2 Functions
%%%===================================================================

%%-export([authorize_password/3]).
authorize_password(Realm, User, Scope) ->
    {oauth2, authorize_password, Realm, User, Scope}.

%%-export([authorize_password/4]).
authorize_password(Realm, User, Client, Scope) ->
    {oauth2, authorize_password, Realm, User, Client, Scope}.

%%-export([authorize_password/5]).
authorize_password(Realm, User, Client, RedirUri, Scope) ->
    {oauth2, authorize_password, Realm, User, Client, RedirUri, Scope}.

%% -export([authorize_client_credentials/3]).
authorize_client_credentials(Realm, Client, Scope) ->
    {oauth2, authorize_client_credentials, Realm, Client, Scope}.

%% -export([authorize_code_grant/4]).
authorize_code_grant(Realm, Client, Code, RedirUri) ->
    {oauth2, authorize_code_grant, Realm, Client, Code, RedirUri}.

%% -export([authorize_code_request/5]).
authorize_code_request(Realm, User, Client, RedirUri, Scope) ->
    {oauth2, authorize_code_request, Realm, User, Client, RedirUri, Scope}.

%% -export([issue_code/2]).
issue_code(Realm, Auth) ->
    {oauth2, issue_code, Realm, Auth}.

%% -export([issue_token/2]).
issue_token(Realm, Auth) ->
    {oauth2, issue_token, Realm, Auth}.

%% -export([issue_token_and_refresh/2]).
issue_token_and_refresh(Realm, Auth) ->
    {oauth2, issue_token_and_refresh, Realm, Auth}.

%% -export([verify_access_token/2]).
verify_access_token(Realm, Token) ->
    {oauth2, verify_access_token, Realm, Token}.

%% -export([verify_access_code/2]).
verify_access_code(Realm, AccessCode) ->
    {oauth2, verify_access_code, Realm, AccessCode}.

%% -export([verify_access_code/3]).
verify_access_code(Realm, AccessCode, Client) ->
    {oauth2, verify_access_code, Realm, AccessCode, Client}.

%% -export([refresh_access_token/4]).
refresh_access_token(Realm, Client, RefreshToken, Scope) ->
    {oauth2, refresh_access_token, Realm, Client, RefreshToken, Scope}.

%%%===================================================================
%%% Internal Functions
%%%===================================================================
