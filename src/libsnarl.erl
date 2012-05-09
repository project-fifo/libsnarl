%%%-------------------------------------------------------------------
%%% @author Heinz N. Gies <>
%%% @copyright (C) 2012, Heinz N. Gies
%%% @doc
%%%
%%% @end
%%% Created :  5 May 2012 by Heinz N. Gies <>
%%%-------------------------------------------------------------------
-module(libsnarl).

-export([auth/2,
	 allowed/3]).

-export([user_add/3,
	 user_passwd/3,
	 user_delete/2,
	 user_get/2,
	 user_name/2,
	 user_permissions/2,
	 user_cache/2,
	 user_add_to_group/3,
	 user_delete_from_group/3,
	 user_grant/3,
	 user_revoke/3]).

-export([group_add/2,
	 group_delete/2,
	 group_get/2,
	 group_name/2,
	 group_permissions/2,
	 group_grant/3,
	 group_revoke/3,
	 group_add_user/3,
	 group_delete_user/3]).
%%%===================================================================
%%% API
%%%===================================================================

%%--------------------------------------------------------------------
%% @doc
%% @spec
%% @end
%%--------------------------------------------------------------------

auth(Name, Pass) ->
    snarl_call(system, {user, auth, Name, Pass}).

user_add(Auth, Name, Pass) ->
    snarl_call(Auth, {user, add, Name, Pass}).

user_passwd(Auth, {UUID, _}, Pass) ->
    user_passwd(Auth, UUID, Pass);
user_passwd(Auth, UUID, Pass) ->
    snarl_call(Auth, {user, passwd, UUID, Pass}).

user_delete(Auth, {UUID, _}) ->
    user_delete(Auth, UUID);
user_delete(Auth, UUID) ->
    snarl_call(Auth, {user, delete, UUID}).

user_get(Auth, Name) ->
    snarl_call(Auth, {user, get, Name}).


user_name(Auth, {UUID, _}) ->
    user_name(Auth, UUID);
user_name(Auth, UUID) ->
    snarl_call(Auth, {user, name, UUID}).

user_permissions(Auth, {UUID, _}) ->
    user_permissions(Auth, UUID);
user_permissions(Auth, UUID) ->
    snarl_call(Auth, {user, permissions, UUID}).

user_cache(Auth, {UUID, _}) ->
    user_cache(Auth, UUID);
user_cache(Auth, UUID) ->
    case snarl_call(Auth, {user, allowed, UUID, [user, UUID, allowed]}) of
	true ->
	    case snarl_call(Auth, {user, permissions, UUID}) of
		{ok, Perms}  -> 
		    {ok, {Auth, Perms}};
		E ->
		    E
	    end;
	E ->
	    E
    end.

allowed(_Auth, system, _Perm) ->
    true;

allowed(_Auth, {system, _}, _Perm) ->
    true;

allowed(_Auth, {_Auth1, Perms}, Perm) ->
    test_perms(Perm, Perms);

allowed(Auth, UUID, Perm) ->
    snarl_call(Auth, {user, allowed, UUID, Perm}).


user_add_to_group(Auth, {UUUID, _}, GUUID) ->
    user_add_to_group(Auth, UUUID, GUUID);
user_add_to_group(Auth, UUUID, GUUID) ->
    snarl_call(Auth, {user, groups, add, UUUID, GUUID}).

user_delete_from_group(Auth, {UUUID, _}, GUUID) ->
    user_delete_from_group(Auth, UUUID, GUUID);
user_delete_from_group(Auth, UUUID, GUUID) ->
    snarl_call(Auth, {user, groups, delete, UUUID, GUUID}).

user_grant(Auth, {UUID, _}, Perm) ->
    user_grant(Auth, UUID, Perm);
user_grant(Auth, UUID, Perm) ->
    snarl_call(Auth, {user, grant, UUID, Perm}).

user_revoke(Auth, {UUID, _}, Perm) ->
    user_revoke(Auth, UUID, Perm);
user_revoke(Auth, UUID, Perm) ->
    snarl_call(Auth, {user, revoke, UUID, Perm}).

group_add(Auth, Name) ->
    snarl_call(Auth, {group, add, Name}).

group_delete(Auth, UUID) ->
    snarl_call(Auth, {group, delete, UUID}).

group_get(Auth, Name) ->
    snarl_call(Auth, {group, get, Name}).

group_name(Auth, UUID) ->
    snarl_call(Auth, {group, name, UUID}).

group_permissions(Auth, UUID) ->
    snarl_call(Auth, {group, permissions, UUID}).

group_grant(Auth, UUID, Perm) ->
    snarl_call(Auth, {group, grant, UUID, Perm}).

group_revoke(Auth, UUID, Perm) ->
    snarl_call(Auth, {group, revoke, UUID, Perm}).


group_add_user(Auth, GUUID, {UUUID, _}) ->
    group_add_user(Auth, GUUID, UUUID);
group_add_user(Auth, GUUID, UUUID) ->
    snarl_call(Auth, {group, users, add, GUUID, UUUID}).

group_delete_user(Auth, GUUID, {UUUID, _}) ->
    group_delete_user(Auth, GUUID, UUUID);
group_delete_user(Auth, GUUID, UUUID) ->
    snarl_call(Auth, {group, users, delete, GUUID, UUUID}).



%%%===================================================================
%%% Internal functions
%%%===================================================================


snarl_call({Auth, _Perms}, Call) ->
    snarl_call(Auth, Call);
snarl_call(Auth, Call) ->
    gen_server:call(snarl(), {call,  Auth, Call}).

snarl() ->
    gproc:lookup_pid({n, g, snarl}).

match([], []) ->
    true;

match(_, ['...']) ->
    true;

match([], ['...'|_Rest]) ->
    false;

match([], [_X|_R]) ->
    false;

match([X | InRest], ['...', X|TestRest] = Test) ->
    match(InRest, TestRest) orelse match(InRest, Test);

match([_,X|InRest], ['...', X|TestRest] = Test) ->
    match(InRest, TestRest) orelse match([X| InRest], Test);

match([X|InRest], [X|TestRest]) ->
    match(InRest, TestRest);

match([_|InRest], ['_'|TestRest]) ->
    match(InRest, TestRest);

match(_, _) ->
    false.

test_perms(_Perm, []) ->
    false;

test_perms(Perm, [Test|Tests]) ->
    match(Perm, Test) orelse test_perms(Perm, Tests).
