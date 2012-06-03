%%%-------------------------------------------------------------------
%%% @author Heinz N. Gies <heinz@licenser.net>
%%% @copyright (C) 2012, Heinz N. Gies
%%% @doc
%%%
%%% @end
%%% Created :  5 May 2012 by Heinz N. Gies <heinz@licenser.net>
%%%-------------------------------------------------------------------
-module(libsnarl).

-export([auth/2,
	 allowed/3]).

-export([user_add/3,
	 user_passwd/3,
	 user_delete/2,
	 user_list/1,
	 user_get/2,
	 user_name/2,
	 user_groups/2,
	 user_permissions/2,
	 user_own_permissions/2,
	 user_cache/2,
	 user_add_to_group/3,
	 user_delete_from_group/3,
	 user_grant/3,
	 user_revoke/3]).

-export([group_add/2,
	 group_delete/2,
	 group_get/2,
	 group_users/2,
	 group_list/1,
	 group_name/2,
	 group_permissions/2,
	 group_grant/3,
	 group_revoke/3,
	 group_add_user/3,
	 group_delete_user/3]).

-export([option_list/2,
	 option_get/3,
	 option_delete/3,
	 option_set/4]).

-export([network_add/5,
	 network_delete/2,
	 network_get/2,
	 network_get_net/2,
	 network_get_mask/2,
	 network_get_gateway/2,
	 network_get_ip/2,
	 network_release_ip/3,
	 parse_ip/1,
	 ip_to_str/1]).
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

user_list(Auth) ->
    snarl_call(Auth, {user, list}).

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

user_own_permissions(Auth, {UUID, _}) ->
    user_own_permissions(Auth, UUID);
user_own_permissions(Auth, UUID) ->
    snarl_call(Auth, {user, own_permissions, UUID}).


user_groups(Auth, {UUID, _}) ->
    user_groups(Auth, UUID);
user_groups(Auth, UUID) ->
    snarl_call(Auth, {user, groups, UUID}).
user_cache(Auth, {UUID, _}) ->
    user_cache(Auth, UUID);
user_cache(_Auth, system) ->
    system;
user_cache(Auth, UUID) ->
    case snarl_call(Auth, {user, allowed, UUID, [user, UUID, allowed]}) of
	true ->
	    case snarl_call(Auth, {user, permissions, UUID}) of
		{ok, Perms}  -> 
		    {ok, {UUID, Perms}};
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

group_users(Auth, UUID) ->
    snarl_call(Auth, {group, users, UUID}).

group_list(Auth) ->
    snarl_call(Auth, {group, list}).

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

option_list(Auth, Category) ->
    snarl_call(Auth, {option, list, Category}).

option_get(Auth, Category, Name) ->
    snarl_call(Auth, {option, get, Category, Name}).

option_delete(Auth, Category, Name) ->
    snarl_call(Auth, {option, delete, Category, Name}).

option_set(Auth, Category, Name, Value) ->
    snarl_call(Auth, {option, set, Category, Name, Value}).

network_add(Auth, Name, First, Netmask, Gateway) when is_binary(First) orelse is_list(First) ->
    network_add(Auth, Name, parse_ip(First), Netmask, Gateway);
network_add(Auth, Name, First, Netmask, Gateway) when is_binary(Netmask) orelse is_list(Netmask) ->
    network_add(Auth, Name, First, parse_ip(Netmask), Gateway);
network_add(Auth, Name, First, Netmask, Gateway) when is_binary(Gateway) orelse is_list(Gateway) ->
    network_add(Auth, Name, First, Netmask, parse_ip(Gateway));
network_add(Auth, Name, First, Netmask, Gateway) ->
    snarl_call(Auth, {network, add, Name, First, Netmask, Gateway}).

network_delete(Auth, Name) ->
    snarl_call(Auth, {network, delete, Name}).

network_get(Auth, Name) ->
    snarl_call(Auth, {network, get, Name}).

network_get_net(Auth, Name) ->
    snarl_call(Auth, {network, get, net, Name}).

network_get_mask(Auth, Name) ->
    snarl_call(Auth, {network, get, mask, Name}).


network_get_gateway(Auth, Name) ->
    snarl_call(Auth, {network, get, gateway, Name}).

network_get_ip(Auth, Name) ->
    snarl_call(Auth, {network, get, ip, Name}).

network_release_ip(Auth, Name, IP) when is_binary(IP) orelse is_list(IP) ->
    network_release_ip(Auth, Name, parse_ip(IP));
network_release_ip(Auth, Name, IP) when is_integer(IP) ->
    snarl_call(Auth, {network, release, ip, Name, IP}).

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

parse_ip(IP) ->
    {match,[A,B,C,D]} =
	re:run(IP, <<"\\b(25[0-5]|2[0-4][0-9]|[01]?[0-9][0-9]?)\\.(25[0-5]|2[0-4][0-9]|[01]?[0-9][0-9]?)\\.(25[0-5]|2[0-4][0-9]|[01]?[0-9][0-9]?)\\.(25[0-5]|2[0-4][0-9]|[01]?[0-9][0-9]?)\\b">>, [{capture, all_but_first, list}]),
    {Ai, []} = string:to_integer(A),
    {Bi, []} = string:to_integer(B),
    {Ci, []} = string:to_integer(C),
    {Di, []} = string:to_integer(D),
    <<IPi:32>> = <<Ai:8, Bi:8, Ci:8, Di:8>>,
    IPi.

ip_to_str(IP) when is_integer(IP) ->
    ip_to_str(<<IP:32>>);
ip_to_str(<<A:8, B:8, C:8, D:8>>) ->
    list_to_binary(io_lib:format("~p.~p.~p.~p", [A, B, C, D])).
