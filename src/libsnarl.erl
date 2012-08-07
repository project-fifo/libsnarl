%%%-------------------------------------------------------------------
%%% @author Heinz N. Gies <heinz@licenser.net>
%%% @copyright (C) 2012, Heinz N. Gies
%%% @doc This module provides a remote interface to the snarl server.
%%% 
%%% The functions exported are mostly remote calls using gproc to
%%% identify the Server.
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
	 network_release_ip/3]).

-export([parse_ip/1,
	 ip_to_str/1,
	 msg/3]).

%%%===================================================================
%%% Types
%%%===================================================================


%% @type ip() = integer() | binary() | atom().
-type ip() ::
	integer() |
	binary() |
	list().

%% @type permission() = atom() | binary().
-type permission() ::
	atom() |
	binary().

%% @type permissions() = [permission()].
-type permissions() ::
	[permission()].


%% @type uuid() = binary().
-type uuid() ::
	binary().

%% @type network() = {Network::integer(), FirstFree::integer(), NetMask::integer(), Gateway::integer()}.
-type network() :: 
	{Network::integer(), FirstFree::integer(), NetMask::integer(), Gateway::integer()}.

%% @type user() = uuid().
-type user() :: uuid().

%% @type group() = uuid().
-type group() :: uuid().

%% @type name() = binary().
-type name() :: binary().

%% @type cached_auth() = {user(), permissions()}.
-type cached_auth() :: 
	{user(), permissions()}.

%% @type auth() = system | user() | cached_auth().
-type auth() ::
	system | 
	user() |
	cached_auth().

%%%===================================================================
%%% API
%%%===================================================================

%%--------------------------------------------------------------------
%% @spec (binary(), binary()) -> user()
%%
%% @doc Authenticates a user.
%%
%% This fuction is used to retrieve an authentication token (User)
%% based a username and password.
%% @end
%%--------------------------------------------------------------------

auth(Name, Pass) ->
    snarl_call(system, {user, auth, Name, Pass}).

%%--------------------------------------------------------------------
%% @spec  (auth(), binary(), binary()) -> user()
%%
%% @doc Adds a new user.
%%
%% Adds a new user from a given password and username, returns 
%% the new users User. This also grants the created user basic
%% permissions to handle itself.
%% @end
%%--------------------------------------------------------------------

user_add(Auth, Name, Pass) ->
    snarl_call(Auth, {user, add, Name, Pass}).

%%--------------------------------------------------------------------
%% @spec (auth(), auth(), binary()) -> ok
%%
%% @doc Sets the password for an existing user.
%% @end
%%--------------------------------------------------------------------

user_passwd(Auth, {User, _}, Pass) ->
    user_passwd(Auth, User, Pass);
user_passwd(Auth, User, Pass) ->
    snarl_call(Auth, {user, passwd, User, Pass}).

%%--------------------------------------------------------------------
%% @spec (auth(), auth()) -> ok
%%
%% @doc Deletes a user.
%% @end
%%--------------------------------------------------------------------

user_delete(Auth, {User, _}) ->
    user_delete(Auth, User);
user_delete(Auth, User) ->
    snarl_call(Auth, {user, delete, User}).

%%--------------------------------------------------------------------
%% @spec (auth()) -> [user()]
%%
%% @doc Lists all uses.
%% @end
%%--------------------------------------------------------------------

user_list(Auth) ->
    snarl_call(Auth, {user, list}).


%%--------------------------------------------------------------------
%% @spec (auth(), binary()) -> {ok, user()}
%%
%% @doc Retrieves a user.
%%
%% This function retrieves a user bypassing the authentication,
%% it is meant primarily for admin/system internal use mosty.
%% @end
%%--------------------------------------------------------------------

user_get(Auth, Name) ->
    snarl_call(Auth, {user, get, Name}).

%%--------------------------------------------------------------------
%% @spec (auth(), auth()) -> Name::binary()
%%
%% @doc Retrieves a users name.
%% @end
%%--------------------------------------------------------------------

user_name(Auth, {User, _}) ->
    user_name(Auth, User);
user_name(Auth, User) ->
    snarl_call(Auth, {user, name, User}).

%%--------------------------------------------------------------------
%% @spec (auth(), auth()) -> Permissions::permissions()
%%
%% @doc Retrives the uesrs <b>full</b> permissions.
%%
%% This function fetches all the permissions a user has, this 
%% <b>includes</b> the ones delegated from groups the user is part of.
%% @end
%%--------------------------------------------------------------------

user_permissions(Auth, {User, _}) ->
    user_permissions(Auth, User);
user_permissions(Auth, User) ->
    snarl_call(Auth, {user, permissions, User}).

%%--------------------------------------------------------------------
%% @spec (auth(), auth()) -> Permissions::permissions()
%%
%% @doc Retrives the uesrs <b>own</b> permissions.
%%
%% This function fetches the users own permissions, this does <b>not 
%% includes</b> the ones delegated from groups the user is part of.
%% @end
%%--------------------------------------------------------------------

user_own_permissions(Auth, {User, _}) ->
    user_own_permissions(Auth, User);
user_own_permissions(Auth, User) ->
    snarl_call(Auth, {user, own_permissions, User}).


%%--------------------------------------------------------------------
%% @spec (auth(), auth()) -> [group()]
%%
%% @doc Retrives the uesrs groups.
%% @end
%%--------------------------------------------------------------------


user_groups(Auth, {User, _}) ->
    user_groups(Auth, User);
user_groups(Auth, User) ->
    snarl_call(Auth, {user, groups, User}).

%%--------------------------------------------------------------------
%% @spec (auth(), auth()) -> cached_auth()
%%
%% @doc Creates a cached version of the users permissions.
%%
%% This function is used to prefetch the permissions of a user, it is
%% supposed to be used to improve performance and minimize calls to
%% the snarl server. With a cached auth all permission checks done by
%% <b>allowed</b> can be performed localy in the process.
%% @end
%%--------------------------------------------------------------------

user_cache(Auth, {User, _}) ->
    user_cache(Auth, User);
user_cache(_Auth, system) ->
    {ok, system};
user_cache(Auth, User) ->
    case snarl_call(Auth, {user, allowed, User, [user, User, allowed]}) of
	true ->
	    case snarl_call(Auth, {user, permissions, User}) of
		{ok, Perms}  -> 
		    {ok, {User, Perms}};
		E ->
		    E
	    end;
	E ->
	    E
    end.

%%--------------------------------------------------------------------
%% @spec (auth(), auth(), permission()) -> true | false
%%
%% @doc Checks the users permissions
%%
%% This is the core funcion of this library, it performs matches on
%% the users permission to test if he is allowed to perform a certin
%% action.
%% it has a three step handeling of validationg the permissions:
%% 1) the <b>system</b> user is always allowed to perform an action.
%% 2) cached users are validated locally without a call to snarl.
%% 3) The users permissions are validated remotely on the snarl server.
%% @end
%%--------------------------------------------------------------------

allowed(_Auth, system, _Perm) ->
    true;

allowed(_Auth, {system, _}, _Perm) ->
    true;

allowed(_Auth, {_Auth1, Perms}, Perm) ->
    test_perms(Perm, Perms);

allowed(Auth, User, Perm) ->
    snarl_call(Auth, {user, allowed, User, Perm}).

%%--------------------------------------------------------------------
%% @spec (auth(), auth(), group()) -> ok
%%
%% @doc Adds the user to a group
%%
%% @end
%%--------------------------------------------------------------------

user_add_to_group(Auth, {User, _}, Group) ->
    user_add_to_group(Auth, User, Group);
user_add_to_group(Auth, User, Group) ->
    snarl_call(Auth, {user, groups, add, User, Group}).

%%--------------------------------------------------------------------
%% @spec (auth(), auth(), group()) -> ok
%%
%% @doc Removes the user to a group
%%
%% @end
%%--------------------------------------------------------------------

user_delete_from_group(Auth, {User, _}, Group) ->
    user_delete_from_group(Auth, User, Group);
user_delete_from_group(Auth, User, Group) ->
    snarl_call(Auth, {user, groups, delete, User, Group}).

%%--------------------------------------------------------------------
%% @spec (auth(), auth(), permission()) -> ok
%%
%% @doc Grants the user a permission
%%
%% @end
%%--------------------------------------------------------------------

user_grant(Auth, {User, _}, Perm) ->
    user_grant(Auth, User, Perm);
user_grant(Auth, User, Perm) ->
    snarl_call(Auth, {user, grant, User, Perm}).

%%--------------------------------------------------------------------
%% @spec (auth(), auth(), permission()) -> ok
%%
%% @doc Revokes a permission from a user
%%
%% @end
%%--------------------------------------------------------------------

user_revoke(Auth, {User, _}, Perm) ->
    user_revoke(Auth, User, Perm);
user_revoke(Auth, User, Perm) ->
    snarl_call(Auth, {user, revoke, User, Perm}).

%%--------------------------------------------------------------------
%% @spec (auth(), binary()) -> group()
%%
%% @doc Creates a new group.
%%
%% @end
%%--------------------------------------------------------------------

group_add(Auth, Name) ->
    snarl_call(Auth, {group, add, Name}).

%%--------------------------------------------------------------------
%% @spec (auth(), group()) -> ok
%%
%% @doc Deletes a group
%%
%% @end
%%--------------------------------------------------------------------

group_delete(Auth, Group) ->
    snarl_call(Auth, {group, delete, Group}).

%%--------------------------------------------------------------------
%% @spec (auth(), binary()) -> group()
%%
%% @doc Retrievs the group from it's name.
%%
%% @end
%%--------------------------------------------------------------------

group_get(Auth, Name) ->
    snarl_call(Auth, {group, get, Name}).

%%--------------------------------------------------------------------
%% @spec (auth(), group()) -> [user()]
%%
%% @doc Returns a list of users in a group.
%%
%% @end
%%--------------------------------------------------------------------

group_users(Auth, Group) ->
    snarl_call(Auth, {group, users, Group}).

%%--------------------------------------------------------------------
%% @spec (auth()) -> [group()]
%%
%% @doc Returns a list of all visible groups.
%%
%% @end
%%--------------------------------------------------------------------

group_list(Auth) ->
    snarl_call(Auth, {group, list}).

%%--------------------------------------------------------------------
%% @spec (auth(), group()) -> Name::binary()
%%
%% @doc Returns the name of a group
%%
%% @end
%%--------------------------------------------------------------------

group_name(Auth, Group) ->
    snarl_call(Auth, {group, name, Group}).

%%--------------------------------------------------------------------
%% @spec (auth(), group()) -> permissions()
%%
%% @doc Retrieves the permissions of a group
%%
%% @end
%%--------------------------------------------------------------------

group_permissions(Auth, Group) ->
    snarl_call(Auth, {group, permissions, Group}).

%%--------------------------------------------------------------------
%% @spec (auth(), group(), permission()) -> ok
%%
%% @doc Grants a permission to a group
%%
%% @end
%%--------------------------------------------------------------------

group_grant(Auth, Group, Perm) ->
    snarl_call(Auth, {group, grant, Group, Perm}).

%%--------------------------------------------------------------------
%% @spec (auth(), group(), permission()) -> ok
%%
%% @doc Revokes the permission from the group
%%
%% @end
%%--------------------------------------------------------------------

group_revoke(Auth, Group, Perm) ->
    snarl_call(Auth, {group, revoke, Group, Perm}).

%%--------------------------------------------------------------------
%% @spec (auth(), group(), auth()) -> ok
%%
%% @doc Adds a user to the group
%%
%% @end
%%--------------------------------------------------------------------

group_add_user(Auth, Group, {User, _}) ->
    group_add_user(Auth, Group, User);
group_add_user(Auth, Group, User) ->
    snarl_call(Auth, {group, users, add, Group, User}).

%%--------------------------------------------------------------------
%% @spec (auth(), group(), auth()) -> ok
%%
%% @doc Removes a user from the group
%%
%% @end
%%--------------------------------------------------------------------

group_delete_user(Auth, Group, {User, _}) ->
    group_delete_user(Auth, Group, User);

group_delete_user(Auth, Group, User) ->
    snarl_call(Auth, {group, users, delete, Group, User}).

%%--------------------------------------------------------------------
%% @spec (auth(), binary()) -> [binary()]
%%
%% @doc Lists all options in a category.
%%
%% @end
%%--------------------------------------------------------------------

option_list(Auth, Category) ->
    snarl_call(Auth, {option, list, Category}).

%%--------------------------------------------------------------------
%% @spec (auth(), binary(), binary()) -> Value::binary()
%%
%% @doc Retrievs an option from a category
%%
%% @end
%%--------------------------------------------------------------------

option_get(Auth, Category, Name) ->
    snarl_call(Auth, {option, get, Category, Name}).


%%--------------------------------------------------------------------
%% @spec (auth(), binary(), binary()) -> ok
%%
%% @doc Deletes the option from the category
%%
%% @end
%%--------------------------------------------------------------------

option_delete(Auth, Category, Name) ->
    snarl_call(Auth, {option, delete, Category, Name}).

%%--------------------------------------------------------------------
%% @spec (auth(), binary(), binary(), term()) -> ok
%%
%% @doc Sets the option.
%% 
%% Value can be any kind of erlang term.
%% @end
%%--------------------------------------------------------------------

option_set(Auth, Category, Name, Value) ->
    snarl_call(Auth, {option, set, Category, Name, Value}).

%%--------------------------------------------------------------------
%% @spec (auth(), binary(), ip(), ip(), ip()) -> ok
%%
%% @doc Creates a new IP range.
%% 
%% This command creats a new IP range, the IP first must not be the
%% network IP, if it is not, the IP range will recognize every IP
%% between the first IP of the network and the IP passed as first as
%% reserved and never be assigned to a virtual machine.
%% @end
%%--------------------------------------------------------------------

network_add(Auth, Name, First, Netmask, Gateway) when is_binary(First) orelse is_list(First) ->
    network_add(Auth, Name, parse_ip(First), Netmask, Gateway);
network_add(Auth, Name, First, Netmask, Gateway) when is_binary(Netmask) orelse is_list(Netmask) ->
    network_add(Auth, Name, First, parse_ip(Netmask), Gateway);
network_add(Auth, Name, First, Netmask, Gateway) when is_binary(Gateway) orelse is_list(Gateway) ->
    network_add(Auth, Name, First, Netmask, parse_ip(Gateway));
network_add(Auth, Name, First, Netmask, Gateway) ->
    snarl_call(Auth, {network, add, Name, First, Netmask, Gateway}).

%%--------------------------------------------------------------------
%% @spec (auth(), binary()) -> ok
%%
%% @doc Deletes a network rage.
%% 
%% The IP addresses handed out from this network are not affected!
%% @end
%%--------------------------------------------------------------------

network_delete(Auth, Name) ->
    snarl_call(Auth, {network, delete, Name}).

%%--------------------------------------------------------------------
%% @spec (auth(), binary()) -> network()
%%
%% @doc Fetches all details about a network.
%% 
%% @end
%%--------------------------------------------------------------------

network_get(Auth, Name) ->
    snarl_call(Auth, {network, get, Name}).

%%--------------------------------------------------------------------
%% @spec (auth(), binary()) -> NetworkIP::integer()
%%
%% @doc Fetches the network IP.
%% 
%% @end
%%--------------------------------------------------------------------

network_get_net(Auth, Name) ->
    snarl_call(Auth, {network, get, net, Name}).

%%--------------------------------------------------------------------
%% @spec (auth(), binary()) -> Netmask::integer()
%%
%% @doc Fetches the netmask.
%% 
%% @end
%%--------------------------------------------------------------------

network_get_mask(Auth, Name) ->
    snarl_call(Auth, {network, get, mask, Name}).

%%--------------------------------------------------------------------
%% @spec (auth(), binary()) -> Gateway::integer()
%%
%% @doc Fetches the gateway.
%% 
%% @end
%%--------------------------------------------------------------------

network_get_gateway(Auth, Name) ->
    snarl_call(Auth, {network, get, gateway, Name}).

%%--------------------------------------------------------------------
%% @spec (auth(), binary()) -> IP::integer()
%%
%% @doc Requests a IP.
%% 
%% This command will reserve an IP, this means this function will not
%% return the same result twice without freeing the ip again.
%% The IP is first retrieved from recently freed IP's then takes the
%% first free IP from the network.
%% @end
%%--------------------------------------------------------------------

network_get_ip(Auth, Name) ->
    snarl_call(Auth, {network, get, ip, Name}).

%%--------------------------------------------------------------------
%% @spec (auth(), binary(), ip()) -> ok
%%
%% @doc Frees an IP that was previousely reserved.
%% 
%% IP's that once were reserved via the network_get_ip/2 function
%% must be freed before they can be reused. This function does exactly
%% that, free the IP passed and retuns it to the pool.
%% @end
%%--------------------------------------------------------------------

network_release_ip(Auth, Name, IP) when is_binary(IP) orelse is_list(IP) ->
    network_release_ip(Auth, Name, parse_ip(IP));
network_release_ip(Auth, Name, IP) when is_integer(IP) ->
    snarl_call(Auth, {network, release, ip, Name, IP}).

%%--------------------------------------------------------------------
%% @spec (list()|binary()) -> IP::integer()
%%
%% @doc Parses the string representation of a IP.
%% 
%% @end
%%--------------------------------------------------------------------

parse_ip(IP) ->
    {match,[A,B,C,D]} =
	re:run(IP, <<"\\b(25[0-5]|2[0-4][0-9]|[01]?[0-9][0-9]?)\\.(25[0-5]|2[0-4][0-9]|[01]?[0-9][0-9]?)\\.(25[0-5]|2[0-4][0-9]|[01]?[0-9][0-9]?)\\.(25[0-5]|2[0-4][0-9]|[01]?[0-9][0-9]?)\\b">>, [{capture, all_but_first, list}]),
    {Ai, []} = string:to_integer(A),
    {Bi, []} = string:to_integer(B),
    {Ci, []} = string:to_integer(C),
    {Di, []} = string:to_integer(D),
    <<IPi:32>> = <<Ai:8, Bi:8, Ci:8, Di:8>>,
    IPi.


%%--------------------------------------------------------------------
%% @spec (integer()) -> IP::binary()
%%
%% @doc Formats an integer IP into the string representation.
%% 
%% @end
%%--------------------------------------------------------------------

ip_to_str(IP) when is_integer(IP) ->
    ip_to_str(<<IP:32>>);
ip_to_str(<<A:8, B:8, C:8, D:8>>) ->
    list_to_binary(io_lib:format("~p.~p.~p.~p", [A, B, C, D])).


%%--------------------------------------------------------------------
%% @spec (user(), Type::binary(), Msg::binary()) -> ok
%%
%% @doc Sends a message to the user.
%% 
%% @end
%%--------------------------------------------------------------------


msg({Auth, _}, Type, Msg) ->
    msg(Auth, Type, Msg);

msg(Auth, Type, Msg) ->
    gproc:send({p, g, {user, Auth}}, {msg, ensure_binary(Type), ensure_binary(Msg)}).


%%%===================================================================
%%% Internal functions
%%%===================================================================

ensure_binary(A) when is_atom(A) ->
    ensure_binary(atom_to_list(A));
ensure_binary(L) when is_list(L) ->
    list_to_binary(L);
ensure_binary(B) when is_binary(B) ->
    B.


    

snarl_call({Auth, _Perms}, Call) ->
    snarl_call(Auth, Call);
snarl_call(Auth, Call) ->
    lager:debug([{fifi_component, libsnarl}], "libsnarl:call - Auth: ~p, Call: ~p", [Auth, Call]),
    gen_server:call(snarl(), {call,  Auth, Call}).

snarl() ->
    try
	lager:debug([{fifi_component, libsnarl}], "libsnarl:snarl", []),
	gproc:lookup_pid({n, g, snarl})
    catch
	T:E ->
	    lager:debug([{fifi_component, libsnarl}], "libsnarl:snarl - Error: ~p:~p.", [T, E])
    end.

match([], []) ->
    true;

match(_, ['...']) ->
    true;

match([], ['...'|_Rest] = Allowed) ->
    lager:warning([{fifi_component, libsnarl}], "libsnarl:match - failed: ~p.", [Allowed]),
    false;

match([], [_X|_R] = Allowed) ->
    lager:warning([{fifi_component, libsnarl}], "libsnarl:match - failed: ~p.", [Allowed]),
    false;

match([X | InRest], ['...', X|TestRest] = Test) ->
    match(InRest, TestRest) orelse match(InRest, Test);

match([_,X|InRest], ['...', X|TestRest] = Test) ->
    match(InRest, TestRest) orelse match([X| InRest], Test);

match([X|InRest], [X|TestRest]) ->
    match(InRest, TestRest);

match([_|InRest], ['_'|TestRest]) ->
    match(InRest, TestRest);

match(Perm, Allowed) ->
    lager:warning([{fifi_component, libsnarl}], "libsnarl:match - failed: ~p vs. ~p.", [Perm, Allowed]),
    false.

test_perms(Perm, []) ->
    lager:warning([{fifi_component, libsnarl}], "libsnarl:match - failed: ~p.", [Perm]),
    false;

test_perms(Perm, [Test|Tests]) ->
    match(Perm, Test) orelse test_perms(Perm, Tests).
