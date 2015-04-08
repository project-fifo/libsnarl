-module(libsnarl).

-export([
         servers/0,
         start/0,
         status/0
        ]).

-export([
         allowed/2,
         auth/2,
         auth/3,
         test/2,
         version/0,
         keystr_to_id/1
        ]).

%%%===================================================================
%%% Ignore
%%%===================================================================

-ignore_xref([
              servers/0,
              start/0,
              status/0
             ]).

-ignore_xref([
              allowed/2,
              auth/2,
              auth/3,
              test/2,
              version/0,
              keystr_to_id/1
             ]).


%%%===================================================================
%%% Generatl Functions
%%%===================================================================

%%--------------------------------------------------------------------
%% @doc Reads the overall cloud status.
%% @end
%%--------------------------------------------------------------------
-spec status() -> {'error','no_servers'} |
                  {ok, {Resources::fifo:object(),
                        Warnings::fifo:object()}}.
status() ->
    send({cloud, status}).

%%--------------------------------------------------------------------
%% @private
%% @doc Starts the service.
%% @spec start() -> ok
%% @end
%%--------------------------------------------------------------------
-spec start() ->
                   ok.
start() ->
    application:start(libsnarlmatch),
    application:start(mdns_client_lib),
    application:start(libsnarl).


keystr_to_id(S) ->
    << <<D:8>> || {ok, [D], []} <- [io_lib:fread("~16u", P) || P <- re:split(S, ":", [{return, list}])]>>.

%%--------------------------------------------------------------------
%% @doc Tests cached permissions.
%% @spec test([term()], [[term()]]) -> true | false
%% @end
%%--------------------------------------------------------------------
-spec test(fifo:permission(), [fifo:permission()]) ->
                  true | false.
test(Permission, Permissions) ->
    libsnarlmatch:test_perms(Permission, Permissions).

%%--------------------------------------------------------------------
%% @doc Gets a list of servers
%% @spec servers() -> [term()]
%% @end
%%--------------------------------------------------------------------
-spec servers() ->
                     [term()].
servers() ->
    libsnarl_server:servers().

%%--------------------------------------------------------------------
%% @private
%% @doc Fetches version
%% @spec version() -> binary
%% @end
%%--------------------------------------------------------------------
-spec version() -> {ok, binary()} |
                   {error, no_servers}.
version() ->
    ServerVersion = send(version),
    ServerVersion.

%%--------------------------------------------------------------------
%% @doc Authenticates a user and returns a token that can be used for
%%  the session.
%% @end
%%--------------------------------------------------------------------
-spec auth(User::fifo:user_id(), Pass::binary()) ->
                  not_found |
                  {ok, {token, fifo:user_id()}} |
                  {error, no_servers}.
auth(User, Pass) ->
    send(libsnarl_msg:auth(r(), User, Pass)).

%%--------------------------------------------------------------------
%% @doc Authenticates a user and returns a token that can be used for
%%  the session. This version takes a Yubikey OTP.
%% @end
%%--------------------------------------------------------------------
-spec auth(User::fifo:user_id(), Pass::binary(), OTP::binary() | basic) ->
                  not_found |
                  {ok, {token, fifo:user_id()}} |
                  {error, no_servers}.
auth(User, Pass, OTP) ->
    send(libsnarl_msg:auth(r(), User, Pass, OTP)).

%%--------------------------------------------------------------------
%% @doc Checks if the user has the given permission.
%% @end
%%--------------------------------------------------------------------
-spec allowed(User::fifo:user_token_id() | {token, binary()},
              Permission::fifo:permission()) ->
                     {error, no_servers} |
                     not_found |
                     true |
                     false.
allowed(User, Permission) ->
    send(libsnarl_msg:allowed(r(), User, Permission)).
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
