%%%-------------------------------------------------------------------
%%% @author Heinz Nikolaus Gies <heinz@licenser.net>
%%% @copyright (C) 2012, Heinz Nikolaus Gies
%%% @doc
%%%
%%% @end
%%% Created : 20 Aug 2012 by Heinz Nikolaus Gies <heinz@licenser.net>
%%%-------------------------------------------------------------------
-module(libsnarl_server).

-behaviour(gen_server).

%% API
-export([start_link/0,
	 call/1,
	 call/2,
	 cast/1,
	 servers/0]).

%% gen_server callbacks
-export([init/1,
	 handle_call/3,
	 handle_cast/2,
	 handle_info/2,
	 terminate/2,
	 code_change/3]).

-define(SERVER, ?MODULE).

-record(state, {zmq_worker}).

%%%===================================================================
%%% API
%%%===================================================================

%%--------------------------------------------------------------------
%% @doc
%% Starts the server.
%%
%% @spec start_link() -> {ok, Pid} | ignore | {error, Error}
%% @end
%%--------------------------------------------------------------------
start_link() ->
    gen_server:start_link({local, ?SERVER}, ?MODULE, [], []).

%%--------------------------------------------------------------------
%% @doc
%% This function sends a message to the server and waits for a reply.
%%
%% @spec call(Msg::term()) -> {error, no_server} |
%%                            {ok, Reply::term()}
%% @end
%%--------------------------------------------------------------------

-spec call(Msg :: tuple() | atom()) ->
                  {error, no_servers} |
                  {error, term()} |
                  {reply, Reply :: term()}.
call(Msg) ->
    gen_server:call(?SERVER, {call, Msg}).

-spec call(Msg :: tuple() | atom(), Timeout :: pos_integer()) ->
                  {error, no_servers} |
                  {error, term()} |
                  {reply, Reply :: term()}.
call(Msg, Timeout) ->
    gen_server:call(?SERVER, {call, Msg, Timeout}).

%%--------------------------------------------------------------------
%% @doc
%% This function sends a message to the server and just return. Since
%% there is no way of determinign the success of sending the library
%% will try to retransmitt once the server is back online. Be careful
%% it won't be guarnateed that your messages are delivered in order!
%%
%% @spec cast(Msg::term()) -> ok
%% @end
%%--------------------------------------------------------------------

cast(Msg) ->
    gen_server:cast(?SERVER, {cast, Msg}).

%%--------------------------------------------------------------------
%% @doc
%% Returns a list of all connected servers
%%
%% @spec servers() -> [] | [Server::term()]
%% @end
%%--------------------------------------------------------------------

servers() ->
    gen_server:call(?SERVER, servers).
 
%%%===================================================================
%%% gen_server callbacks
%%%===================================================================

%%--------------------------------------------------------------------
%% @private
%% @doc
%% Initializes the server
%%
%% @spec init(Args) -> {ok, State} |
%%                     {ok, State, Timeout} |
%%                     ignore |
%%                     {stop, Reason}
%% @end
%%--------------------------------------------------------------------

init([]) ->
    {ok, Pid} = mdns_client_lib:instance("snarl"),
    {ok, #state{zmq_worker = Pid}}.

%%--------------------------------------------------------------------
%% @private
%% @doc
%% Handling call messages
%%
%% @spec handle_call(Request, From, State) ->
%%                                   {reply, Reply, State} |
%%                                   {reply, Reply, State, Timeout} |
%%                                   {noreply, State} |
%%                                   {noreply, State, Timeout} |
%%                                   {stop, Reason, Reply, State} |
%%                                   {stop, Reason, State}
%% @end
%%--------------------------------------------------------------------

handle_call(servers, _From, #state{zmq_worker = Pid} = State) ->

    Reply = mdns_client_lib:servers(Pid),
    {reply, Reply, State};

handle_call({call, Msg}, From, #state{zmq_worker = Pid} = State) ->
    spawn(fun() ->
		  Reply = mdns_client_lib:call(Pid, Msg),
		  gen_server:reply(From, Reply)
	  end),
    {noreply, State};

handle_call({call, Msg, Timeout}, From, #state{zmq_worker = Pid} = State) ->
    spawn(fun() ->
		  Reply = mdns_client_lib:call(Pid, Msg, Timeout),
		  gen_server:reply(From, Reply)
	  end),
    {noreply, State};

handle_call(_Request, _From, State) ->
    Reply = ok,
    {reply, Reply, State}.

%%--------------------------------------------------------------------
%% @private
%% @doc
%% Handling cast messages
%%
%% @spec handle_cast(Msg, State) -> {noreply, State} |
%%                                  {noreply, State, Timeout} |
%%                                  {stop, Reason, State}
%% @end
%%--------------------------------------------------------------------

handle_cast({cast, Msg}, #state{zmq_worker = Pid} = State) ->
    mdns_client_lib:cast(Pid, Msg),
    {noreply, State};

handle_cast(_Msg, State) ->
    {noreply, State}.

%%--------------------------------------------------------------------
%% @private
%% @doc
%% Handling all non call/cast messages
%%
%% @spec handle_info(Info, State) -> {noreply, State} |
%%                                   {noreply, State, Timeout} |
%%                                   {stop, Reason, State}
%% @end
%%--------------------------------------------------------------------
handle_info(_Info, State) ->
    {noreply, State}.

%%--------------------------------------------------------------------
%% @private
%% @doc
%% This function is called by a gen_server when it is about to
%% terminate. It should be the opposite of Module:init/1 and do any
%% necessary cleaning up. When it returns, the gen_server terminates
%% with Reason. The return value is ignored.
%%
%% @spec terminate(Reason, State) -> void()
%% @end
%%--------------------------------------------------------------------
terminate(_Reason, _State) ->
    ok.

%%--------------------------------------------------------------------
%% @private
%% @doc
%% Convert process state when code is changed
%%
%% @spec code_change(OldVsn, State, Extra) -> {ok, NewState}
%% @end
%%--------------------------------------------------------------------
code_change(_OldVsn, State, _Extra) ->
    {ok, State}.

%%%===================================================================
%%% Internal functions
%%%===================================================================
