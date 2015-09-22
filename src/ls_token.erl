-module(ls_token).

-export([
         delete/1,
         get/1,
         add/2,
         add/3
        ]).

-ignore_xref([
              delete/1,
              get/1,
              add/2,
              add/3
             ]).


%%%===================================================================
%%% Token Functions
%%%===================================================================

%%--------------------------------------------------------------------
%% @doc Deletes a user.
%% @spec token_delete(Token::binary()) ->
%%                    {error, not_found|no_servers} | ok
%% @end
%%--------------------------------------------------------------------

-spec delete(Token::fifo:token()) ->
                    {error, no_servers} |
                    not_found |
                    ok.
delete(Token) ->
    send(libsnarl_msg:token_delete(r(), Token)).

%%--------------------------------------------------------------------
%% @doc Adds a new token.
%% @end
%%--------------------------------------------------------------------

-spec get(Token::term()) ->
                 {error, no_servers} |
                 {ok, Token :: binary()}.
get(Token) ->
    send(libsnarl_msg:token_get(r(), Token)).

%%--------------------------------------------------------------------
%% @doc Adds a new token.
%% @end
%%--------------------------------------------------------------------

-spec add(Timeout::integer(), Data::term()) ->
                 {error, no_servers} |
                 {ok, Token :: binary()}.

add(Timeout, Data) ->
    send(libsnarl_msg:token_add(r(), Timeout, Data)).

%%--------------------------------------------------------------------
%% @doc Adds a new token.
%% @end
%%--------------------------------------------------------------------

-spec add(Token::term(), Timeout::integer(), Data::term()) ->
                 {error, no_servers} |
                 {ok, Token :: binary()}.
add(Token, Timeout, Data) ->
    send(libsnarl_msg:token_add(r(), Token, Timeout, Data)).

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
                  ok |
                  not_found |
                  {ok, Reply::term()} |
                  {error, no_servers}.
send(Msg) ->
    case libsnarl_server:call(Msg) of
        {reply, Reply} ->
            Reply;
        E ->
            E
    end.

r() ->
    application:get_env(libsnarl, realm, <<"default">>).
