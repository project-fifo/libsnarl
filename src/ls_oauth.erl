-module(ls_oauth).

-export([authorize_password/2]).
-export([authorize_password/3]).
-export([authorize_password/4]).
-export([authorize_client_credentials/2]).
-export([authorize_code_grant/3]).
-export([authorize_code_request/4]).
-export([issue_code/1]).
-export([scope/0]).
-export([scope/1]).
-export([issue_token/1]).
-export([issue_token_and_refresh/1]).
-export([verify_access_token/1]).
-export([verify_access_code/1]).
-export([verify_access_code/2]).
-export([refresh_access_token/3]).
-define(SLOW_TIMEOUT, 3000).

%%%===================================================================
%%% User Functions
%%%===================================================================

%%-export([authorize_password/3]).
authorize_password(User, Scope) ->
    send_slow(libsnarl_msg:authorize_password(r(), User, Scope)).

%%-export([authorize_password/4]).
authorize_password(User, Client, Scope) ->
    send_slow(libsnarl_msg:authorize_password(r(), User, Client, Scope)).

%%-export([authorize_password/5]).
authorize_password(User, Client, RedirUri, Scope) ->
    send_slow(libsnarl_msg:authorize_password(r(), User, Client, RedirUri, Scope)).

%% -export([authorize_client_credentials/3]).
authorize_client_credentials(Client, Scope) ->
    send_slow(libsnarl_msg:authorize_client_credentials(r(), Client, Scope)).

%% -export([authorize_code_grant/4]).
authorize_code_grant(Client, Code, RedirUri) ->
    send(libsnarl_msg:authorize_code_grant(r(), Client, Code, RedirUri)).

%% -export([authorize_code_request/5]).
authorize_code_request(User, Client, RedirUri, Scope) ->
    send_slow(libsnarl_msg:authorize_code_request(r(), User, Client, RedirUri, Scope)).

%% -export([issue_code/2]).
issue_code(Auth) ->
    send(libsnarl_msg:issue_code(r(), Auth)).

%% -export([issue_token/2]).
issue_token(Auth) ->
    send(libsnarl_msg:issue_token(r(), Auth)).

%% -export([issue_token_and_refresh/2]).
issue_token_and_refresh(Auth) ->
    send(libsnarl_msg:issue_token_and_refresh(r(), Auth)).

%% -export([verify_access_token/2]).
verify_access_token(Token) ->
    send(libsnarl_msg:verify_access_token(r(), Token)).

%% -export([verify_access_code/2]).
verify_access_code(AccessCode) ->
    send(libsnarl_msg:verify_access_code(r(), AccessCode)).

%% -export([verify_access_code/3]).
verify_access_code(AccessCode, Client) ->
    send(libsnarl_msg:verify_access_code(r(), AccessCode, Client)).

%% -export([refresh_access_token/4]).
refresh_access_token(Client, RefreshToken, Scope) ->
    send(libsnarl_msg:refresh_access_token(r(), Client, RefreshToken, Scope)).

scope() ->
    send(libsnarl_msg:scope(r())).

scope(Subscope) ->
    send(libsnarl_msg:scope(r(), Subscope)).

-spec send(Msg::fifo:snarl_user_message()) ->
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

send_slow(Msg) ->
    case libsnarl_server:call(Msg, ?SLOW_TIMEOUT) of
        {reply, Reply} ->
            Reply;
        E ->
            E
    end.

r() ->
    application:get_env(libsnarl, realm, <<"default">>).
