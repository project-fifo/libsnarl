-module(ls_oauth).

-export([authorize_password_otp/4]).
-export([authorize_password_otp/5]).
-export([authorize_password_otp/6]).
-export([authorize_password/3]).
-export([authorize_password/4]).
-export([authorize_password/5]).
-export([authorize_client_credentials/3]).
-export([authorize_code_grant/3]).
-export([authorize_code_request/5]).
-export([authorize_code_request_otp/6]).
-export([issue_code/1]).
-export([issue_token/1]).
-export([issue_token_and_refresh/1]).
-export([verify_access_token/1]).
-export([verify_access_code/1]).
-export([verify_access_code/2]).
-export([refresh_access_token/4]).

%%%===================================================================
%%% User Functions
%%%===================================================================

%%-export([authorize_password_otp/3]).
authorize_password_otp(User, Password, OTP, Scope) ->
    send(libsnarl_msg:authorize_password_otp(r(), User, Password, OTP, Scope)).

%%-export([authorize_password_otp/4]).
authorize_password_otp(User, Password, OTP, Client, Scope) ->
    send(libsnarl_msg:authorize_password_otp(r(), User, Password, OTP, Client, Scope)).

%%-export([authorize_password_otp/5]).

authorize_password_otp(User, Password, OTP, Client, RedirUri, Scope) ->
    send(libsnarl_msg:authorize_password_otp(r(), User, Password, OTP, Client, RedirUri, Scope)).

%%-export([authorize_password/3]).
authorize_password(User, Password, Scope) ->
    send(libsnarl_msg:authorize_password(r(), User, Password, Scope)).

%%-export([authorize_password/4]).
authorize_password(User, Password, Client, Scope) ->
    send(libsnarl_msg:authorize_password(r(), User, Password, Client, Scope)).

%%-export([authorize_password/5]).
authorize_password(User, Password, Client, RedirUri, Scope) ->
    send(libsnarl_msg:authorize_password(r(), User, Password, Client, RedirUri, Scope)).

%% -export([authorize_client_credentials/3]).
authorize_client_credentials(Client, Secret, Scope) ->
    send(libsnarl_msg:authorize_client_credentials(r(), Client, Secret, Scope)).

%% -export([authorize_code_grant/4]).
authorize_code_grant(Client, Code, RedirUri) ->
    send(libsnarl_msg:authorize_code_grant(r(), Client, Code, RedirUri)).

%% -export([authorize_code_request/5]).
authorize_code_request(User, Pass, Client, RedirUri, Scope) ->
    send(libsnarl_msg:authorize_code_request(r(), User, Pass, Client, RedirUri, Scope)).

%% -export([authorize_code_request/5]).
authorize_code_request_otp(User, Pass, Otp, Client, RedirUri, Scope) ->
    send(libsnarl_msg:authorize_code_request_otp(r(), User, Pass, Otp, Client, RedirUri, Scope)).

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
refresh_access_token(Client, ClientSecret, RefreshToken, Scope) ->
    send(libsnarl_msg:refresh_access_token(r(), Client, ClientSecret, RefreshToken, Scope)).

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

r() ->
    application:get_env(libsnarl, realm, <<"default">>).
