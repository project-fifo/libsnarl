-module(ls_client).

-export([
         add/1, add/2,
         delete/1,
         get/1,
         grant/2,
         join/2,
         uri_add/2,
         uri_remove/2,
         leave/2,
         list/0,
         list/2,
         stream/3,
         lookup/1,
         secret/2,
         revoke/2,
         revoke_prefix/2,
         set_metadata/2
        ]).

-ignore_xref([
              add/1,
              delete/1,
              get/1,
              grant/2,
              join/2,
              uri_add/2,
              uri_remove/2,
              leave/2,
              list/0,
              list/2,
              lookup/1,
              secret/2,
              revoke/2,
              revoke_prefix/2,
              set_metadata/2
             ]).

%%%===================================================================
%%% Client Functions
%%%===================================================================

-spec set_metadata(Client::fifo:client_id(), Attrs::fifo:attr_list()) ->
                          {error, no_servers} |
                          ok.
set_metadata(Client, Attrs) ->
    send(libsnarl_msg:client_set_metadata(r(), Client, Attrs)).

%%--------------------------------------------------------------------
%% @doc Retrievs a list of all client id's.
%% @spec list() ->
%%                 [term()]
%% @end
%%--------------------------------------------------------------------
-spec list() ->
                  {error, no_servers} |
                  {ok, [fifo:client_id()]}.
list() ->
    send(libsnarl_msg:client_list(r())).

%%--------------------------------------------------------------------
%% @doc Retrievs a filtered list for clients.
%% @end
%%--------------------------------------------------------------------
-spec list(Reqs::[fifo:matcher()], boolean()) ->
                  {error, no_servers} |
                  {ok, [{integer(), fifo:client_id()}]} |
                  {ok, [{integer(), fifo:client()}]}.

list(Reqs, Full) ->
    send(libsnarl_msg:client_list(r(), Reqs, Full)).

%%--------------------------------------------------------------------
%% @doc Streams the VM's in chunks.
%% @end
%%--------------------------------------------------------------------
-spec stream(Reqs::[fifo:matcher()], mdns_client_lib:stream_fun(), term()) ->
                  {ok, [{Ranking::integer(), fifo:client_id()}]} |
                  {ok, [{Ranking::integer(), fifo:client()}]} |
                  {'error', 'no_servers'}.
stream(Reqs, StreamFn, Acc0) ->
    case libsnarl_server:stream({client, stream, r(), Reqs}, StreamFn, Acc0) of
        {reply, Reply} ->
            Reply;
        noreply ->
            ok;
        E ->
            E
    end.

%%--------------------------------------------------------------------
%% @doc Retrieves client data from the server.
%% @spec get(Client::binary()) ->
%%                 {error, not_found|no_servers} | term()
%% @end
%%--------------------------------------------------------------------
-spec get(Client::fifo:client_id()) ->
                 not_found |
                 {error, no_servers} |
                 {ok, fifo:client()}.
get(Client) ->
    send(libsnarl_msg:client_get(r(), Client)).

%%--------------------------------------------------------------------
%% @doc Retrieves client data from the server.
%% @spec lookup(Client::binary()) ->
%%                 {error, not_found|no_servers} | term()
%% @end
%%--------------------------------------------------------------------
-spec lookup(Client::fifo:client_id()) ->
                    not_found |
                    {error, no_servers} |
                    {ok, fifo:client()}.
lookup(Client) ->
    send(libsnarl_msg:client_lookup(r(), Client)).

%%--------------------------------------------------------------------
%% @doc Adds a new client.
%% @spec add(Client::binary()) ->
%%                 {error, duplicate} | ok
%% @end
%%--------------------------------------------------------------------
-spec add(ClientName::binary()) ->
                 {error, no_servers} |
                 duplicate |
                 {ok, UUID::fifo:client_id()}.
add(ClientName) ->
    send(libsnarl_msg:client_add(r(), ClientName)).


%%--------------------------------------------------------------------
%% @doc Adds a new client from perspective of a creator, triggering
%%      Org events in the process
%% @end
%%--------------------------------------------------------------------
-spec add(Creator::fifo:client_id(),
          ClientName::binary()) ->
                 {error, no_servers} |
                 duplicate |
                 {ok, UUID::fifo:client_id()}.
add(Creator, ClientName) ->
    send(libsnarl_msg:client_add(r(), Creator, ClientName)).

%%--------------------------------------------------------------------
%% @doc Deletes a client.
%% @spec delete(Client::binary()) ->
%%                    {error, not_found|no_servers} | ok
%% @end
%%--------------------------------------------------------------------
-spec delete(Client::fifo:client_id()) ->
                    {error, no_servers} |
                    not_found |
                    ok.
delete(Client) ->
    send(libsnarl_msg:client_delete(r(), Client)).

%%--------------------------------------------------------------------
%% @doc Grants a right of a client.
%% @spec grant(Client::binary(),
%%                  Permission::[atom()|binary()|string()]) ->
%%                  {error, not_found|no_servers} | ok
%% @end
%%--------------------------------------------------------------------

-spec grant(Client::fifo:client_id(),
            Permission::fifo:permission()) ->
                   {error, no_servers} |
                   not_found |
                   ok.
grant(Client, Permission) ->
    send(libsnarl_msg:client_grant(r(), Client, Permission)).

%%--------------------------------------------------------------------
%% @doc Revokes a right of a client.
%% @spec revoke(Client::binary(),
%%                   Permission::fifo:permission()) ->
%%                   {error, not_found|no_servers} | ok
%% @end
%%--------------------------------------------------------------------
-spec revoke(Client::fifo:client_id(),
             Permission::fifo:permission()) ->
                    {error, no_servers} |
                    not_found |
                    ok.
revoke(Client, Permission) ->
    send(libsnarl_msg:client_revoke(r(), Client, Permission)).

%%--------------------------------------------------------------------
%% @doc Revokes all right with a certain prefix from a client.
%% @end
%%--------------------------------------------------------------------
-spec revoke_prefix(Client::fifo:client_id(),
                    Prefix::fifo:permission()) ->
                           {error, no_servers} |
                           not_found |
                           ok.
revoke_prefix(Client, Prefix) ->
    send(libsnarl_msg:client_revoke_prefix(r(), Client, Prefix)).

%%--------------------------------------------------------------------
%% @doc Changes the Password of a client.
%% @end
%%--------------------------------------------------------------------
-spec secret(Client::fifo:client_id(), Secret::binary()) ->
                    {error, no_servers} |
                    not_found |
                    ok.
secret(Client, Secret) ->
    send(libsnarl_msg:client_secret(r(), Client, Secret)).

%%--------------------------------------------------------------------
%% @doc Adds a client to a role.
%% @end
%%--------------------------------------------------------------------
-spec join(Client::fifo:client_id(), Role::fifo:role_id()) ->
                  {error, no_servers} |
                  not_found |
                  ok.
join(Client, Role) ->
    send(libsnarl_msg:client_join(r(), Client, Role)).

%%--------------------------------------------------------------------
%% @doc Adds a key to the clients SSH keys.
%% @end
%%--------------------------------------------------------------------
-spec uri_add(Client::fifo:client_id(), OTP::binary()) ->
                         {error, no_servers} |
                         not_found |
                         ok.
uri_add(Client, OTP) ->
    send(libsnarl_msg:client_uri_add(r(), Client, OTP)).

%%--------------------------------------------------------------------
%% @doc Removes a key from the clients SSH keys.
%% @end
%%--------------------------------------------------------------------
-spec uri_remove(Client::fifo:client_id(), KeyID::binary()) ->
                            {error, no_servers} |
                            not_found |
                            ok.
uri_remove(Client, KeyID) ->
    send(libsnarl_msg:client_uri_remove(r(), Client, KeyID)).

%%--------------------------------------------------------------------
%% @doc Removes a client from a role.
%% @end
%%--------------------------------------------------------------------
-spec leave(Client::fifo:client_id(), Role::fifo:role_id()) ->
                   {error, no_servers} |
                   not_found |
                   ok.
leave(Client, Role) ->
    send(libsnarl_msg:client_leave(r(), Client, Role)).

%%%===================================================================
%%% Internal Functions
%%%===================================================================

%%--------------------------------------------------------------------
%% @private
%% @doc Sends a message.
%% @spec send(Msg::term()) -> {ok, Reply::term()} | {error, no_server}
%% @end
%%--------------------------------------------------------------------

-spec send(Msg::fifo:snarl_client_message()) ->
                  ok |
                  not_found |
                  duplicate |
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
