-module(ls_org).

-export([
         add/1,
         delete/1,
         get/1,
         add_trigger/2,
         list/0,
         list/2,
         stream/3,
         set_metadata/2,
         remove_trigger/2,
         execute_trigger/3,
         resource_inc/3,
         resource_dec/3
        ]).

-ignore_xref([
              add/1,
              delete/1,
              get/1,
              add_trigger/2,
              list/0,
              list/2,
              remove_trigger/2,
              execute_trigger/3,
              set_metadata/2,
              resource_inc/3,
              resource_dec/3
             ]).

%%%===================================================================
%%% org Functions
%%%===================================================================

-spec set_metadata(User::fifo:user_id(), Attrs::fifo:attr_list()) ->
                          {error, no_servers} |
                          ok.
set_metadata(Org, Attrs) ->
    send(libsnarl_msg:org_set_metadata(r(), Org, Attrs)).

%%--------------------------------------------------------------------
%% @doc Retrievs a list of all org id's.
%% @end
%%--------------------------------------------------------------------
-spec list() ->
                  {error, no_servers} |
                  {ok, [fifo:org_id()]}.
list() ->
    send(libsnarl_msg:org_list(r())).

%%--------------------------------------------------------------------
%% @doc Retrievs a filtered list for orgs.
%% @end
%%--------------------------------------------------------------------
-spec list(Reqs::[fifo:matcher()], boolean()) ->
                  {error, no_servers} |
                  {ok, [{Rank::integer(), fifo:org_id()}]} |
                  {ok, [{Rank::integer(), fifo:org()}]}.

list(Reqs, Full) ->
    send(libsnarl_msg:org_list(r(), Reqs, Full)).

%%--------------------------------------------------------------------
%% @doc Streams the VM's in chunks.
%% @end
%%--------------------------------------------------------------------
-spec stream(Reqs::[fifo:matcher()], mdns_client_lib:stream_fun(), term()) ->
                  {ok, [{Ranking::integer(), fifo:vm_id()}]} |
                  {ok, [{Ranking::integer(), fifo:vm()}]} |
                  {'error', 'no_servers'}.
stream(Reqs, StreamFn, Acc0) ->
    case libsnarl_server:stream({org, stream, r(), Reqs}, StreamFn, Acc0) of
        {reply, Reply} ->
            Reply;
        noreply ->
            ok;
        E ->
            E
    end.



%%--------------------------------------------------------------------
%% @doc Retrieves org data from the server.
%% @end
%%--------------------------------------------------------------------
-spec get(Org::fifo:org_id()) ->
                 not_found |
                 {error, no_servers} |
                 {ok, fifo:org()}.
get(Org) ->
    send(libsnarl_msg:org_get(r(), Org)).

%%--------------------------------------------------------------------
%% @doc Adds a new org.
%% @end
%%--------------------------------------------------------------------
-spec add(Org::fifo:org_id()) ->
                 {error, no_servers} |
                 duplicate |
                 {ok, UUID :: fifo:org_id()}.
add(Org) ->
    send(libsnarl_msg:org_add(r(), Org)).

%%--------------------------------------------------------------------
%% @doc Deletes a org.
%% @spec delete(Org::binary()) ->
%%                    {error, not_found|no_servers} | ok
%% @end
%%--------------------------------------------------------------------
-spec delete(Org::fifo:org_id()) ->
                    {error, no_servers} |
                    not_found |
                    ok.
delete(Org) ->
    send(libsnarl_msg:org_delete(r(), Org)).

%%--------------------------------------------------------------------
%% @doc Adds a trigger to an organisation.
%% @end
%%--------------------------------------------------------------------
-spec add_trigger(Org::fifo:org_id(),
                  Trigger::fifo:trigger()) ->
                         {error, no_servers} |
                         not_found |
                         ok.
add_trigger(Org, Trigger) ->
    send(libsnarl_msg:org_add_trigger(r(), Org, Trigger)).

%%--------------------------------------------------------------------
%% @doc Removes a trigger from an organisation.
%% @end
%%--------------------------------------------------------------------
-spec remove_trigger(Org::fifo:org_id(),
                     Trigger::fifo:trigger()) ->
                            {error, no_servers} |
                            not_found |
                            ok.
remove_trigger(Org, Trigger) ->
    send(libsnarl_msg:org_remove_trigger(r(), Org, Trigger)).

%%--------------------------------------------------------------------
%% @doc Revokes all rights matching a prefix from a org.
%% @end
%%--------------------------------------------------------------------
-spec execute_trigger(Org::fifo:org_id(),
                      Event::fifo:event(),
                      Payload::term()) ->
                             {error, no_servers} |
                             not_found |
                             ok.
execute_trigger(Org, Event, Payload) ->
    send(libsnarl_msg:org_execute_trigger(r(), Org, Event, Payload)).

%%--------------------------------------------------------------------
%% @doc Adds a value to a orgs resource.
%% @end
%%--------------------------------------------------------------------
-spec resource_inc(Org::fifo:org_id(),
                   Resource::binary(),
                   Delta::pos_integer()) ->
                             {error, no_servers} |
                             not_found |
                             ok.
resource_inc(Org, Res, Delta) ->
    send(libsnarl_msg:org_resource_inc(r(), Org, Res, Delta)).

%%--------------------------------------------------------------------
%% @doc Substracts a value to a orgs resource.
%% @end
%%--------------------------------------------------------------------
-spec resource_dec(Org::fifo:org_id(),
                   Resource::binary(),
                   Delta::pos_integer()) ->
                             {error, no_servers} |
                             not_found |
                             ok.
resource_dec(Org, Res, Delta) ->
    send(libsnarl_msg:org_resource_dec(r(), Org, Res, Delta)).
%%%===================================================================
%%% Internal Functions
%%%===================================================================

%%--------------------------------------------------------------------
%% @private
%% @doc Sends a message.
%% @spec send(Msg::term()) -> {ok, Reply::term()} | {error, no_server}
%% @end
%%--------------------------------------------------------------------

-spec send(Msg::fifo:snarl_org_message()) ->
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
