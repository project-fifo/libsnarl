-module(ls_org).

-export([
         add/1,
         delete/1,
         get/1,
         add_trigger/2,
         list/0,
         list/2,
         remove_trigger/2,
         execute_trigger/3,
         set/2,
         set/3
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
              set/2,
              set/3
             ]).

%%%===================================================================
%%% org Functions
%%%===================================================================

%%--------------------------------------------------------------------
%% @doc Sets an attribute on the org.
%% @end
%%--------------------------------------------------------------------
-spec set(Org::fifo:id(),
              Attribute::fifo:keys(),
              Value::fifo:value() | delete) -> ok | not_found |
                                               {'error','no_servers'}.
set(Org, Attribute, Value) when
      is_binary(Org) ->
    send(libsnarl_msg:set(r(), Org, Attribute, Value)).

%%--------------------------------------------------------------------
%% @doc Sets multiple attributes on the org.
%% @end
%%--------------------------------------------------------------------
-spec set(Org::fifo:id(),
              Attributes::fifo:attr_list()) ->
                     ok | not_found |
                     {'error','no_servers'}.
set(Org, Attributes) when
      is_binary(Org) ->
    send(libsnarl_msg:org_set(r(), Org, Attributes)).

%%--------------------------------------------------------------------
%% @doc Retrievs a list of all org id's.
%% @end
%%--------------------------------------------------------------------
-spec list() ->
                      {error, no_servers} |
                      {ok, [fifo:id()]}.
list() ->
    send(libsnarl_msg:org_list(r())).

%%--------------------------------------------------------------------
%% @doc Retrievs a filtered list for orgs.
%% @end
%%--------------------------------------------------------------------
-spec list(Reqs::[fifo:matcher()], boolean()) ->
                      {error, timeout} |
                      {ok, [fifo:id()]}.
list(Reqs, Full) ->
    send(libsnarl_msg:org_list(r(), Reqs, Full)).

%%--------------------------------------------------------------------
%% @doc Retrieves org data from the server.
%% @spec get(Org::binary()) ->
%%                 {error, not_found|no_servers} | term()
%% @end
%%--------------------------------------------------------------------
-spec get(Org::fifo:id()) ->
                     not_found |
                     {error, no_servers} |
                     {ok, fifo:org()}.
get(Org) ->
    send(libsnarl_msg:org_get(r(), Org)).

%%--------------------------------------------------------------------
%% @doc Adds a new org.
%% @spec add(Org::binary()) ->
%%                 {error, duplicate} | ok
%% @end
%%--------------------------------------------------------------------
-spec add(Org::fifo:id()) ->
                     {error, no_servers} |
                     duplicate |
                     ok.
add(Org) ->
    send(libsnarl_msg:org_add(r(), Org)).

%%--------------------------------------------------------------------
%% @doc Deletes a org.
%% @spec delete(Org::binary()) ->
%%                    {error, not_found|no_servers} | ok
%% @end
%%--------------------------------------------------------------------
-spec delete(Org::fifo:id()) ->
                        {error, no_servers} |
                        not_found |
                        ok.
delete(Org) ->
    send(libsnarl_msg:org_delete(r(), Org)).

%%--------------------------------------------------------------------
%% @doc Grants a right of a org.
%% @spec grant(Org::binary(),
%%                   Permission::[atom()|binary()|string()]) ->
%%                   {error, not_found|no_servers} | ok
%% @end
%%--------------------------------------------------------------------
-spec add_trigger(Org::fifo:id(),
                      Trigger::fifo:trigger()) ->
                             {error, no_servers} |
                             not_found |
                             ok.
add_trigger(Org, Trigger) ->
    send(libsnarl_msg:org_add_trigger(r(), Org, Trigger)).

%%--------------------------------------------------------------------
%% @doc Revokes a right of a org.
%% @spec revoke(Org::binary(),
%%                    Permission::fifo:permission()) ->
%%                    {error, not_found|no_servers} | ok
%% @end
%%--------------------------------------------------------------------
-spec remove_trigger(Org::fifo:id(),
                         Trigger::fifo:trigger()) ->
                                {error, no_servers} |
                                not_found |
                                ok.
remove_trigger(Org, Trigger) ->
    send(libsnarl_msg:org_remove_trigger(r(), Org, Trigger)).

%%--------------------------------------------------------------------
%% @doc Revokes all rights matching a prefix from a org.
%% @spec revoke(Org::binary(),
%%                    Prefix::fifo:permission()) ->
%%                    {error, not_found|no_servers} | ok
%% @end
%%--------------------------------------------------------------------
-spec execute_trigger(Org::fifo:id(),
                          Event::fifo:event(),
                          Payload::term()) ->
                                 {error, no_servers} |
                                 not_found |
                                 ok.
execute_trigger(Org, Event, Payload) ->
    send(libsnarl_msg:org_execute_trigger(r(), Org, Event, Payload)).

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
    applicaiton:get_env(libsnarl, realm, <<"default">>).
