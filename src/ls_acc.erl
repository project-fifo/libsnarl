-module(ls_acc).

-export([
         create/4,
         update/4,
         destroy/4,
         get/1,
         get/2,
         get/3
        ]).

-ignore_xref([
              create/4,
              update/4,
              destroy/4,
              get/1,
              get/2,
              get/3
             ]).

%%%===================================================================
%%% org Functions
%%%===================================================================

%%--------------------------------------------------------------------
%% @doc Creates a new resource for a given org.
%% @end
%%--------------------------------------------------------------------

-spec create(Org::fifo:org_id(), Resource::binary(), Time::pos_integer(),
             Metadata::term()) ->
                    {error, no_servers} |
                    ok.
create(Org, Resource, Time, Metadata)
  when is_binary(Org),
       is_binary(Resource),
       is_integer(Time), Time > 0 ->
    send(libsnarl_msg:acc_create(r(), Org, Resource, Time, Metadata)).

%%--------------------------------------------------------------------
%% @doc Updates a resource for a given org.
%% @end
%%--------------------------------------------------------------------

-spec update(Org::fifo:org_id(), Resource::binary(), Time::pos_integer(),
             Metadata::fifo:attr_list()) ->
                    {error, no_servers} |
                    ok.
update(Org, Resource, Time, Metadata)
  when is_binary(Org),
       is_binary(Resource),
       is_integer(Time), Time > 0 ->
    send(libsnarl_msg:acc_update(r(), Org, Resource, Time, Metadata)).

%%--------------------------------------------------------------------
%% @doc Destroys a resource for a given org.
%% @end
%%--------------------------------------------------------------------

-spec destroy(Org::fifo:org_id(), Resource::binary(), Time::pos_integer(),
              Metadata::fifo:attr_list()) ->
                     {error, no_servers} |
                     ok.
destroy(Org, Resource, Time, Metadata)
  when is_binary(Org),
       is_binary(Resource),
       is_integer(Time), Time > 0 ->
    send(libsnarl_msg:acc_destroy(r(), Org, Resource, Time, Metadata)).



%%--------------------------------------------------------------------
%% @doc Gets all entries related to an organisation.
%% @end
%%--------------------------------------------------------------------

-spec get(Org::fifo:org_id()) ->
                 {error, no_servers} |
                 {ok, [{Time::pos_integer(), create|update|destroy,
                        Resource::binary(), Metadata::term()}]}.
get(Org)
  when is_binary(Org) ->
    send(libsnarl_msg:acc_get(r(), Org)).

%%--------------------------------------------------------------------
%% @doc Gets all entries related to a resource and organisation.
%% @end
%%--------------------------------------------------------------------

-spec get(Org::fifo:org_id(), Resource::binary()) ->
                 {error, no_servers} |
                 {ok, [{Time::pos_integer(), create|update|destroy, Metadata::term()}]}.
get(Org, Resource)
  when is_binary(Org),
       is_binary(Resource) ->
    send(libsnarl_msg:acc_get(r(), Org, Resource)).


%%--------------------------------------------------------------------
%% @doc Gets all entries related to resource of an organisation that
%%      exist between two timestamps.
%% @end
%%--------------------------------------------------------------------

-spec get(Org::fifo:org_id(),
          Start::pos_integer(), End::pos_integer())  ->
                 {error, no_servers} |
                 {ok, [{Time::pos_integer(), create|update|destroy,
                        Resource::binary(), Metadata::term()}]}.


get(Org, Start, End)
  when is_binary(Org),
       is_integer(Start),
       is_integer(End),
        Start > 0,
        End > Start ->
    send(libsnarl_msg:acc_get(r(), Org, Start, End)).

%%%===================================================================
%%% Internal Functions
%%%===================================================================

%%--------------------------------------------------------------------
%% @private
%% @doc Sends a message.
%% @spec send(Msg::term()) -> {ok, Reply::term()} | {error, no_servers}
%% @end
%%--------------------------------------------------------------------

-spec send(Msg::fifo:snarl_acc_message()) ->
                  atom() |
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
