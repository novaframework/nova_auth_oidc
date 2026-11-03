-module(nova_auth_oidc_introspect_tests).
-include_lib("eunit/include/eunit.hrl").

-define(FIELDS, [
    active, client_id, exp, scope, username, token_type, iat, nbf, sub, aud, iss, jti, extra
]).

record_layout_matches_oidcc_test() ->
    ?assertEqual(?FIELDS, oidcc_record_fields()).

introspect_maps_record_fields_test_() ->
    {setup,
        fun() ->
            ok = meck:new(oidcc, [no_link]),
            ok = meck:expect(oidcc, introspect_token, fun(_, _, _, _, _) ->
                {ok, introspection()}
            end)
        end,
        fun(_) -> meck:unload(oidcc) end, fun() ->
            ?assertEqual(
                {ok, #{
                    active => true,
                    client_id => ~"test-client-id",
                    exp => 1700000000,
                    scope => [~"openid"],
                    username => ~"jane",
                    token_type => ~"Bearer",
                    iss => ~"https://auth.example.com/application/o/myapp",
                    extra => #{~"custom" => ~"value"}
                }},
                nova_auth_oidc_introspect:introspect(test_oidc_config, authentik, ~"token")
            )
        end}.

introspection() ->
    Values = #{
        active => true,
        client_id => ~"test-client-id",
        exp => 1700000000,
        scope => [~"openid"],
        username => ~"jane",
        token_type => ~"Bearer",
        iss => ~"https://auth.example.com/application/o/myapp",
        extra => #{~"custom" => ~"value"}
    },
    list_to_tuple([
        oidcc_token_introspection | [maps:get(Field, Values, undefined) || Field <- ?FIELDS]
    ]).

oidcc_record_fields() ->
    Dir = code:lib_dir(oidcc),
    true = is_list(Dir),
    {ok, Forms} = epp:parse_file(Dir ++ "/include/oidcc_token_introspection.hrl", []),
    [Fields] = [
        Fs
     || {attribute, _, record, {oidcc_token_introspection, Fs}} <- Forms, is_list(Fs)
    ],
    [field_name(Field) || Field <- Fields].

field_name({typed_record_field, Field, _Type}) -> field_name(Field);
field_name({record_field, _, {atom, _, Name}}) -> Name;
field_name({record_field, _, {atom, _, Name}, _Default}) -> Name.

introspect_unknown_record_shape_test_() ->
    {setup,
        fun() ->
            ok = meck:new(oidcc, [no_link]),
            ok = meck:expect(oidcc, introspect_token, fun(_, _, _, _, _) ->
                {ok, list_to_tuple([oidcc_token_introspection | lists:duplicate(14, undefined)])}
            end)
        end,
        fun(_) -> meck:unload(oidcc) end, fun() ->
            ?assertEqual(
                {error, unsupported_oidcc_introspection},
                nova_auth_oidc_introspect:introspect(test_oidc_config, authentik, ~"token")
            )
        end}.
