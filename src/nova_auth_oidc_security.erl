-module(nova_auth_oidc_security).
-moduledoc ~"""
Nova security callbacks for OIDC-protected routes. Extends the base
`nova_auth_security` with JWT bearer validation.

## Usage

```erlang
%% API routes accepting JWT bearer tokens
#{prefix => ~"/api",
  security => nova_auth_oidc_security:require_bearer(my_oidc_config),
  routes => [...]}.

%% Routes accepting both session and bearer auth
#{prefix => ~"/api",
  security => nova_auth_oidc_security:require_any(my_oidc_config),
  routes => [...]}.
```
""".

-export([require_bearer/1, require_bearer/2, require_any/1]).

-doc "Return a security fun that validates JWT bearer tokens.".
-spec require_bearer(module()) -> fun((cowboy_req:req()) -> term()).
require_bearer(AuthMod) ->
    fun(Req) -> require_bearer(AuthMod, Req) end.

-doc "Validate a JWT bearer token from the request.".
-spec require_bearer(module(), cowboy_req:req()) ->
    {true, nova_auth:actor()} | {false, integer(), map(), binary()}.
require_bearer(AuthMod, Req) ->
    case nova_auth_oidc_jwt:validate_bearer(AuthMod, Req) of
        {ok, Actor} ->
            {true, Actor};
        {error, _} ->
            unauthorized()
    end.

-doc """
Return a security fun that tries session auth first, then JWT bearer.
Useful for routes that accept both browser and API clients.
""".
-spec require_any(module()) -> fun((cowboy_req:req()) -> term()).
require_any(AuthMod) ->
    fun(Req) ->
        case nova_auth_actor:fetch(Req) of
            {ok, Actor} ->
                {true, Actor};
            {error, not_found} ->
                case nova_auth_oidc_jwt:validate_bearer(AuthMod, Req) of
                    {ok, Actor} ->
                        {true, Actor};
                    {error, _} ->
                        unauthorized()
                end
        end
    end.

unauthorized() ->
    Body = iolist_to_binary(json:encode(#{~"error" => ~"unauthorized"})),
    {false, 401, #{~"content-type" => ~"application/json"}, Body}.
