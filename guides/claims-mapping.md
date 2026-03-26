# Claims Mapping

After a successful OIDC callback or JWT validation, raw provider claims
need to be transformed into an actor map. The `claims_mapping` config option
controls this transformation using `nova_auth_claims` from the nova_auth library.

## Default Behaviour

With no `claims_mapping` configured (or `#{}`), the controller creates a
minimal actor:

```erlang
#{
    id => maps:get(~"sub", Userinfo),   %% falls back to ~"email"
    provider => authentik,
    claims => Userinfo                   %% raw claims preserved
}
```

## Static Mapping

Map binary claim keys to atom actor keys:

```erlang
claims_mapping => #{
    ~"sub" => id,
    ~"email" => email,
    ~"name" => display_name,
    ~"groups" => roles
}
```

Given Authentik claims:

```erlang
#{
    ~"sub" => ~"abc123",
    ~"email" => ~"jane@example.com",
    ~"name" => ~"Jane Doe",
    ~"groups" => [~"admins", ~"developers"],
    ~"iss" => ~"https://auth.example.com/..."
}
```

The resulting actor is:

```erlang
#{
    id => ~"abc123",
    provider => authentik,
    email => ~"jane@example.com",
    display_name => ~"Jane Doe",
    roles => [~"admins", ~"developers"]
}
```

Note that `provider` is always added automatically. Claims not in the mapping
(like `iss`) are dropped.

## Callback Mapping

For complex transformations, use a `{Module, Function}` tuple:

```erlang
claims_mapping => {my_claims, map_authentik}
```

The function receives the raw claims map and must return an actor map:

```erlang
-module(my_claims).
-export([map_authentik/1]).

map_authentik(Claims) ->
    Groups = maps:get(~"groups", Claims, []),
    Role = case lists:member(~"admins", Groups) of
        true -> admin;
        false -> user
    end,
    #{
        id => maps:get(~"sub", Claims),
        email => maps:get(~"email", Claims, undefined),
        role => Role
    }.
```

## Using Claims with Policies

After mapping, you can use `nova_auth_policy:allow_claim/2` for authorization:

```erlang
%% With static mapping: ~"groups" => roles
%% Actor has: #{roles => [~"admins", ~"developers"], ...}

nova_auth_policy:allow_claim(roles, ~"admins")
%% Checks if ~"admins" is in the actor's roles list

%% With callback mapping: groups → role atom
%% Actor has: #{role => admin, ...}

nova_auth_policy:allow_claim(role, [admin, editor])
%% Checks if role is admin or editor
```

## Provider-Specific Examples

### Authentik

Authentik includes groups and entitlements in tokens:

```erlang
claims_mapping => #{
    ~"sub" => id,
    ~"email" => email,
    ~"preferred_username" => username,
    ~"name" => display_name,
    ~"groups" => roles
}
```

### Keycloak

Keycloak nests roles under `realm_access.roles`. Use a callback:

```erlang
claims_mapping => {my_claims, map_keycloak}

%% my_claims.erl
map_keycloak(Claims) ->
    RealmAccess = maps:get(~"realm_access", Claims, #{}),
    Roles = maps:get(~"roles", RealmAccess, []),
    #{
        id => maps:get(~"sub", Claims),
        email => maps:get(~"email", Claims, undefined),
        roles => Roles
    }.
```

### Google

Google claims are flat:

```erlang
claims_mapping => #{
    ~"sub" => id,
    ~"email" => email,
    ~"name" => display_name,
    ~"picture" => avatar_url
}
```
