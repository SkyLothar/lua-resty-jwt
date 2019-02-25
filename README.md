Lua-resty-jwt-48606
====

This project is forked from [Lua-resty-jwt](https://github.com/SkyLothar/lua-resty-jwt).

According to the [issue](https://github.com/SkyLothar/lua-resty-jwt/issues/81#issuecomment-396151672), replace the hmac.lua(sum 54340) can work well in openssl 1.0 version.

lua-resty-jwt - [JWT](http://self-issued.info/docs/draft-jones-json-web-token-01.html) for ngx_lua and LuaJIT

[![Build Status](https://img.shields.io/travis/SkyLothar/lua-resty-jwt.svg?style=flat-square)](https://travis-ci.org/SkyLothar/lua-resty-jwt)


**Attention :exclamation: the hmac lib used here is [lua-resty-hmac](https://github.com/jkeys089/lua-resty-hmac), not the one in luarocks.**

Installation
============
- opm: `opm get SkyLothar/lua-resty-jwt`
- luarocks: `luarocks install lua-resty-jwt`
- Head to [release page](https://github.com/SkyLothar/lua-resty-jwt/releases) and download `tar.gz`

version
=======

0.1.10


Table of Contents
=================

* [Name](#name)
* [Status](#status)
* [Description](#description)
* [Synopsis](#synopsis)
* [Methods](#methods)
    * [sign](#sign)
    * [verify](#verify)
    * [load and verify](#load--verify)
    * [sign JWE](#sign-jwe)
* [Verification](#verification)
    * [JWT Validators](#jwt-validators)
    * [Legacy/Timeframe options](#legacy-timeframe-options)
* [Example](#examples)
* [Installation](#installation)
* [Testing With Docker](#testing-with-docker)
* [Authors](AUTHORS.md)
* [See Also](#see-also)

Status
======

This library is under active development but is considered production ready.

Description
===========

This library requires an nginx build with OpenSSL,
the [ngx_lua module](http://wiki.nginx.org/HttpLuaModule),
the [LuaJIT 2.0](http://luajit.org/luajit.html),
the [lua-resty-hmac](https://github.com/jkeys089/lua-resty-hmac),
and the [lua-resty-string](https://github.com/openresty/lua-resty-string),


Synopsis
========

```lua
    # nginx.conf:

    lua_package_path "/path/to/lua-resty-jwt/lib/?.lua;;";

    server {
        default_type text/plain;
        location = /verify {
            content_by_lua '
                local cjson = require "cjson"
                local jwt = require "resty.jwt"

                local jwt_token = "eyJ0eXAiOiJKV1QiLCJhbGciOiJIUzI1NiJ9" ..
                    ".eyJmb28iOiJiYXIifQ" ..
                    ".VAoRL1IU0nOguxURF2ZcKR0SGKE1gCbqwyh8u2MLAyY"
                local jwt_obj = jwt:verify("lua-resty-jwt", jwt_token)
                ngx.say(cjson.encode(jwt_obj))
            ';
        }
        location = /sign {
            content_by_lua '
                local cjson = require "cjson"
                local jwt = require "resty.jwt"

                local jwt_token = jwt:sign(
                    "lua-resty-jwt",
                    {
                        header={typ="JWT", alg="HS256"},
                        payload={foo="bar"}
                    }
                )
                ngx.say(jwt_token)
            ';
        }
    }
```

[Back to TOC](#table-of-contents)

Methods
=======

To load this library,

1. you need to specify this library's path in ngx_lua's [lua_package_path](https://github.com/openresty/lua-nginx-module#lua_package_path) directive. For example, `lua_package_path "/path/to/lua-resty-jwt/lib/?.lua;;";`.
2. you use `require` to load the library into a local Lua variable:

```lua
    local jwt = require "resty.jwt"
```

[Back to TOC](#table-of-contents)


sign
----

`syntax: local jwt_token = jwt:sign(key, table_of_jwt)`

sign a table_of_jwt to a jwt_token.

The `alg` argument specifies which hashing algorithm to use (`HS256`, `HS512`, `RS256`).

### sample of table_of_jwt ###
```
{
    "header": {"typ": "JWT", "alg": "HS512"},
    "payload": {"foo": "bar"}
}
```

verify
------
`syntax: local jwt_obj = jwt:verify(key, jwt_token [, claim_spec [, ...]])`

verify a jwt_token and returns a jwt_obj table.  `key` can be a pre-shared key (as a string), *or* a function which takes a single parameter (the value of `kid` from the header) and returns either the pre-shared key (as a string) for the `kid` or `nil` if the `kid` lookup failed.  This call will fail if you try to specify a function for `key` and there is no `kid` existing in the header.

See [Verification](#verification) for details on the format of `claim_spec` parameters.


load & verify
-------------
```
syntax: local jwt_obj = jwt:load_jwt(jwt_token)
syntax: local verified = jwt:verify_jwt_obj(key, jwt_obj [, claim_spec [, ...]])
```


__verify = load_jwt +  verify_jwt_obj__

load jwt, check for kid, then verify it with the correct key


### sample of jwt_obj ###
```
{
    "raw_header": "eyJ0eXAiOiJKV1QiLCJhbGciOiJIUzI1NiJ9",
    "raw_payload: "eyJmb28iOiJiYXIifQ",
    "signature": "wrong-signature",
    "header": {"typ": "JWT", "alg": "HS256"},
    "payload": {"foo": "bar"},
    "verified": false,
    "valid": true,
    "reason": "signature mismatched: wrong-signature"
}
```

sign-jwe
--------

`syntax: local jwt_token = jwt:sign(key, table_of_jwt)`

sign a table_of_jwt to a jwt_token.

The `alg` argument specifies which hashing algorithm to use for encrypting key (`dir`).
The `enc` argument specifies which hashing algorithm to use for encrypting payload (`A128CBC-HS256`, `A256CBC-HS512`)

### sample of table_of_jwt ###
```
{
    "header": {"typ": "JWE", "alg": "dir", "enc":"A128CBC-HS256"},
    "payload": {"foo": "bar"}
}
```

[Back to TOC](#table-of-contents)


Verification
============

Both the `jwt:load` and `jwt:verify_jwt_obj` functions take, as additional parameters, any number of optional `claim_spec` parameters.  A `claim_spec` is simply a lua table of claims and validators.  Each key in the `claim_spec` table corresponds to a matching key in the payload, and the `validator` is a function that will be called to determine if the claims are met.

The signature of a `validator` function is:

```
function(val, claim, jwt_json)
```

Where `val` is the value of the claim from the `jwt_obj` being tested (or nil if it doesn't exist in the object's payload), `claim` is the name of the claim that is being verified, and `jwt_json` is a json-serialized representation of the object that is being verified.  If the function has no need of the `claim` or `jwt_json`, parameters, they may be left off.

A `validator` function returns either `true` or `false`.  Any `validator` *MAY* raise an error, and the validation will be treated as a failure, and the error that was raised will be put into the reason field of the resulting object.  If a `validator` returns nothing (i.e. `nil`), then the function is treated to have succeeded - under the assumption that it would have raised an error if it would have failed.

A special claim named `__jwt` can be used such that if a `validator` function exists for it, then the `validator` will be called with a deep clone of the entire parsed jwt object as the value of `val`.  This is so that you can write verifications for an entire object that may depend on one or more claims.

Multiple `claim_spec` tables can be specified to the `jwt:load` and `jwt:verify_jwt_obj` - and they will be executed in order.  There is no guarantee of the execution order of individual `validators` within a single `claim_spec`.  If a `claim_spec` fails, then any following `claim_specs` will *NOT* be executed.


### sample `claim_spec` ###
```
{
    sub = function(val) return string.match("^[a-z]+$", val) end,
    iss = function(val)
        for _, value in pairs({ "first", "second" }) do
            if value == val then return true end
        end
        return false
    end,
    __jwt = function(val, claim, jwt_json)
        if val.payload.foo == nil or val.payload.bar == nil then
            error("Need to specify either 'foo' or 'bar'")
        end
    end
}
```

JWT Validators
--------------

A library of helpful `validator` functions exists at `resty.jwt-validators`.  You can use this library by including:
```
local validators = require "resty.jwt-validators"
```

The following functions are currently defined in the validator library.  Those marked with "(opt)" means that the same function exists named `opt_<name>` which takes the same parameters.  The "opt" version of the function will return `true` if the key does not exist in the payload of the jwt_object being verified, while the "non-opt" version of the function will return false if the key does not exist in the payload of the jwt_object being verified.

#### `validators.chain(...)` ####
Returns a validator that chains the given functions together, one after another - as long as they keep passing their checks.

#### `validators.required(chain_function)` ####
Returns a validator that returns `false` if a value doesn't exist.  If the value exists and a `chain_function` is specified, then the value of `chain_function(val, claim, jwt_json)` will be returned, otherwise, `true` will be returned.  This allows for specifying that a value is both required *and* it must match some additional check.

#### `validators.require_one_of(claim_keys)` ####
Returns a validator which errors with a message if *NONE* of the given claim keys exist.  It is expected that this function is used against a full jwt object.  The claim_keys must be a non-empty table of strings.

#### `validators.check(check_val, check_function, name, check_type)` (opt)  ####
Returns a validator that checks if the result of calling the given `check_function` for the tested value and `check_val` returns true.  The value of `check_val` and `check_function` cannot be nil.  The optional `name` is used for error messages and defaults to "check_value".  The optional `check_type` is used to make sure that the check type matches and defaults to `type(check_val)`.  The first parameter passed to check_function will *never* be nil.  If the `check_function` raises an error, that will be appended to the error message.

#### `validators.equals(check_val)` (opt) ####
Returns a validator that checks if a value exactly equals (using `==`) the given check_value. The value of `check_val` cannot be nil.

#### `validators.matches(pattern)` (opt) ####
Returns a validator that checks if a value matches the given pattern (using `string.match`).  The value of `pattern` must be a string.

#### `validators.any_of(check_values, check_function, name, check_type, table_type)` (opt) ####
Returns a validator which calls the given `check_function` for each of the given `check_values` and the tested value.  If any of these calls return `true`, then this function returns `true`.  The value of `check_values` must be a non-empty table with all the same types, and the value of `check_function` must not be `nil`.  The optional `name` is used for error messages and defaults to "check_values".  The optional `check_type` is used to make sure that the check type matches and defaults to `type(check_values[1])` - the table type.

#### `validators.equals_any_of(check_values)` (opt) ####
Returns a validator that checks if a value exactly equals any of the given `check_values`.

#### `validators.matches_any_of(patterns)` (opt) ####
Returns a validator that checks if a value matches any of the given `patterns`.

#### `validators.contains_any_of(check_values,name)` (opt) ####
Returns a validator that checks if a value of expected type `string` exists in any of the given `check_values`.  The value of `check_values`must be a non-empty table with all the same types.  The optional name is used for error messages and defaults to `check_values`.

#### `validators.greater_than(check_val)` (opt) ####
Returns a validator that checks how a value compares (numerically, using `>`) to a given `check_value`.  The value of `check_val` cannot be `nil` and must be a number.

#### `validators.greater_than_or_equal(check_val)` (opt) ####
Returns a validator that checks how a value compares (numerically, using `>=`) to a given `check_value`.  The value of `check_val` cannot be `nil` and must be a number.

#### `validators.less_than(check_val)` (opt) ####
Returns a validator that checks how a value compares (numerically, using `<`) to a given `check_value`.  The value of `check_val` cannot be `nil` and must be a number.

#### `validators.less_than_or_equal(check_val)` (opt) ####
Returns a validator that checks how a value compares (numerically, using `<=`) to a given `check_value`.  The value of `check_val` cannot be `nil` and must be a number.

#### `validators.is_not_before()` (opt) ####
Returns a validator that checks if the current time is not before the tested value within the system's leeway.  This means that:
```
val <= (system_clock() + system_leeway).
```

#### `validators.is_not_expired()` (opt) ####
Returns a validator that checks if the current time is not equal to or after the tested value within the system's leeway.  This means that:
```
val > (system_clock() - system_leeway).
```

#### `validators.is_at()` (opt) ####
Returns a validator that checks if the current time is the same as the tested value within the system's leeway.  This means that:
```
val >= (system_clock() - system_leeway) and val <= (system_clock() + system_leeway).
```

#### `validators.set_system_leeway(leeway)` ####
A function to set the leeway (in seconds) used for `is_not_before` and `is_not_expired`.  The default is to use `0` seconds

#### `validators.set_system_clock(clock)` ####
A function to set the system clock used for `is_not_before` and `is_not_expired`.  The default is to use `ngx.now`

### sample `claim_spec` using validators ###
```
local validators = require "resty.jwt-validators"
local claim_spec = {
    sub = validators.opt_matches("^[a-z]+$),
    iss = validators.equals_any_of({ "first", "second" }),
    __jwt = validators.require_one_of({ "foo", "bar" })
}
```


Legacy/Timeframe options
------------------------

In order to support code which used previous versions of this library, as well as to simplify specifying timeframe-based `claim_specs`, you may use in place of any single `claim_spec` parameter a table of `validation_options`.  The parameter should be expressed as a key/value table. Each key of the table should be picked from the following list.

When using legacy `validation_options`, you *MUST ONLY* specify these options.  That is, you cannot mix legacy `validation_options` with other `claim_spec` validators.  In order to achieve that, you must specify multiple options to the `jwt:load`/`jwt:verify_jwt_obj` functions.

* `lifetime_grace_period`: Define the leeway in seconds to account for clock skew between the server that generated the jwt and the server validating it. Value should be zero (`0`) or a positive integer.

    * When this validation option is specified, the process will ensure that the jwt contains at least one of the two `nbf` or `exp` claim and compare the current clock time against those boundaries. Would the jwt be deemed as expired or not valid yet, verification will fail.

    * When none of the `nbf` and `exp` claims can be found, verification will fail.

    * `nbf` and `exp` claims are expected to be expressed in the jwt as numerical values. Wouldn't that be the case, verification will fail.

    * Specifying this option is equivalent to calling:
      ```
      validators.set_system_leeway(leeway)
      ```

      and specifying as a `claim_spec`:
      ```
      {
        __jwt = validators.require_one_of({ "nbf", "exp" }),
        nbf = validators.opt_is_not_before(),
        exp = validators.opt_is_not_expired()
      }
      ```

* `require_nbf_claim`: Express if the `nbf` claim is optional or not. Value should be a boolean.

    * When this validation option is set to `true` and no `lifetime_grace_period` has been specified, a zero (`0`) leeway is implied.

    * Specifying this option is equivalent to specifying as a `claim_spec`:
      ```
      {
        nbf = validators.is_not_before(),
      }
      ```

* `require_exp_claim`: Express if the `exp` claim is optional or not. Value should be a boolean.

    * When this validation option is set to `true` and no `lifetime_grace_period` has been specified, a zero (`0`) leeway is implied.

    * Specifying this option is equivalent to specifying as a `claim_spec`:
      ```
      {
        exp = validators.is_not_expired(),
      }
      ```

* `valid_issuers`: Whitelist the vetted issuers of the jwt. Value should be a array of strings.

    * When this validation option is specified, the process will compare the jwt `iss` claim against the list of valid issuers. Comparison is done in a case sensitive manner. Would the jwt issuer not be found in the whitelist, verification will fail.

    * `iss` claim is expected to be expressed in the jwt as a string. Wouldn't that be the case, verification will fail.

    * Specifying this option is equivalent to specifying as a `claim_spec`:
      ```
      {
        iss = validators.equals_any_of(valid_issuers),
      }
      ```


### sample of validation_options usage ###
```
local jwt_obj = jwt:verify(key, jwt_token,
    {
        lifetime_grace_period = 120,
        require_exp_claim = true,
        valid_issuers = { "my-trusted-issuer", "my-other-trusteed-issuer" }
    }
)
```



Examples
========
* [JWT Auth With Query and Cookie](examples/README.md#jwt-auth-using-query-and-cookie)
* [JWT Auth With KID and Store Your Key in Redis](examples/README.md#jwt-auth-with-kid-and-store-keys-in-redis)

[Back to TOC](#table-of-contents)


Installation
============

Using Luarocks
```bash
luarocks install lua-resty-jwt
```

It is recommended to use the latest [ngx_openresty bundle](http://openresty.org) directly.

Also, You need to configure
the [lua_package_path](https://github.com/openresty/lua-nginx-module#lua_package_path) directive to
add the path of your lua-resty-jwt source tree to ngx_lua's Lua module search path, as in

```nginx
    # nginx.conf
    http {
        lua_package_path "/path/to/lua-resty-jwt/lib/?.lua;;";
        ...
    }
```

and then load the library in Lua:

```lua
    local jwt = require "resty.jwt"
```


[Back to TOC](#table-of-contents)

Testing With Docker
===================

```
./ci script
```

[Back to TOC](#table-of-contents)


See Also
========
* the ngx_lua module: http://wiki.nginx.org/HttpLuaModule

[Back to TOC](#table-of-contents)
