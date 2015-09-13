Name
====

lua-resty-jwt - [JWT](http://self-issued.info/docs/draft-jones-json-web-token-01.html) for ngx_lua and LuaJIT

version
=======

0.1.2


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
* [Example](#examples)
* [Installation](#installation)
* [Testing With Docker](#testing-with-docker)
* [Authors](AUTHORS.md)
* [See Also](#see-also)

Status
======

This library is still under active development and is considered production ready.

Description
===========

This library requires an nginx build with OpenSSL,
the [ngx_lua module](http://wiki.nginx.org/HttpLuaModule),
the [LuaJIT 2.0](http://luajit.org/luajit.html),
and the [lua-resty-hmac](https://github.com/jkeys089/lua-resty-hmac)

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
`syntax: local jwt_obj = jwt:verify(key, jwt_token, [, leeway])`

verify a jwt_token and returns a jwt_obj table


load & verify
----------------------------------------
```
syntax: local jwt_obj = jwt:load_jwt(jwt_token)
syntax: local verified = jwt:verify_jwt_obj(key, jwt_obj, [, leeway])
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
    "reason": "signature mismatche: wrong-signature"
}
```

[Back to TOC](#table-of-contents)

Examples
========
* [JWT Auth With Query and Cookie](examples/README.md#jwt-auth-using-query-and-cookie)
* [JWT Auth With KID and Store Your Key in Redis](examples/README.md#jwt-auth-with-kid-and-store-keys-in-redis)

[Back to TOC](#table-of-contents)


Installation
============

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
docker build -t lua-resty-jwt .
docker run --rm -it -v `pwd`:/lua-resty-jwt lua-resty-jwt make test
```

[Back to TOC](#table-of-contents)


See Also
========
* the ngx_lua module: http://wiki.nginx.org/HttpLuaModule

[Back to TOC](#table-of-contents)
