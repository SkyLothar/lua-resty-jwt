use Test::Nginx::Socket::Lua;

repeat_each(2);

plan tests => repeat_each() * (3 * blocks());

our $HttpConfig = <<'_EOC_';
    lua_package_path 'lib/?.lua;;';
_EOC_

no_long_string();

run_tests();

__DATA__


=== TEST 1: JWT simple with invalid exp ("exp": "17")
--- http_config eval: $::HttpConfig
--- config
    location /t {
        content_by_lua '
            local jwt = require "resty.jwt"
            local jwt_obj = jwt:verify(
                "lua-resty-jwt",
                "eyJ0eXAiOiJKV1QiLCJhbGciOiJIUzI1NiJ9" ..
                ".eyJmb28iOiJiYXIiLCJleHAiOiIxNyJ9" ..
                ".6gWBliIuNT1qF_RhD1ymI-zRyN38zGme0dHvYkOFgxM"
            )
            ngx.say(jwt_obj["verified"])
            ngx.say(jwt_obj["reason"])
        ';
    }
--- request
GET /t
--- response_body
false
jwt 'exp' claim is malformed. Expected to be a positive numeric value.
--- no_error_log
[error]


=== TEST 2: JWT simple with invalid exp ("exp": -17)
--- http_config eval: $::HttpConfig
--- config
    location /t {
        content_by_lua '
            local jwt = require "resty.jwt"
            local jwt_obj = jwt:verify(
                "lua-resty-jwt",
                "eyJ0eXAiOiJKV1QiLCJhbGciOiJIUzI1NiJ9" ..
                ".eyJmb28iOiJiYXIiLCJleHAiOi0xN30" ..
                ".Jd3_eeMBJeWAeyke5SbXD3TecVPpci7lNLWGze9OP9o"
            )
            ngx.say(jwt_obj["verified"])
            ngx.say(jwt_obj["reason"])
        ';
    }
--- request
GET /t
--- response_body
false
jwt 'exp' claim is malformed. Expected to be a positive numeric value.
--- no_error_log
[error]


=== TEST 3: JWT simple with invalid nbf ("nbf": "17")
--- http_config eval: $::HttpConfig
--- config
    location /t {
        content_by_lua '
            local jwt = require "resty.jwt"
            local jwt_obj = jwt:verify(
                "lua-resty-jwt",
                "eyJ0eXAiOiJKV1QiLCJhbGciOiJIUzI1NiJ9" ..
                ".eyJmb28iOiJiYXIiLCJuYmYiOiIxNyJ9" ..
                ".kYzPvYDRiW37rsdYNfFd57KDBuZpm1loCRIJSUlQjbE"
            )
            ngx.say(jwt_obj["verified"])
            ngx.say(jwt_obj["reason"])
        ';
    }
--- request
GET /t
--- response_body
false
jwt 'nbf' claim is malformed. Expected to be a positive numeric value.
--- no_error_log
[error]


=== TEST 4: JWT simple with invalid nbf ("nbf": -17)
--- http_config eval: $::HttpConfig
--- config
    location /t {
        content_by_lua '
            local jwt = require "resty.jwt"
            local jwt_obj = jwt:verify(
                "lua-resty-jwt",
                "eyJ0eXAiOiJKV1QiLCJhbGciOiJIUzI1NiJ9" ..
                ".eyJmb28iOiJiYXIiLCJuYmYiOi0xN30" ..
                ".jNUyAIYISmDcemGO3gE17byPZ_ZO-WZxaMt59UNslPc"
            )
            ngx.say(jwt_obj["verified"])
            ngx.say(jwt_obj["reason"])
        ';
    }
--- request
GET /t
--- response_body
false
jwt 'nbf' claim is malformed. Expected to be a positive numeric value.
--- no_error_log
[error]


=== TEST 5: JWT simple with invalid negative validity grace period
--- http_config eval: $::HttpConfig
--- config
    location /t {
        content_by_lua '
            local jwt = require "resty.jwt"
            local jwt_obj = jwt:verify(
                "lua-resty-jwt",
                "eyJ0eXAiOiJKV1QiLCJhbGciOiJIUzI1NiJ9" ..
                ".eyJmb28iOiJiYXIifQ" ..
                ".VAoRL1IU0nOguxURF2ZcKR0SGKE1gCbqwyh8u2MLAyY",
                { validity_grace_period = -1 }
            )
            ngx.say(jwt_obj["verified"])
            ngx.say(jwt_obj["reason"])
        ';
    }
--- request
GET /t
--- error_code: 500
--- error_log
'validity_grace_period' validation option is expected to be a positive number of seconds.
[error]


=== TEST 6: JWT simple with invalid alpha validity grace period
--- http_config eval: $::HttpConfig
--- config
    location /t {
        content_by_lua '
            local jwt = require "resty.jwt"
            local jwt_obj = jwt:verify(
                "lua-resty-jwt",
                "eyJ0eXAiOiJKV1QiLCJhbGciOiJIUzI1NiJ9" ..
                ".eyJmb28iOiJiYXIifQ" ..
                ".VAoRL1IU0nOguxURF2ZcKR0SGKE1gCbqwyh8u2MLAyY",
                { validity_grace_period = "boom ?" }
            )
            ngx.say(jwt_obj["verified"])
            ngx.say(jwt_obj["reason"])
        ';
    }
--- request
GET /t
--- error_code: 500
--- error_log
'validity_grace_period' validation option is expected to be a positive number of seconds.
[error]


=== TEST 7: JWT simple with default validity grace period and valid exp
--- http_config eval: $::HttpConfig
--- config
    location /t {
        content_by_lua '
            local jwt = require "resty.jwt"
            local jwt_obj = jwt:verify(
                "lua-resty-jwt",
                "eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9" ..
                ".eyJmb28iOiJiYXIiLCJleHAiOjk5OTk5OTk5OTl9" ..
                ".Y503HYultweqOpvvNF3fj2FTb_rH7ZwKAXap6cPqXjw"
            )
            ngx.say(jwt_obj["verified"])
            ngx.say(jwt_obj["reason"])
        ';
    }
--- request
GET /t
--- response_body
true
everything is awesome~ :p
--- no_error_log
[error]


=== TEST 8: JWT simple with default validity grace period and invalid exp
--- http_config eval: $::HttpConfig
--- config
    location /t {
        content_by_lua '
            local jwt = require "resty.jwt"
            local jwt_obj = jwt:verify(
                "lua-resty-jwt",
                "eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9" ..
                ".eyJmb28iOiJiYXIiLCJleHAiOjB9" ..
                ".btivkb1guN1sQBYYVcrigEuNVvDOp1PDrbgaNSD3Whg"
            )
            ngx.say(jwt_obj["verified"])
            ngx.say(jwt_obj["reason"])
        ';
    }
--- request
GET /t
--- response_body
false
jwt token expired at: Thu, 01 Jan 1970 00:00:00 GMT
--- no_error_log
[error]


=== TEST 9: JWT simple with default validity grace period and valid nbf
--- http_config eval: $::HttpConfig
--- config
    location /t {
        content_by_lua '
            local jwt = require "resty.jwt"
            local jwt_obj = jwt:verify(
                "lua-resty-jwt",
                "eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9" ..
                ".eyJmb28iOiJiYXIiLCJuYmYiOjB9" ..
                ".qZeWRQBHZhRcszwbiL7JV6Nf-irT75u4IHhoQBTqkzo"
            )
            ngx.say(jwt_obj["verified"])
            ngx.say(jwt_obj["reason"])
        ';
    }
--- request
GET /t
--- response_body
true
everything is awesome~ :p
--- no_error_log
[error]


=== TEST 10: JWT simple with default validity grace period and invalid nbf
--- http_config eval: $::HttpConfig
--- config
    location /t {
        content_by_lua '
            local jwt = require "resty.jwt"
            local jwt_obj = jwt:verify(
                "lua-resty-jwt",
                "eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9" ..
                ".eyJmb28iOiJiYXIiLCJuYmYiOjk5OTk5OTk5OTl9" ..
                ".Wfu3owxbzlrb0GXvV0D22Si8WEDP0WeRGwZNPAoYHMI"
            )
            ngx.say(jwt_obj["verified"])
            ngx.say(jwt_obj["reason"])
        ';
    }
--- request
GET /t
--- response_body
false
jwt token not valid until: Sat, 20 Nov 2286 17:46:39 GMT
--- no_error_log
[error]


=== TEST 11: JWT simple with super large validity grace period and invalid nbf
--- http_config eval: $::HttpConfig
--- config
    location /t {
        content_by_lua '
            local jwt = require "resty.jwt"
            local jwt_obj = jwt:verify(
                "lua-resty-jwt",
                "eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9" ..
                ".eyJmb28iOiJiYXIiLCJuYmYiOjk5OTk5OTk5OTl9" ..
                ".Wfu3owxbzlrb0GXvV0D22Si8WEDP0WeRGwZNPAoYHMI",
                { validity_grace_period = 9999999999 }
            )
            ngx.say(jwt_obj["verified"])
            ngx.say(jwt_obj["reason"])
        ';
    }
--- request
GET /t
--- response_body
true
everything is awesome~ :p
--- no_error_log
[error]


=== TEST 12: JWT simple with super large validity grace period and invalid exp
--- http_config eval: $::HttpConfig
--- config
    location /t {
        content_by_lua '
            local jwt = require "resty.jwt"
            local jwt_obj = jwt:verify(
                "lua-resty-jwt",
                "eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9" ..
                ".eyJmb28iOiJiYXIiLCJleHAiOjB9" ..
                ".btivkb1guN1sQBYYVcrigEuNVvDOp1PDrbgaNSD3Whg",
                { validity_grace_period = 9999999999 }
            )
            ngx.say(jwt_obj["verified"])
            ngx.say(jwt_obj["reason"])
        ';
    }
--- request
GET /t
--- response_body
true
everything is awesome~ :p
--- no_error_log
[error]