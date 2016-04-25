use Test::Nginx::Socket::Lua;

repeat_each(2);

plan tests => repeat_each() * (3 * blocks());

our $HttpConfig = <<'_EOC_';
    lua_package_path 'lib/?.lua;;';
_EOC_

no_long_string();

run_tests();

__DATA__


=== TEST 1: JWT with invalid exp ("exp": "17")
--- http_config eval: $::HttpConfig
--- config
    location /t {
        content_by_lua '
            local jwt = require "resty.jwt"
            local validators = require "resty.jwt-validators"
            validators.set_system_leeway(0)
            local jwt_obj = jwt:verify(
                "lua-resty-jwt",
                "eyJ0eXAiOiJKV1QiLCJhbGciOiJIUzI1NiJ9" ..
                ".eyJmb28iOiJiYXIiLCJleHAiOiIxNyJ9" ..
                ".6gWBliIuNT1qF_RhD1ymI-zRyN38zGme0dHvYkOFgxM",
                {
                  __jwt = validators.require_one_of({ "nbf", "exp" }),
                  nbf = validators.opt_is_not_before(),
                  exp = validators.opt_is_not_expired()
                }
            )
            ngx.say(jwt_obj["verified"])
            ngx.say(jwt_obj["reason"])
        ';
    }
--- request
GET /t
--- response_body
false
'exp' is malformed.  Expected to be a positive numeric value.
--- no_error_log
[error]


=== TEST 2: JWT with invalid exp ("exp": -17)
--- http_config eval: $::HttpConfig
--- config
    location /t {
        content_by_lua '
            local jwt = require "resty.jwt"
            local validators = require "resty.jwt-validators"
            validators.set_system_leeway(0)
            local jwt_obj = jwt:verify(
                "lua-resty-jwt",
                "eyJ0eXAiOiJKV1QiLCJhbGciOiJIUzI1NiJ9" ..
                ".eyJmb28iOiJiYXIiLCJleHAiOi0xN30" ..
                ".Jd3_eeMBJeWAeyke5SbXD3TecVPpci7lNLWGze9OP9o",
                {
                  __jwt = validators.require_one_of({ "nbf", "exp" }),
                  nbf = validators.opt_is_not_before(),
                  exp = validators.opt_is_not_expired()
                }
            )
            ngx.say(jwt_obj["verified"])
            ngx.say(jwt_obj["reason"])
        ';
    }
--- request
GET /t
--- response_body
false
'exp' is malformed.  Expected to be a positive numeric value.
--- no_error_log
[error]


=== TEST 3: JWT with invalid nbf ("nbf": "17")
--- http_config eval: $::HttpConfig
--- config
    location /t {
        content_by_lua '
            local jwt = require "resty.jwt"
            local validators = require "resty.jwt-validators"
            validators.set_system_leeway(0)
            local jwt_obj = jwt:verify(
                "lua-resty-jwt",
                "eyJ0eXAiOiJKV1QiLCJhbGciOiJIUzI1NiJ9" ..
                ".eyJmb28iOiJiYXIiLCJuYmYiOiIxNyJ9" ..
                ".kYzPvYDRiW37rsdYNfFd57KDBuZpm1loCRIJSUlQjbE",
                {
                  __jwt = validators.require_one_of({ "nbf", "exp" }),
                  nbf = validators.opt_is_not_before(),
                  exp = validators.opt_is_not_expired()
                }
            )
            ngx.say(jwt_obj["verified"])
            ngx.say(jwt_obj["reason"])
        ';
    }
--- request
GET /t
--- response_body
false
'nbf' is malformed.  Expected to be a positive numeric value.
--- no_error_log
[error]


=== TEST 4: JWT with invalid nbf ("nbf": -17)
--- http_config eval: $::HttpConfig
--- config
    location /t {
        content_by_lua '
            local jwt = require "resty.jwt"
            local validators = require "resty.jwt-validators"
            validators.set_system_leeway(0)
            local jwt_obj = jwt:verify(
                "lua-resty-jwt",
                "eyJ0eXAiOiJKV1QiLCJhbGciOiJIUzI1NiJ9" ..
                ".eyJmb28iOiJiYXIiLCJuYmYiOi0xN30" ..
                ".jNUyAIYISmDcemGO3gE17byPZ_ZO-WZxaMt59UNslPc",
                {
                  __jwt = validators.require_one_of({ "nbf", "exp" }),
                  nbf = validators.opt_is_not_before(),
                  exp = validators.opt_is_not_expired()
                }
            )
            ngx.say(jwt_obj["verified"])
            ngx.say(jwt_obj["reason"])
        ';
    }
--- request
GET /t
--- response_body
false
'nbf' is malformed.  Expected to be a positive numeric value.
--- no_error_log
[error]


=== TEST 5: JWT with invalid negative lifetime grace period
--- http_config eval: $::HttpConfig
--- config
    location /t {
        content_by_lua '
            local jwt = require "resty.jwt"
            local validators = require "resty.jwt-validators"
            validators.set_system_leeway(-1)
            local jwt_obj = jwt:verify(
                "lua-resty-jwt",
                "eyJ0eXAiOiJKV1QiLCJhbGciOiJIUzI1NiJ9" ..
                ".eyJmb28iOiJiYXIifQ" ..
                ".VAoRL1IU0nOguxURF2ZcKR0SGKE1gCbqwyh8u2MLAyY",
                {
                  __jwt = validators.require_one_of({ "nbf", "exp" }),
                  nbf = validators.opt_is_not_before(),
                  exp = validators.opt_is_not_expired()
                }
            )
            ngx.say(jwt_obj["verified"])
            ngx.say(jwt_obj["reason"])
        ';
    }
--- request
GET /t
--- error_code: 500
--- error_log
leeway must be a non-negative number
[error]


=== TEST 6: JWT with invalid alpha lifetime grace period
--- http_config eval: $::HttpConfig
--- config
    location /t {
        content_by_lua '
            local jwt = require "resty.jwt"
            local validators = require "resty.jwt-validators"
            validators.set_system_leeway("boom ?")
            local jwt_obj = jwt:verify(
                "lua-resty-jwt",
                "eyJ0eXAiOiJKV1QiLCJhbGciOiJIUzI1NiJ9" ..
                ".eyJmb28iOiJiYXIifQ" ..
                ".VAoRL1IU0nOguxURF2ZcKR0SGKE1gCbqwyh8u2MLAyY",
                {
                  __jwt = validators.require_one_of({ "nbf", "exp" }),
                  nbf = validators.opt_is_not_before(),
                  exp = validators.opt_is_not_expired()
                }
            )
            ngx.say(jwt_obj["verified"])
            ngx.say(jwt_obj["reason"])
        ';
    }
--- request
GET /t
--- error_code: 500
--- error_log
leeway must be a non-negative number
[error]


=== TEST 7: JWT with no lifetime grace period and valid exp ("exp": 9999999999)
--- http_config eval: $::HttpConfig
--- config
    location /t {
        content_by_lua '
            local jwt = require "resty.jwt"
            local validators = require "resty.jwt-validators"
            validators.set_system_leeway(0)
            local jwt_obj = jwt:verify(
                "lua-resty-jwt",
                "eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9" ..
                ".eyJmb28iOiJiYXIiLCJleHAiOjk5OTk5OTk5OTl9" ..
                ".Y503HYultweqOpvvNF3fj2FTb_rH7ZwKAXap6cPqXjw",
                {
                  __jwt = validators.require_one_of({ "nbf", "exp" }),
                  nbf = validators.opt_is_not_before(),
                  exp = validators.opt_is_not_expired()
                }
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


=== TEST 8: JWT with no lifetime grace period and invalid exp ("exp": 0)
--- http_config eval: $::HttpConfig
--- config
    location /t {
        content_by_lua '
            local jwt = require "resty.jwt"
            local validators = require "resty.jwt-validators"
            validators.set_system_leeway(0)
            local jwt_obj = jwt:verify(
                "lua-resty-jwt",
                "eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9" ..
                ".eyJmb28iOiJiYXIiLCJleHAiOjB9" ..
                ".btivkb1guN1sQBYYVcrigEuNVvDOp1PDrbgaNSD3Whg",
                {
                  __jwt = validators.require_one_of({ "nbf", "exp" }),
                  nbf = validators.opt_is_not_before(),
                  exp = validators.opt_is_not_expired()
                }
            )
            ngx.say(jwt_obj["verified"])
            ngx.say(jwt_obj["reason"])
        ';
    }
--- request
GET /t
--- response_body
false
'exp' claim expired at Thu, 01 Jan 1970 00:00:00 GMT
--- no_error_log
[error]


=== TEST 9: JWT with no lifetime grace period and valid nbf ("nbf": 0)
--- http_config eval: $::HttpConfig
--- config
    location /t {
        content_by_lua '
            local jwt = require "resty.jwt"
            local validators = require "resty.jwt-validators"
            validators.set_system_leeway(0)
            local jwt_obj = jwt:verify(
                "lua-resty-jwt",
                "eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9" ..
                ".eyJmb28iOiJiYXIiLCJuYmYiOjB9" ..
                ".qZeWRQBHZhRcszwbiL7JV6Nf-irT75u4IHhoQBTqkzo",
                {
                  __jwt = validators.require_one_of({ "nbf", "exp" }),
                  nbf = validators.opt_is_not_before(),
                  exp = validators.opt_is_not_expired()
                }
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


=== TEST 10: JWT with no lifetime grace period and invalid nbf ("nbf": 9999999999)
--- http_config eval: $::HttpConfig
--- config
    location /t {
        content_by_lua '
            local jwt = require "resty.jwt"
            local validators = require "resty.jwt-validators"
            validators.set_system_leeway(0)
            local jwt_obj = jwt:verify(
                "lua-resty-jwt",
                "eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9" ..
                ".eyJmb28iOiJiYXIiLCJuYmYiOjk5OTk5OTk5OTl9" ..
                ".Wfu3owxbzlrb0GXvV0D22Si8WEDP0WeRGwZNPAoYHMI",
                {
                  __jwt = validators.require_one_of({ "nbf", "exp" }),
                  nbf = validators.opt_is_not_before(),
                  exp = validators.opt_is_not_expired()
                }
            )
            ngx.say(jwt_obj["verified"])
            ngx.say(jwt_obj["reason"])
        ';
    }
--- request
GET /t
--- response_body
false
'nbf' claim not valid until Sat, 20 Nov 2286 17:46:39 GMT
--- no_error_log
[error]


=== TEST 11: JWT with super large lifetime grace period and invalid nbf ("nbf": 9999999999)
--- http_config eval: $::HttpConfig
--- config
    location /t {
        content_by_lua '
            local jwt = require "resty.jwt"
            local validators = require "resty.jwt-validators"
            validators.set_system_leeway(9999999999)
            local jwt_obj = jwt:verify(
                "lua-resty-jwt",
                "eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9" ..
                ".eyJmb28iOiJiYXIiLCJuYmYiOjk5OTk5OTk5OTl9" ..
                ".Wfu3owxbzlrb0GXvV0D22Si8WEDP0WeRGwZNPAoYHMI",
                {
                  __jwt = validators.require_one_of({ "nbf", "exp" }),
                  nbf = validators.opt_is_not_before(),
                  exp = validators.opt_is_not_expired()
                }
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


=== TEST 12: JWT with super large lifetime grace period and invalid exp ("exp": 0)
--- http_config eval: $::HttpConfig
--- config
    location /t {
        content_by_lua '
            local jwt = require "resty.jwt"
            local validators = require "resty.jwt-validators"
            validators.set_system_leeway(9999999999)
            local jwt_obj = jwt:verify(
                "lua-resty-jwt",
                "eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9" ..
                ".eyJmb28iOiJiYXIiLCJleHAiOjB9" ..
                ".btivkb1guN1sQBYYVcrigEuNVvDOp1PDrbgaNSD3Whg",
                {
                  __jwt = validators.require_one_of({ "nbf", "exp" }),
                  nbf = validators.opt_is_not_before(),
                  exp = validators.opt_is_not_expired()
                }
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


=== TEST 13: JWT without exp nor nbf claim without lifetime related requirement
--- http_config eval: $::HttpConfig
--- config
    location /t {
        content_by_lua '
            local jwt = require "resty.jwt"
            local jwt_obj = jwt:verify(
                "lua-resty-jwt",
                "eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9" ..
                ".eyJmb28iOiJiYXIifQ" ..
                ".VxhQcGihWyHuJeHhpUiq2FU7aW2s_3ZJlY6h1kdlmJY",
                { }
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


=== TEST 14: JWT without exp nor nbf claim without lifetime related requirement - Take 2
--- http_config eval: $::HttpConfig
--- config
    location /t {
        content_by_lua '
            local jwt = require "resty.jwt"
            local validators = require "resty.jwt-validators"
            local jwt_obj = jwt:verify(
                "lua-resty-jwt",
                "eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9" ..
                ".eyJmb28iOiJiYXIifQ" ..
                ".VxhQcGihWyHuJeHhpUiq2FU7aW2s_3ZJlY6h1kdlmJY",
                {
                  nbf = validators.opt_is_not_before(),
                  exp = validators.opt_is_not_expired()
                }
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


=== TEST 15: JWT without exp nor nbf claim without lifetime related requirement - Take 3
--- http_config eval: $::HttpConfig
--- config
    location /t {
        content_by_lua '
            local jwt = require "resty.jwt"
            local validators = require "resty.jwt-validators"
            local jwt_obj = jwt:verify(
                "lua-resty-jwt",
                "eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9" ..
                ".eyJmb28iOiJiYXIifQ" ..
                ".VxhQcGihWyHuJeHhpUiq2FU7aW2s_3ZJlY6h1kdlmJY",
                {
                  nbf = validators.opt_is_not_before(),
                  exp = validators.opt_is_not_expired()
                }
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


=== TEST 16: JWT without exp nor nbf claim while lifetime grace period specified
--- http_config eval: $::HttpConfig
--- config
    location /t {
        content_by_lua '
            local jwt = require "resty.jwt"
            local validators = require "resty.jwt-validators"
            validators.set_system_leeway(1)
            local jwt_obj = jwt:verify(
                "lua-resty-jwt",
                "eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9" ..
                ".eyJmb28iOiJiYXIifQ" ..
                ".VxhQcGihWyHuJeHhpUiq2FU7aW2s_3ZJlY6h1kdlmJY",
                {
                  __jwt = validators.require_one_of({ "nbf", "exp" }),
                  nbf = validators.opt_is_not_before(),
                  exp = validators.opt_is_not_expired()
                }
            )
            ngx.say(jwt_obj["verified"])
            ngx.say(jwt_obj["reason"])
        ';
    }
--- request
GET /t
--- response_body
false
Missing one of claims - [ nbf, exp ].
--- no_error_log
[error]


=== TEST 17: JWT without exp nor nbf claim while lifetime grace period specified - Take 2
--- http_config eval: $::HttpConfig
--- config
    location /t {
        content_by_lua '
            local jwt = require "resty.jwt"
            local validators = require "resty.jwt-validators"
            validators.set_system_leeway(0)
            local jwt_obj = jwt:verify(
                "lua-resty-jwt",
                "eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9" ..
                ".eyJmb28iOiJiYXIifQ" ..
                ".VxhQcGihWyHuJeHhpUiq2FU7aW2s_3ZJlY6h1kdlmJY",
                {
                  __jwt = validators.require_one_of({ "nbf", "exp" }),
                  nbf = validators.opt_is_not_before(),
                  exp = validators.opt_is_not_expired()
                }
            )
            ngx.say(jwt_obj["verified"])
            ngx.say(jwt_obj["reason"])
        ';
    }
--- request
GET /t
--- response_body
false
Missing one of claims - [ nbf, exp ].
--- no_error_log
[error]


=== TEST 18: JWT without exp nor nbf claim while exp claim required
--- http_config eval: $::HttpConfig
--- config
    location /t {
        content_by_lua '
            local jwt = require "resty.jwt"
            local validators = require "resty.jwt-validators"
            local jwt_obj = jwt:verify(
                "lua-resty-jwt",
                "eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9" ..
                ".eyJmb28iOiJiYXIifQ" ..
                ".VxhQcGihWyHuJeHhpUiq2FU7aW2s_3ZJlY6h1kdlmJY",
                {
                  nbf = validators.opt_is_not_before(),
                  exp = validators.is_not_expired()
                }
            )
            ngx.say(jwt_obj["verified"])
            ngx.say(jwt_obj["reason"])
        ';
    }
--- request
GET /t
--- response_body
false
'exp' claim is required.
--- no_error_log
[error]


=== TEST 19: JWT without exp nor nbf claim while nbf claim required
--- http_config eval: $::HttpConfig
--- config
    location /t {
        content_by_lua '
            local jwt = require "resty.jwt"
            local validators = require "resty.jwt-validators"
            local jwt_obj = jwt:verify(
                "lua-resty-jwt",
                "eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9" ..
                ".eyJmb28iOiJiYXIifQ" ..
                ".VxhQcGihWyHuJeHhpUiq2FU7aW2s_3ZJlY6h1kdlmJY",
                {
                  nbf = validators.is_not_before(),
                  exp = validators.opt_is_not_expired()
                }
            )
            ngx.say(jwt_obj["verified"])
            ngx.say(jwt_obj["reason"])
        ';
    }
--- request
GET /t
--- response_body
false
'nbf' claim is required.
--- no_error_log
[error]


=== TEST 20: JWT with valid exp ("exp": 9999999999) while exp claim required
--- http_config eval: $::HttpConfig
--- config
    location /t {
        content_by_lua '
            local jwt = require "resty.jwt"
            local validators = require "resty.jwt-validators"
            local jwt_obj = jwt:verify(
                "lua-resty-jwt",
                "eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9" ..
                ".eyJmb28iOiJiYXIiLCJleHAiOjk5OTk5OTk5OTl9" ..
                ".Y503HYultweqOpvvNF3fj2FTb_rH7ZwKAXap6cPqXjw",
                {
                  nbf = validators.opt_is_not_before(),
                  exp = validators.is_not_expired()
                }
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


=== TEST 21: JWT with valid exp ("exp": 9999999999) while nbf claim required
--- http_config eval: $::HttpConfig
--- config
    location /t {
        content_by_lua '
            local jwt = require "resty.jwt"
            local validators = require "resty.jwt-validators"
            local jwt_obj = jwt:verify(
                "lua-resty-jwt",
                "eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9" ..
                ".eyJmb28iOiJiYXIiLCJleHAiOjk5OTk5OTk5OTl9" ..
                ".Y503HYultweqOpvvNF3fj2FTb_rH7ZwKAXap6cPqXjw",
                {
                  nbf = validators.is_not_before(),
                  exp = validators.opt_is_not_expired()
                }
            )
            ngx.say(jwt_obj["verified"])
            ngx.say(jwt_obj["reason"])
        ';
    }
--- request
GET /t
--- response_body
false
'nbf' claim is required.
--- no_error_log
[error]


=== TEST 22: JWT with valid nbf ("nbf": 0) while nbf claim required
--- http_config eval: $::HttpConfig
--- config
    location /t {
        content_by_lua '
            local jwt = require "resty.jwt"
            local validators = require "resty.jwt-validators"
            local jwt_obj = jwt:verify(
                "lua-resty-jwt",
                "eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9" ..
                ".eyJmb28iOiJiYXIiLCJuYmYiOjB9" ..
                ".qZeWRQBHZhRcszwbiL7JV6Nf-irT75u4IHhoQBTqkzo",
                {
                  nbf = validators.is_not_before(),
                  exp = validators.opt_is_not_expired()
                }
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


=== TEST 23: JWT with valid nbf ("nbf": 0) while exp claim required
--- http_config eval: $::HttpConfig
--- config
    location /t {
        content_by_lua '
            local jwt = require "resty.jwt"
            local validators = require "resty.jwt-validators"
            local jwt_obj = jwt:verify(
                "lua-resty-jwt",
                "eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9" ..
                ".eyJmb28iOiJiYXIiLCJuYmYiOjB9" ..
                ".qZeWRQBHZhRcszwbiL7JV6Nf-irT75u4IHhoQBTqkzo",
                {
                  nbf = validators.opt_is_not_before(),
                  exp = validators.is_not_expired()
                }
            )
            ngx.say(jwt_obj["verified"])
            ngx.say(jwt_obj["reason"])
        ';
    }
--- request
GET /t
--- response_body
false
'exp' claim is required.
--- no_error_log
[error]
