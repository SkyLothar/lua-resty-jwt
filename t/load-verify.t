use Test::Nginx::Socket::Lua;

repeat_each(2);

plan tests => repeat_each() * (3 * blocks());

our $HttpConfig = <<'_EOC_';
    lua_package_path 'lib/?.lua;;';
_EOC_

no_long_string();

run_tests();

__DATA__


=== TEST 1: JWT table encode
--- http_config eval: $::HttpConfig
--- config
    location /t {
        content_by_lua '
            local jwt = require "resty.jwt"
            ngx.say(
                "urlsafe b64encoded {foo: bar}: ",
                jwt:jwt_encode({foo="bar"})
            )
        ';
    }
--- request
GET /t
--- response_body
urlsafe b64encoded {foo: bar}: eyJmb28iOiJiYXIifQ2
--- no_error_log
[error]


=== TEST 2: JWT str encode
--- http_config eval: $::HttpConfig
--- config
    location /t {
        content_by_lua '
            local jwt = require "resty.jwt"
            ngx.say(
                "urlsafe b64encoded {foo: bar}: ",
                jwt:jwt_encode("{\\"foo\\":\\"bar\\"}")
            )
        ';
    }
--- request
GET /t
--- response_body
urlsafe b64encoded {foo: bar}: eyJmb28iOiJiYXIifQ2
--- no_error_log
[error]


=== TEST 3: JWT table decode
--- http_config eval: $::HttpConfig
--- config
    location /t {
        content_by_lua '
            local jwt = require "resty.jwt"
            local decoded = jwt:jwt_decode("eyJmb28iOiJiYXIifQ", true)
            ngx.say("table eyJmb28iOiJiYXIifQ2: foo=", decoded["foo"])
        ';
    }
--- request
GET /t
--- response_body
table eyJmb28iOiJiYXIifQ2: foo=bar
--- no_error_log
[error]


=== TEST 4: JWT str decode
--- http_config eval: $::HttpConfig
--- config
    location /t {
        content_by_lua '
            local jwt = require "resty.jwt"
            local decoded = jwt:jwt_decode("eyJmb28iOiJiYXIifQ")
            ngx.say("table eyJmb28iOiJiYXIifQ2: ", decoded)
        ';
    }
--- request
GET /t
--- response_body
table eyJmb28iOiJiYXIifQ2: {"foo":"bar"}
--- no_error_log
[error]


=== TEST 5: JWT load valid
--- http_config eval: $::HttpConfig
--- config
    location /t {
        content_by_lua '
            local jwt = require "resty.jwt"
            local jwt_obj = jwt:load_jwt(
                "eyJ0eXAiOiJKV1QiLCJhbGciOiJIUzI1NiJ9" ..
                ".eyJmb28iOiJiYXIifQ" ..
                ".signature"
            )
            ngx.say("alg is: ", jwt_obj.header.alg ," foo is: ", jwt_obj.payload.foo)
        ';
    }
--- request
GET /t
--- response_body
alg is: HS256 foo is: bar
--- no_error_log
[error]


=== TEST 6: JWT load invalid part
--- http_config eval: $::HttpConfig
--- config
    location /t {
        content_by_lua '
            local jwt = require "resty.jwt"
            local jwt_obj = jwt:load_jwt(
                "eyJ0eXAiOiJKV1QiLCJhbGciOiJIUzI1NiJ9" ..
                ".eyJmb28iOiJiYXIifQbad-format" ..
                ".signature"
            )
            ngx.say("reason: ", jwt_obj.reason)
        ';
    }
--- request
GET /t
--- response_body
reason: invalid payload: eyJmb28iOiJiYXIifQbad-format
--- no_error_log
[error]


=== TEST 7: JWT load invalid
--- http_config eval: $::HttpConfig
--- config
    location /t {
        content_by_lua '
            local jwt = require "resty.jwt"
            local jwt_obj = jwt:load_jwt(
                "lua-resty-jwt", "invalid-random-str"
            )
            ngx.say(jwt_obj["verified"])
            ngx.say(jwt_obj["reason"])
        ';
    }
--- request
GET /t
--- response_body
false
invalid jwt string
--- no_error_log
[error]


=== TEST 8: JWT verify wrong signature
--- http_config eval: $::HttpConfig
--- config
    location /t {
        content_by_lua '
            local jwt = require "resty.jwt"
            local jwt_str = "eyJ0eXAiOiJKV1QiLCJhbGciOiJIUzI1NiJ9" ..
                ".eyJmb28iOiJiYXIifQ" ..
                ".signature"
            local jwt_obj = jwt:load_jwt(jwt_str)
            local verified_obj = jwt:verify_jwt_obj("lua-resty-jwt", jwt_obj)
            ngx.say(jwt_obj["verified"])
            ngx.say(jwt_obj["reason"])
        ';
    }
--- request
GET /t
--- response_body
false
signature mismatch: signature
--- no_error_log
[error]


=== TEST 9: JWT simple verify
--- http_config eval: $::HttpConfig
--- config
    location /t {
        content_by_lua '
            local jwt = require "resty.jwt"
            local jwt_str = "eyJ0eXAiOiJKV1QiLCJhbGciOiJIUzI1NiJ9" ..
                ".eyJmb28iOiJiYXIifQ" ..
                ".VAoRL1IU0nOguxURF2ZcKR0SGKE1gCbqwyh8u2MLAyY"

            local jwt_obj = jwt:load_jwt(jwt_str)
            local verified_obj = jwt:verify_jwt_obj("lua-resty-jwt", jwt_obj)
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


=== TEST 10: JWT simple with default leeway and valid exp
--- http_config eval: $::HttpConfig
--- config
    location /t {
        content_by_lua '
            local jwt = require "resty.jwt"
            local jwt_str = "eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9" ..
                ".eyJmb28iOiJiYXIiLCJleHAiOjk5OTk5OTk5OTl9" ..
                ".Y503HYultweqOpvvNF3fj2FTb_rH7ZwKAXap6cPqXjw"

            local jwt_obj = jwt:load_jwt(jwt_str)
            local verified_obj = jwt:verify_jwt_obj(
                "lua-resty-jwt", jwt_obj
            )
            ngx.say(verified_obj["verified"])
            ngx.say(verified_obj["reason"])
        ';
    }
--- request
GET /t
--- response_body
true
everything is awesome~ :p
--- no_error_log
[error]


=== TEST 11: JWT simple with default leeway and invalid exp
--- http_config eval: $::HttpConfig
--- config
    location /t {
        content_by_lua '
            local jwt = require "resty.jwt"
            local jwt_str = "eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9" ..
                ".eyJmb28iOiJiYXIiLCJleHAiOjB9" ..
                ".btivkb1guN1sQBYYVcrigEuNVvDOp1PDrbgaNSD3Whg"

            local jwt_obj = jwt:load_jwt(jwt_str)
            local verified_obj = jwt:verify_jwt_obj(
                "lua-resty-jwt", jwt_obj
            )
            ngx.say(verified_obj["verified"])
            ngx.say(verified_obj["reason"])
        ';
    }
--- request
GET /t
--- response_body
false
jwt token expired at: Thu, 01 Jan 1970 00:00:00 GMT
--- no_error_log
[error]


=== TEST 12: JWT simple with default leeway and valid nbf
--- http_config eval: $::HttpConfig
--- config
    location /t {
        content_by_lua '
            local jwt = require "resty.jwt"
            local jwt_str = "eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9" ..
                ".eyJmb28iOiJiYXIiLCJuYmYiOjB9" ..
                ".qZeWRQBHZhRcszwbiL7JV6Nf-irT75u4IHhoQBTqkzo"

            local jwt_obj = jwt:load_jwt(jwt_str)
            local verified_obj = jwt:verify_jwt_obj(
                "lua-resty-jwt", jwt_obj
            )
            ngx.say(verified_obj["verified"])
            ngx.say(verified_obj["reason"])
        ';
    }
--- request
GET /t
--- response_body
true
everything is awesome~ :p
--- no_error_log
[error]


=== TEST 13: JWT simple with default leeway and invalid nbf
--- http_config eval: $::HttpConfig
--- config
    location /t {
        content_by_lua '
            local jwt = require "resty.jwt"
            local jwt_str = "eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9" ..
                ".eyJmb28iOiJiYXIiLCJuYmYiOjk5OTk5OTk5OTl9" ..
                ".Wfu3owxbzlrb0GXvV0D22Si8WEDP0WeRGwZNPAoYHMI"

            local jwt_obj = jwt:load_jwt(jwt_str)
            local verified_obj = jwt:verify_jwt_obj(
                "lua-resty-jwt", jwt_obj
            )
            ngx.say(verified_obj["verified"])
            ngx.say(verified_obj["reason"])
        ';
    }
--- request
GET /t
--- response_body
false
jwt token not valid until: Sat, 20 Nov 2286 17:46:39 GMT
--- no_error_log
[error]


=== TEST 14: JWT simple with super large leeway and invalid nbf
--- http_config eval: $::HttpConfig
--- config
    location /t {
        content_by_lua '
            local jwt = require "resty.jwt"
            local jwt_str = "eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9" ..
                ".eyJmb28iOiJiYXIiLCJuYmYiOjk5OTk5OTk5OTl9" ..
                ".Wfu3owxbzlrb0GXvV0D22Si8WEDP0WeRGwZNPAoYHMI"

            local jwt_obj = jwt:load_jwt(jwt_str)
            local verified_obj = jwt:verify_jwt_obj(
                "lua-resty-jwt", jwt_obj, 9999999999
            )
            ngx.say(verified_obj["verified"])
            ngx.say(verified_obj["reason"])
        ';
    }
--- request
GET /t
--- response_body
true
everything is awesome~ :p
--- no_error_log
[error]
