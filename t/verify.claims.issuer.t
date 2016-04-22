use Test::Nginx::Socket::Lua;

repeat_each(2);

plan tests => repeat_each() * (3 * blocks());

our $HttpConfig = <<'_EOC_';
    lua_package_path 'lib/?.lua;;';
_EOC_

no_long_string();

run_tests();

__DATA__

=== TEST 1: JWT without iss claim without valid_issuers requirement
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


=== TEST 2: JWT without iss claim with malformed valid_issuers requirement
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
                { valid_issuers = 17 }
            )
            ngx.say(jwt_obj["verified"])
            ngx.say(jwt_obj["reason"])
        ';
    }
--- request
GET /t
--- error_code: 500
--- error_log
Cannot create validator for non-table check_values
[error]


=== TEST 3: JWT without iss claim with malformed valid_issuers requirement - Take 2
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
                { valid_issuers = { } }
            )
            ngx.say(jwt_obj["verified"])
            ngx.say(jwt_obj["reason"])
        ';
    }
--- request
GET /t
--- error_code: 500
--- error_log
Cannot create validator for empty table check_values
[error]


=== TEST 4: JWT without iss claim with malformed valid_issuers requirement - Take 3
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
                { valid_issuers = { "a", "b", true } }
            )
            ngx.say(jwt_obj["verified"])
            ngx.say(jwt_obj["reason"])
        ';
    }
--- request
GET /t
--- error_code: 500
--- error_log
Cannot create validator for non-string table check_values
[error]


=== TEST 5: JWT without iss claim while valid_issuers specified
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
                { valid_issuers = { "a", "b" } }
            )
            ngx.say(jwt_obj["verified"])
            ngx.say(jwt_obj["reason"])
        ';
    }
--- request
GET /t
--- response_body
false
'iss' claim is required.
--- no_error_log
[error]


=== TEST 6: JWT with malformed iss claim ("iss": 17) while valid_issuers specified
--- http_config eval: $::HttpConfig
--- config
    location /t {
        content_by_lua '
            local jwt = require "resty.jwt"
            local jwt_obj = jwt:verify(
                "lua-resty-jwt",
                "eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9" ..
                ".eyJmb28iOiJiYXIiLCJpc3MiOjE3fQ" ..
                ".IYbJt_WGO_2pIM0Mh19HbP5W0y1i9CGw4PNQqjHeIx0",
                { valid_issuers = { "a", "b" } }
            )
            ngx.say(jwt_obj["verified"])
            ngx.say(jwt_obj["reason"])
        ';
    }
--- request
GET /t
--- response_body
false
'iss' is malformed.  Expected to be a string.
--- no_error_log
[error]


=== TEST 7: JWT with valid but unknown iss claim ("iss": "hello") while valid_issuers specified
--- http_config eval: $::HttpConfig
--- config
    location /t {
        content_by_lua '
            local jwt = require "resty.jwt"
            local jwt_obj = jwt:verify(
                "lua-resty-jwt",
                "eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9" ..
                ".eyJmb28iOiJiYXIiLCJpc3MiOiJoZWxsbyJ9" ..
                ".d8P9QJIJG2LSgQrLOfADw7WqGugRSD3xl-nmZ0FpmC8",
                { valid_issuers = { "a", "b" } }
            )
            ngx.say(jwt_obj["verified"])
            ngx.say(jwt_obj["reason"])
        ';
    }
--- request
GET /t
--- response_body
false
Claim 'iss' ('hello') returned failure
--- no_error_log
[error]


=== TEST 8: JWT with valid iss claim ("iss": "hello") while valid_issuers specified
--- http_config eval: $::HttpConfig
--- config
    location /t {
        content_by_lua '
            local jwt = require "resty.jwt"
            local jwt_obj = jwt:verify(
                "lua-resty-jwt",
                "eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9" ..
                ".eyJmb28iOiJiYXIiLCJpc3MiOiJoZWxsbyJ9" ..
                ".d8P9QJIJG2LSgQrLOfADw7WqGugRSD3xl-nmZ0FpmC8",
                { valid_issuers = { "hello" } }
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


=== TEST 9: JWT with valid iss claim ("iss": "hello") while valid_issuers specified
--- http_config eval: $::HttpConfig
--- config
    location /t {
        content_by_lua '
            local jwt = require "resty.jwt"
            local jwt_obj = jwt:verify(
                "lua-resty-jwt",
                "eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9" ..
                ".eyJmb28iOiJiYXIiLCJpc3MiOiJoZWxsbyJ9" ..
                ".d8P9QJIJG2LSgQrLOfADw7WqGugRSD3xl-nmZ0FpmC8",
                { valid_issuers = { "hello", "a" } }
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


=== TEST 10: JWT with valid iss claim ("iss": "hello") while valid_issuers specified
--- http_config eval: $::HttpConfig
--- config
    location /t {
        content_by_lua '
            local jwt = require "resty.jwt"
            local jwt_obj = jwt:verify(
                "lua-resty-jwt",
                "eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9" ..
                ".eyJmb28iOiJiYXIiLCJpc3MiOiJoZWxsbyJ9" ..
                ".d8P9QJIJG2LSgQrLOfADw7WqGugRSD3xl-nmZ0FpmC8",
                { valid_issuers = { "a", "hello" } }
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
