use Test::Nginx::Socket::Lua;

repeat_each(2);

plan tests => repeat_each() * (3 * blocks());

our $HttpConfig = <<'_EOC_';
    lua_package_path 'lib/?.lua;;';
_EOC_

no_long_string();

run_tests();

__DATA__


=== TEST 1: JWT sign HS256 (with function secret)
--- http_config eval: $::HttpConfig
--- config
    location /t {
        content_by_lua '
            local jwt = require "resty.jwt"
            local jwt_token = jwt:sign(
                function(kid) return kid == "lua-resty-kid" and "lua-resty-jwt" or nil end,
                {
                    header={typ="JWT",alg="HS256",kid="lua-resty-kid"},
                    raw_header=jwt:jwt_encode("{\\"typ\\":\\"JWT\\",\\"alg\\":\\"HS256\\",\\"kid\\":\\"lua-resty-kid\\"}"),
                    raw_payload=jwt:jwt_encode("{\\"foo\\":\\"bar\\"}")
                }
            )
            ngx.say(jwt_token)
        ';
    }
--- request
GET /t
--- response_body
eyJ0eXAiOiJKV1QiLCJhbGciOiJIUzI1NiIsImtpZCI6Imx1YS1yZXN0eS1raWQifQ.eyJmb28iOiJiYXIifQ.oHF49PvVWPaLt2rx4K7vPlPq_hBES7YEmgOC_ObCd7w
--- no_error_log
[error]


=== TEST 2: JWT sign HS512 (with function secret)
--- http_config eval: $::HttpConfig
--- config
    location /t {
        content_by_lua '
            local jwt = require "resty.jwt"
            local jwt_token = jwt:sign(
                function(kid) return kid == "lua-resty-kid" and "lua-resty-jwt" or nil end,
                {
                    header={typ="JWT",alg="HS512",kid="lua-resty-kid"},
                    raw_header=jwt:jwt_encode("{\\"typ\\":\\"JWT\\",\\"alg\\":\\"HS512\\",\\"kid\\":\\"lua-resty-kid\\"}"),
                    raw_payload=jwt:jwt_encode("{\\"foo\\":\\"bar\\"}")
                }
            )
            ngx.say(jwt_token)
        ';
    }
--- request
GET /t
--- response_body
eyJ0eXAiOiJKV1QiLCJhbGciOiJIUzUxMiIsImtpZCI6Imx1YS1yZXN0eS1raWQifQ.eyJmb28iOiJiYXIifQ.QrA-NGD-OyPH8xM4_NIAMHnCySCQT0kWKXfWS_a41Gmd_1-J2iNyXc05hvDVe-2OrwyTEQ2U_Lg7w18JhRSxdA
--- no_error_log
[error]


=== TEST 3: Function secret missing KID
--- http_config eval: $::HttpConfig
--- config
    location /t {
        content_by_lua '
            local jwt = require "resty.jwt"
            local success, err = pcall(function() jwt:sign(
                function(kid) return kid == "lua-resty-kid" and "lua-resty-jwt" or nil end,
                {
                    header={typ="JWT",alg="HS256"},
                    raw_header=jwt:jwt_encode("{\\"typ\\":\\"JWT\\",\\"alg\\":\\"HS256\\"}"),
                    raw_payload=jwt:jwt_encode("{\\"foo\\":\\"bar\\"}")
                }
            ) end)
            ngx.say(err["reason"])
        ';
    }
--- request
GET /t
--- response_body
secret function specified without kid in header
--- no_error_log
[error]


=== TEST 4: Function secret wrong KID
--- http_config eval: $::HttpConfig
--- config
    location /t {
        content_by_lua '
            local jwt = require "resty.jwt"
            local success, err = pcall(function() jwt:sign(
                function(kid) return kid == "lua-resty-kid" and "lua-resty-jwt" or nil end,
                {
                    header={typ="JWT",alg="HS256",kid="non-existant-kid"},
                    raw_header=jwt:jwt_encode("{\\"typ\\":\\"JWT\\",\\"alg\\":\\"HS256\\",\\"kid\\":\\"non-existant-kid\\"}"),
                    raw_payload=jwt:jwt_encode("{\\"foo\\":\\"bar\\"}")
                }
            ) end)
            ngx.say(err["reason"])
        ';
    }
--- request
GET /t
--- response_body
function returned nil for kid: non-existant-kid
--- no_error_log
[error]


=== TEST 5: Function secret verify invalid
--- http_config eval: $::HttpConfig
--- config
    location /t {
        content_by_lua '
            local jwt = require "resty.jwt"
            local jwt_obj = jwt:verify(
                function(kid) return kid == "lua-resty-kid" and "lua-resty-jwt" or nil end, 
                "invalid-random-str"
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

=== TEST 6: Function secret verify wrong signature
--- http_config eval: $::HttpConfig
--- config
    location /t {
        content_by_lua '
            local jwt = require "resty.jwt"
            local jwt_obj = jwt:verify(
                function(kid) return kid == "lua-resty-kid" and "lua-resty-jwt" or nil end,
                "eyJ0eXAiOiJKV1QiLCJhbGciOiJIUzI1NiIsImtpZCI6Imx1YS1yZXN0eS1raWQifQ" ..
                ".eyJmb28iOiJiYXIifQ" ..
                ".signature"
            )
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

=== TEST 7: Function secret simple verify with no validation option
--- http_config eval: $::HttpConfig
--- config
    location /t {
        content_by_lua '
            local jwt = require "resty.jwt"
            local jwt_obj = jwt:verify(
                function(kid) return kid == "lua-resty-kid" and "lua-resty-jwt" or nil end,
                "eyJ0eXAiOiJKV1QiLCJhbGciOiJIUzI1NiIsImtpZCI6Imx1YS1yZXN0eS1raWQifQ" ..
                ".eyJmb28iOiJiYXIifQ" ..
                ".oHF49PvVWPaLt2rx4K7vPlPq_hBES7YEmgOC_ObCd7w",
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


=== TEST 8: Function secret verify missing KID
--- http_config eval: $::HttpConfig
--- config
    location /t {
        content_by_lua '
            local jwt = require "resty.jwt"
            local jwt_obj = jwt:verify(
                function(kid) return kid == "lua-resty-kid" and "lua-resty-jwt" or nil end,
                "eyJ0eXAiOiJKV1QiLCJhbGciOiJIUzI1NiJ9" ..
                ".eyJmb28iOiJiYXIifQ" ..
                ".VAoRL1IU0nOguxURF2ZcKR0SGKE1gCbqwyh8u2MLAyY",
                { }
            )
            ngx.say(jwt_obj["verified"])
            ngx.say(jwt_obj["reason"])
        ';
    }
--- request
GET /t
--- response_body
false
secret function specified without kid in header
--- no_error_log
[error]


=== TEST 9: Function secret simple verify wrong KID
--- http_config eval: $::HttpConfig
--- config
    location /t {
        content_by_lua '
            local jwt = require "resty.jwt"
            local jwt_obj = jwt:verify(
                function(kid) return kid == "lua-resty-kid" and "lua-resty-jwt" or nil end,
                "eyJ0eXAiOiJKV1QiLCJhbGciOiJIUzI1NiIsImtpZCI6Im5vbi1leGlzdGFudC1raWQifQ" ..
                ".eyJmb28iOiJiYXIifQ" ..
                ".8hZ5eQNcLDF0jxsE_3AmK4AdNM4eKG465_krN7pF-O8",
                { }
            )
            ngx.say(jwt_obj["verified"])
            ngx.say(jwt_obj["reason"])
        ';
    }
--- request
GET /t
--- response_body
false
function returned nil for kid: non-existant-kid
--- no_error_log
[error]


=== TEST 10: Function secret sign and verify
--- http_config eval: $::HttpConfig
--- config
    location /t {
        content_by_lua '
            local jwt = require "resty.jwt"
            
            local function get_kid(kid) return kid == "lua-resty-kid" and "lua-resty-jwt" or nil end

            local jwt_token = jwt:sign(
                get_kid,
                {
                    header={typ="JWT",alg="HS256",kid="lua-resty-kid"},
                    payload={foo="bar", exp=9999999999}
                }
            )

            local jwt_obj = jwt:verify(get_kid, jwt_token)
            ngx.say(jwt_obj["verified"])
            ngx.say(jwt_obj["reason"])
            ngx.say(jwt_obj["payload"]["foo"])
        ';
    }
--- request
GET /t
--- response_body
true
everything is awesome~ :p
bar
--- no_error_log
[error]

