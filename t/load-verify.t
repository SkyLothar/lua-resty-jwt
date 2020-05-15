use Test::Nginx::Socket::Lua;



repeat_each(2);

plan tests => repeat_each() * (3 * blocks());

our $HttpConfig = <<'_EOC_';
    lua_package_path 'lib/?.lua;;';
_EOC_

log_level('debug');


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
            local jwt_obj = jwt:load_jwt("invalid-random-str")
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


=== TEST 9: JWT simple verify with no validation option
--- http_config eval: $::HttpConfig
--- config
    location /t {
        content_by_lua '
            local jwt = require "resty.jwt"
            local jwt_str = "eyJ0eXAiOiJKV1QiLCJhbGciOiJIUzI1NiJ9" ..
                ".eyJmb28iOiJiYXIifQ" ..
                ".VAoRL1IU0nOguxURF2ZcKR0SGKE1gCbqwyh8u2MLAyY"

            local jwt_obj = jwt:load_jwt(jwt_str)
            local verified_obj = jwt:verify_jwt_obj(
                "lua-resty-jwt", jwt_obj, { }
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


=== TEST 10: JWT simple with default lifetime grace period and valid exp
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


=== TEST 11: JWT simple with a zero lifetime grace period and invalid exp
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
                "lua-resty-jwt", jwt_obj,
                { lifetime_grace_period = 0 }
            )
            ngx.say(verified_obj["verified"])
            ngx.say(verified_obj["reason"])
        ';
    }
--- request
GET /t
--- response_body
false
'exp' claim expired at Thu, 01 Jan 1970 00:00:00 GMT
--- no_error_log
[error]


=== TEST 12: JWT simple with default lifetime grace period and valid nbf
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


=== TEST 13: JWT simple with a zero lifetime grace period and invalid nbf
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
                "lua-resty-jwt", jwt_obj,
                { lifetime_grace_period = 0 }
            )
            ngx.say(verified_obj["verified"])
            ngx.say(verified_obj["reason"])
        ';
    }
--- request
GET /t
--- response_body
false
'nbf' claim not valid until Sat, 20 Nov 2286 17:46:39 GMT
--- no_error_log
[error]


=== TEST 14: JWT simple with super large lifetime grace period and invalid nbf
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
                "lua-resty-jwt", jwt_obj,
                { lifetime_grace_period = 9999999999 }
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


=== TEST 15: Verify valid RS256 signed jwt using a certificate
--- http_config eval: $::HttpConfig
--- config
    location /t {
        content_by_lua '
            local jwt = require "resty.jwt"

            local function get_public_key(url, iss, kid)
                if iss ~= nil then
                    error("Unexpected iss has been passed. Duh :(")
                end

                if kid ~= nil then
                    error("Unexpected kid has been passed. Duh :(")
                end

                local f = io.open("/lua-resty-jwt/testcerts/cert.pem", "rb");
                local cert = f:read("*all");
                f:close()
                return cert
            end

            jwt:set_trusted_certs_file("/lua-resty-jwt/testcerts/root.pem")
            jwt:set_alg_whitelist({ RS256 = 1 })
            jwt:set_x5u_content_retriever(get_public_key)

            local jwt_token = "eyJ4NXUiOiJodHRwczovL3Rlc3QvdXJsIiwiYWxnIjoiUlMyNTYiLCJ0eXAiOiJKV1QifQ."
                             .."eyJmb28iOiJiYXIiLCJleHAiOjk5OTk5OTk5OTl9."
                             .."i1zf3cgIHPb7sod4zByDTexOjMixOYrcdO85BXP7MRwevFIfXy-lMpLImY1XHrmBH9v4zeoEClbV0GEXcuRovKW_pef600F6ooKYaaINsjyDsrLZ9rBU9TntzeIcnDUs7N2Ph1RvFfipvIrzQcij8XvignxvfgKzsokBlY6_yOJ7PRVnY3puLGPMiCdpbODhGgYlOi-En2BUtoMOZHkROOSuIUBm6rHyfDE_R5r5MDZQSTSIC1JgrTHbF3yZZKy7clYKO6K7naPYxO9JtgF-RfRYxoFWna1EfGMZM6TWIoFXq6kMIPspkR7QeL6GqMkrMC8KJL3SSzPVJKi1TiYYAg"
            
            local jwt_obj = jwt:verify(nil, jwt_token)
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


=== TEST 16: Verify RS256 signed jwt with bogus signature using a certificate
--- http_config eval: $::HttpConfig
--- config
    location /t {
        content_by_lua '
            local jwt = require "resty.jwt"

            local function get_public_key(url)
                local f = io.open("/lua-resty-jwt/testcerts/cert.pem", "rb");
                local cert = f:read("*all");
                f:close()
                return cert
            end

            jwt:set_trusted_certs_file("/lua-resty-jwt/testcerts/root.pem")
            jwt:set_alg_whitelist({ RS256 = 1 })
            jwt:set_x5u_content_retriever(get_public_key)

            local jwt_token = "eyJ4NXUiOiJodHRwczpcL1wvZHVtbXkuY29tXC9jZXJ0cyIsImFsZyI6IlJTMjU2IiwidHlwIjoiSldUIn0"
                .. ".eyJmb28iOiJiYXIifQ"
                .. ".h4fOshUFSiVoSjV0zoJNXSaAFGIzFScI_VRHQYLefZ5uuGWWEd69q6GBx1XVN4er67WuKDTmgbsW5b_ya2eU89U6LC"
                .. "3r2Rdu9FtYmm4aoQ5WesvC7UI63gJrhLFcbQGv1eDDPANZh-k_aOhGQLBjxdx_J2n95eKlYfqH3aZHTPtSnF7lEV4ZR"
                .. "RsHbX3jgS2Kcx-DvNQ77A81yQsTWtECKE-fiUZ5nOMn172rOPWM-DYTimsyOzuRErqE0xoB1u8ClVxmb1Mrg4LWSPoz"
                .. "nv5vhd8JkOXMg_5zYii6p5eIegH58IpxNYuDQ-rSo320nOvZOU7d8UOeYixYeEcEc1fMlQ"

            -- Alter the jwt
            jwt_token = jwt_token .. "123"

            local jwt_obj = jwt:verify(nil, jwt_token)
            ngx.say(jwt_obj["verified"])
            ngx.say(jwt_obj["reason"])
        ';
    }
--- request
GET /t
--- response_body
false
Wrongly encoded signature
--- no_error_log
[error]

=== TEST 17: Verify valid RS256 signed jwt using a rsa public key
--- http_config eval: $::HttpConfig
--- config
    location /t {
        content_by_lua '
            local jwt = require "resty.jwt"

            local public_key = [[
-----BEGIN PUBLIC KEY-----
MIIBIjANBgkqhkiG9w0BAQEFAAOCAQ8AMIIBCgKCAQEAtM/RXjMp7AvPrnb1/i3I
mcZ4ebkY+AvUurTXngJSBgn0GJNM1HDRQqApE5JzUHf2BImsAyzW8QarrWzA2dWm
q8rNWtJWJlHlSwiKr8wZDyU0kLAqKUEPVfFrk9uds8zc7OvHVRjXQiXeSTUUMpKc
HsZp4zz79Jr4+4vF4Bt+/U8luj/llleaJHlJFyfXiUtqLg2HUdkjPQaFVvhYMQ7u
gZl4aM1uRH7J2oxaexy/JEApSNEDnO/cripd+Pdqx+m8xbBZ9pX8FsvYnO3D/BKQ
k3hadbRWg/r8QYT2ZHk0NRyseoUOc3hyAeckiSWe2n9lvK+HkxmM23UVtuAwxwj4
WQIDAQAB
-----END PUBLIC KEY-----
                ]]

            jwt:set_alg_whitelist({ RS256 = 1 })
            local jwt_token = "eyJ0eXAiOiAiSldUIiwgImFsZyI6ICJSUzI1NiJ9."
              .. "eyJpc3MiOiAidGVzdCIsICJpYXQiOiAxNDYxOTE0MDE3fQ."
              .. "dng6Vc-p_ISwiWc61ifWahbFYKBNWfaIr-W3bTPpgL-awG8"
              .. "UlaCONkQk2PHJw_xndbpenQYl_-hipCKynokeFBTXVcSL6H"
              .. "7XL4D9laQVDVFnI63hcXOMQxgICsQPVdcfVSBl2jHyV8kuw"
              .. "XpUHbXQTxMawlE9SkI1-7UukxL9OyFIkT1D1uW7P96irVDs"
              .. "GkEdTLVUPJerH-jlW4rRbW9twSHsgzHgkaqnQ41giW_e2Zz"
              .. "r0U2euFH-AxlyvWBJd8Y7rQ_aD40USKsJilZ5qSykGZ7KHd"
              .. "PzuwTXioCwB8bGVE2YoL-DKYj7-tOwoNsMK7UJzyjqzHqwuqvZWtbhmeRlww"

            local jwt_obj = jwt:verify(public_key, jwt_token)
            ngx.say(jwt_obj["verified"])
            ngx.say(jwt_obj["reason"])
            ngx.say(jwt_obj["payload"]["iss"])
        ';
    }
--- request
GET /t
--- response_body
true
everything is awesome~ :p
test
--- no_error_log
[error]

=== TEST 18: Verify RS256 signed jwt with bogus signature using a rsa public key
--- http_config eval: $::HttpConfig
--- config
    location /t {
        content_by_lua '
            local jwt = require "resty.jwt"

            -- pubkey.pem
            local public_key = [[
-----BEGIN PUBLIC KEY-----
MIIBIjANBgkqhkiG9w0BAQEFAAOCAQ8AMIIBCgKCAQEAtM/RXjMp7AvPrnb1/i3I
mcZ4ebkY+AvUurTXngJSBgn0GJNM1HDRQqApE5JzUHf2BImsAyzW8QarrWzA2dWm
q8rNWtJWJlHlSwiKr8wZDyU0kLAqKUEPVfFrk9uds8zc7OvHVRjXQiXeSTUUMpKc
HsZp4zz79Jr4+4vF4Bt+/U8luj/llleaJHlJFyfXiUtqLg2HUdkjPQaFVvhYMQ7u
gZl4aM1uRH7J2oxaexy/JEApSNEDnO/cripd+Pdqx+m8xbBZ9pX8FsvYnO3D/BKQ
k3hadbRWg/r8QYT2ZHk0NRyseoUOc3hyAeckiSWe2n9lvK+HkxmM23UVtuAwxwj4
WQIDAQAB
-----END PUBLIC KEY-----
                ]]

            jwt:set_alg_whitelist({ RS256 = 1 })
            local jwt_token = "eyJ0eXAiOiAiSldUIiwgImFsZyI6ICJSUzI1NiJ9."
              .. "eyJpc3MiOiAidGVzdCIsICJpYXQiOiAxNDYxOTE0MDE3fQ."
              .. "dng6Vc-p_ISwiWc61ifWahbFYKBNWfaIr-W3bTPpgL-awG8"
              .. "UlaCONkQk2PHJw_xndbpenQYl_-hipCKynokeFBTXVcSL6H"
              .. "7XL4D9laQVDVFnI63hcXOMQxgICsQPVdcfVSBl2jHyV8kuw"
              .. "XpUHbXQTxMawlE9SkI1-7UukxL9OyFIkT1D1uW7P96irVDs"
              .. "GkEdTLVUPJerH-jlW4rRbW9twSHsgzHgkaqnQ41giW_e2Zz"
              .. "r0U2euFH-AxlyvWBJd8Y7rQ_aD40USKsJilZ5qSykGZ7KHd"
              .. "PzuwTXioCwB8bGVE2YoL-DKYj7-tOwoNsMK7UJzyjqzHqwuqvZWtbhmeRlww"

            -- Alter the jwt
            jwt_token = jwt_token .. "123"

            local jwt_obj = jwt:verify(public_key, jwt_token)
            ngx.say(jwt_obj["verified"])
            ngx.say(jwt_obj["reason"])
        ';
    }
--- request
GET /t
--- response_body
false
Wrongly encoded signature
--- no_error_log
[error]


=== TEST 19: make sure invalid RS256 is INVALID
--- http_config eval: $::HttpConfig
--- config
    location /t {
        content_by_lua '
            local jwt = require "resty.jwt"

            local function get_public_key(url, iss, kid)
                if iss ~= nil then
                    error("Unexpected iss has been passed. Duh :(")
                end

                if kid ~= nil then
                    error("Unexpected kid has been passed. Duh :(")
                end

                local f = io.open("/lua-resty-jwt/testcerts/cert.pem", "rb");
                local cert = f:read("*all");
                f:close()
                return cert
            end

            jwt:set_trusted_certs_file("/lua-resty-jwt/testcerts/root.pem")
            jwt:set_alg_whitelist({ RS256 = 1 })
            jwt:set_x5u_content_retriever(get_public_key)

            local jwt_token = "eyJ4NXUiOiJodHRwczpcL1wvZHVtbXkuY29tXC9jZXJ0cyIsImFsZyI6IlJTMjU2IiwidHlwIjoiSldUIn0"
                .. ".eyJmb28iOiJiYXIifQ"
                .. ".h4fOshUFSiVoSjV0zoJNXSaAFGIzFScI_VRHQYLefZ5uuGWWEd69q6GBx1XVN4er67WuKDTmgbsW5b_ya2eU89U6LC"
                .. "3r2Rdu9FtYmm4aoQ5WesvC7UI63gJrhLFcbQGv1eDDPANZh-k_aOhGQLBjxdx_J2n95eKlYfqH3aZHTPtSnF7lEV4ZR"
                .. "RsHbX3jgS2Kcx-DvNQ77A81yQsTWtECKE-fiUZ5nOMn172rOPWM-DYTimsyOzuRErqE0xoB1u8ClVxmb1Mrg4LWSPoz"
                .. "nv5vhd8JkOXMg_5zYii6p5eIegH58IpxNYuDQ-rSo320nOvZOU7d8UOeYixYeEcEc1fMlQx"

            local jwt_obj = jwt:verify(nil, jwt_token)
            ngx.say(jwt_obj["verified"])
            ngx.say(jwt_obj["reason"])
        ';
    }
--- request
GET /t
--- response_body
false
Verification failed
--- no_error_log
[error]


=== TEST 20: invalid public key is not constructed
--- http_config eval: $::HttpConfig
--- config
    location /t {
        content_by_lua '
            local jwt = require "resty.jwt"

            local public_key = [[
-----BEGIN PUBLIC KEY-----
R0FSQkFHRQo=
-----END PUBLIC KEY-----
]]
            jwt:set_alg_whitelist({ RS256 = 1 })
            local jwt_token = "eyJ0eXAiOiAiSldUIiwgImFsZyI6ICJSUzI1NiJ9."
              .. "eyJpc3MiOiAidGVzdCIsICJpYXQiOiAxNDYxOTE0MDE3fQ."
              .. "dng6Vc-p_ISwiWc61ifWahbFYKBNWfaIr-W3bTPpgL-awG8"
              .. "UlaCONkQk2PHJw_xndbpenQYl_-hipCKynokeFBTXVcSL6H"
              .. "7XL4D9laQVDVFnI63hcXOMQxgICsQPVdcfVSBl2jHyV8kuw"
              .. "XpUHbXQTxMawlE9SkI1-7UukxL9OyFIkT1D1uW7P96irVDs"
              .. "GkEdTLVUPJerH-jlW4rRbW9twSHsgzHgkaqnQ41giW_e2Zz"
              .. "r0U2euFH-AxlyvWBJd8Y7rQ_aD40USKsJilZ5qSykGZ7KHd"
              .. "PzuwTXioCwB8bGVE2YoL-DKYj7-tOwoNsMK7UJzyjqzHqwuqvZWtbhmeRlww"

            local jwt_obj = jwt:verify(public_key, jwt_token)
            ngx.say(jwt_obj["verified"])
            ngx.say(jwt_obj["reason"])
            ngx.say(jwt_obj["payload"]["iss"])
        ';
    }
--- request
GET /t
--- response_body
false
Decode secret is not a valid cert/public key
test
--- no_error_log
[error]

=== TEST 21: Verify valid RS256 signed jwt containing x5c
--- http_config eval: $::HttpConfig
--- config
    location /t {
        content_by_lua '
            local jwt = require "resty.jwt"

            local function get_public_key(url, iss, kid)
                if iss ~= nil then
                    error("Unexpected iss has been passed. Duh :(")
                end

                if kid ~= nil then
                    error("Unexpected kid has been passed. Duh :(")
                end

                local f = io.open("/lua-resty-jwt/testcerts/cert.pem", "rb");
                local cert = f:read("*all");
                print(cert)
                f:close()
                return cert
            end

            jwt:set_trusted_certs_file("/lua-resty-jwt/testcerts/root.pem")
            jwt:set_alg_whitelist({ RS256 = 1 })
            jwt:set_x5u_content_retriever(get_public_key)

             local jwt_token = "eyJ4NWMiOlsiTUlJRU5UQ0NBeDJnQXdJQkFnSVVha3NvTmxjaXBQQlEwWldyMEE2TGoyUzYyR0F3RFFZSktvWklodmNOQVFFTEJRQXdkekVMTUFrR0ExVUVCaE1DVlZNeEVUQVBCZ05WQkFnVENFNWxkeUJaYjNKck1SRXdEd1lEVlFRSEV3aE9aWGNnV1c5eWF6RU1NQW9HQTFVRUNoTURTbGRVTVJJd0VBWURWUVFMRXdsWFQxSk1SRmRKUkVVeElEQWVCZ05WQkFNVEYyOXdaVzV5WlhOMGVTMXFkM1F0ZEdWemRDMWpaWEowTUI0WERUSXdNRFV4TkRFd05UUXdNRm9YRFRN"
             .. "d01EVXhNakV3TlRRd01Gb3dlakVMTUFrR0ExVUVCaE1DVlZNeEV6QVJCZ05WQkFnVENsZGhjMmhwYm1kMGIyNHhFREFPQmdOVkJBY1RCMU5sWVhSMGJHVXhEREFLQmdOVkJBb1RBMHBYVkRFV01CUUdBMVVFQ3hNTlRtOTBJRmR2Y214a2QybGtaVEVlTUJ3R0ExVUVBeE1WZEdWemRHbHVaeTVxZDNRdWQyOXliR1IzYVdSbE1JSUJJakFOQmdrcWhraUc5dzBCQVFFRkFBT0NBUThBTUlJQkNnS0NBUUVBdGVOVERHNHVUeXRzT01LL0xoYm9TVmdoRVZlakRJU2tnemgwS1NOTjFsWjMzR"
             .. "21YTk5McVAvdGhwbU9kNnU2SGQxUDFyUVYzbGIyTHlxYjcwNHpsM2F0WUl3aG1JTDljREJBVkpkc1dIbXFtbXlCYm1nTXhzdGh1RkdPSjJrV3hSeUlzVEQ3dXoyWEJnQ09XWWJUVWcrUGNwbGt6aFdjYUtjalNZcXIxc2FwUXBRUURDTHBpdG9jeDZ2QUtmRXExZjVIRFVpc2VCWmx4RURBUmpxbnVzTTZKRU5mQkpTb0g5cnY5aS93MGo4YmhGMUVQMHl5ZXc4aFk2aXJzSVBITEhEYmoyQkMrTk1FWlF1QS9aTGl4aEgrckpQUk5IL1dpYkZ3Tk1FWU5Fb2tMeEY4b2RoVUNIQ2pJTFdFK3B6"
             .. "c25ub3FHUEE2NGlmNGJYTlVENjZoMHlRSURBUUFCbzRHMU1JR3lNQTRHQTFVZER3RUIvd1FFQXdJRm9EQVRCZ05WSFNVRUREQUtCZ2dyQmdFRkJRY0RBakFNQmdOVkhSTUJBZjhFQWpBQU1CMEdBMVVkRGdRV0JCUXRpUEs5NnVHZ01CNGFSZGxjSmI1dXlqV0kwREFmQmdOVkhTTUVHREFXZ0JTckZMZjRCMFFjMDhkUEMraUJOWkpMOFdKZ0RUQTlCZ05WSFJFRU5qQTBnaFYwWlhOMGFXNW5MbXAzZEM1M2IzSnNaSGRwWkdXQ0cyeHZZMkZzTG5SbGMzUnBibWN1YW5kMExuZHZjbXhrZDJs"
             .. "a1pUQU5CZ2txaGtpRzl3MEJBUXNGQUFPQ0FRRUFPUWZZV3VrUy9LMDBSLzdHSVZnMDFoakM1b1k4TnE0MHN0blRyZGlJcFBLd2NLRldoSnFBZ1JLbnE5YWVlSFNTRDYzWFMyazY3dmFYS1Ayc2ZYcjQweVl4SXpvbDlYOEw1cmRRT3ZVR2dySXZ0VlBqL3NGMFc5T1BJQkFNMWh3TEJtNmZldzQ4d25lWUl2aTFGdTBuZzdDQ2wxUkNhWFQ1S2UyR3ZWdUtwaUswVmMwLzRVaWQ1dDY3Z0NYRGM0M2lQTVk1bnR4eFZQdDdMdlZmUHRqaG03M0t0Qkcwd0gxWkhaSWFCQkVIdSs4WEhZN1hnNUFLb"
             .. "XF4OTgzRE1UUy9ja1ozdzA3OUxMNlhiMURuL2hnMm1QOVYxOC9XODkzbWhkb1FweHhOK2lyWHFTUVNFTml1TGVUNGZpZHZZY1FzZy82OXBZbEVjZXNvUnN2ZExESUl5T0E9PSUiXSwiYWxnIjoiUlMyNTYiLCJ0eXAiOiJKV1QifQ.eyJmb28iOiJiYXIiLCJleHAiOjk5OTk5OTk5OTl9.OJpx-3C4Yyt88J2gic38eupMZa4E1pggGBmatINzgPg_AtFQdF8X19miWtvZpDIis08SvTCN2u6f9vs1M7MAtlBoENU4S3gFwu3n8zdNExzR8idioSFYXGWmU_Ow87iF4ELdY7SdYmTPW2U5xVQ1yMG"
             .. "pK5qu9LqzEc-jT01SWfFFMkl9tDUftM525wtw6iAqSiZXOJmUGOCz4iHeef46x9huKiWQnptEjHesD3VQ5JeruRhzBFIbtkECT2y21IqtLq5KPSF1DHJJi0btMKMLMW7UmzVLDx_-3LdZqYNGhL13MSRCgHRTmpLn8EARGXlfmSNE0W4F9DBJBImBmE6I5w"
            
            local jwt_obj = jwt:verify(nil, jwt_token)
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

=== TEST 22: Verify valid ES256 signed jwt using a EC public key
--- http_config eval: $::HttpConfig
--- config
    location /t {
        content_by_lua '
            local jwt = require "resty.jwt"

            local public_key = [[
-----BEGIN PUBLIC KEY-----
MFkwEwYHKoZIzj0CAQYIKoZIzj0DAQcDQgAEm9ehYHp34sZPfZoxJlotxG/LF02e
ZPmM51hCYIL1jn50e30i8KqEL6y6wl06z6P4co0uew5CzD7JlOQlLB+Ryg==
-----END PUBLIC KEY-----
                ]]

            jwt:set_alg_whitelist({ ES256 = 1 })
            local jwt_token = "eyJ0eXAiOiJKV1QiLCJhbGciOiJFUzI1NiJ9.eyJpc3MiOiJ0ZXN0IiwiaWF0IjoxNDYxOTE0MDE3fQ.U38g80dOEKrGQG08KDRY_XWXvolBAhz6G16QZqgePFQljooqsZXw9sIyH6hXFpsAxQbupQBqgUAw6IwUqbAXzg"

            local jwt_obj = jwt:verify(public_key, jwt_token)
            ngx.say(jwt_obj["verified"])
            ngx.say(jwt_obj["reason"])
            ngx.say(jwt_obj["payload"]["iss"])
        ';
    }
--- request
GET /t
--- response_body
true
everything is awesome~ :p
test
--- no_error_log
[error]