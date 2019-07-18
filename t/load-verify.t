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

            local jwt_token = "eyJ4NXUiOiJodHRwczpcL1wvdGVzdFwvdXJsIiwiYWxnIjoiUlMyNTYiLCJ0eXAiOiJKV1QifQ."
                             .."eyJmb28iOiJiYXIiLCJleHAiOjk5OTk5OTk5OTl9."
                             .."WOPIUGsi6bITvoqdpIlvQa86QLUKKuhs-LDn-7Pn4Q7RB3JJqICZdGLk_jW8rUhA7uUxepPepHoG1xSX19qAt-96Ult91gIuLNXjf58pJXG-iXcmYUKHgZ3jEk5udN90sKeuTvWcn7aNAbMFZMz686J_GRGC4FubKrDgzXfFwlXpN7klSCDxgh73O4GmG8nJPRGPp3Aud5hAxoMRwA3gJ86IbL9fEYk_v9l0Rc0zA7A2dL7vRa17Gm9EDLXQsUU1eiIpZuahRACPnCu9v9UX4z7jSWv5VKmJ2kjACOPwIZ3fpBxnKZ3Z-WVKLVgH-hhCRNFYRsxY0xODNjw-4U0mWw"
            
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

             local jwt_token = "eyJ4NWMiOlsiTUlJRVB6Q0NBeWVnQXdJQkFnSVVmNlREQ0xWK25tT1ZOTnBUc2NicjBrVEQwdnd3RFFZSktvWklodmNOQVFFTEJRQXdkekVMTUFrR0ExVUVCaE1DVlZNeEVUQVBCZ05WQkFnVENFNWxkeUJaYjNKck1SRXdEd1lEVlFRSEV3aE9aWGNnV1c5eWF6RU1NQW9HQTFVRUNoTURTbGRVTVJJd0VBWURWUVFMRXdsWFQxSk1SRmRKUkVVeElEQWVCZ05WQkFNVEYyOXdaVzV5WlhOMGVTMXFkM1F0ZEdWemRDMWpaWEowTUI0WERURTVNRFF3TlRJek1EZ3dNRm9YRFRJ"
             .. "d01EUXdOREl6TURnd01Gb3dlakVMTUFrR0ExVUVCaE1DVlZNeEV6QVJCZ05WQkFnVENsZGhjMmhwYm1kMGIyNHhFREFPQmdOVkJBY1RCMU5sWVhSMGJHVXhEREFLQmdOVkJBb1RBMHBYVkRFV01CUUdBMVVFQ3hNTlRtOTBJRmR2Y214a2QybGtaVEVlTUJ3R0ExVUVBeE1WZEdWemRHbHVaeTVxZDNRdWQyOXliR1IzYVdSbE1JSUJJakFOQmdrcWhraUc5dzBCQVFFRkFBT0NBUThBTUlJQkNnS0NBUUVBcU5CNzRJRFpPRkJ3SEJCK3o4dDR6NDVPMVBOQVpqXC9DSklLT1hKMDVuaVFDb"
             .. "jBpdUxrNUpHNmY0a2RyRFRjNVJiTHJ0bHRhZ3ZIbnNQR0ZXVjQzZ1RwNVF2WjJYT2FrUFU0MDE4RHQrZndDTm5UOE9zZllhaUdqdEJ2VWhTOE9KekxteXRNYmQ1eGl0Uzd2anVEQlQwb1IzK2o2SlpRVmZ6ekFhS2Q1T0RJN2ltWUJ5ejJRMytPWFBPQkUxdHNhdDhPVU9TeXo3anBLcVwvUkpYK2RnOHFGSnBaUnBhYnJMeDhFQXBDMTFlck11M2Zyc3pGOVJWdXBSczAzeFVaWGxyV0kwT21Md3g3UkJyelVXdDdPOXdzczVucGJFRFUwY1hodHVRVHNmc3dJVWJ6a1NxRU84aTJIRGUxVkFr"
             .. "Tm5hdGxNdzk4Q2VrZ3k3SVowTzJVcFJlK3dJREFRQUJvNEdcL01JRzhNQTRHQTFVZER3RUJcL3dRRUF3SUZvREFkQmdOVkhTVUVGakFVQmdnckJnRUZCUWNEQVFZSUt3WUJCUVVIQXdJd0RBWURWUjBUQVFIXC9CQUl3QURBZEJnTlZIUTRFRmdRVVNMSllRRUlZQm54R2JoQm9oZGFlMzluZUs3a3dId1lEVlIwakJCZ3dGb0FVcXhTMytBZEVITlBIVHd2b2dUV1NTXC9GaVlBMHdQUVlEVlIwUkJEWXdOSUlWZEdWemRHbHVaeTVxZDNRdWQyOXliR1IzYVdSbGdodHNiMk5oYkM1MFpYTjBh"
             .. "VzVuTG1wM2RDNTNiM0pzWkhkcFpHVXdEUVlKS29aSWh2Y05BUUVMQlFBRGdnRUJBSVMydzlvNFA2bkQ3VCt6ZlM1QVhlQVJXWENDZ1pReFhNbzhHT0JlVjMxS3U0TzcydmRNRmtSRnE3SFpBRFBYak9nWFBySFMrbndpVkxKMnZ5UGRwNU1ZME0wSGoxYmJtSEgxbFZWUXVwb2lIdCs0a3dJZUVjUENOTW54WUpoY1wvbkQrVnVkUFBaenpGQ1l5dFlmZ0R4Sk9STG9lalJzWGRFWStLOUxsNkJ2bDdUSFB2SjZ5UDNHaFd1UmNCXC80RVVSYXpSZWwxNUhTWFIxNXJPdWVrd20xNkZYcTJWMERsb" 
             .. "kNlK0lFek5ZR2hPTG9FaVowNjBGY2NIa2N1QWp6Zk8yQkp4SGZzRVNSOG1uN1dNRmx4MUxOeVlDRk9NMzZWdlwvUDFnVFwvbzZXN3d4M1FCQzBMN0hvSVRTQ3FBaUVyQmI5bXN3dFVtWTVVb29cL21MRk1kWUpPZms9Il0sImFsZyI6IlJTMjU2IiwidHlwIjoiSldUIn0.eyJmb28iOiJiYXIiLCJleHAiOjk5OTk5OTk5OTl9.I8ctJVjeQdmdEEgGIpulPgZc9bWPd9qxBCHBmz5p_QsgEoKSopNVI2WFralzrQ-J-dGIusQ35hpOl90fXXSBvdxCd_FSvtXfmSi1FpvifDOBYdp1nwoisAVqV8"
             .. "U5G8TfX5GZqpVeda6KtsqhoPgzib1UVBu9JLmSBl3k4xtmmW6EL1ZUUz_Br0peXjj5LI9mUPgTyZFRb-gaDQ6qtso58gGoA2t0mB0fE6VXNP1MbELdkhqcDHP-ePNLsW-3EeQ5GLu38stXiEQYgCZs8X42EmfDt4FqvrLMDCrIpD8HK7Oqjl0lW4XX8OAXsCw8CBeIfj1TrovVg2iYRu7LZbiF7A"
            
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