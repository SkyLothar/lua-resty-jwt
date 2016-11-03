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
        set $cert '-----BEGIN CERTIFICATE-----\nMIIC2jCCAkMCAg38MA0GCSqGSIb3DQEBBQUAMIGbMQswCQYDVQQGEwJKUDEOMAwG\nA1UECBMFVG9reW8xEDAOBgNVBAcTB0NodW8ta3UxETAPBgNVBAoTCEZyYW5rNERE\nMRgwFgYDVQQLEw9XZWJDZXJ0IFN1cHBvcnQxGDAWBgNVBAMTD0ZyYW5rNEREIFdl\nYiBDQTEjMCEGCSqGSIb3DQEJARYUc3VwcG9ydEBmcmFuazRkZC5jb20wHhcNMTIw\nODIyMDUyNzQxWhcNMTcwODIxMDUyNzQxWjBKMQswCQYDVQQGEwJKUDEOMAwGA1UE\nCAwFVG9reW8xETAPBgNVBAoMCEZyYW5rNEREMRgwFgYDVQQDDA93d3cuZXhhbXBs\nZS5jb20wggEiMA0GCSqGSIb3DQEBAQUAA4IBDwAwggEKAoIBAQC0z9FeMynsC8+u\ndvX+LciZxnh5uRj4C9S6tNeeAlIGCfQYk0zUcNFCoCkTknNQd/YEiawDLNbxBqut\nbMDZ1aarys1a0lYmUeVLCIqvzBkPJTSQsCopQQ9V8WuT252zzNzs68dVGNdCJd5J\nNRQykpwexmnjPPv0mvj7i8XgG379TyW6P+WWV5okeUkXJ9eJS2ouDYdR2SM9BoVW\n+FgxDu6BmXhozW5EfsnajFp7HL8kQClI0QOc79yuKl3492rH6bzFsFn2lfwWy9ic\n7cP8EpCTeFp1tFaD+vxBhPZkeTQ1HKx6hQ5zeHIB5ySJJZ7af2W8r4eTGYzbdRW2\n4DDHCPhZAgMBAAEwDQYJKoZIhvcNAQEFBQADgYEAQMv+BFvGdMVzkQaQ3/+2noVz\n/uAKbzpEL8xTcxYyP3lkOeh4FoxiSWqy5pGFALdPONoDuYFpLhjJSZaEwuvjI/Tr\nrGhLV1pRG9frwDFshqD2Vaj4ENBCBh6UpeBop5+285zQ4SI7q4U9oSebUDJiuOx6\n+tZ9KynmrbJpTSi0+BM=\n-----END CERTIFICATE-----';
        content_by_lua '
            local jwt = require "resty.jwt"

            local function get_public_key(url, iss, kid)
                if iss ~= nil then
                    error("Unexpected iss has been passed. Duh :(")
                end

                if kid ~= nil then
                    error("Unexpected kid has been passed. Duh :(")
                end

                return ngx.var.cert
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
        set $cert '-----BEGIN CERTIFICATE-----\nMIIC2jCCAkMCAg38MA0GCSqGSIb3DQEBBQUAMIGbMQswCQYDVQQGEwJKUDEOMAwG\nA1UECBMFVG9reW8xEDAOBgNVBAcTB0NodW8ta3UxETAPBgNVBAoTCEZyYW5rNERE\nMRgwFgYDVQQLEw9XZWJDZXJ0IFN1cHBvcnQxGDAWBgNVBAMTD0ZyYW5rNEREIFdl\nYiBDQTEjMCEGCSqGSIb3DQEJARYUc3VwcG9ydEBmcmFuazRkZC5jb20wHhcNMTIw\nODIyMDUyNzQxWhcNMTcwODIxMDUyNzQxWjBKMQswCQYDVQQGEwJKUDEOMAwGA1UE\nCAwFVG9reW8xETAPBgNVBAoMCEZyYW5rNEREMRgwFgYDVQQDDA93d3cuZXhhbXBs\nZS5jb20wggEiMA0GCSqGSIb3DQEBAQUAA4IBDwAwggEKAoIBAQC0z9FeMynsC8+u\ndvX+LciZxnh5uRj4C9S6tNeeAlIGCfQYk0zUcNFCoCkTknNQd/YEiawDLNbxBqut\nbMDZ1aarys1a0lYmUeVLCIqvzBkPJTSQsCopQQ9V8WuT252zzNzs68dVGNdCJd5J\nNRQykpwexmnjPPv0mvj7i8XgG379TyW6P+WWV5okeUkXJ9eJS2ouDYdR2SM9BoVW\n+FgxDu6BmXhozW5EfsnajFp7HL8kQClI0QOc79yuKl3492rH6bzFsFn2lfwWy9ic\n7cP8EpCTeFp1tFaD+vxBhPZkeTQ1HKx6hQ5zeHIB5ySJJZ7af2W8r4eTGYzbdRW2\n4DDHCPhZAgMBAAEwDQYJKoZIhvcNAQEFBQADgYEAQMv+BFvGdMVzkQaQ3/+2noVz\n/uAKbzpEL8xTcxYyP3lkOeh4FoxiSWqy5pGFALdPONoDuYFpLhjJSZaEwuvjI/Tr\nrGhLV1pRG9frwDFshqD2Vaj4ENBCBh6UpeBop5+285zQ4SI7q4U9oSebUDJiuOx6\n+tZ9KynmrbJpTSi0+BM=\n-----END CERTIFICATE-----';
        content_by_lua '
            local jwt = require "resty.jwt"

            local function get_public_key(url)
                return ngx.var.cert
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
        set $cert '-----BEGIN CERTIFICATE-----\nMIIC2jCCAkMCAg38MA0GCSqGSIb3DQEBBQUAMIGbMQswCQYDVQQGEwJKUDEOMAwG\nA1UECBMFVG9reW8xEDAOBgNVBAcTB0NodW8ta3UxETAPBgNVBAoTCEZyYW5rNERE\nMRgwFgYDVQQLEw9XZWJDZXJ0IFN1cHBvcnQxGDAWBgNVBAMTD0ZyYW5rNEREIFdl\nYiBDQTEjMCEGCSqGSIb3DQEJARYUc3VwcG9ydEBmcmFuazRkZC5jb20wHhcNMTIw\nODIyMDUyNzQxWhcNMTcwODIxMDUyNzQxWjBKMQswCQYDVQQGEwJKUDEOMAwGA1UE\nCAwFVG9reW8xETAPBgNVBAoMCEZyYW5rNEREMRgwFgYDVQQDDA93d3cuZXhhbXBs\nZS5jb20wggEiMA0GCSqGSIb3DQEBAQUAA4IBDwAwggEKAoIBAQC0z9FeMynsC8+u\ndvX+LciZxnh5uRj4C9S6tNeeAlIGCfQYk0zUcNFCoCkTknNQd/YEiawDLNbxBqut\nbMDZ1aarys1a0lYmUeVLCIqvzBkPJTSQsCopQQ9V8WuT252zzNzs68dVGNdCJd5J\nNRQykpwexmnjPPv0mvj7i8XgG379TyW6P+WWV5okeUkXJ9eJS2ouDYdR2SM9BoVW\n+FgxDu6BmXhozW5EfsnajFp7HL8kQClI0QOc79yuKl3492rH6bzFsFn2lfwWy9ic\n7cP8EpCTeFp1tFaD+vxBhPZkeTQ1HKx6hQ5zeHIB5ySJJZ7af2W8r4eTGYzbdRW2\n4DDHCPhZAgMBAAEwDQYJKoZIhvcNAQEFBQADgYEAQMv+BFvGdMVzkQaQ3/+2noVz\n/uAKbzpEL8xTcxYyP3lkOeh4FoxiSWqy5pGFALdPONoDuYFpLhjJSZaEwuvjI/Tr\nrGhLV1pRG9frwDFshqD2Vaj4ENBCBh6UpeBop5+285zQ4SI7q4U9oSebUDJiuOx6\n+tZ9KynmrbJpTSi0+BM=\n-----END CERTIFICATE-----';
        content_by_lua '
            local jwt = require "resty.jwt"

            local function get_public_key(url, iss, kid)
                if iss ~= nil then
                    error("Unexpected iss has been passed. Duh :(")
                end

                if kid ~= nil then
                    error("Unexpected kid has been passed. Duh :(")
                end

                return ngx.var.cert
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
