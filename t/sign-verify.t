use Test::Nginx::Socket::Lua;

repeat_each(2);

plan tests => repeat_each() * (3 * blocks());

our $HttpConfig = <<'_EOC_';
    lua_package_path 'lib/?.lua;;';
_EOC_

no_long_string();

run_tests();

__DATA__


=== TEST 1: JWT sign HS256
--- http_config eval: $::HttpConfig
--- config
    location /t {
        content_by_lua '
            local jwt = require "resty.jwt"
            local jwt_token = jwt:sign(
                "lua-resty-jwt",
                {
                    header={typ="JWT",alg="HS256"},
                    raw_header=jwt:jwt_encode("{\\"typ\\":\\"JWT\\",\\"alg\\":\\"HS256\\"}"),
                    raw_payload=jwt:jwt_encode("{\\"foo\\":\\"bar\\"}")
                }
            )
            ngx.say(jwt_token)
        ';
    }
--- request
GET /t
--- response_body
eyJ0eXAiOiJKV1QiLCJhbGciOiJIUzI1NiJ9.eyJmb28iOiJiYXIifQ.VAoRL1IU0nOguxURF2ZcKR0SGKE1gCbqwyh8u2MLAyY
--- no_error_log
[error]


=== TEST 2: JWT sign HS512
--- http_config eval: $::HttpConfig
--- config
    location /t {
        content_by_lua '
            local jwt = require "resty.jwt"
            local jwt_token = jwt:sign(
                "lua-resty-jwt",
                {
                    header={typ="JWT",alg="HS512"},
                    raw_header=jwt:jwt_encode("{\\"typ\\":\\"JWT\\",\\"alg\\":\\"HS512\\"}"),
                    raw_payload=jwt:jwt_encode("{\\"foo\\":\\"bar\\"}")
                }
            )
            ngx.say(jwt_token)
        ';
    }
--- request
GET /t
--- response_body
eyJ0eXAiOiJKV1QiLCJhbGciOiJIUzUxMiJ9.eyJmb28iOiJiYXIifQ._r7cUx1935GlmpI41mElmYQJlY4LqAZ50mdLyPUaVfbbC13Afhi6NmrqQvk1yefSSIn3ZOJ0h9Rvwm_RtbsInA
--- no_error_log
[error]


=== TEST 3: JWT verify invalid
--- http_config eval: $::HttpConfig
--- config
    location /t {
        content_by_lua '
            local jwt = require "resty.jwt"
            local jwt_obj = jwt:verify(
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


=== TEST 4: JWT verify wrong signature
--- http_config eval: $::HttpConfig
--- config
    location /t {
        content_by_lua '
            local jwt = require "resty.jwt"
            local jwt_obj = jwt:verify(
                "lua-resty-jwt",
                "eyJ0eXAiOiJKV1QiLCJhbGciOiJIUzI1NiJ9" ..
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


=== TEST 5: JWT simple verify with no validation option
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


=== TEST 6: JWT sign and verify
--- http_config eval: $::HttpConfig
--- config
    location /t {
        content_by_lua '
            local jwt = require "resty.jwt"

            local jwt_token = jwt:sign(
                "lua-resty-jwt",
                {
                    header={typ="JWT",alg="HS256"},
                    payload={foo="bar", exp=9999999999}
                }
            )

            local jwt_obj = jwt:verify("lua-resty-jwt", jwt_token)
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


=== TEST 7: JWT sign and verify RS256
--- http_config eval: $::HttpConfig
--- config
    location /t {
        content_by_lua '
            local jwt = require "resty.jwt"

            local function get_testcert(name)
                local f = io.open("/lua-resty-jwt/testcerts/" .. name)
                local contents = f:read("*all")
                f:close()
                return contents
            end

            -- x5c wants a base64 encoded der, not pem.. aka, the pem minus the header+footer
            local pubkey_pem = get_testcert("cert.pem") 
            local ssl = require "ngx.ssl"
            local der, err = ssl.cert_pem_to_der(pubkey_pem)
            local jwt_token = jwt:sign(
                get_testcert("cert-key.pem"),
                {
                    header={
                        typ="JWT",
                        alg="RS256",
                        x5c={
                            ngx.encode_base64(der),
                        } },
                    payload={foo="bar", exp=9999999999}
                }
            )

            local jwt_obj = jwt:verify(get_testcert("cert.pem"), jwt_token)
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


=== TEST 8: RS256 malformed header
--- http_config eval: $::HttpConfig
--- config
    location /t {
        set $cert '-----BEGIN CERTIFICATE-----\nMIIEEDCCAvigAwIBAgIBATANBgkqhkiG9w0BAQUFADCBhDETMBEGCgmSJomT8ixk\nARkWA2NvbTEWMBQGCgmSJomT8ixkARkWBmRvY2tlcjETMBEGA1UECgwKRG9ja2Vy\nIEluYzEfMB0GA1UECwwWRG9ja2VyIFRlc3QgU2lnbmluZyBDQTEfMB0GA1UEAwwW\nRG9ja2VyIFRlc3QgU2lnbmluZyBDQTAeFw0xNTA1MTMyMzAxMzlaFw0xNzA1MTIy\nMzAxMzlaMGsxEzARBgoJkiaJk/IsZAEZFgNjb20xFjAUBgoJkiaJk/IsZAEZFgZk\nb2NrZXIxEzARBgNVBAoMCkRvY2tlciBJbmMxDDAKBgNVBAsMA2h1YjEZMBcGA1UE\nAwwQaHViZ3cuZG9ja2VyLmNvbTCCASIwDQYJKoZIhvcNAQEBBQADggEPADCCAQoC\nggEBANt4HzdXTDX9yklf5wemrt39peRmdJAHpodYn3PQBhkv8VGEU5+kpV8M9zg5\nj7SSjOED9+3LZ09l6iTBT+dQCJMEgyHN1gHPzkyjklrKfCC6yIKUIt+I/oUoHm3e\nloACrJZXYniZxCpiDf5JeitHCaVxJRGj+MXORe5SVY+V7MLlA3NSDHX6gIhknq59\nBOmSVJyww3Ka54kYtZwz3KZzMdrfvCdkjiCeD1zMJwYX6IU9z746DfHNuMnsH7Di\nmrzhoX/3CMFj9sXdpcrzFSlMDqUxIQunFyN6G4JKZywf9Dvs30Ay6q8gBhursRFd\nx6otDl0z7tqfJkA3e4GSt4/DR7MCAwEAAaOBpDCBoTAOBgNVHQ8BAf8EBAMCBLAw\nCQYDVR0TBAIwADAnBgNVHSUEIDAeBggrBgEFBQcDAQYIKwYBBQUHAwIGCCsGAQUF\nBwMDMB0GA1UdDgQWBBQa440jFVFkVPsnGp3sp2bEdtz+6jAfBgNVHSMEGDAWgBQi\nzqX0zdgLeF6GAy7a+zvT4pBCLjAbBgNVHREEFDASghBodWJndy5kb2NrZXIuY29t\nMA0GCSqGSIb3DQEBBQUAA4IBAQB8PdN14gs6zB2m2eB1JpyoFSwho4O1z9UkZqdb\nGUB5SmElVydR2nOMLLUuJoa1zTd1FcX0zlHtDKuRXmO7xaPtrH4Uxiq3Lpu7i2WB\nUDTnMXuzX7hzc5DeU7k7mMbwKRkb+kijJTkET6wcaJwwDSyhzOCZgXW3V0WjHdbD\nprJc52tUk3CHOZY8iZWDVf9gHQpVeJnKzospXJRs3qQksEzD6ciRXu0VHnxeC0DP\n5pnQC17Kkm1QOCHRrsIGDHk9wB1zJlMoeMgIPrCLcC0GappmUlHSMka+3MZYgeW4\nAVlzdia3EYSUuM8Gb5tjSSm/6rTOnXR+zL4PBhNZdAD17hyY\n-----END CERTIFICATE-----';
        set $key '-----BEGIN PRIVATE KEY-----\nMIIEvQIBADANBgkqhkiG9w0BAQEFAASCBKcwggSjAgEAAoIBAQDbeB83V0w1/cpJ\nX+cHpq7d/aXkZnSQB6aHWJ9z0AYZL/FRhFOfpKVfDPc4OY+0kozhA/fty2dPZeok\nwU/nUAiTBIMhzdYBz85Mo5JaynwgusiClCLfiP6FKB5t3paAAqyWV2J4mcQqYg3+\nSXorRwmlcSURo/jFzkXuUlWPlezC5QNzUgx1+oCIZJ6ufQTpklScsMNymueJGLWc\nM9ymczHa37wnZI4gng9czCcGF+iFPc++Og3xzbjJ7B+w4pq84aF/9wjBY/bF3aXK\n8xUpTA6lMSELpxcjehuCSmcsH/Q77N9AMuqvIAYbq7ERXceqLQ5dM+7anyZAN3uB\nkrePw0ezAgMBAAECggEBAIZga0SYN/qK9ROuG6fsn/8eMjfBn7ccaBNQ6PihM0qy\ntyABVK5XwkWLi8cqP1oBrS6NHn3D3/KWZSGyFzl7IHTb+2p0PIeJdDgqow7iEdR8\naQ7CowOZPrXLFa6R7jZc7M10nb9X7utAdG7xEFN1QGvC9j5x1n1OyjScxvSOiJPf\nQMyR7pAUW3GoNYBdgs8YWmMU7SiS8hp4LRsQ2aJpZUexUVk3o1E3ZIeM/joE+jFZ\nNX+rL0Aqmn0JVgKqZI2CbDB5AwJdSpUYd/m0Ko3E/Hxdu/CbeJqdjSl4ArVIyRBL\nJWY4aMbC81B6ftYGyjpBujXIoyTYNIhf+CYYXzNrsOkCgYEA8J4ajDpKtxowkbIj\nT+9FTY54d+SWcvwEKA22KayyFwx/mXWTnfsylzF6JbGAiZKSG9gbUOP1LsoGDsGj\nhFdLMSfmi151IbOJg1l74E7nM5bqW9ULGyLBOpWlvopXt31jV6uQd/t/+gdflyw0\nMtr642krwfz8UOshkeEIsk+7mmUCgYEA6X/omGsvMyLpa2IWjxwuw+51pCdIoZvL\n7BpV1YHqwO8jWVv1KKpOKzrYZVu93w0WMCHoG/g9FGQtOBmMRk2OKOxmCF+H1or4\nI1+iI/dhTPA2tEeAELX+yGtu4fpEHe+dga1QCNdq06366rn0bhWB5hst1DdVQnXn\n+0KjhLmg7DcCgYAxqQ/lnSpKfBdGGrP7DXEKPrtSU1VRyf25norYMxJWe3fiXkfn\nNS8N0WJaYTYcLqoFIScSHNo/m+aAKSrsZ2/XZ1rHrOkT2ZAqEc/lTaOeHCmmZmPy\nZ8vloXkhyD+uWSylrX0VpkyVd+wcsTzcuiFJyi0Dzojs0nqNNxqqYpZfmQKBgDep\npUIIcyUGkoxlwqj09/T/OI4cS0UzRaaQFJwkL1k06MFZmZTLHH1TtthayWWN0hdB\nTfq076KXyuvPs0/jFxuMVzpxw4kScdrE5nsactiLfw706IOTTxxp9/Ho3iogv/R0\n41poN/AkTmd8UteXSvMW0ZMAadPBFb8hAKgYNFN7AoGAbw6WYYPnhikP7gqWmTh0\n0SOeET5WbRfseiUWMfLGL+R5GmNiBhw63n8srz+KJVLJv0PJ/WKDR7o/Hxjv3w9c\ndkqcFG1MW2NKjrdxztptrRaSD7JyA750rB+CsrwvqzJCvwbulp1iRfWkTqq2fnUU\nQvpxhOYnq/ZlXPjUiE5w67w=\n-----END PRIVATE KEY-----';
        content_by_lua '
            local jwt = require "resty.jwt"
            jwt:set_trusted_certs_file("/path/to/cert")

            local jwt_token = jwt:sign(
                ngx.var.key,
                {
                    header={
                        typ="JWT",
                        alg="RS256",
                        x5c={nil, } },
                    payload={foo="bar"}
                }
            )

            local jwt_obj = jwt:verify(ngx.var.cert, jwt_token)
            ngx.say(jwt_obj["verified"])
            ngx.say(jwt_obj["reason"])
            ngx.say(jwt_obj["payload"]["foo"])
        ';
    }
--- request
GET /t
--- response_body
false
Unsupported RS256 key model
bar
--- no_error_log
[error]


=== TEST 9: RS256 malformed header 2
--- http_config eval: $::HttpConfig
--- config
    location /t {
        set $cert '-----BEGIN CERTIFICATE-----\nMIIEEDCCAvigAwIBAgIBATANBgkqhkiG9w0BAQUFADCBhDETMBEGCgmSJomT8ixk\nARkWA2NvbTEWMBQGCgmSJomT8ixkARkWBmRvY2tlcjETMBEGA1UECgwKRG9ja2Vy\nIEluYzEfMB0GA1UECwwWRG9ja2VyIFRlc3QgU2lnbmluZyBDQTEfMB0GA1UEAwwW\nRG9ja2VyIFRlc3QgU2lnbmluZyBDQTAeFw0xNTA1MTMyMzAxMzlaFw0xNzA1MTIy\nMzAxMzlaMGsxEzARBgoJkiaJk/IsZAEZFgNjb20xFjAUBgoJkiaJk/IsZAEZFgZk\nb2NrZXIxEzARBgNVBAoMCkRvY2tlciBJbmMxDDAKBgNVBAsMA2h1YjEZMBcGA1UE\nAwwQaHViZ3cuZG9ja2VyLmNvbTCCASIwDQYJKoZIhvcNAQEBBQADggEPADCCAQoC\nggEBANt4HzdXTDX9yklf5wemrt39peRmdJAHpodYn3PQBhkv8VGEU5+kpV8M9zg5\nj7SSjOED9+3LZ09l6iTBT+dQCJMEgyHN1gHPzkyjklrKfCC6yIKUIt+I/oUoHm3e\nloACrJZXYniZxCpiDf5JeitHCaVxJRGj+MXORe5SVY+V7MLlA3NSDHX6gIhknq59\nBOmSVJyww3Ka54kYtZwz3KZzMdrfvCdkjiCeD1zMJwYX6IU9z746DfHNuMnsH7Di\nmrzhoX/3CMFj9sXdpcrzFSlMDqUxIQunFyN6G4JKZywf9Dvs30Ay6q8gBhursRFd\nx6otDl0z7tqfJkA3e4GSt4/DR7MCAwEAAaOBpDCBoTAOBgNVHQ8BAf8EBAMCBLAw\nCQYDVR0TBAIwADAnBgNVHSUEIDAeBggrBgEFBQcDAQYIKwYBBQUHAwIGCCsGAQUF\nBwMDMB0GA1UdDgQWBBQa440jFVFkVPsnGp3sp2bEdtz+6jAfBgNVHSMEGDAWgBQi\nzqX0zdgLeF6GAy7a+zvT4pBCLjAbBgNVHREEFDASghBodWJndy5kb2NrZXIuY29t\nMA0GCSqGSIb3DQEBBQUAA4IBAQB8PdN14gs6zB2m2eB1JpyoFSwho4O1z9UkZqdb\nGUB5SmElVydR2nOMLLUuJoa1zTd1FcX0zlHtDKuRXmO7xaPtrH4Uxiq3Lpu7i2WB\nUDTnMXuzX7hzc5DeU7k7mMbwKRkb+kijJTkET6wcaJwwDSyhzOCZgXW3V0WjHdbD\nprJc52tUk3CHOZY8iZWDVf9gHQpVeJnKzospXJRs3qQksEzD6ciRXu0VHnxeC0DP\n5pnQC17Kkm1QOCHRrsIGDHk9wB1zJlMoeMgIPrCLcC0GappmUlHSMka+3MZYgeW4\nAVlzdia3EYSUuM8Gb5tjSSm/6rTOnXR+zL4PBhNZdAD17hyY\n-----END CERTIFICATE-----';
        set $key '-----BEGIN PRIVATE KEY-----\nMIIEvQIBADANBgkqhkiG9w0BAQEFAASCBKcwggSjAgEAAoIBAQDbeB83V0w1/cpJ\nX+cHpq7d/aXkZnSQB6aHWJ9z0AYZL/FRhFOfpKVfDPc4OY+0kozhA/fty2dPZeok\nwU/nUAiTBIMhzdYBz85Mo5JaynwgusiClCLfiP6FKB5t3paAAqyWV2J4mcQqYg3+\nSXorRwmlcSURo/jFzkXuUlWPlezC5QNzUgx1+oCIZJ6ufQTpklScsMNymueJGLWc\nM9ymczHa37wnZI4gng9czCcGF+iFPc++Og3xzbjJ7B+w4pq84aF/9wjBY/bF3aXK\n8xUpTA6lMSELpxcjehuCSmcsH/Q77N9AMuqvIAYbq7ERXceqLQ5dM+7anyZAN3uB\nkrePw0ezAgMBAAECggEBAIZga0SYN/qK9ROuG6fsn/8eMjfBn7ccaBNQ6PihM0qy\ntyABVK5XwkWLi8cqP1oBrS6NHn3D3/KWZSGyFzl7IHTb+2p0PIeJdDgqow7iEdR8\naQ7CowOZPrXLFa6R7jZc7M10nb9X7utAdG7xEFN1QGvC9j5x1n1OyjScxvSOiJPf\nQMyR7pAUW3GoNYBdgs8YWmMU7SiS8hp4LRsQ2aJpZUexUVk3o1E3ZIeM/joE+jFZ\nNX+rL0Aqmn0JVgKqZI2CbDB5AwJdSpUYd/m0Ko3E/Hxdu/CbeJqdjSl4ArVIyRBL\nJWY4aMbC81B6ftYGyjpBujXIoyTYNIhf+CYYXzNrsOkCgYEA8J4ajDpKtxowkbIj\nT+9FTY54d+SWcvwEKA22KayyFwx/mXWTnfsylzF6JbGAiZKSG9gbUOP1LsoGDsGj\nhFdLMSfmi151IbOJg1l74E7nM5bqW9ULGyLBOpWlvopXt31jV6uQd/t/+gdflyw0\nMtr642krwfz8UOshkeEIsk+7mmUCgYEA6X/omGsvMyLpa2IWjxwuw+51pCdIoZvL\n7BpV1YHqwO8jWVv1KKpOKzrYZVu93w0WMCHoG/g9FGQtOBmMRk2OKOxmCF+H1or4\nI1+iI/dhTPA2tEeAELX+yGtu4fpEHe+dga1QCNdq06366rn0bhWB5hst1DdVQnXn\n+0KjhLmg7DcCgYAxqQ/lnSpKfBdGGrP7DXEKPrtSU1VRyf25norYMxJWe3fiXkfn\nNS8N0WJaYTYcLqoFIScSHNo/m+aAKSrsZ2/XZ1rHrOkT2ZAqEc/lTaOeHCmmZmPy\nZ8vloXkhyD+uWSylrX0VpkyVd+wcsTzcuiFJyi0Dzojs0nqNNxqqYpZfmQKBgDep\npUIIcyUGkoxlwqj09/T/OI4cS0UzRaaQFJwkL1k06MFZmZTLHH1TtthayWWN0hdB\nTfq076KXyuvPs0/jFxuMVzpxw4kScdrE5nsactiLfw706IOTTxxp9/Ho3iogv/R0\n41poN/AkTmd8UteXSvMW0ZMAadPBFb8hAKgYNFN7AoGAbw6WYYPnhikP7gqWmTh0\n0SOeET5WbRfseiUWMfLGL+R5GmNiBhw63n8srz+KJVLJv0PJ/WKDR7o/Hxjv3w9c\ndkqcFG1MW2NKjrdxztptrRaSD7JyA750rB+CsrwvqzJCvwbulp1iRfWkTqq2fnUU\nQvpxhOYnq/ZlXPjUiE5w67w=\n-----END PRIVATE KEY-----';
        content_by_lua '
            local jwt = require "resty.jwt"
            jwt:set_trusted_certs_file("/path/to/cert")

            local jwt_token = jwt:sign(
                ngx.var.key,
                {
                    header={
                        typ="JWT",
                        alg="RS256",
                        x5c={"not a valid certificate", } },
                    payload={foo="bar"}
                }
            )

            local jwt_obj = jwt:verify(ngx.var.cert, jwt_token)
            ngx.say(jwt_obj["verified"])
            ngx.say(jwt_obj["reason"])
            ngx.say(jwt_obj["payload"]["foo"])
        ';
    }
--- request
GET /t
--- response_body
false
Malformed x5c header
bar
--- no_error_log
[error]


=== TEST 10: RS256 unsupported alg
--- http_config eval: $::HttpConfig
--- config
    location /t {
        content_by_lua '
            local jwt = require "resty.jwt"

            jwt:set_alg_whitelist({RS256=1})

            local jwt_obj = jwt:verify(
                "lua-resty-jwt",
                "eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9."
                .. "eyJmb28iOiJiYXIifQ."
                .. "VxhQcGihWyHuJeHhpUiq2FU7aW2s_3ZJlY6h1kdlmJY"
            )
            ngx.say(jwt_obj["verified"])
            ngx.say(jwt_obj["reason"])
        ';
    }
--- request
GET /t
--- response_body
false
whitelist unsupported alg: HS256
--- no_error_log
[error]


=== TEST 11: JWT sign and verify RS256 - Take 2
--- http_config eval: $::HttpConfig
--- config
    location /t {
        content_by_lua '
            local jwt = require "resty.jwt"

            local function get_testcert(name)
                local f = io.open("/lua-resty-jwt/testcerts/" .. name)
                local contents = f:read("*all")
                f:close()
                return contents
            end

            local function get_public_key(url, iss, kid)
                if iss ~= "Authz" then
                    error("No issuer. Duh :(")
                end

                if kid ~= "IamAPubl1cKeV" then
                    error("No key identifier. Duh :(")
                end

                return get_testcert("cert.pem")
            end

            jwt:set_trusted_certs_file("/lua-resty-jwt/testcerts/root.pem")
            jwt:set_alg_whitelist({ RS256 = 1 })
            jwt:set_x5u_content_retriever(get_public_key)

            local jwt_token = jwt:sign(
                get_testcert("cert-key.pem"),
                {
                    header={
                        typ="JWT",
                        alg="RS256",
                        x5u="https://dummy.com/certs",
                        kid="IamAPubl1cKeV",
                    },
                    payload={foo="bar", iss="Authz", exp=9999999999}
                }
            )

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


=== TEST 12: JWT sign and verify ES256
--- http_config eval: $::HttpConfig
--- config
    location /t {
        content_by_lua '
            local jwt = require "resty.jwt"
            local function get_testcert(name)
                local f = io.open("/lua-resty-jwt/testcerts/" .. name)
                local contents = f:read("*all")
                f:close()
                return contents
            end
            -- x5c wants a base64 encoded der, not pem.. aka, the pem minus the header+footer
            local pubkey_pem = get_testcert("ec_cert.pem") 
            local ssl = require "ngx.ssl"
            local der, err = ssl.cert_pem_to_der(pubkey_pem)
            local jwt_token = jwt:sign(
                get_testcert("ec_cert-key.pem"),
                {
                    header={
                        typ="JWT",
                        alg="ES256",
                        x5c={
                            ngx.encode_base64(der),
                        } },
                    payload={foo="bar", exp=9999999999}
                }
            )
            local jwt_obj = jwt:verify(get_testcert("ec_cert.pem"), jwt_token)
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
=== TEST 13: JWT simple verify failure
--- http_config eval: $::HttpConfig
--- config
    location /t {
        content_by_lua '
            local jwt = require "resty.jwt"
            
            local function get_testcert(name)
                local f = io.open("/lua-resty-jwt/testcerts/" .. name)
                local contents = f:read("*all")
                f:close()
                return contents
            end
            local jwt_obj = jwt:verify(get_testcert("ec_cert.pem"),
                "eyJhbGciOiJFUzI1NiIsInR5cCI6IkpXVCJ9" ..
                ".eyJmb28iOiJiYXIiLCJleHAiOjk5OTk5OTk5OTl9" ..
                ".doMPovbvarZF_6CnwJVMVW6sx9U0TKoQ4fekrxvQNCGlgUxxIYqR6sFWqgjOorUFWYHX5R1mCLGNWUKjXdlqAg",
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
Verification failed
--- no_error_log
[error] 

=== TEST 14: JWT sign and verify ES512
--- http_config eval: $::HttpConfig
--- config
    location /t {
        content_by_lua '
            local jwt = require "resty.jwt"
            local function get_testcert(name)
                local f = io.open("/lua-resty-jwt/testcerts/" .. name)
                local contents = f:read("*all")
                f:close()
                return contents
            end
            -- x5c wants a base64 encoded der, not pem.. aka, the pem minus the header+footer
            local pubkey_pem = get_testcert("ec_cert_p521.pem")
            local ssl = require "ngx.ssl"
            local der, err = ssl.cert_pem_to_der(pubkey_pem)
            local jwt_token = jwt:sign(
                get_testcert("ec_cert_p521-key.pem"),
                {
                    header={
                        typ="JWT",
                        alg="ES512",
                        x5c={
                            ngx.encode_base64(der),
                        } },
                    payload={foo="bar", exp=9999999999}
                }
            )
            local jwt_obj = jwt:verify(get_testcert("ec_cert_p521.pem"), jwt_token)
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

=== TEST 15: JWT sign and verify RS512
--- http_config eval: $::HttpConfig
--- config
    location /t {
        content_by_lua '
            local jwt = require "resty.jwt"

            local function get_testcert(name)
                local f = io.open("/lua-resty-jwt/testcerts/" .. name)
                local contents = f:read("*all")
                f:close()
                return contents
            end

            -- x5c wants a base64 encoded der, not pem.. aka, the pem minus the header+footer
            local pubkey_pem = get_testcert("cert.pem") 
            local ssl = require "ngx.ssl"
            local der, err = ssl.cert_pem_to_der(pubkey_pem)
            local jwt_token = jwt:sign(
                get_testcert("cert-key.pem"),
                {
                    header={
                        typ="JWT",
                        alg="RS512",
                        x5c={
                            ngx.encode_base64(der),
                        } },
                    payload={foo="bar", exp=9999999999}
                }
            )

            local jwt_obj = jwt:verify(get_testcert("cert.pem"), jwt_token)
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