use Test::Nginx::Socket::Lua;

repeat_each(2);

plan tests => repeat_each() * (3 * blocks());

our $HttpConfig = <<'_EOC_';
    lua_package_path 'lib/?.lua;;';
_EOC_

no_long_string();

run_tests();

__DATA__

=== TEST 1: JWT without sub claim and without claim requirement
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


=== TEST 2: JWT with sub claim and with exact string claim requirement
--- http_config eval: $::HttpConfig
--- config
    location /t {
        content_by_lua '
            local jwt = require "resty.jwt"
            local validators = require "resty.jwt-validators"
            local jwt_obj = jwt:verify(
                "lua-resty-jwt",
                "eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9" ..
                ".eyJmb28iOiJiYXIiLCJzdWIiOiJUZXN0IFN1YmplY3QifQ" ..
                ".UDSQ6edgmmSR9Us53p7Mg2MvcsbVNLCQISJj-rE7zPI",
                {
                  sub = validators.equals("Test Subject")
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


=== TEST 3: JWT with sub claim and with pattern matching string claim requirement
--- http_config eval: $::HttpConfig
--- config
    location /t {
        content_by_lua '
            local jwt = require "resty.jwt"
            local validators = require "resty.jwt-validators"
            local jwt_obj = jwt:verify(
                "lua-resty-jwt",
                "eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9" ..
                ".eyJmb28iOiJiYXIiLCJzdWIiOiJUZXN0IFN1YmplY3QifQ" ..
                ".UDSQ6edgmmSR9Us53p7Mg2MvcsbVNLCQISJj-rE7zPI",
                {
                  sub = validators.matches("^Test [a-zA-Z]+$")
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


=== TEST 4: JWT with sub claim and with non-anchored matching string claim requirement
--- http_config eval: $::HttpConfig
--- config
    location /t {
        content_by_lua '
            local jwt = require "resty.jwt"
            local validators = require "resty.jwt-validators"
            local jwt_obj = jwt:verify(
                "lua-resty-jwt",
                "eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9" ..
                ".eyJmb28iOiJiYXIiLCJzdWIiOiJUZXN0IFN1YmplY3QifQ" ..
                ".UDSQ6edgmmSR9Us53p7Mg2MvcsbVNLCQISJj-rE7zPI",
                {
                  sub = validators.matches("st Sub")
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


=== TEST 5: JWT with sub claim and with non-matching string claim requirement
--- http_config eval: $::HttpConfig
--- config
    location /t {
        content_by_lua '
            local jwt = require "resty.jwt"
            local validators = require "resty.jwt-validators"
            local jwt_obj = jwt:verify(
                "lua-resty-jwt",
                "eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9" ..
                ".eyJmb28iOiJiYXIiLCJzdWIiOiJUZXN0IFN1YmplY3QifQ" ..
                ".UDSQ6edgmmSR9Us53p7Mg2MvcsbVNLCQISJj-rE7zPI",
                {
                  sub = validators.equals("Some Other")
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
Claim 'sub' ('Test Subject') returned failure
--- no_error_log
[error]


=== TEST 6: JWT with sub claim and with matching function claim requirement
--- http_config eval: $::HttpConfig
--- config
    location /t {
        content_by_lua '
            local jwt = require "resty.jwt"
            local validators = require "resty.jwt-validators"
            local jwt_obj = jwt:verify(
                "lua-resty-jwt",
                "eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9" ..
                ".eyJmb28iOiJiYXIiLCJzdWIiOiJUZXN0IFN1YmplY3QifQ" ..
                ".UDSQ6edgmmSR9Us53p7Mg2MvcsbVNLCQISJj-rE7zPI",
                {
                  sub = validators.required(function(val)
                    ngx.say("Checking " .. val)
                    if val ~= "Test Subject" then
                      error(val .. " does not pass function")
                    end
                  end)
                }
            )
            ngx.say(jwt_obj["verified"])
            ngx.say(jwt_obj["reason"])
        ';
    }
--- request
GET /t
--- response_body
Checking Test Subject
true
everything is awesome~ :p
--- no_error_log
[error]


=== TEST 7: JWT with sub claim and with non-matching function claim requirement
--- http_config eval: $::HttpConfig
--- config
    location /t {
        content_by_lua '
            local jwt = require "resty.jwt"
            local validators = require "resty.jwt-validators"
            local jwt_obj = jwt:verify(
                "lua-resty-jwt",
                "eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9" ..
                ".eyJmb28iOiJiYXIiLCJzdWIiOiJUZXN0IFN1YmplY3QifQ" ..
                ".UDSQ6edgmmSR9Us53p7Mg2MvcsbVNLCQISJj-rE7zPI",
                {
                  sub = validators.required(function(val)
                    ngx.say("Checking " .. val)
                    if val ~= "Some Other" then
                      error({ reason = val .. " does not pass function" })
                    end
                  end)
                }
            )
            ngx.say(jwt_obj["verified"])
            ngx.say(jwt_obj["reason"])
        ';
    }
--- request
GET /t
--- response_body
Checking Test Subject
false
Test Subject does not pass function
--- no_error_log
[error]


=== TEST 8: JWT without sub claim and with string claim requirement
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
                  sub = validators.equals("Test Subject")
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
'sub' claim is required.
--- no_error_log
[error]


=== TEST 9: JWT without sub claim and with function claim requirement
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
                  sub = validators.required(function(val)
                    ngx.say("Checking " .. val)
                    if val ~= "Test Subject" then
                      error({ reason = val .. " does not pass function" })
                    end
                  end)
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
'sub' claim is required.
--- no_error_log
[error]


=== TEST 10: JWT with sub claim and with invalid claim requirement
--- http_config eval: $::HttpConfig
--- config
    location /t {
        content_by_lua '
            local jwt = require "resty.jwt"
            local success, err = pcall(function () jwt:verify(
                "lua-resty-jwt",
                "eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9" ..
                ".eyJmb28iOiJiYXIiLCJzdWIiOiJUZXN0IFN1YmplY3QifQ" ..
                ".UDSQ6edgmmSR9Us53p7Mg2MvcsbVNLCQISJj-rE7zPI",
                {
                  sub = true
                }
            ) end)
            err = string.gsub(err, "^.*: ", "")
            ngx.say(err)
        ';
    }
--- request
GET /t
--- response_body
Claim spec value must be a function - see jwt-validators.lua for helper functions
--- no_error_log
[error]


=== TEST 11: JWT with sub claim and with invalid (string) claim requirement
--- http_config eval: $::HttpConfig
--- config
    location /t {
        content_by_lua '
            local jwt = require "resty.jwt"
            local success, err = pcall(function () jwt:verify(
                "lua-resty-jwt",
                "eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9" ..
                ".eyJmb28iOiJiYXIiLCJzdWIiOiJUZXN0IFN1YmplY3QifQ" ..
                ".UDSQ6edgmmSR9Us53p7Mg2MvcsbVNLCQISJj-rE7zPI",
                {
                  sub = "abc"
                }
            ) end)
            err = string.gsub(err, "^.*: ", "")
            ngx.say(err)
        ';
    }
--- request
GET /t
--- response_body
Claim spec value must be a function - see jwt-validators.lua for helper functions
--- no_error_log
[error]


=== TEST 12: JWT with sub claim and with function returning true
--- http_config eval: $::HttpConfig
--- config
    location /t {
        content_by_lua '
            local jwt = require "resty.jwt"
            local validators = require "resty.jwt-validators"
            local jwt_obj = jwt:verify(
                "lua-resty-jwt",
                "eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9" ..
                ".eyJmb28iOiJiYXIiLCJzdWIiOiJUZXN0IFN1YmplY3QifQ" ..
                ".UDSQ6edgmmSR9Us53p7Mg2MvcsbVNLCQISJj-rE7zPI",
                {
                  sub = validators.required(function(val)
                    return val == "Test Subject" and true or false
                  end)
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


=== TEST 13: JWT with sub claim and with function returning false
--- http_config eval: $::HttpConfig
--- config
    location /t {
        content_by_lua '
            local jwt = require "resty.jwt"
            local validators = require "resty.jwt-validators"
            local jwt_obj = jwt:verify(
                "lua-resty-jwt",
                "eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9" ..
                ".eyJmb28iOiJiYXIiLCJzdWIiOiJUZXN0IFN1YmplY3QifQ" ..
                ".UDSQ6edgmmSR9Us53p7Mg2MvcsbVNLCQISJj-rE7zPI",
                {
                  sub = validators.required(function(val) return false end)
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
Claim 'sub' ('Test Subject') returned failure
--- no_error_log
[error]


=== TEST 14: JWT with sub claim and with function that errors with a string only
--- http_config eval: $::HttpConfig
--- config
    location /t {
        content_by_lua '
            local jwt = require "resty.jwt"
            local validators = require "resty.jwt-validators"
            local jwt_obj = jwt:verify(
                "lua-resty-jwt",
                "eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9" ..
                ".eyJmb28iOiJiYXIiLCJzdWIiOiJUZXN0IFN1YmplY3QifQ" ..
                ".UDSQ6edgmmSR9Us53p7Mg2MvcsbVNLCQISJj-rE7zPI",
                {
                  sub = validators.required(function(val) error("Error String") end)
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
Error String
--- no_error_log
[error]


=== TEST 15: JWT with sub claim and with function that does nothing (so it checks existance only)
--- http_config eval: $::HttpConfig
--- config
    location /t {
        content_by_lua '
            local jwt = require "resty.jwt"
            local validators = require "resty.jwt-validators"
            local jwt_obj = jwt:verify(
                "lua-resty-jwt",
                "eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9" ..
                ".eyJmb28iOiJiYXIiLCJzdWIiOiJUZXN0IFN1YmplY3QifQ" ..
                ".UDSQ6edgmmSR9Us53p7Mg2MvcsbVNLCQISJj-rE7zPI",
                {
                  sub = validators.required(function(val) end)
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


=== TEST 16: JWT without sub claim and with function that does nothing (so it checks existance only)
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
                  sub = validators.required(function(val) end)
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
'sub' claim is required.
--- no_error_log
[error]


=== TEST 17: JWT verification that does "bad things" to the object
--- http_config eval: $::HttpConfig
--- config
    location /t {
        content_by_lua '
            local jwt = require "resty.jwt"
            local validators = require "resty.jwt-validators"
            local cjson = require "cjson.safe"
            local jwt_obj = jwt:verify(
                "lua-resty-jwt",
                "eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9" ..
                ".eyJmb28iOiJiYXIifQ" ..
                ".VxhQcGihWyHuJeHhpUiq2FU7aW2s_3ZJlY6h1kdlmJY",
                {
                  sub = function(val, claim, jwt_json)
                    local tgt_obj = cjson.decode(jwt_json)
                    ngx.say(tgt_obj.payload["foo"])
                    tgt_obj["BAD"] = true
                    jwt_json = "GO AWAY"
                  end
                }
            )
            ngx.say(jwt_obj["verified"])
            ngx.say(jwt_obj["reason"])
            ngx.say(jwt_obj["BAD"])
        ';
    }
--- request
GET /t
--- response_body
bar
true
everything is awesome~ :p
nil
--- no_error_log
[error]


=== TEST 18: JWT with sub claim and full-object validation claim
--- http_config eval: $::HttpConfig
--- config
    location /t {
        content_by_lua '
            local jwt = require "resty.jwt"
            local validators = require "resty.jwt-validators"
            local jwt_obj = jwt:verify(
                "lua-resty-jwt",
                "eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9" ..
                ".eyJmb28iOiJiYXIiLCJzdWIiOiJUZXN0IFN1YmplY3QifQ" ..
                ".UDSQ6edgmmSR9Us53p7Mg2MvcsbVNLCQISJj-rE7zPI",
                {
                  __jwt = function(val, claim, jwt_json)
                    if claim ~= "__jwt" then error("Claim is not __jwt") end
                    if type(val) ~= "table" then error("Value is not a table") end
                    ngx.say("Checking " .. val.payload.sub)
                    return val.payload.sub == "Test Subject" and true or false
                  end
                }
            )
            ngx.say(jwt_obj["verified"])
            ngx.say(jwt_obj["reason"])
        ';
    }
--- request
GET /t
--- response_body
Checking Test Subject
true
everything is awesome~ :p
--- no_error_log
[error]


=== TEST 19: JWT full-object verification that does "bad things" to the value
--- http_config eval: $::HttpConfig
--- config
    location /t {
        content_by_lua '
            local jwt = require "resty.jwt"
            local validators = require "resty.jwt-validators"
            local jwt_obj = jwt:verify(
                "lua-resty-jwt",
                "eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9" ..
                ".eyJmb28iOiJiYXIiLCJzdWIiOiJUZXN0IFN1YmplY3QifQ" ..
                ".UDSQ6edgmmSR9Us53p7Mg2MvcsbVNLCQISJj-rE7zPI",
                {
                  __jwt = function(val, claim, jwt_json)
                    ngx.say(val.payload["foo"])
                    val.payload["BAD"] = true
                    val["HELLO"] = "THERE"
                    return val.payload.sub == "Test Subject" and true or false
                  end
                },
                {
                  __jwt = function(val, claim, jwt_json)
                    ngx.say(val.payload["foo"])
                    if val.payload["BAD"] then error("You have been poisoned!") end
                    if val["HELLO"] then error ("HELLO " .. val["HELLO"]) end
                  end
                }
            )
            ngx.say(jwt_obj["verified"])
            ngx.say(jwt_obj["reason"])
            ngx.say(jwt_obj.payload["BAD"])
            ngx.say(jwt_obj["HELLO"])
        ';
    }
--- request
GET /t
--- response_body
bar
bar
true
everything is awesome~ :p
nil
nil
--- no_error_log
[error]


=== TEST 20: Multiple claim specs
--- http_config eval: $::HttpConfig
--- config
    location /t {
        content_by_lua '
            local jwt = require "resty.jwt"
            local validators = require "resty.jwt-validators"
            local cjson = require "cjson.safe"
            local jwt_obj = jwt:verify(
                "lua-resty-jwt",
                "eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9" ..
                ".eyJmb28iOiJiYXIiLCJzdWIiOiJUZXN0IFN1YmplY3QifQ" ..
                ".UDSQ6edgmmSR9Us53p7Mg2MvcsbVNLCQISJj-rE7zPI",
                {
                  __jwt = function(val, claim, jwt_json)
                    ngx.say("BEFORE")
                  end
                },
                {
                  __jwt = function(val, claim, jwt_json)
                    ngx.say("DURING")
                  end,
                  sub = validators.equals("Test Subject")
                },
                {
                  __jwt = function(val, claim, jwt_json)
                    ngx.say("AFTER")
                  end
                }
            )
            ngx.say(jwt_obj["verified"])
            ngx.say(jwt_obj["reason"])
        ';
    }
--- request
GET /t
--- response_body
BEFORE
DURING
AFTER
true
everything is awesome~ :p
--- no_error_log
[error]


=== TEST 21: JWT validate exp by default
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
'exp' claim expired at Thu, 01 Jan 1970 00:00:00 GMT
--- no_error_log
[error]


