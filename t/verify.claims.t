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


=== TEST 2: JWT without sub claim and with empty claim requirement
--- http_config eval: $::HttpConfig
--- config
    location /t {
        content_by_lua '
            local jwt = require "resty.jwt"
            local success, err = pcall(function () jwt:verify(
                "lua-resty-jwt",
                "eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9" ..
                ".eyJmb28iOiJiYXIifQ" ..
                ".VxhQcGihWyHuJeHhpUiq2FU7aW2s_3ZJlY6h1kdlmJY",
                {
                  claims = {}
                }
            ) end)
            err = string.gsub(err, "^.*: ", "")
            ngx.say(err)
        ';
    }
--- request
GET /t
--- response_body
'claims' validation option is expected to be a non empty table.
--- no_error_log
[error]


=== TEST 3: JWT with sub claim and with empty claim requirement
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
                  claims = {}
                }
            ) end)
            err = string.gsub(err, "^.*: ", "")
            ngx.say(err)
        ';
    }
--- request
GET /t
--- response_body
'claims' validation option is expected to be a non empty table.
--- no_error_log
[error]


=== TEST 4: JWT with sub claim and with exact string claim requirement
--- http_config eval: $::HttpConfig
--- config
    location /t {
        content_by_lua '
            local jwt = require "resty.jwt"
            local jwt_obj = jwt:verify(
                "lua-resty-jwt",
                "eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9" ..
                ".eyJmb28iOiJiYXIiLCJzdWIiOiJUZXN0IFN1YmplY3QifQ" ..
                ".UDSQ6edgmmSR9Us53p7Mg2MvcsbVNLCQISJj-rE7zPI",
                {
                  claims = {sub = "Test Subject"}
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


=== TEST 5: JWT with sub claim and with pattern matching string claim requirement
--- http_config eval: $::HttpConfig
--- config
    location /t {
        content_by_lua '
            local jwt = require "resty.jwt"
            local jwt_obj = jwt:verify(
                "lua-resty-jwt",
                "eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9" ..
                ".eyJmb28iOiJiYXIiLCJzdWIiOiJUZXN0IFN1YmplY3QifQ" ..
                ".UDSQ6edgmmSR9Us53p7Mg2MvcsbVNLCQISJj-rE7zPI",
                {
                  claims = {sub = "^Test [a-zA-Z]+$"}
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


=== TEST 6: JWT with sub claim and with non-anchored matching string claim requirement
--- http_config eval: $::HttpConfig
--- config
    location /t {
        content_by_lua '
            local jwt = require "resty.jwt"
            local jwt_obj = jwt:verify(
                "lua-resty-jwt",
                "eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9" ..
                ".eyJmb28iOiJiYXIiLCJzdWIiOiJUZXN0IFN1YmplY3QifQ" ..
                ".UDSQ6edgmmSR9Us53p7Mg2MvcsbVNLCQISJj-rE7zPI",
                {
                  claims = {sub = "st Sub"}
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


=== TEST 7: JWT with sub claim and with non-matching string claim requirement
--- http_config eval: $::HttpConfig
--- config
    location /t {
        content_by_lua '
            local jwt = require "resty.jwt"
            local jwt_obj = jwt:verify(
                "lua-resty-jwt",
                "eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9" ..
                ".eyJmb28iOiJiYXIiLCJzdWIiOiJUZXN0IFN1YmplY3QifQ" ..
                ".UDSQ6edgmmSR9Us53p7Mg2MvcsbVNLCQISJj-rE7zPI",
                {
                  claims = {sub = "Some Other"}
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
Claim 'sub' ('Test Subject') does not match string requirement: 'Some Other'
--- no_error_log
[error]


=== TEST 8: JWT with sub claim and with matching function claim requirement
--- http_config eval: $::HttpConfig
--- config
    location /t {
        content_by_lua '
            local jwt = require "resty.jwt"
            local jwt_obj = jwt:verify(
                "lua-resty-jwt",
                "eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9" ..
                ".eyJmb28iOiJiYXIiLCJzdWIiOiJUZXN0IFN1YmplY3QifQ" ..
                ".UDSQ6edgmmSR9Us53p7Mg2MvcsbVNLCQISJj-rE7zPI",
                {
                  claims = {
                    sub = function(val)
                      ngx.say("Checking " .. val)
                      if val ~= "Test Subject" then
                        error(val .. " does not pass function")
                      end
                    end
                  }
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


=== TEST 9: JWT with sub claim and with non-matching function claim requirement
--- http_config eval: $::HttpConfig
--- config
    location /t {
        content_by_lua '
            local jwt = require "resty.jwt"
            local jwt_obj = jwt:verify(
                "lua-resty-jwt",
                "eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9" ..
                ".eyJmb28iOiJiYXIiLCJzdWIiOiJUZXN0IFN1YmplY3QifQ" ..
                ".UDSQ6edgmmSR9Us53p7Mg2MvcsbVNLCQISJj-rE7zPI",
                {
                  claims = {
                    sub = function(val)
                      ngx.say("Checking " .. val)
                      if val ~= "Some Other" then
                        error({ reason = val .. " does not pass function" })
                      end
                    end
                  }
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


=== TEST 10: JWT without sub claim and with string claim requirement
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
                {
                  claims = {sub = "Test Subject"}
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
Missing required claim sub
--- no_error_log
[error]


=== TEST 11: JWT without sub claim and with function claim requirement
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
                {
                  claims = {
                    sub = function(val)
                      ngx.say("Checking " .. val)
                      if val ~= "Test Subject" then
                        error({ reason = val .. " does not pass function" })
                      end
                    end
                  }
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
Missing required claim sub
--- no_error_log
[error]


=== TEST 12: JWT with sub claim and with invalid claim requirement
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
                  claims = {sub = true}
                }
            ) end)
            err = string.gsub(err, "^.*: ", "")
            ngx.say(err)
        ';
    }
--- request
GET /t
--- response_body
Spec requirements must be either a string or a function
--- no_error_log
[error]


=== TEST 13: JWT with sub claim and with function returning true
--- http_config eval: $::HttpConfig
--- config
    location /t {
        content_by_lua '
            local jwt = require "resty.jwt"
            local jwt_obj = jwt:verify(
                "lua-resty-jwt",
                "eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9" ..
                ".eyJmb28iOiJiYXIiLCJzdWIiOiJUZXN0IFN1YmplY3QifQ" ..
                ".UDSQ6edgmmSR9Us53p7Mg2MvcsbVNLCQISJj-rE7zPI",
                {
                  claims = {
                    sub = function(val)
                      return val == "Test Subject" and true or false
                    end
                  }
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


=== TEST 14: JWT with sub claim and with function returning false
--- http_config eval: $::HttpConfig
--- config
    location /t {
        content_by_lua '
            local jwt = require "resty.jwt"
            local jwt_obj = jwt:verify(
                "lua-resty-jwt",
                "eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9" ..
                ".eyJmb28iOiJiYXIiLCJzdWIiOiJUZXN0IFN1YmplY3QifQ" ..
                ".UDSQ6edgmmSR9Us53p7Mg2MvcsbVNLCQISJj-rE7zPI",
                {
                  claims = {
                    sub = function(val) return false end
                  }
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


=== TEST 15: JWT with sub claim and with function that errors with a string only
--- http_config eval: $::HttpConfig
--- config
    location /t {
        content_by_lua '
            local jwt = require "resty.jwt"
            local jwt_obj = jwt:verify(
                "lua-resty-jwt",
                "eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9" ..
                ".eyJmb28iOiJiYXIiLCJzdWIiOiJUZXN0IFN1YmplY3QifQ" ..
                ".UDSQ6edgmmSR9Us53p7Mg2MvcsbVNLCQISJj-rE7zPI",
                {
                  claims = {
                    sub = function(val) error("Error String") end
                  }
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


=== TEST 16: JWT with sub claim and with function that does nothing (so it checks existance only)
--- http_config eval: $::HttpConfig
--- config
    location /t {
        content_by_lua '
            local jwt = require "resty.jwt"
            local jwt_obj = jwt:verify(
                "lua-resty-jwt",
                "eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9" ..
                ".eyJmb28iOiJiYXIiLCJzdWIiOiJUZXN0IFN1YmplY3QifQ" ..
                ".UDSQ6edgmmSR9Us53p7Mg2MvcsbVNLCQISJj-rE7zPI",
                {
                  claims = { sub = function(val) end }
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
            local jwt_obj = jwt:verify(
                "lua-resty-jwt",
                "eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9" ..
                ".eyJmb28iOiJiYXIifQ" ..
                ".VxhQcGihWyHuJeHhpUiq2FU7aW2s_3ZJlY6h1kdlmJY",
                {
                  claims = { sub = function(val) end }
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
Missing required claim sub
--- no_error_log
[error]


