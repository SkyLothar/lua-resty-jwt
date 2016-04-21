use Test::Nginx::Socket::Lua;

repeat_each(2);

plan tests => repeat_each() * (3 * blocks());

our $HttpConfig = <<'_EOC_';
    lua_package_path 'lib/?.lua;;';
    init_by_lua '
      function __runSay(fn, ...)
        local status, rslt = pcall(fn, ...)
        if status then
          local t = type(rslt)
          if t == "function" or t == "nil" then
            ngx.say("TYPE: " .. t)
          elseif t == "table" then
            local cjson = require "cjson.safe"
            ngx.say(cjson.encode(rslt))
          else
            ngx.say(rslt)
          end
        else
          ngx.say(rslt.reason or string.gsub(rslt, "^.*: ", ""))
        end
      end
      function __testValidator(validator, spec, obj)
        __runSay(validator, obj.payload[spec], spec, obj)
      end
    ';
_EOC_

no_long_string();

run_tests();

__DATA__


=== TEST 1: Validator.required
--- http_config eval: $::HttpConfig
--- config
    location /t {
        content_by_lua '
            local validators = require "resty.jwt-validators"
            local tval = validators.required()
            local obj = {
              header = { type="JWT", alg="HS256" },
              payload = { foo="bar" }
            }
            __testValidator(tval, "foo", obj)
            __testValidator(tval, "blah", obj)
        ';
    }
--- request
GET /t
--- response_body
true
'blah' claim is required.
--- no_error_log
[error]


=== TEST 2: Validator.required with chain function
--- http_config eval: $::HttpConfig
--- config
    location /t {
        content_by_lua '
            local validators = require "resty.jwt-validators"
            local tval = validators.required(function(val, claim, jwt_obj)
              if val == nil then error("SOMETHING BAD") end
              if claim == "foo" and val == "bar" then return true end
              return false
            end)
            local obj = {
              header = { type="JWT", alg="HS256" },
              payload = { foo="bar", baz="boo" }
            }
            __testValidator(tval, "foo", obj)
            __testValidator(tval, "baz", obj)
            __testValidator(tval, "blah", obj)
        ';
    }
--- request
GET /t
--- response_body
true
false
'blah' claim is required.
--- no_error_log
[error]


=== TEST 3: Validator.required with invalid chain function
--- http_config eval: $::HttpConfig
--- config
    location /t {
        content_by_lua '
            local validators = require "resty.jwt-validators"
            __runSay(validators.required, "abc")
        ';
    }
--- request
GET /t
--- response_body
Cannot create validator for non-function chain_function
--- no_error_log
[error]


=== TEST 4: Validator.check
--- http_config eval: $::HttpConfig
--- config
    location /t {
        content_by_lua '
            local validators = require "resty.jwt-validators"
            local tval = validators.check("checker", function(v1, v2)
              if v2 ~= "checker" then error("SOMETHING BAD") end
              if v1 == nil then error("SOMETHING BAD") end
              if v1 == "bar" then error("Custom Error") end
              return v1 == "boo"
            end, "my_name", "string")
            local obj = {
              header = { type="JWT", alg="HS256" },
              payload = { foo="bar", baz="boo", num=42 }
            }
            __testValidator(tval, "foo", obj)
            __testValidator(tval, "baz", obj)
            __testValidator(tval, "blah", obj)
            __testValidator(tval, "num", obj)
        ';
    }
--- request
GET /t
--- response_body
Custom Error
true
true
'num' is malformed.  Expected to be a string.
--- no_error_log
[error]


=== TEST 5: Validator.check invalid function
--- http_config eval: $::HttpConfig
--- config
    location /t {
        content_by_lua '
            local validators = require "resty.jwt-validators"
            __runSay(validators.check, "checker", "abc", "my_name", "string")
        ';
    }
--- request
GET /t
--- response_body
Cannot create validator for non-function check_function
--- no_error_log
[error]


=== TEST 6: Validator.check nil value
--- http_config eval: $::HttpConfig
--- config
    location /t {
        content_by_lua '
            local validators = require "resty.jwt-validators"
            __runSay(validators.check, nil, function(v1, v2) return true end, "my_name")
            __runSay(validators.check, nil, function(v1, v2) return true end)
        ';
    }
--- request
GET /t
--- response_body
Cannot create validator for nil my_name
Cannot create validator for nil check_val
--- no_error_log
[error]


=== TEST 7: Validator.check wrong type
--- http_config eval: $::HttpConfig
--- config
    location /t {
        content_by_lua '
            local validators = require "resty.jwt-validators"
            local tval = validators.check("checker", function(v1, v2)
              if v2 ~= "checker" then error("SOMETHING BAD") end
              if v1 == nil then error("SOMETHING BAD") end
              if v1 == "bar" then error("Custom Error") end
              return v1 == 42
            end, "my_name", "number")
            local obj = {
              header = { type="JWT", alg="HS256" },
              payload = { foo="bar", baz="boo", num=42 }
            }
            __testValidator(tval, "foo", obj)
            __testValidator(tval, "baz", obj)
            __testValidator(tval, "blah", obj)
            __testValidator(tval, "num", obj)
        ';
    }
--- request
GET /t
--- response_body
'foo' is malformed.  Expected to be a number.
'baz' is malformed.  Expected to be a number.
true
true
--- no_error_log
[error]


=== TEST 8: Validator.check wrong implicit type
--- http_config eval: $::HttpConfig
--- config
    location /t {
        content_by_lua '
            local validators = require "resty.jwt-validators"
            local tval = validators.check(42, function(v1, v2)
              if v2 ~= 42 then error("SOMETHING BAD") end
              if v1 == nil then error("SOMETHING BAD") end
              return v1 == 42
            end, "my_name", "number")
            local obj = {
              header = { type="JWT", alg="HS256" },
              payload = { foo="bar", baz="boo", num=42 }
            }
            __testValidator(tval, "foo", obj)
            __testValidator(tval, "baz", obj)
            __testValidator(tval, "blah", obj)
            __testValidator(tval, "num", obj)
        ';
    }
--- request
GET /t
--- response_body
'foo' is malformed.  Expected to be a number.
'baz' is malformed.  Expected to be a number.
true
true
--- no_error_log
[error]


=== TEST 9: Validator.required_check
--- http_config eval: $::HttpConfig
--- config
    location /t {
        content_by_lua '
            local validators = require "resty.jwt-validators"
            local tval = validators.required_check("checker", function(v1, v2)
              if v2 ~= "checker" then error("SOMETHING BAD") end
              if v1 == nil then error("SOMETHING BAD") end
              if v1 == "bar" then ngx.say("BAR") end
              return v1 == "boo"
            end, "my_name", "string")
            local obj = {
              header = { type="JWT", alg="HS256" },
              payload = { foo="bar", baz="boo", num=42 }
            }
            __testValidator(tval, "foo", obj)
            __testValidator(tval, "baz", obj)
            __testValidator(tval, "blah", obj)
            __testValidator(tval, "num", obj)
        ';
    }
--- request
GET /t
--- response_body
BAR
false
true
'blah' claim is required.
'num' is malformed.  Expected to be a string.
--- no_error_log
[error]


=== TEST 10: Validator.equals
--- http_config eval: $::HttpConfig
--- config
    location /t {
        content_by_lua '
            local validators = require "resty.jwt-validators"
            local tval = validators.equals("bar")
            local obj = {
              header = { type="JWT", alg="HS256" },
              payload = { foo="bar", baz="boo", num=42 }
            }
            __testValidator(tval, "foo", obj)
            __testValidator(tval, "baz", obj)
            __testValidator(tval, "blah", obj)
            __testValidator(tval, "num", obj)
        ';
    }
--- request
GET /t
--- response_body
true
false
true
'num' is malformed.  Expected to be a string.
--- no_error_log
[error]


=== TEST 11: Validator.equals number
--- http_config eval: $::HttpConfig
--- config
    location /t {
        content_by_lua '
            local validators = require "resty.jwt-validators"
            local tval = validators.equals(42)
            local obj = {
              header = { type="JWT", alg="HS256" },
              payload = { foo="bar", baz="boo", num=42 }
            }
            __testValidator(tval, "foo", obj)
            __testValidator(tval, "baz", obj)
            __testValidator(tval, "blah", obj)
            __testValidator(tval, "num", obj)
        ';
    }
--- request
GET /t
--- response_body
'foo' is malformed.  Expected to be a number.
'baz' is malformed.  Expected to be a number.
true
true
--- no_error_log
[error]


=== TEST 12: Validator.required_equals
--- http_config eval: $::HttpConfig
--- config
    location /t {
        content_by_lua '
            local validators = require "resty.jwt-validators"
            local tval = validators.required_equals("bar")
            local obj = {
              header = { type="JWT", alg="HS256" },
              payload = { foo="bar", baz="boo", num=42 }
            }
            __testValidator(tval, "foo", obj)
            __testValidator(tval, "baz", obj)
            __testValidator(tval, "blah", obj)
            __testValidator(tval, "num", obj)
        ';
    }
--- request
GET /t
--- response_body
true
false
'blah' claim is required.
'num' is malformed.  Expected to be a string.
--- no_error_log
[error]


=== TEST 13: Validator.matches
--- http_config eval: $::HttpConfig
--- config
    location /t {
        content_by_lua '
            local validators = require "resty.jwt-validators"
            local tval = validators.matches("^b[a-z]*$")
            local obj = {
              header = { type="JWT", alg="HS256" },
              payload = { foo="bar", baz="boo", num=42 }
            }
            __testValidator(tval, "foo", obj)
            __testValidator(tval, "baz", obj)
            __testValidator(tval, "blah", obj)
            __testValidator(tval, "num", obj)
        ';
    }
--- request
GET /t
--- response_body
true
true
true
'num' is malformed.  Expected to be a string.
--- no_error_log
[error]


=== TEST 14: Validator.matches number
--- http_config eval: $::HttpConfig
--- config
    location /t {
        content_by_lua '
            local validators = require "resty.jwt-validators"
            __runSay(validators.matches, 42)
        ';
    }
--- request
GET /t
--- response_body
Cannot create validator for non-string pattern
--- no_error_log
[error]


=== TEST 15: Validator.required_matches
--- http_config eval: $::HttpConfig
--- config
    location /t {
        content_by_lua '
            local validators = require "resty.jwt-validators"
            local tval = validators.required_matches("^ba[a-z]*$")
            local obj = {
              header = { type="JWT", alg="HS256" },
              payload = { foo="bar", baz="boo", num=42 }
            }
            __testValidator(tval, "foo", obj)
            __testValidator(tval, "baz", obj)
            __testValidator(tval, "blah", obj)
            __testValidator(tval, "num", obj)
        ';
    }
--- request
GET /t
--- response_body
true
false
'blah' claim is required.
'num' is malformed.  Expected to be a string.
--- no_error_log
[error]


=== TEST 16: Validator.any_of
--- http_config eval: $::HttpConfig
--- config
    location /t {
        content_by_lua '
            local cjson = require "cjson.safe"
            local validators = require "resty.jwt-validators"
            local tval = validators.any_of({ "foo", "bar" }, function(v1, v2)
              if v2 ~= "foo" and v2 ~= "bar" then error("SOMETHING BAD") end
              if v1 == nil then error("SOMETHING BAD") end
              if v1 == "bar" then error("Custom Error") end
              return v1 == "boo"
            end, "my_name", "string")
            local obj = {
              header = { type="JWT", alg="HS256" },
              payload = { foo="bar", baz="boo", num=42 }
            }
            __testValidator(tval, "foo", obj)
            __testValidator(tval, "baz", obj)
            __testValidator(tval, "blah", obj)
            __testValidator(tval, "num", obj)
        ';
    }
--- request
GET /t
--- response_body
Custom Error
true
true
'num' is malformed.  Expected to be a string.
--- no_error_log
[error]


=== TEST 17: Validator.any_of number
--- http_config eval: $::HttpConfig
--- config
    location /t {
        content_by_lua '
            local cjson = require "cjson.safe"
            local validators = require "resty.jwt-validators"
            local tval = validators.any_of({ "foo", "bar" }, function(v1, v2)
              if v2 ~= "foo" and v2 ~= "bar" then error("SOMETHING BAD") end
              if v1 == nil then error("SOMETHING BAD") end
              if v1 == "bar" then error("Custom Error") end
              ngx.say("HEY")
              return v1 == 42
            end, "my_name", "number")
            local obj = {
              header = { type="JWT", alg="HS256" },
              payload = { foo="bar", baz="boo", num=42 }
            }
            __testValidator(tval, "foo", obj)
            __testValidator(tval, "baz", obj)
            __testValidator(tval, "blah", obj)
            __testValidator(tval, "num", obj)
        ';
    }
--- request
GET /t
--- response_body
'foo' is malformed.  Expected to be a number.
'baz' is malformed.  Expected to be a number.
true
HEY
true
--- no_error_log
[error]


=== TEST 18: Validator.any_of implied number
--- http_config eval: $::HttpConfig
--- config
    location /t {
        content_by_lua '
            local cjson = require "cjson.safe"
            local validators = require "resty.jwt-validators"
            local tval = validators.any_of({ 42, 43 }, function(v1, v2)
              if v2 ~= 42 and v2 ~= 43 then error("SOMETHING BAD") end
              if v1 == nil then error("SOMETHING BAD") end
              ngx.say("HEY")
              return v1 == 42
            end, "my_name", "number")
            local obj = {
              header = { type="JWT", alg="HS256" },
              payload = { foo="bar", baz="boo", num=42 }
            }
            __testValidator(tval, "foo", obj)
            __testValidator(tval, "baz", obj)
            __testValidator(tval, "blah", obj)
            __testValidator(tval, "num", obj)
        ';
    }
--- request
GET /t
--- response_body
'foo' is malformed.  Expected to be a number.
'baz' is malformed.  Expected to be a number.
true
HEY
true
--- no_error_log
[error]


=== TEST 19: Validator.any_of empty table
--- http_config eval: $::HttpConfig
--- config
    location /t {
        content_by_lua '
            local cjson = require "cjson.safe"
            local validators = require "resty.jwt-validators"
            __runSay(validators.any_of, {}, function(v1, v2) return true end, "my_name", "string")
        ';
    }
--- request
GET /t
--- response_body
Cannot create validator for empty table my_name
--- no_error_log
[error]


=== TEST 20: Validator.any_of invalid table
--- http_config eval: $::HttpConfig
--- config
    location /t {
        content_by_lua '
            local cjson = require "cjson.safe"
            local validators = require "resty.jwt-validators"
            __runSay(validators.any_of, "abc", function(v1, v2) return true end, "my_name", "string")
        ';
    }
--- request
GET /t
--- response_body
Cannot create validator for non-table my_name
--- no_error_log
[error]


=== TEST 21: Validator.any_of mixed type table
--- http_config eval: $::HttpConfig
--- config
    location /t {
        content_by_lua '
            local cjson = require "cjson.safe"
            local validators = require "resty.jwt-validators"
            __runSay(validators.any_of, { "abc", 123 }, function(v1, v2) return true end, "my_name", "string")
        ';
    }
--- request
GET /t
--- response_body
Cannot create validator for non-string table my_name
--- no_error_log
[error]


=== TEST 22: Validator.required_any_of
--- http_config eval: $::HttpConfig
--- config
    location /t {
        content_by_lua '
            local validators = require "resty.jwt-validators"
            local tval = validators.required_any_of({ "foo", "bar" }, function(v1, v2)
              if v2 ~= "foo" and v2 ~= "bar" then error("SOMETHING BAD") end
              if v1 == nil then error("SOMETHING BAD") end
              if v1 == "bar" then ngx.say("BAR") else ngx.say("OTHER") end
              return v1 == "boo"
            end, "my_name", "string")
            local obj = {
              header = { type="JWT", alg="HS256" },
              payload = { foo="bar", baz="boo", num=42 }
            }
            __testValidator(tval, "foo", obj)
            __testValidator(tval, "baz", obj)
            __testValidator(tval, "blah", obj)
            __testValidator(tval, "num", obj)
        ';
    }
--- request
GET /t
--- response_body
BAR
BAR
false
OTHER
true
'blah' claim is required.
'num' is malformed.  Expected to be a string.
--- no_error_log
[error]


=== TEST 23: Validator.equals_any_of
--- http_config eval: $::HttpConfig
--- config
    location /t {
        content_by_lua '
            local validators = require "resty.jwt-validators"
            local tval = validators.equals_any_of({ "foo", "bar" })
            local obj = {
              header = { type="JWT", alg="HS256" },
              payload = { foo="bar", baz="boo", num=42 }
            }
            __testValidator(tval, "foo", obj)
            __testValidator(tval, "baz", obj)
            __testValidator(tval, "blah", obj)
            __testValidator(tval, "num", obj)
        ';
    }
--- request
GET /t
--- response_body
true
false
true
'num' is malformed.  Expected to be a string.
--- no_error_log
[error]


=== TEST 24: Validator.equals_any_of number
--- http_config eval: $::HttpConfig
--- config
    location /t {
        content_by_lua '
            local validators = require "resty.jwt-validators"
            local tval = validators.equals_any_of({ 41, 42, 42 })
            local obj = {
              header = { type="JWT", alg="HS256" },
              payload = { foo="bar", baz="boo", num=42 }
            }
            __testValidator(tval, "foo", obj)
            __testValidator(tval, "baz", obj)
            __testValidator(tval, "blah", obj)
            __testValidator(tval, "num", obj)
        ';
    }
--- request
GET /t
--- response_body
'foo' is malformed.  Expected to be a number.
'baz' is malformed.  Expected to be a number.
true
true
--- no_error_log
[error]


=== TEST 25: Validator.equals_any_of empty table
--- http_config eval: $::HttpConfig
--- config
    location /t {
        content_by_lua '
            local cjson = require "cjson.safe"
            local validators = require "resty.jwt-validators"
            __runSay(validators.equals_any_of, {})
        ';
    }
--- request
GET /t
--- response_body
Cannot create validator for empty table check_values
--- no_error_log
[error]


=== TEST 26: Validator.equals_any_of invalid table
--- http_config eval: $::HttpConfig
--- config
    location /t {
        content_by_lua '
            local cjson = require "cjson.safe"
            local validators = require "resty.jwt-validators"
            __runSay(validators.equals_any_of, "abc")
        ';
    }
--- request
GET /t
--- response_body
Cannot create validator for non-table check_values
--- no_error_log
[error]


=== TEST 27: Validator.equals_any_of mixed type table
--- http_config eval: $::HttpConfig
--- config
    location /t {
        content_by_lua '
            local cjson = require "cjson.safe"
            local validators = require "resty.jwt-validators"
            __runSay(validators.equals_any_of, { "abc", 123 })
        ';
    }
--- request
GET /t
--- response_body
Cannot create validator for non-string table check_values
--- no_error_log
[error]


=== TEST 28: Validator.required_equals_any_of
--- http_config eval: $::HttpConfig
--- config
    location /t {
        content_by_lua '
            local validators = require "resty.jwt-validators"
            local tval = validators.required_equals_any_of({ "foo", "bar" })
            local obj = {
              header = { type="JWT", alg="HS256" },
              payload = { foo="bar", baz="boo", num=42 }
            }
            __testValidator(tval, "foo", obj)
            __testValidator(tval, "baz", obj)
            __testValidator(tval, "blah", obj)
            __testValidator(tval, "num", obj)
        ';
    }
--- request
GET /t
--- response_body
true
false
'blah' claim is required.
'num' is malformed.  Expected to be a string.
--- no_error_log
[error]


=== TEST 29: Validator.matches_any_of
--- http_config eval: $::HttpConfig
--- config
    location /t {
        content_by_lua '
            local validators = require "resty.jwt-validators"
            local tval = validators.matches_any_of({ "^b[a-z]*$", "^abc$" })
            local obj = {
              header = { type="JWT", alg="HS256" },
              payload = { foo="bar", baz="boo", num=42 }
            }
            __testValidator(tval, "foo", obj)
            __testValidator(tval, "baz", obj)
            __testValidator(tval, "blah", obj)
            __testValidator(tval, "num", obj)
        ';
    }
--- request
GET /t
--- response_body
true
true
true
'num' is malformed.  Expected to be a string.
--- no_error_log
[error]


=== TEST 30: Validator.matches_any_of number
--- http_config eval: $::HttpConfig
--- config
    location /t {
        content_by_lua '
            local validators = require "resty.jwt-validators"
            __runSay(validators.matches_any_of, { 41, 42 })
        ';
    }
--- request
GET /t
--- response_body
Cannot create validator for non-string table patterns
--- no_error_log
[error]


=== TEST 31: Validator.matches_any_of empty table
--- http_config eval: $::HttpConfig
--- config
    location /t {
        content_by_lua '
            local cjson = require "cjson.safe"
            local validators = require "resty.jwt-validators"
            __runSay(validators.matches_any_of, {})
        ';
    }
--- request
GET /t
--- response_body
Cannot create validator for empty table patterns
--- no_error_log
[error]


=== TEST 32: Validator.matches_any_of invalid table
--- http_config eval: $::HttpConfig
--- config
    location /t {
        content_by_lua '
            local cjson = require "cjson.safe"
            local validators = require "resty.jwt-validators"
            __runSay(validators.matches_any_of, "abc")
        ';
    }
--- request
GET /t
--- response_body
Cannot create validator for non-table patterns
--- no_error_log
[error]


=== TEST 33: Validator.matches_any_of mixed type table
--- http_config eval: $::HttpConfig
--- config
    location /t {
        content_by_lua '
            local cjson = require "cjson.safe"
            local validators = require "resty.jwt-validators"
            __runSay(validators.matches_any_of, { "abc", 123 })
        ';
    }
--- request
GET /t
--- response_body
Cannot create validator for non-string table patterns
--- no_error_log
[error]


=== TEST 34: Validator.matches_any_of non-string
--- http_config eval: $::HttpConfig
--- config
    location /t {
        content_by_lua '
            local cjson = require "cjson.safe"
            local validators = require "resty.jwt-validators"
            __runSay(validators.matches_any_of, { 41, 42 })
        ';
    }
--- request
GET /t
--- response_body
Cannot create validator for non-string table patterns
--- no_error_log
[error]


=== TEST 35: Validator.required_matches_any_of
--- http_config eval: $::HttpConfig
--- config
    location /t {
        content_by_lua '
            local validators = require "resty.jwt-validators"
            local tval = validators.required_matches_any_of({ "^ba[a-z]*$", "^abc$" })
            local obj = {
              header = { type="JWT", alg="HS256" },
              payload = { foo="bar", baz="boo", num=42 }
            }
            __testValidator(tval, "foo", obj)
            __testValidator(tval, "baz", obj)
            __testValidator(tval, "blah", obj)
            __testValidator(tval, "num", obj)
        ';
    }
--- request
GET /t
--- response_body
true
false
'blah' claim is required.
'num' is malformed.  Expected to be a string.
--- no_error_log
[error]


=== TEST 36: Validator.greater_than
--- http_config eval: $::HttpConfig
--- config
    location /t {
        content_by_lua '
            local validators = require "resty.jwt-validators"
            local tval = validators.greater_than(42)
            local obj = {
              header = { type="JWT", alg="HS256" },
              payload = { foo="bar", num1=41, num2=42, num3=43 }
            }
            __testValidator(tval, "foo", obj)
            __testValidator(tval, "blah", obj)
            __testValidator(tval, "num1", obj)
            __testValidator(tval, "num2", obj)
            __testValidator(tval, "num3", obj)
        ';
    }
--- request
GET /t
--- response_body
'foo' is malformed.  Expected to be a number.
true
false
false
true
--- no_error_log
[error]


=== TEST 37: Validator.greater_than invalid value
--- http_config eval: $::HttpConfig
--- config
    location /t {
        content_by_lua '
            local validators = require "resty.jwt-validators"
            __runSay(validators.greater_than, "abc")
        ';
    }
--- request
GET /t
--- response_body
Cannot create validator for non-number check_val
--- no_error_log
[error]


=== TEST 38: Validator.required_greater_than
--- http_config eval: $::HttpConfig
--- config
    location /t {
        content_by_lua '
            local validators = require "resty.jwt-validators"
            local tval = validators.required_greater_than(42)
            local obj = {
              header = { type="JWT", alg="HS256" },
              payload = { foo="bar", num1=41, num2=42, num3=43 }
            }
            __testValidator(tval, "foo", obj)
            __testValidator(tval, "blah", obj)
            __testValidator(tval, "num1", obj)
            __testValidator(tval, "num2", obj)
            __testValidator(tval, "num3", obj)
        ';
    }
--- request
GET /t
--- response_body
'foo' is malformed.  Expected to be a number.
'blah' claim is required.
false
false
true
--- no_error_log
[error]


=== TEST 39: Validator.greater_than_or_equal
--- http_config eval: $::HttpConfig
--- config
    location /t {
        content_by_lua '
            local validators = require "resty.jwt-validators"
            local tval = validators.greater_than_or_equal(42)
            local obj = {
              header = { type="JWT", alg="HS256" },
              payload = { foo="bar", num1=41, num2=42, num3=43 }
            }
            __testValidator(tval, "foo", obj)
            __testValidator(tval, "blah", obj)
            __testValidator(tval, "num1", obj)
            __testValidator(tval, "num2", obj)
            __testValidator(tval, "num3", obj)
        ';
    }
--- request
GET /t
--- response_body
'foo' is malformed.  Expected to be a number.
true
false
true
true
--- no_error_log
[error]


=== TEST 40: Validator.greater_than_or_equal invalid value
--- http_config eval: $::HttpConfig
--- config
    location /t {
        content_by_lua '
            local validators = require "resty.jwt-validators"
            __runSay(validators.greater_than_or_equal, "abc")
        ';
    }
--- request
GET /t
--- response_body
Cannot create validator for non-number check_val
--- no_error_log
[error]


=== TEST 41: Validator.required_greater_than_or_equal
--- http_config eval: $::HttpConfig
--- config
    location /t {
        content_by_lua '
            local validators = require "resty.jwt-validators"
            local tval = validators.required_greater_than_or_equal(42)
            local obj = {
              header = { type="JWT", alg="HS256" },
              payload = { foo="bar", num1=41, num2=42, num3=43 }
            }
            __testValidator(tval, "foo", obj)
            __testValidator(tval, "blah", obj)
            __testValidator(tval, "num1", obj)
            __testValidator(tval, "num2", obj)
            __testValidator(tval, "num3", obj)
        ';
    }
--- request
GET /t
--- response_body
'foo' is malformed.  Expected to be a number.
'blah' claim is required.
false
true
true
--- no_error_log
[error]


=== TEST 42: Validator.less_than
--- http_config eval: $::HttpConfig
--- config
    location /t {
        content_by_lua '
            local validators = require "resty.jwt-validators"
            local tval = validators.less_than(42)
            local obj = {
              header = { type="JWT", alg="HS256" },
              payload = { foo="bar", num1=41, num2=42, num3=43 }
            }
            __testValidator(tval, "foo", obj)
            __testValidator(tval, "blah", obj)
            __testValidator(tval, "num1", obj)
            __testValidator(tval, "num2", obj)
            __testValidator(tval, "num3", obj)
        ';
    }
--- request
GET /t
--- response_body
'foo' is malformed.  Expected to be a number.
true
true
false
false
--- no_error_log
[error]


=== TEST 43: Validator.less_than invalid value
--- http_config eval: $::HttpConfig
--- config
    location /t {
        content_by_lua '
            local validators = require "resty.jwt-validators"
            __runSay(validators.less_than, "abc")
        ';
    }
--- request
GET /t
--- response_body
Cannot create validator for non-number check_val
--- no_error_log
[error]


=== TEST 44: Validator.required_less_than
--- http_config eval: $::HttpConfig
--- config
    location /t {
        content_by_lua '
            local validators = require "resty.jwt-validators"
            local tval = validators.required_less_than(42)
            local obj = {
              header = { type="JWT", alg="HS256" },
              payload = { foo="bar", num1=41, num2=42, num3=43 }
            }
            __testValidator(tval, "foo", obj)
            __testValidator(tval, "blah", obj)
            __testValidator(tval, "num1", obj)
            __testValidator(tval, "num2", obj)
            __testValidator(tval, "num3", obj)
        ';
    }
--- request
GET /t
--- response_body
'foo' is malformed.  Expected to be a number.
'blah' claim is required.
true
false
false
--- no_error_log
[error]


=== TEST 45: Validator.less_than_or_equal
--- http_config eval: $::HttpConfig
--- config
    location /t {
        content_by_lua '
            local validators = require "resty.jwt-validators"
            local tval = validators.less_than_or_equal(42)
            local obj = {
              header = { type="JWT", alg="HS256" },
              payload = { foo="bar", num1=41, num2=42, num3=43 }
            }
            __testValidator(tval, "foo", obj)
            __testValidator(tval, "blah", obj)
            __testValidator(tval, "num1", obj)
            __testValidator(tval, "num2", obj)
            __testValidator(tval, "num3", obj)
        ';
    }
--- request
GET /t
--- response_body
'foo' is malformed.  Expected to be a number.
true
true
true
false
--- no_error_log
[error]


=== TEST 46: Validator.less_than_or_equal invalid value
--- http_config eval: $::HttpConfig
--- config
    location /t {
        content_by_lua '
            local validators = require "resty.jwt-validators"
            __runSay(validators.less_than_or_equal, "abc")
        ';
    }
--- request
GET /t
--- response_body
Cannot create validator for non-number check_val
--- no_error_log
[error]


=== TEST 47: Validator.required_less_than_or_equal
--- http_config eval: $::HttpConfig
--- config
    location /t {
        content_by_lua '
            local validators = require "resty.jwt-validators"
            local tval = validators.required_less_than_or_equal(42)
            local obj = {
              header = { type="JWT", alg="HS256" },
              payload = { foo="bar", num1=41, num2=42, num3=43 }
            }
            __testValidator(tval, "foo", obj)
            __testValidator(tval, "blah", obj)
            __testValidator(tval, "num1", obj)
            __testValidator(tval, "num2", obj)
            __testValidator(tval, "num3", obj)
        ';
    }
--- request
GET /t
--- response_body
'foo' is malformed.  Expected to be a number.
'blah' claim is required.
true
true
false
--- no_error_log
[error]


=== TEST 47: Validator.is_not_before
--- http_config eval: $::HttpConfig
--- config
    location /t {
        content_by_lua '
            local validators = require "resty.jwt-validators"
            local tval = validators.is_not_before()
            local obj = {
              header = { type="JWT", alg="HS256" },
              payload = { foo="bar", past=956354998, future=4112028598 }
            }
            __testValidator(tval, "foo", obj)
            __testValidator(tval, "blah", obj)
            __testValidator(tval, "past", obj)
            __testValidator(tval, "future", obj)
        ';
    }
--- request
GET /t
--- response_body
'foo' is malformed.  Expected to be a number.
true
true
false
--- no_error_log
[error]


=== TEST 48: Validator.is_not_before with leeway
--- http_config eval: $::HttpConfig
--- config
    location /t {
        content_by_lua '
            local validators = require "resty.jwt-validators"
            local tval = validators.is_not_before(3153600000)
            local obj = {
              header = { type="JWT", alg="HS256" },
              payload = { foo="bar", past=956354998, future=4112028598 }
            }
            __testValidator(tval, "foo", obj)
            __testValidator(tval, "blah", obj)
            __testValidator(tval, "past", obj)
            __testValidator(tval, "future", obj)
        ';
    }
--- request
GET /t
--- response_body
'foo' is malformed.  Expected to be a number.
true
true
true
--- no_error_log
[error]


=== TEST 49: Validator.is_not_before specific time
--- http_config eval: $::HttpConfig
--- config
    location /t {
        content_by_lua '
            local validators = require "resty.jwt-validators"
            local tval = validators.is_not_before(0, 956354999)
            local obj = {
              header = { type="JWT", alg="HS256" },
              payload = { foo="bar", past=956354998, now=956354999, future=956355000 }
            }
            __testValidator(tval, "foo", obj)
            __testValidator(tval, "blah", obj)
            __testValidator(tval, "past", obj)
            __testValidator(tval, "now", obj)
            __testValidator(tval, "future", obj)
        ';
    }
--- request
GET /t
--- response_body
'foo' is malformed.  Expected to be a number.
true
true
true
false
--- no_error_log
[error]



=== TEST 50: Validator.is_not_before specific time and leeway
--- http_config eval: $::HttpConfig
--- config
    location /t {
        content_by_lua '
            local validators = require "resty.jwt-validators"
            local tval = validators.is_not_before(1, 956354999)
            local obj = {
              header = { type="JWT", alg="HS256" },
              payload = { foo="bar", past=956354998, now=956354999, future=956355000 }
            }
            __testValidator(tval, "foo", obj)
            __testValidator(tval, "blah", obj)
            __testValidator(tval, "past", obj)
            __testValidator(tval, "now", obj)
            __testValidator(tval, "future", obj)
        ';
    }
--- request
GET /t
--- response_body
'foo' is malformed.  Expected to be a number.
true
true
true
true
--- no_error_log
[error]


=== TEST 51: Validator.is_not_before invalid leeway
--- http_config eval: $::HttpConfig
--- config
    location /t {
        content_by_lua '
            local validators = require "resty.jwt-validators"
            __runSay(validators.is_not_before, "abc")
        ';
    }
--- request
GET /t
--- response_body
Cannot create validator for non-number leeway
--- no_error_log
[error]


=== TEST 52: Validator.is_not_before negative leeway
--- http_config eval: $::HttpConfig
--- config
    location /t {
        content_by_lua '
            local validators = require "resty.jwt-validators"
            __runSay(validators.is_not_before, -1)
        ';
    }
--- request
GET /t
--- response_body
Cannot create validator with negative leeway
--- no_error_log
[error]


=== TEST 53: Validator.is_not_before invalid time
--- http_config eval: $::HttpConfig
--- config
    location /t {
        content_by_lua '
            local validators = require "resty.jwt-validators"
            __runSay(validators.is_not_before, 0, "abc")
        ';
    }
--- request
GET /t
--- response_body
Cannot create validator for non-number now
--- no_error_log
[error]


=== TEST 54: Validator.is_not_before negative time
--- http_config eval: $::HttpConfig
--- config
    location /t {
        content_by_lua '
            local validators = require "resty.jwt-validators"
            __runSay(validators.is_not_before, 0, -1)
        ';
    }
--- request
GET /t
--- response_body
Cannot create validator with negative now
--- no_error_log
[error]


=== TEST 55: Validator.required_is_not_before
--- http_config eval: $::HttpConfig
--- config
    location /t {
        content_by_lua '
            local validators = require "resty.jwt-validators"
            local tval = validators.required_is_not_before()
            local obj = {
              header = { type="JWT", alg="HS256" },
              payload = { foo="bar", past=956354998, future=4112028598 }
            }
            __testValidator(tval, "foo", obj)
            __testValidator(tval, "blah", obj)
            __testValidator(tval, "past", obj)
            __testValidator(tval, "future", obj)
        ';
    }
--- request
GET /t
--- response_body
'foo' is malformed.  Expected to be a number.
'blah' claim is required.
true
false
--- no_error_log
[error]


=== TEST 56: Validator.is_not_after
--- http_config eval: $::HttpConfig
--- config
    location /t {
        content_by_lua '
            local validators = require "resty.jwt-validators"
            local tval = validators.is_not_after()
            local obj = {
              header = { type="JWT", alg="HS256" },
              payload = { foo="bar", past=956354998, future=4112028598 }
            }
            __testValidator(tval, "foo", obj)
            __testValidator(tval, "blah", obj)
            __testValidator(tval, "past", obj)
            __testValidator(tval, "future", obj)
        ';
    }
--- request
GET /t
--- response_body
'foo' is malformed.  Expected to be a number.
true
false
true
--- no_error_log
[error]


=== TEST 57: Validator.is_not_after with leeway
--- http_config eval: $::HttpConfig
--- config
    location /t {
        content_by_lua '
            local validators = require "resty.jwt-validators"
            local tval = validators.is_not_after(3153600000)
            local obj = {
              header = { type="JWT", alg="HS256" },
              payload = { foo="bar", past=956354998, future=4112028598 }
            }
            __testValidator(tval, "foo", obj)
            __testValidator(tval, "blah", obj)
            __testValidator(tval, "past", obj)
            __testValidator(tval, "future", obj)
        ';
    }
--- request
GET /t
--- response_body
'foo' is malformed.  Expected to be a number.
true
true
true
--- no_error_log
[error]


=== TEST 58: Validator.is_not_after specific time
--- http_config eval: $::HttpConfig
--- config
    location /t {
        content_by_lua '
            local validators = require "resty.jwt-validators"
            local tval = validators.is_not_after(0, 956354999)
            local obj = {
              header = { type="JWT", alg="HS256" },
              payload = { foo="bar", past=956354998, now=956354999, future=956355000 }
            }
            __testValidator(tval, "foo", obj)
            __testValidator(tval, "blah", obj)
            __testValidator(tval, "past", obj)
            __testValidator(tval, "now", obj)
            __testValidator(tval, "future", obj)
        ';
    }
--- request
GET /t
--- response_body
'foo' is malformed.  Expected to be a number.
true
false
true
true
--- no_error_log
[error]



=== TEST 59: Validator.is_not_after specific time and leeway
--- http_config eval: $::HttpConfig
--- config
    location /t {
        content_by_lua '
            local validators = require "resty.jwt-validators"
            local tval = validators.is_not_after(1, 956354999)
            local obj = {
              header = { type="JWT", alg="HS256" },
              payload = { foo="bar", past=956354998, now=956354999, future=956355000 }
            }
            __testValidator(tval, "foo", obj)
            __testValidator(tval, "blah", obj)
            __testValidator(tval, "past", obj)
            __testValidator(tval, "now", obj)
            __testValidator(tval, "future", obj)
        ';
    }
--- request
GET /t
--- response_body
'foo' is malformed.  Expected to be a number.
true
true
true
true
--- no_error_log
[error]


=== TEST 60: Validator.is_not_after invalid leeway
--- http_config eval: $::HttpConfig
--- config
    location /t {
        content_by_lua '
            local validators = require "resty.jwt-validators"
            __runSay(validators.is_not_after, "abc")
        ';
    }
--- request
GET /t
--- response_body
Cannot create validator for non-number leeway
--- no_error_log
[error]


=== TEST 61: Validator.is_not_after negative leeway
--- http_config eval: $::HttpConfig
--- config
    location /t {
        content_by_lua '
            local validators = require "resty.jwt-validators"
            __runSay(validators.is_not_after, -1)
        ';
    }
--- request
GET /t
--- response_body
Cannot create validator with negative leeway
--- no_error_log
[error]


=== TEST 62: Validator.is_not_after invalid time
--- http_config eval: $::HttpConfig
--- config
    location /t {
        content_by_lua '
            local validators = require "resty.jwt-validators"
            __runSay(validators.is_not_after, 0, "abc")
        ';
    }
--- request
GET /t
--- response_body
Cannot create validator for non-number now
--- no_error_log
[error]


=== TEST 63: Validator.is_not_after negative time
--- http_config eval: $::HttpConfig
--- config
    location /t {
        content_by_lua '
            local validators = require "resty.jwt-validators"
            __runSay(validators.is_not_after, 0, -1)
        ';
    }
--- request
GET /t
--- response_body
Cannot create validator with negative now
--- no_error_log
[error]


=== TEST 64: Validator.required_is_not_after
--- http_config eval: $::HttpConfig
--- config
    location /t {
        content_by_lua '
            local validators = require "resty.jwt-validators"
            local tval = validators.required_is_not_after()
            local obj = {
              header = { type="JWT", alg="HS256" },
              payload = { foo="bar", past=956354998, future=4112028598 }
            }
            __testValidator(tval, "foo", obj)
            __testValidator(tval, "blah", obj)
            __testValidator(tval, "past", obj)
            __testValidator(tval, "future", obj)
        ';
    }
--- request
GET /t
--- response_body
'foo' is malformed.  Expected to be a number.
'blah' claim is required.
false
true
--- no_error_log
[error]


