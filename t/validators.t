use Test::Nginx::Socket::Lua;

repeat_each(2);

plan tests => repeat_each() * (3 * blocks());

our $HttpConfig = <<'_EOC_';
    lua_package_path 'lib/?.lua;;';
    init_by_lua '
      local cjson = require "cjson.safe"
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
        if spec == "__jwt" then
          __runSay(validator, obj, spec, cjson.encode(obj))
        else
          __runSay(validator, obj.payload[spec], spec, cjson.encode(obj))
        end
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
Cannot create validator for non-function chain_function.
--- no_error_log
[error]


=== TEST 4: Validator.opt_check
--- http_config eval: $::HttpConfig
--- config
    location /t {
        content_by_lua '
            local validators = require "resty.jwt-validators"
            local tval = validators.opt_check("checker", function(v1, v2)
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


=== TEST 5: Validator.opt_check invalid function
--- http_config eval: $::HttpConfig
--- config
    location /t {
        content_by_lua '
            local validators = require "resty.jwt-validators"
            __runSay(validators.opt_check, "checker", "abc", "my_name", "string")
        ';
    }
--- request
GET /t
--- response_body
Cannot create validator for non-function check_function.
--- no_error_log
[error]


=== TEST 6: Validator.opt_check nil value
--- http_config eval: $::HttpConfig
--- config
    location /t {
        content_by_lua '
            local validators = require "resty.jwt-validators"
            __runSay(validators.opt_check, nil, function(v1, v2) return true end, "my_name")
            __runSay(validators.opt_check, nil, function(v1, v2) return true end)
        ';
    }
--- request
GET /t
--- response_body
Cannot create validator for nil my_name.
Cannot create validator for nil check_val.
--- no_error_log
[error]


=== TEST 7: Validator.opt_check wrong type
--- http_config eval: $::HttpConfig
--- config
    location /t {
        content_by_lua '
            local validators = require "resty.jwt-validators"
            local tval = validators.opt_check("checker", function(v1, v2)
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


=== TEST 8: Validator.opt_check wrong implicit type
--- http_config eval: $::HttpConfig
--- config
    location /t {
        content_by_lua '
            local validators = require "resty.jwt-validators"
            local tval = validators.opt_check(42, function(v1, v2)
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


=== TEST 9: Validator.check
--- http_config eval: $::HttpConfig
--- config
    location /t {
        content_by_lua '
            local validators = require "resty.jwt-validators"
            local tval = validators.check("checker", function(v1, v2)
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


=== TEST 10: Validator.opt_equals
--- http_config eval: $::HttpConfig
--- config
    location /t {
        content_by_lua '
            local validators = require "resty.jwt-validators"
            local tval = validators.opt_equals("bar")
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


=== TEST 11: Validator.opt_equals number
--- http_config eval: $::HttpConfig
--- config
    location /t {
        content_by_lua '
            local validators = require "resty.jwt-validators"
            local tval = validators.opt_equals(42)
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


=== TEST 12: Validator.equals
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
'blah' claim is required.
'num' is malformed.  Expected to be a string.
--- no_error_log
[error]


=== TEST 13: Validator.opt_matches
--- http_config eval: $::HttpConfig
--- config
    location /t {
        content_by_lua '
            local validators = require "resty.jwt-validators"
            local tval = validators.opt_matches("^b[a-z]*$")
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


=== TEST 14: Validator.opt_matches number
--- http_config eval: $::HttpConfig
--- config
    location /t {
        content_by_lua '
            local validators = require "resty.jwt-validators"
            __runSay(validators.opt_matches, 42)
        ';
    }
--- request
GET /t
--- response_body
Cannot create validator for non-string pattern.
--- no_error_log
[error]


=== TEST 15: Validator.matches
--- http_config eval: $::HttpConfig
--- config
    location /t {
        content_by_lua '
            local validators = require "resty.jwt-validators"
            local tval = validators.matches("^ba[a-z]*$")
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


=== TEST 16: Validator.opt_any_of
--- http_config eval: $::HttpConfig
--- config
    location /t {
        content_by_lua '
            local cjson = require "cjson.safe"
            local validators = require "resty.jwt-validators"
            local tval = validators.opt_any_of({ "foo", "bar" }, function(v1, v2)
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


=== TEST 17: Validator.opt_any_of number
--- http_config eval: $::HttpConfig
--- config
    location /t {
        content_by_lua '
            local cjson = require "cjson.safe"
            local validators = require "resty.jwt-validators"
            local tval = validators.opt_any_of({ "foo", "bar" }, function(v1, v2)
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


=== TEST 18: Validator.opt_any_of implied number
--- http_config eval: $::HttpConfig
--- config
    location /t {
        content_by_lua '
            local cjson = require "cjson.safe"
            local validators = require "resty.jwt-validators"
            local tval = validators.opt_any_of({ 42, 43 }, function(v1, v2)
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


=== TEST 19: Validator.opt_any_of empty table
--- http_config eval: $::HttpConfig
--- config
    location /t {
        content_by_lua '
            local cjson = require "cjson.safe"
            local validators = require "resty.jwt-validators"
            __runSay(validators.opt_any_of, {}, function(v1, v2) return true end, "my_name", "string")
        ';
    }
--- request
GET /t
--- response_body
Cannot create validator for empty table my_name.
--- no_error_log
[error]


=== TEST 20: Validator.opt_any_of invalid table
--- http_config eval: $::HttpConfig
--- config
    location /t {
        content_by_lua '
            local cjson = require "cjson.safe"
            local validators = require "resty.jwt-validators"
            __runSay(validators.opt_any_of, "abc", function(v1, v2) return true end, "my_name", "string")
        ';
    }
--- request
GET /t
--- response_body
Cannot create validator for non-table my_name.
--- no_error_log
[error]


=== TEST 21: Validator.opt_any_of mixed type table
--- http_config eval: $::HttpConfig
--- config
    location /t {
        content_by_lua '
            local cjson = require "cjson.safe"
            local validators = require "resty.jwt-validators"
            __runSay(validators.opt_any_of, { "abc", 123 }, function(v1, v2) return true end, "my_name", "string")
        ';
    }
--- request
GET /t
--- response_body
Cannot create validator for non-string table my_name.
--- no_error_log
[error]


=== TEST 22: Validator.any_of
--- http_config eval: $::HttpConfig
--- config
    location /t {
        content_by_lua '
            local validators = require "resty.jwt-validators"
            local tval = validators.any_of({ "foo", "bar" }, function(v1, v2)
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


=== TEST 23: Validator.opt_equals_any_of
--- http_config eval: $::HttpConfig
--- config
    location /t {
        content_by_lua '
            local validators = require "resty.jwt-validators"
            local tval = validators.opt_equals_any_of({ "foo", "bar" })
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


=== TEST 24: Validator.opt_equals_any_of number
--- http_config eval: $::HttpConfig
--- config
    location /t {
        content_by_lua '
            local validators = require "resty.jwt-validators"
            local tval = validators.opt_equals_any_of({ 41, 42, 42 })
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


=== TEST 25: Validator.opt_equals_any_of empty table
--- http_config eval: $::HttpConfig
--- config
    location /t {
        content_by_lua '
            local cjson = require "cjson.safe"
            local validators = require "resty.jwt-validators"
            __runSay(validators.opt_equals_any_of, {})
        ';
    }
--- request
GET /t
--- response_body
Cannot create validator for empty table check_values.
--- no_error_log
[error]


=== TEST 26: Validator.opt_equals_any_of invalid table
--- http_config eval: $::HttpConfig
--- config
    location /t {
        content_by_lua '
            local cjson = require "cjson.safe"
            local validators = require "resty.jwt-validators"
            __runSay(validators.opt_equals_any_of, "abc")
        ';
    }
--- request
GET /t
--- response_body
Cannot create validator for non-table check_values.
--- no_error_log
[error]


=== TEST 27: Validator.opt_equals_any_of mixed type table
--- http_config eval: $::HttpConfig
--- config
    location /t {
        content_by_lua '
            local cjson = require "cjson.safe"
            local validators = require "resty.jwt-validators"
            __runSay(validators.opt_equals_any_of, { "abc", 123 })
        ';
    }
--- request
GET /t
--- response_body
Cannot create validator for non-string table check_values.
--- no_error_log
[error]


=== TEST 28: Validator.equals_any_of
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
'blah' claim is required.
'num' is malformed.  Expected to be a string.
--- no_error_log
[error]


=== TEST 29: Validator.opt_matches_any_of
--- http_config eval: $::HttpConfig
--- config
    location /t {
        content_by_lua '
            local validators = require "resty.jwt-validators"
            local tval = validators.opt_matches_any_of({ "^b[a-z]*$", "^abc$" })
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


=== TEST 30: Validator.opt_matches_any_of number
--- http_config eval: $::HttpConfig
--- config
    location /t {
        content_by_lua '
            local validators = require "resty.jwt-validators"
            __runSay(validators.opt_matches_any_of, { 41, 42 })
        ';
    }
--- request
GET /t
--- response_body
Cannot create validator for non-string table patterns.
--- no_error_log
[error]


=== TEST 31: Validator.opt_matches_any_of empty table
--- http_config eval: $::HttpConfig
--- config
    location /t {
        content_by_lua '
            local cjson = require "cjson.safe"
            local validators = require "resty.jwt-validators"
            __runSay(validators.opt_matches_any_of, {})
        ';
    }
--- request
GET /t
--- response_body
Cannot create validator for empty table patterns.
--- no_error_log
[error]


=== TEST 32: Validator.opt_matches_any_of invalid table
--- http_config eval: $::HttpConfig
--- config
    location /t {
        content_by_lua '
            local cjson = require "cjson.safe"
            local validators = require "resty.jwt-validators"
            __runSay(validators.opt_matches_any_of, "abc")
        ';
    }
--- request
GET /t
--- response_body
Cannot create validator for non-table patterns.
--- no_error_log
[error]


=== TEST 33: Validator.opt_matches_any_of mixed type table
--- http_config eval: $::HttpConfig
--- config
    location /t {
        content_by_lua '
            local cjson = require "cjson.safe"
            local validators = require "resty.jwt-validators"
            __runSay(validators.opt_matches_any_of, { "abc", 123 })
        ';
    }
--- request
GET /t
--- response_body
Cannot create validator for non-string table patterns.
--- no_error_log
[error]


=== TEST 34: Validator.opt_matches_any_of non-string
--- http_config eval: $::HttpConfig
--- config
    location /t {
        content_by_lua '
            local cjson = require "cjson.safe"
            local validators = require "resty.jwt-validators"
            __runSay(validators.opt_matches_any_of, { 41, 42 })
        ';
    }
--- request
GET /t
--- response_body
Cannot create validator for non-string table patterns.
--- no_error_log
[error]


=== TEST 35: Validator.matches_any_of
--- http_config eval: $::HttpConfig
--- config
    location /t {
        content_by_lua '
            local validators = require "resty.jwt-validators"
            local tval = validators.matches_any_of({ "^ba[a-z]*$", "^abc$" })
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


=== TEST 36: Validator.opt_greater_than
--- http_config eval: $::HttpConfig
--- config
    location /t {
        content_by_lua '
            local validators = require "resty.jwt-validators"
            local tval = validators.opt_greater_than(42)
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


=== TEST 37: Validator.opt_greater_than invalid value
--- http_config eval: $::HttpConfig
--- config
    location /t {
        content_by_lua '
            local validators = require "resty.jwt-validators"
            __runSay(validators.opt_greater_than, "abc")
        ';
    }
--- request
GET /t
--- response_body
Cannot create validator for non-number check_val.
--- no_error_log
[error]


=== TEST 38: Validator.greater_than
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
'blah' claim is required.
false
false
true
--- no_error_log
[error]


=== TEST 39: Validator.opt_greater_than_or_equal
--- http_config eval: $::HttpConfig
--- config
    location /t {
        content_by_lua '
            local validators = require "resty.jwt-validators"
            local tval = validators.opt_greater_than_or_equal(42)
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


=== TEST 40: Validator.opt_greater_than_or_equal invalid value
--- http_config eval: $::HttpConfig
--- config
    location /t {
        content_by_lua '
            local validators = require "resty.jwt-validators"
            __runSay(validators.opt_greater_than_or_equal, "abc")
        ';
    }
--- request
GET /t
--- response_body
Cannot create validator for non-number check_val.
--- no_error_log
[error]


=== TEST 41: Validator.greater_than_or_equal
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
'blah' claim is required.
false
true
true
--- no_error_log
[error]


=== TEST 42: Validator.opt_less_than
--- http_config eval: $::HttpConfig
--- config
    location /t {
        content_by_lua '
            local validators = require "resty.jwt-validators"
            local tval = validators.opt_less_than(42)
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


=== TEST 43: Validator.opt_less_than invalid value
--- http_config eval: $::HttpConfig
--- config
    location /t {
        content_by_lua '
            local validators = require "resty.jwt-validators"
            __runSay(validators.opt_less_than, "abc")
        ';
    }
--- request
GET /t
--- response_body
Cannot create validator for non-number check_val.
--- no_error_log
[error]


=== TEST 44: Validator.less_than
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
'blah' claim is required.
true
false
false
--- no_error_log
[error]


=== TEST 45: Validator.opt_less_than_or_equal
--- http_config eval: $::HttpConfig
--- config
    location /t {
        content_by_lua '
            local validators = require "resty.jwt-validators"
            local tval = validators.opt_less_than_or_equal(42)
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


=== TEST 46: Validator.opt_less_than_or_equal invalid value
--- http_config eval: $::HttpConfig
--- config
    location /t {
        content_by_lua '
            local validators = require "resty.jwt-validators"
            __runSay(validators.opt_less_than_or_equal, "abc")
        ';
    }
--- request
GET /t
--- response_body
Cannot create validator for non-number check_val.
--- no_error_log
[error]


=== TEST 47: Validator.less_than_or_equal
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
'blah' claim is required.
true
true
false
--- no_error_log
[error]


=== TEST 48: Validator.opt_is_not_before
--- http_config eval: $::HttpConfig
--- config
    location /t {
        content_by_lua '
            local validators = require "resty.jwt-validators"
            local tval = validators.opt_is_not_before()
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
'foo' is malformed.  Expected to be a positive numeric value.
true
true
'future' claim not valid until Wed, 21 Apr 2100 22:09:58 GMT
--- no_error_log
[error]


=== TEST 49: Validator.set_system_leeway invalid leeway
--- http_config eval: $::HttpConfig
--- config
    location /t {
        content_by_lua '
            local validators = require "resty.jwt-validators"
            __runSay(validators.set_system_leeway, "abc")
        ';
    }
--- request
GET /t
--- response_body
leeway must be a non-negative number
--- no_error_log
[error]


=== TEST 50: Validator.set_system_leeway negative leeway
--- http_config eval: $::HttpConfig
--- config
    location /t {
        content_by_lua '
            local validators = require "resty.jwt-validators"
            __runSay(validators.set_system_leeway, -1)
        ';
    }
--- request
GET /t
--- response_body
leeway must be a non-negative number
--- no_error_log
[error]


=== TEST 51: Validator.set_system_clock invalid
--- http_config eval: $::HttpConfig
--- config
    location /t {
        content_by_lua '
            local validators = require "resty.jwt-validators"
            __runSay(validators.set_system_clock, "abc")
        ';
    }
--- request
GET /t
--- response_body
clock must be a function
--- no_error_log
[error]


=== TEST 52: Validator.set_system_clock returns invalid time
--- http_config eval: $::HttpConfig
--- config
    location /t {
        content_by_lua '
            local validators = require "resty.jwt-validators"
            __runSay(validators.set_system_clock, function() return "abc" end)
        ';
    }
--- request
GET /t
--- response_body
clock function must return a non-negative number
--- no_error_log
[error]


=== TEST 53: Validator.set_system_clock returns negative time
--- http_config eval: $::HttpConfig
--- config
    location /t {
        content_by_lua '
            local validators = require "resty.jwt-validators"
            __runSay(validators.set_system_clock, function() return -1 end)
        ';
    }
--- request
GET /t
--- response_body
clock function must return a non-negative number
--- no_error_log
[error]


=== TEST 54: Validator.opt_is_not_before with leeway
--- http_config eval: $::HttpConfig
--- config
    location /t {
        content_by_lua '
            local validators = require "resty.jwt-validators"
            validators.set_system_leeway(3153600000)
            local tval = validators.opt_is_not_before()
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
'foo' is malformed.  Expected to be a positive numeric value.
true
true
true
--- no_error_log
[error]


=== TEST 55: Validator.opt_is_not_before specific time
--- http_config eval: $::HttpConfig
--- config
    location /t {
        content_by_lua '
            local validators = require "resty.jwt-validators"
            validators.set_system_clock(function() return 956354999 end)
            local tval = validators.opt_is_not_before()
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
'foo' is malformed.  Expected to be a positive numeric value.
true
true
true
'future' claim not valid until Fri, 21 Apr 2000 22:10:00 GMT
--- no_error_log
[error]



=== TEST 56: Validator.opt_is_not_before specific time and leeway
--- http_config eval: $::HttpConfig
--- config
    location /t {
        content_by_lua '
            local validators = require "resty.jwt-validators"
            validators.set_system_leeway(1)
            validators.set_system_clock(function() return 956354999 end)
            local tval = validators.opt_is_not_before()
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
'foo' is malformed.  Expected to be a positive numeric value.
true
true
true
true
--- no_error_log
[error]


=== TEST 57: Validator.is_not_before
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
'foo' is malformed.  Expected to be a positive numeric value.
'blah' claim is required.
true
'future' claim not valid until Wed, 21 Apr 2100 22:09:58 GMT
--- no_error_log
[error]

=== TEST 58: Validator.opt_is_not_expired
--- http_config eval: $::HttpConfig
--- config
    location /t {
        content_by_lua '
            local validators = require "resty.jwt-validators"
            local tval = validators.opt_is_not_expired()
            local obj = {
              header = { type="JWT", alg="HS256" },
              payload = { foo="bar", past=956354998, future=4112028598, near_future=(ngx.time()+1) }
            }
            __testValidator(tval, "foo", obj)
            __testValidator(tval, "blah", obj)
            __testValidator(tval, "past", obj)
            __testValidator(tval, "future", obj)

            __testValidator(tval, "near_future", obj)
           ngx.sleep(2)
           local cjson = require "cjson.safe"
           local status, rslt = pcall(tval, obj.payload["near_future"], "near_future", cjson.encode(obj))
           if rslt == true then
              ngx.say("near_future claim is still valid")
           else
              ngx.say("near_future claim expired")
           end
        ';
    }
--- request
GET /t
--- response_body
'foo' is malformed.  Expected to be a positive numeric value.
true
'past' claim expired at Fri, 21 Apr 2000 22:09:58 GMT
true
true
near_future claim expired
--- no_error_log
[error]


=== TEST 59: Validator.opt_is_not_expired with leeway
--- http_config eval: $::HttpConfig
--- config
    location /t {
        content_by_lua '
            local validators = require "resty.jwt-validators"
            validators.set_system_leeway(3153600000)
            local tval = validators.opt_is_not_expired()
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
'foo' is malformed.  Expected to be a positive numeric value.
true
true
true
--- no_error_log
[error]


=== TEST 60: Validator.opt_is_not_expired specific time
--- http_config eval: $::HttpConfig
--- config
    location /t {
        content_by_lua '
            local validators = require "resty.jwt-validators"
            validators.set_system_clock(function() return 956354999 end)
            local tval = validators.opt_is_not_expired()
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
'foo' is malformed.  Expected to be a positive numeric value.
true
'past' claim expired at Fri, 21 Apr 2000 22:09:58 GMT
'now' claim expired at Fri, 21 Apr 2000 22:09:59 GMT
true
--- no_error_log
[error]



=== TEST 61: Validator.opt_is_not_expired specific time and leeway
--- http_config eval: $::HttpConfig
--- config
    location /t {
        content_by_lua '
            local validators = require "resty.jwt-validators"
            validators.set_system_leeway(1)
            validators.set_system_clock(function() return 956354999 end)
            local tval = validators.opt_is_not_expired()
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
'foo' is malformed.  Expected to be a positive numeric value.
true
'past' claim expired at Fri, 21 Apr 2000 22:09:58 GMT
true
true
--- no_error_log
[error]


=== TEST 62: Validator.is_not_expired
--- http_config eval: $::HttpConfig
--- config
    location /t {
        content_by_lua '
            local validators = require "resty.jwt-validators"
            local tval = validators.is_not_expired()
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
'foo' is malformed.  Expected to be a positive numeric value.
'blah' claim is required.
'past' claim expired at Fri, 21 Apr 2000 22:09:58 GMT
true
--- no_error_log
[error]


=== TEST 63: Validator.chain with multiples
--- http_config eval: $::HttpConfig
--- config
    location /t {
        content_by_lua '
            local validators = require "resty.jwt-validators"
            local tval = validators.chain(function(val, claim)
              ngx.say("1 - " .. claim)
            end, function(val, claim)
              ngx.say("2 - " .. (val or "nil"))
              return true
            end, function(val, claim)
              ngx.say("3 - " .. claim .. " - " .. (val or "nil"))
              return val ~= "bar"
            end, function(val, claim)
              error("ONLY BLAH")
            end)
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
1 - foo
2 - bar
3 - foo - bar
false
1 - blah
2 - nil
3 - blah - nil
ONLY BLAH
--- no_error_log
[error]


=== TEST 64: Validator.require_one_of
--- http_config eval: $::HttpConfig
--- config
    location /t {
        content_by_lua '
            local validators = require "resty.jwt-validators"
            local tval = validators.require_one_of({ "foo", "blah" })
            local obj = {
              header = { type="JWT", alg="HS256" },
              payload = { foo="bar" }
            }
            __testValidator(tval, "__jwt", obj)
        ';
    }
--- request
GET /t
--- response_body
true
--- no_error_log
[error]


=== TEST 65: Validator.require_one_of no match
--- http_config eval: $::HttpConfig
--- config
    location /t {
        content_by_lua '
            local validators = require "resty.jwt-validators"
            local tval = validators.require_one_of({ "blah", "baz" })
            local obj = {
              header = { type="JWT", alg="HS256" },
              payload = { foo="bar" }
            }
            __testValidator(tval, "__jwt", obj)
        ';
    }
--- request
GET /t
--- response_body
Missing one of claims - [ blah, baz ].
--- no_error_log
[error]


=== TEST 66: Validator.require_one_of missing object
--- http_config eval: $::HttpConfig
--- config
    location /t {
        content_by_lua '
            local validators = require "resty.jwt-validators"
            local tval = validators.require_one_of({ "foo", "blah" })
            __testValidator(tval, "__jwt", nil)
        ';
    }
--- request
GET /t
--- response_body
'__jwt' is malformed.  Expected to be a table.
--- no_error_log
[error]


=== TEST 67: Validator.require_one_of missing payload
--- http_config eval: $::HttpConfig
--- config
    location /t {
        content_by_lua '
            local validators = require "resty.jwt-validators"
            local tval = validators.require_one_of({ "foo", "blah" })
            local obj = {
              header = { type="JWT", alg="HS256" },
            }
            __testValidator(tval, "__jwt", obj)
        ';
    }
--- request
GET /t
--- response_body
'__jwt.payload' is malformed.  Expected to be a table.
--- no_error_log
[error]


=== TEST 68: Validator.require_one_of non-string keys
--- http_config eval: $::HttpConfig
--- config
    location /t {
        content_by_lua '
            local validators = require "resty.jwt-validators"
            __runSay(validators.require_one_of, { "foo", true })
        ';
    }
--- request
GET /t
--- response_body
Cannot create validator for non-string table claim_keys.
--- no_error_log
[error]


=== TEST 69: Validator.require_one_of empty keys
--- http_config eval: $::HttpConfig
--- config
    location /t {
        content_by_lua '
            local validators = require "resty.jwt-validators"
            __runSay(validators.require_one_of, {})
        ';
    }
--- request
GET /t
--- response_body
Cannot create validator for empty table claim_keys.
--- no_error_log
[error]


=== TEST 70: Validator.require_one_of invalid keys
--- http_config eval: $::HttpConfig
--- config
    location /t {
        content_by_lua '
            local validators = require "resty.jwt-validators"
            __runSay(validators.require_one_of, "abc")
        ';
    }
--- request
GET /t
--- response_body
Cannot create validator for non-table claim_keys.
--- no_error_log
[error]


=== TEST 71: Validator.require_one_of missing keys
--- http_config eval: $::HttpConfig
--- config
    location /t {
        content_by_lua '
            local validators = require "resty.jwt-validators"
            __runSay(validators.require_one_of)
        ';
    }
--- request
GET /t
--- response_body
Cannot create validator for nil claim_keys.
--- no_error_log
[error]


=== TEST 72: Validator.opt_is_at
--- http_config eval: $::HttpConfig
--- config
    location /t {
        content_by_lua '
            local validators = require "resty.jwt-validators"
            local tval = validators.opt_is_at()
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
'foo' is malformed.  Expected to be a positive numeric value.
true
'past' claim is only valid at Fri, 21 Apr 2000 22:09:58 GMT
'future' claim is only valid at Wed, 21 Apr 2100 22:09:58 GMT
--- no_error_log
[error]


=== TEST 73: Validator.opt_is_at with leeway
--- http_config eval: $::HttpConfig
--- config
    location /t {
        content_by_lua '
            local validators = require "resty.jwt-validators"
            validators.set_system_leeway(3153600000)
            local tval = validators.opt_is_at()
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
'foo' is malformed.  Expected to be a positive numeric value.
true
true
true
--- no_error_log
[error]


=== TEST 74: Validator.opt_is_at specific time
--- http_config eval: $::HttpConfig
--- config
    location /t {
        content_by_lua '
            local validators = require "resty.jwt-validators"
            validators.set_system_clock(function() return 956354999 end)
            local tval = validators.opt_is_at()
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
'foo' is malformed.  Expected to be a positive numeric value.
true
'past' claim is only valid at Fri, 21 Apr 2000 22:09:58 GMT
true
'future' claim is only valid at Fri, 21 Apr 2000 22:10:00 GMT
--- no_error_log
[error]



=== TEST 75: Validator.opt_is_at specific time and leeway
--- http_config eval: $::HttpConfig
--- config
    location /t {
        content_by_lua '
            local validators = require "resty.jwt-validators"
            validators.set_system_leeway(1)
            validators.set_system_clock(function() return 956354999 end)
            local tval = validators.opt_is_at()
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
'foo' is malformed.  Expected to be a positive numeric value.
true
true
true
true
--- no_error_log
[error]


=== TEST 76: Validator.is_at
--- http_config eval: $::HttpConfig
--- config
    location /t {
        content_by_lua '
            local validators = require "resty.jwt-validators"
            local tval = validators.is_at()
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
'foo' is malformed.  Expected to be a positive numeric value.
'blah' claim is required.
'past' claim is only valid at Fri, 21 Apr 2000 22:09:58 GMT
'future' claim is only valid at Wed, 21 Apr 2100 22:09:58 GMT
--- no_error_log
[error]


=== TEST 77: Validator.opt_contains_any_of
--- http_config eval: $::HttpConfig
--- config
    location /t {
        content_by_lua '
            local validators = require "resty.jwt-validators"
            local tval = validators.opt_contains_any_of({ "roleFoo", "roleBar" }, "roles")
            local obj1 = {
              header = { type="JWT", alg="HS256" },
              payload = { foo="bar", baz="boo", num=42, roles={ "roleFoo", "roleBaz" } }
            }
            local obj2 = {
              header = { type="JWT", alg="HS256" },
              payload = { foo="bar", baz="boo", num=42, roles={ "roleBar", "roleBaz" } }
            }
            local obj3 = {
              header = { type="JWT", alg="HS256" },
              payload = { foo="bar", baz="boo", num=42, roles="roleFoo" }
            }
            local obj4 = {
              header = { type="JWT", alg="HS256" },
              payload = { foo="bar", baz="boo", num=42, roles={ "roleBoo", "roleBaz" } }
            }
            __testValidator(tval, "roles", obj1)
            __testValidator(tval, "roles", obj2)
            __testValidator(tval, "roles", obj3)
            __testValidator(tval, "roles", obj4)
        ';
    }
--- request
GET /t
--- response_body
true
true
'roles' is malformed.  Expected to be a table.
false
--- no_error_log
[error]


=== TEST 78: Validator.opt_contains_any_of number
--- http_config eval: $::HttpConfig
--- config
    location /t {
        content_by_lua '
            local validators = require "resty.jwt-validators"
            __runSay(validators.opt_contains_any_of, { 41, 42 }, "table-claim")
        ';
    }
--- request
GET /t
--- response_body
Cannot create validator for non-string table table-claim.
--- no_error_log
[error]


=== TEST 79: Validator.opt_contains_any_of empty table
--- http_config eval: $::HttpConfig
--- config
    location /t {
        content_by_lua '
            local cjson = require "cjson.safe"
            local validators = require "resty.jwt-validators"
            __runSay(validators.opt_contains_any_of, {}, "table-claim")
        ';
    }
--- request
GET /t
--- response_body
Cannot create validator for empty table table-claim.
--- no_error_log
[error]


=== TEST 80: Validator.opt_contains_any_of invalid table
--- http_config eval: $::HttpConfig
--- config
    location /t {
        content_by_lua '
            local cjson = require "cjson.safe"
            local validators = require "resty.jwt-validators"
            __runSay(validators.opt_contains_any_of, "abc", "table-claim")
        ';
    }
--- request
GET /t
--- response_body
Cannot create validator for non-table table-claim.
--- no_error_log
[error]


=== TEST 81: Validator.opt_contains_any_of mixed type table
--- http_config eval: $::HttpConfig
--- config
    location /t {
        content_by_lua '
            local cjson = require "cjson.safe"
            local validators = require "resty.jwt-validators"
            __runSay(validators.opt_contains_any_of, { "abc", 123 }, "table-claim")
        ';
    }
--- request
GET /t
--- response_body
Cannot create validator for non-string table table-claim.
--- no_error_log
[error]


=== TEST 82: Validator.opt_contains_any_of non-string
--- http_config eval: $::HttpConfig
--- config
    location /t {
        content_by_lua '
            local cjson = require "cjson.safe"
            local validators = require "resty.jwt-validators"
            __runSay(validators.opt_contains_any_of, { 41, 42 }, "table-claim")
        ';
    }
--- request
GET /t
--- response_body
Cannot create validator for non-string table table-claim.
--- no_error_log
[error]


=== TEST 83: Validator.contains_any_of
--- http_config eval: $::HttpConfig
--- config
    location /t {
        content_by_lua '
            local validators = require "resty.jwt-validators"

            local tval = validators.contains_any_of({ "roleFoo", "roleBar" }, "roles")
            local obj1 = {
              header = { type="JWT", alg="HS256" },
              payload = { foo="bar", baz="boo", num=42, roles={ "roleFoo", "roleBaz" } }
            }
            local obj2 = {
              header = { type="JWT", alg="HS256" },
              payload = { foo="bar", baz="boo", num=42, roles={ "roleBar", "roleBaz" } }
            }
            local obj3 = {
              header = { type="JWT", alg="HS256" },
              payload = { foo="bar", baz="boo", num=42, roles="roleFoo" }
            }
            local obj4 = {
              header = { type="JWT", alg="HS256" },
              payload = { foo="bar", baz="boo", num=42, roles={ "roleBaz", "roleBoo" } }
            }
            __testValidator(tval, "roles", obj1)
            __testValidator(tval, "roles", obj2)
            __testValidator(tval, "roles", obj3)
            __testValidator(tval, "roles", obj4)
        ';
    }
--- request
GET /t
--- response_body
true
true
'roles' is malformed.  Expected to be a table.
false
--- no_error_log
[error]
