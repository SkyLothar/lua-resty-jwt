local _M = {_VERSION="0.1.3"}

--[[
  This file defines "validators" to be used in validating a spec.  A "validator" is simply a function with
  a signature that matches:

    function(val, claim, jwt_obj)

  This function returns either true or false.  If a validator needs to give more information on why it failed,
  then it can also raise an error (which will be used in the "reason" part of the validated jwt_obj).  If a
  validator returns nil, then it is assumed to have passed (same as returning true) and that you just forgot
  to actually return a value.

  "val" is the value being tested.  It may be nil if the claim doesn't exist in the jwt_obj.  It will also be 
  nil if the validator is being called for the full object.

  "claim" is the claim that is being tested.  It is passed in just in case a validator needs to do additional
  checks.  It will be nil if the validator is being called for the full object.

  "jwt_obj" is the full object that is being tested.  It will never be nil.
]]--


-- Validation messages
local messages = {
  nil_validator = "Cannot create validator for nil %s",
  wrong_type_validator = "Cannot create validator for non-%s %s",
  empty_table_validator = "Cannot create validator for empty table %s",
  wrong_table_type_validator = "Cannot create validator for non-%s table %s",
  required_claim = "'%s' claim is required.",
  wrong_type_claim = "'%s' is malformed.  Expected to be a %s."
}

-- Local function to make sure that a value is non-nil or raises an error
local function ensure_not_nil(v, e, ...)
  return v ~= nil and v or error(string.format(e, ...))
end

-- Local function to make sure that a value is the given type
local function ensure_is_type(v, t, e, ...)
  return type(v) == t and v or error(string.format(e, ...))
end

-- Local function to make sure that a value is a (non-empty) table
local function ensure_is_table(v, e, ...)
  ensure_is_type(v, "table", e, ...)
  return ensure_not_nil(next(v), e, ...)
end

-- Local function to make sure all entries in the table are the given type
local function ensure_is_table_type(v, t, e, ...)
  if v ~= nil then
    ensure_is_table(v, e, ...)
    for _,val in ipairs(v) do
      ensure_is_type(val, t, e, ...)
    end
  end
  return v
end

-- Local function to ensure that a number is non-negative (positive or 0)
local function ensure_is_non_negative(v, e, ...)
  if v ~= nil then
    ensure_is_type(v, "number", e, ...)
    if v >= 0 then
      return v
    else
      error(string.format(e, ...))
    end
  end
end

-- A local function which returns simple equality
local function equality_function(val, check)
  return val == check
end

-- A local function which returns string match
local function string_match_function(val, pattern)
  return string.match(val, pattern) ~= nil
end

-- A local function which returns numeric greater than comparison
local function greater_than_function(val, check)
  return val > check
end

-- A local function which returns numeric greater than or equal comparison
local function greater_than_or_equal_function(val, check)
  return val >= check
end

-- A local function which returns numeric less than comparison
local function less_than_function(val, check)
  return val < check
end

-- A local function which returns numeric less than or equal comparison
local function less_than_or_equal_function(val, check)
  return val <= check
end


--[[
    Returns a validator that returns false if a value doesn't exist.  If
    the value exists and a chain_function is specified, then the value of 
        chain_function(val, claim, jwt_obj)
    will be returned, otherwise, true will be returned.  This allows for 
    specifying that a value is both required *and* it must match some 
    additional check.  This function will be used in the "required_*" shortcut
    functions for simplification.
]]--
function _M.required(chain_function)
  if chain_function ~= nil then
    ensure_is_type(chain_function, "function", messages.wrong_type_validator, "function", "chain_function")
  end
  return function(val, claim, jwt_obj)
    ensure_not_nil(val, messages.required_claim, claim)
    
    if chain_function ~= nil then
      -- Chain function exists - call it
      return chain_function(val, claim, jwt_obj)
    else
      -- Value exists, but no chain function, just return true
      return true
    end
  end
end

--[[
    Returns a validator that checks if the result of calling the given function for
    the tested value and the check value returns true.  If the tested value is nil, 
    then this check succeeds.  The value of check_val and check_function cannot be nil.
    The optional name is used for error messages and defaults to "check_value".  The 
    optional check_type is used to make sure that the check type matches and defaults
    to type(check_val).  The first parameter passed to check_function will *never* be
    nil (check succeeds if value is nil).  Use the required version to fail on nil.
]]--
function _M.check(check_val, check_function, name, check_type)
  name = name or "check_val"
  ensure_not_nil(check_val, messages.nil_validator, name)
  
  ensure_not_nil(check_function, messages.nil_validator, "check_function")
  ensure_is_type(check_function, "function", messages.wrong_type_validator, "function", "check_function")
  
  check_type = check_type or type(check_val)
  return function(val, claim, jwt_obj)
    if val == nil then return true end
    
    ensure_is_type(val, check_type, messages.wrong_type_claim, claim, check_type)
    return check_function(val, check_val)
  end
end
-- And the required version
function _M.required_check(...) return _M.required(_M.check(...)) end


--[[
    Returns a validator that checks if a value exactly equals the given check_value.
    If the value is nil, then this check succeeds.  The value of check_val cannot be
    nil.
]]--
function _M.equals(check_val)
  return _M.check(check_val, equality_function, "check_val")
end
-- And the required version
function _M.required_equals(...) return _M.required(_M.equals(...)) end


--[[
    Returns a validator that checks if a value matches the given pattern.  If the
    value is nil, then this check succeeds.  The value of pattern must be a string.
]]--
function _M.matches(pattern)
  ensure_is_type(pattern, "string", messages.wrong_type_validator, "string", "pattern")
  return _M.check(pattern, string_match_function, "pattern", "string")
end
-- And the required version
function _M.required_matches(...) return _M.required(_M.matches(...)) end


--[[
    Returns a validator which calls the given function for each of the given values
    and the tested value.  If any of these calls return true, then this function
    returns true.  If the tested value is nil, then this check succeeds.  The value
    of check_values must be a non-empty table with all the same types, and the value 
    of check_function must not be nil.  The optional name is used for error messages 
    and defaults to "check_values".  The optional check_type is used to make sure that 
    the check type matches and defaults to type(check_values[1]) - the table type.
]]--
function _M.any_of(check_values, check_function, name, check_type, table_type)
  name = name or "check_values"
  ensure_not_nil(check_values, messages.nil_validator, name)
  ensure_is_type(check_values, "table", messages.wrong_type_validator, "table", name)
  ensure_is_table(check_values, messages.empty_table_validator, name)
  
  table_type = table_type or type(check_values[1])
  ensure_is_table_type(check_values, table_type, messages.wrong_table_type_validator, table_type, name)
  
  ensure_not_nil(check_function, messages.nil_validator, "check_function")
  ensure_is_type(check_function, "function", messages.wrong_type_validator, "function", "check_function")
  
  check_type = check_type or table_type
  return _M.check(check_values, function(v1, v2)
    for i, v in ipairs(v2) do
      if check_function(v1, v) then return true end
    end
    return false
  end, name, check_type)
end
-- And the required version
function _M.required_any_of(...) return _M.required(_M.any_of(...)) end


--[[
    Returns a validator that checks if a value exactly equals any of the given values.
    If the value is nil, then this check succeeds.
]]--
function _M.equals_any_of(check_values)
  return _M.any_of(check_values, equality_function, "check_values")
end
-- And the required version
function _M.required_equals_any_of(...) return _M.required(_M.equals_any_of(...)) end


--[[
    Returns a validator that checks if a value matches any of the given patterns.
    If the value is nil, then this check succeeds.
]]--
function _M.matches_any_of(patterns)
  return _M.any_of(patterns, string_match_function, "patterns", "string", "string")
end
-- And the required version
function _M.required_matches_any_of(...) return _M.required(_M.matches_any_of(...)) end


--[[
    Returns a validator that checks how a value compares (numerically) to a given 
    check_value.  If the value is nil, then this check succeeds.  The value of 
    check_val cannot be nil and must be a number.
]]--
function _M.greater_than(check_val)
  ensure_is_type(check_val, "number", messages.wrong_type_validator, "number", "check_val")
  return _M.check(check_val, greater_than_function, "check_val", "number")
end
function _M.greater_than_or_equal(check_val)
  ensure_is_type(check_val, "number", messages.wrong_type_validator, "number", "check_val")
  return _M.check(check_val, greater_than_or_equal_function, "check_val", "number")
end
function _M.less_than(check_val)
  ensure_is_type(check_val, "number", messages.wrong_type_validator, "number", "check_val")
  return _M.check(check_val, less_than_function, "check_val", "number")
end
function _M.less_than_or_equal(check_val)
  ensure_is_type(check_val, "number", messages.wrong_type_validator, "number", "check_val")
  return _M.check(check_val, less_than_or_equal_function, "check_val", "number")
end
-- And the required versions
function _M.required_greater_than(...) return _M.required(_M.greater_than(...)) end
function _M.required_greater_than_or_equal(...) return _M.required(_M.greater_than_or_equal(...)) end
function _M.required_less_than(...) return _M.required(_M.less_than(...)) end
function _M.required_less_than_or_equal(...) return _M.required(_M.less_than_or_equal(...)) end


--[[
    A function to set the leeway (in seconds) used for is_not_before and is_not_expired.  The
    default is to use 0 seconds
]]--
local system_leeway = 0
function _M.set_system_leeway(leeway)
  ensure_is_type(leeway, "number", "leeway must be a non-negative number")
  ensure_is_non_negative(leeway, "leeway must be a non-negative number")
  system_leeway = leeway
end


--[[
    A function to set the system clock used for is_not_before and is_not_expired.  The
    default is to use ngx.now
]]--
local system_clock = ngx.now
function _M.set_system_clock(clock)
  ensure_is_type(clock, "function", "clock must be a function")
  
  -- Check that clock returns the correct value
  local t = clock()
  ensure_is_type(t, "number", "clock function must return a non-negative number")
  ensure_is_non_negative(t, "clock function must return a non-negative number")
  system_clock = clock
end


--[[
    Returns a validator that checks if the current time is not before the tested value
    within the system's leeway.  This means that:
      val <= (system_clock() + system_leeway).
    If the value is nil, then this check succeeds.
]]--
function _M.is_not_before()
  return _M.less_than_or_equal(system_clock() + system_leeway)
end
-- And the required version
function _M.required_is_not_before(...) return _M.required(_M.is_not_before(...)) end


--[[
    Returns a validator that checks if the current time is not equal to or after the 
    tested value within the system's leeway.  This means that:
      val > (system_clock() - system_leeway).
    If the value is nil, then this check succeeds.
]]--
function _M.is_not_expired()
  return _M.greater_than(system_clock() - system_leeway)
end
-- And the required version
function _M.required_is_not_expired(...) return _M.required(_M.is_not_expired(...)) end


return _M
