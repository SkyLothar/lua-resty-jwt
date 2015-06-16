local function redkey(kid)
    -- get key from redis
    -- nil  (something went wrong, let the request pass)
    -- null (no such key, reject the request)
    -- key  (the key)

    local redis = require "resty.redis"
    local red = redis:new()
    red:set_timeout(100) -- 100ms

    local ok, err = red:connect(ngx.var.redhost, ngx.var.redport)
    if not ok then
        ngx.log(ngx.ERR, "failed to connect to redis: ", err)
        return nil
    end

    if ngx.var.redauth then
        local ok, err = red:auth(ngx.var.redauth)
        if not ok then
            ngx.log("failed to authenticate: ", err)
            return nil
        end
    end

    if ngx.var.reddb then
        local ok, err = red:select(ngx.var.reddb)
        if not ok then
            ngx.log("failed to select db: ", ngx.var.reddb, " ", err)
            return nil
        end
    end

    local res, err = red:get(kid)
    if not res then
        ngx.log(ngx.ERR, "failed to get kid: ", kid ,", ", err)
        return nil
    end

    if res == ngx.null then
        ngx.log(ngx.ERR, "key ", kid, " not found")
        return ngx.null
    end

    local ok, err = red:close()
    if not ok then
        ngx.log(ngx.ERR, "failed to close: ", err)
    end

    return res
end


local jwt = require "resty.jwt"

local jwt_obj = jwt:load_jwt(ngx.var.arg_jwt)
if not jwt_obj.valid then
  ngx.status = ngx.HTTP_BAD_REQUEST
  ngx.say("invalid jwt")
  ngx.exit(ngx.HTTP_OK)
end
local kid = jwt_obj.header.kid
if kid == nil then
  ngx.status = ngx.HTTP_BAD_REQUEST
  ngx.say("missing kid")
  ngx.exit(ngx.HTTP_OK)
end

local jwt_key_dict= ngx.shared.jwt_key_dict
local key = jwt_key_dict:get(kid)
local flush = false
if key == nil then
    -- key not found in cache, let's check if it's in redis
    -- new key found, if the new key is valid, older ones should be deleted
    key = redkey(kid)
    flush = true
end

if key == ngx.null then
    -- no such key
    ngx.status = ngx.HTTP_UNAUTHORIZED
    ngx.say("your kid: [", kid ,"] is not valid")
    ngx.exit(ngx.HTTP_OK)
elseif key == nil then
    -- get key error
    ngx.say("something wrong with our server. I'll let you pass this time")
else
    local verified = jwt:verify_jwt_obj(key, jwt_obj, 30)

    if not verified.verified then
        ngx.status = ngx.HTTP_UNAUTHORIZED
        ngx.say(jwt_obj.reason)
        ngx.exit(ngx.HTTP_OK)
    end

    if flush then
        -- flush all cached keys, if a new valid key showd up
        -- the older ones were expired
        jwt_key_dict:flush_all()
        jwt_key_dict:set(kid, key)
    end
end
