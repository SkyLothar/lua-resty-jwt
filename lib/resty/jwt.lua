local cjson = require "cjson"
local hmac = require "resty.hmac"

local _M = {_VERSION="0.1.0"}
local mt = {__index=_M}


local function get_raw_part(part_name, jwt_obj)
    local raw_part = jwt_obj["raw_" .. part_name]
    if raw_part == nil then
        local part = jwt_obj[part_name]
        if part == nil then
            error({reason="missing part " .. part_name})
        end
        raw_part = _M:jwt_encode(part)
    end
    return raw_part
end


local function parse(token_str)
    local basic_jwt = {}
    local raw_header, raw_payload, signature = string.match(
        token_str,
        '([^%.]+)%.([^%.]+)%.([^%.]+)'
    )
    local header = _M:jwt_decode(raw_header, true)
    if not header then
        error({reason="invalid header: " .. raw_header})
    end

    local payload = _M:jwt_decode(raw_payload, true)
    if not payload then
        error({reason="invalid payload: " .. raw_payload})
    end

    local basic_jwt = {
        raw_header=raw_header,
        raw_payload=raw_payload,
        header=header,
        payload=payload,
        signature=signature
    }
    return basic_jwt
end


function _M.jwt_encode(self, ori)
    if type(ori) == "table" then
        ori = cjson.encode(ori)
    end
    return ngx.encode_base64(ori):gsub("+", "-"):gsub("/", "_"):gsub("=", "")
end


function _M.jwt_decode(self, b64_str, json_decode)
    local reminder = #b64_str % 4
    if reminder > 0 then
        b64_str = b64_str .. string.rep("=", 4 - reminder)
    end
    local data = ngx.decode_base64(b64_str)
    if not data then
        return nil
    end
    if json_decode then
        data = cjson.decode(data)
    end
    return data
end


function _M.sign(self, secret_key, jwt_obj)
    -- header typ check
    local typ = jwt_obj["header"]["typ"]
    if typ ~= "JWT" then
        error({reason="invalid typ: " .. typ})
    end
    -- header alg check
    local alg = jwt_obj["header"]["alg"]
    local hash_alg = nil
    if alg == "HS256" then
        hash_alg = hmac.ALGOS.SHA256
    elseif alg == "HS512" then
        hash_alg = hmac.ALGOS.SHA512
    else
        error({reason="unsupported alg: " .. alg})
    end
    -- assemble jwt parts
    local raw_header = get_raw_part("header", jwt_obj)
    local raw_payload = get_raw_part("payload", jwt_obj)

    local message =raw_header ..  "." ..  raw_payload
    -- cal signature
    local hmac_func = hmac:new(secret_key, hash_alg)
    local signature = _M:jwt_encode(hmac_func:final(message))
    -- return full jwt string
    return message .. "." .. signature
end


function _M.load_jwt(self, jwt_str)
    local success, ret = pcall(parse, jwt_str)
    if not success then
        return {
            valid=false,
            verified=false,
            reason=ret["reason"] or "invalid jwt string"
        }
    end

    local jwt_obj = ret
    jwt_obj["verified"] = false
    jwt_obj["valid"] = true
    return jwt_obj
end


function _M.verify_jwt_obj(self, secret, jwt_obj, leeway)
    local jwt_str = jwt_obj.raw_header .. 
        "." .. jwt_obj.raw_payload ..
        "." .. jwt_obj.signature

    if not jwt_obj.valid then
        return jwt_obj
    end
    local success, ret = pcall(_M.sign, self, secret, jwt_obj)
    if not success then
        -- syntax check
        jwt_obj["reason"] = ret["reason"] or "internal error"
    elseif jwt_str ~= ret then
        -- signature check
        jwt_obj["reason"] = "signature mismatch: " .. jwt_obj["signature"]
    elseif leeway ~= nil then
        local exp = jwt_obj["payload"]["exp"]
        local nbf = jwt_obj["payload"]["nbf"]
        local now = ngx.now()

        if type(exp) == "number" and exp < (now - leeway) then
            jwt_obj["reason"] = "jwt token expired at: " ..
                ngx.http_time(exp)
        elseif type(nbf) == "number" and nbf > (now + leeway) then
            jwt_obj["reason"] = "jwt token not valid until: " ..
                ngx.http_time(nbf)
        end
    end

    if jwt_obj["reason"] == nil then
        jwt_obj["verified"] = true
        jwt_obj["reason"] = "everything is awesome~ :p"
    end
    return jwt_obj
end


function _M.verify(self, secret, jwt_str, leeway)
    jwt_obj = _M.load_jwt(self, jwt_str)
    if not jwt_obj.valid then
         return {verified=false, reason=jwt_obj["reason"]}
    end

    return _M.verify_jwt_obj(self, secret, jwt_obj, leeway)
end

return _M
