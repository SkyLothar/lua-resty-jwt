local cjson = require "cjson"
local hmac = require "resty.hmac"

local _M = {_VERSION="0.0.1"}
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


local function parse(token_str, secret, issuer)
    local basic_jwt = {}
    local raw_header, raw_payload, signature = string.match(
        token_str,
        '([^%.]+)%.([^%.]+)%.([^%.]+)'
    )
    local basic_jwt = {
        raw_header=raw_header,
        raw_payload=raw_payload,
        header=_M:jwt_decode(raw_header, true),
        payload=_M:jwt_decode(raw_payload, true),
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


function _M.verify(self, secret, jwt_str, leeway)
    local success, ret = pcall(parse, jwt_str)
    local jwt_obj = ret
    if not success then
        return {verified=false, reason=ret["reason"] or "invalid jwt string"}
    end

    jwt_obj["verified"] = false
    local success, ret = pcall(_M.sign, nil, secret, jwt_obj)
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
            jwt_obj["reason"] = "jwt token expired at: " .. ngx.http_time(exp)
        elseif type(nbf) == "number" and nbf > (now + leeway) then
            jwt_obj["reason"] = "jwt token not valid until: " .. ngx.http_time(nbf)
        end
    end

    if jwt_obj["reason"] == nil then
        jwt_obj["verified"] = true
        jwt_obj["reason"] = "everything is awesome~ :p"
    end
    return jwt_obj
end

return _M
