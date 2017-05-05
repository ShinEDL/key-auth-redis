local utils = require "kong.tools.utils"


local function check_user(anonymous)
  if anonymous == "" or utils.is_valid_uuid(anonymous) then
    return true
  end

  return false, "the anonymous user must be empty or a valid uuid"
end


local function check_keys(keys)
  for _, key in ipairs(keys) do
    local res, err = utils.validate_header_name(key, false)

    if not res then
      return false, "'" .. key .. "' is illegal: " .. err
    end
  end

  return true
end


local function default_key_names(t)
  if not t.key_names then
    return { "apikey" }
  end
end


return {
  no_consumer = true,
  fields = {
    key_names = {
      required = true,
      type = "array",
      default = default_key_names,
      func = check_keys,
    },
    hide_credentials = {
      type = "boolean",
      default = false,
    },
    anonymous = {
      type = "string",
      default = "",
      func = check_user,
    },
    redis_host = { type = "string", required = true },
    redis_port = { type = "number", default = 6379 },
    redis_password = { type = "string" },
    redis_timeout = { type = "number", default = 2000 },
    rate_limiting = {type = "boolean", default = false},
    second = { type = "number"},
    minute = { type = "number"},
    hour = { type = "number"},
    day = { type = "number"},
    month = { type = "number"},
    year = { type = "number"},
    limit_by = { type = "string", enum = {"consumer", "credential", "ip"}, default = "consumer" },
    policy = { type = "string", enum = {"local", "cluster", "redis"}, default = "cluster" },
    fault_tolerant = { type = "boolean", default = true },
    redis_database = { type = "number", default = 0 },
    apiname_uri_lastest = {type = "boolean", default = false}
  }
}
