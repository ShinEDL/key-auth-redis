local cache = require "kong.tools.database_cache"
local responses = require "kong.tools.responses"
local constants = require "kong.constants"
local singletons = require "kong.singletons"
local BasePlugin = require "kong.plugins.base_plugin"

local ngx_set_header = ngx.req.set_header
local ngx_get_headers = ngx.req.get_headers
local set_uri_args = ngx.req.set_uri_args
local get_uri_args = ngx.req.get_uri_args
local clear_header = ngx.req.clear_header
local type = type

local _realm = 'Key realm="'.._KONG._NAME..'"'
-- 引入redis模块
local redis = require "resty.redis"
-- 引入crud模块
local crud = require "kong.api.crud_helpers"
-- reports utils
local reports = require "kong.core.reports"
local utils = require "kong.tools.utils"

local KeyAuthHandler = BasePlugin:extend()

KeyAuthHandler.PRIORITY = 1000

function KeyAuthHandler:new()
  KeyAuthHandler.super.new(self, "key-auth-redis")
end

local function load_credential(key)
  local creds, err = singletons.dao.keyauth_credentials:find_all {
    key = key
  }
  if not creds then
    return nil, err
  end
  return creds[1]
end

local function load_consumer(consumer_id, anonymous)
  local result, err = singletons.dao.consumers:find { id = consumer_id }
  if not result then
    if anonymous and not err then
      err = 'anonymous consumer "'..consumer_id..'" not found'
    end
    return nil, err
  end
  return result
end

local function set_consumer(consumer, credential)
  ngx_set_header(constants.HEADERS.CONSUMER_ID, consumer.id)
  ngx_set_header(constants.HEADERS.CONSUMER_CUSTOM_ID, consumer.custom_id)
  ngx_set_header(constants.HEADERS.CONSUMER_USERNAME, consumer.username)
  ngx.ctx.authenticated_consumer = consumer
  if credential then
    ngx_set_header(constants.HEADERS.CREDENTIAL_USERNAME, credential.username)
    ngx.ctx.authenticated_credential = credential
    ngx_set_header(constants.HEADERS.ANONYMOUS, nil) -- in case of auth plugins concatenation
  else
    ngx_set_header(constants.HEADERS.ANONYMOUS, true)
  end
end

-- 连接redis方法
local function connect_to_redis(conf)
  local red = redis:new()

  red:set_timeout(conf.redis_timeout)
  
  local ok, err = red:connect(conf.redis_host, conf.redis_port)
  if err then
    return nil, err
  end

  if conf.redis_password and conf.redis_password ~= "" then
    local ok, err = red:auth(conf.redis_password)
    if err then
      return nil, err
    end
  end
  
  return red
end

-- 通过username获取consumer id
local function get_consumer_id_by_name(username)
  local filter = {}
  filter.id = nil
  filter["username"] = username
  local rows, err = singletons.dao.consumers:find_all(filter)
  if err then
    -- error log
    ngx.log(ngx.ERR, "get_consumer_id_by_name consumers find_all error: ", err)
    return 
  end

  local consumer = rows[1]
  if not consumer then
    return nil, "consumer not found"
  end
  return consumer.id
end 

-- 通过API name 获取API ID
local function get_api_id_by_name(api_name)
  local filter = {}
  filter.id = nil
  filter["name"] = api_name
  local rows, err = singletons.dao.apis:find_all(filter)
  if err then
    -- error log
    ngx.log(ngx.ERR, "get_api_id_by_name consumers find_all error: ", err)
    return 
  end

  local api = rows[1]
  if not api then
    return nil, "api no found"
  end
  return api.id
end 

-- 添加rate-limiting插件
local function set_rate_limiting_plugin(conf, username, api_name)
  if conf.rate_limiting then
    local consumer_id, consumer_err = get_consumer_id_by_name(username)
    if consumer_err then 
      return nil, consumer_err
    end
    local config = {}
    if conf.second then
      config.second = conf.second
    end
    if conf.minute then
      config.minute = conf.minute
    end
    if conf.hour then
      config.hour = conf.hour
    end
    if conf.day then
      config.day = conf.day
    end
    if conf.month then
      config.month = conf.month
    end
    if conf.year then
      config.year = conf.year
    end
    config.fault_tolerant = conf.fault_tolerant
    config.limit_by = conf.limit_by
    config.policy = conf.policy
    config.redis_database = conf.redis_database
    config.redis_timeout = conf.redis_timeout
    config.redis_password = conf.redis_password
    config.redis_host = conf.redis_host
    config.redis_port = conf.redis_port
    local params = {}
    params.name = "rate-limiting"
    params.consumer_id = consumer_id
    params.config = config
    if api_name ~= nil then
      local api_id, api_err = get_api_id_by_name(api_name)
      if api_err then
        return nil, api_err
      end
      params.api_id = api_id
    end
    local data, data_err = singletons.dao.plugins:insert(params)
    if data_err then
      return nil, data_err
    end
    reports.send("api", utils.deep_copy(data))
  end 
  return true
end

-- 注册指定用户名的consumer的key(token)
local function post_consumer_key(conf, username, key, api_name)
  local consumer_id, err = get_consumer_id_by_name(username)
  if err then 
    return err
  end
  local params = {}
  params.consumer_id = consumer_id
  params.key = key
  local data, data_err = singletons.dao.keyauth_credentials:insert(params)
  if data_err then
    ngx.log(ngx.ERR, "post_consumer_key keyauth_credentials insert error: ", data_err)
  else
    local ok, err = set_rate_limiting_plugin(conf, username, api_name)
    if err then
      ngx.log(ngx.ERR, "post_consumer_key set_rate_limiting_plugin error: ", err)
    end
  end
end

local function do_authentication(conf, api_name)
  if type(conf.key_names) ~= "table" then
    ngx.log(ngx.ERR, "[key-auth-redis] no conf.key_names set, aborting plugin execution")
    return false, {status = 500, message= "Invalid plugin configuration"}
  end

  -- 连接redis
  local red, err = connect_to_redis(conf)
  if err then
    ngx.log(ngx.ERR, "failed to connect to Redis: ", err)
    return false, {status = 500, message= "Failed to connect to Redis."}
  end

  local key
  local headers = ngx_get_headers()
  local uri_args = get_uri_args()

  -- search in headers & querystring
  for i = 1, #conf.key_names do
    local name = conf.key_names[i]
    local v = headers[name]
    if not v then
      -- search in querystring
      v = uri_args[name]
    end

    if type(v) == "string" then
      key = v
      if conf.hide_credentials then
        uri_args[name] = nil
        set_uri_args(uri_args)
        clear_header(name)
      end
      break
    elseif type(v) == "table" then
      -- duplicate API key, HTTP 401 多个相同的API key请求参数
      return false, {status = 401, message = "Duplicate API key found"}
    end
  end

  -- this request is missing an API key, HTTP 401
  if not key then
    ngx.header["WWW-Authenticate"] = _realm
    return false, {status = 401, message = "No API key found in headers"
                                          .." or querystring"}
  end

  -- retrieve our consumer linked to this API key 
  -- 先在缓存查找credential，再去数据库中查找。
  -- load_credential是回调函数，执行数据库查找证书的操作。
  local credential, err = cache.get_or_set(cache.keyauth_credential_key(key),
                                      nil, load_credential, key)
  if err then
    return responses.send_HTTP_INTERNAL_SERVER_ERROR(err)
  end

  -- no credential in DB, for this key, it is invalid, HTTP 403
  if not credential then
    -- 查询redis
    local cred, err = red:get(key)
    ngx.log(ngx.INFO, "cred: ", cred)
    if not cred or cred == ngx.null then
      return false, {status = 403, message = "Invalid authentication credentials"}
    else
      -- 有凭证，则存入数据库
      local uuid = require 'resty.jit-uuid'
      local consumer_uuid = uuid.generate_v4()
      local insertConsumer, err = singletons.dao.consumers:insert({
          username = consumer_uuid
        })
      if err then
        ngx.log(ngx.ERR, "consumer err: ", err)
      else
        -- 向已生成的consumer添加key-auth
        post_consumer_key(conf, consumer_uuid, key, api_name)
      end
      return true
    end
  end

  -----------------------------------------
  -- Success, this request is authenticated
  -----------------------------------------

  -- retrieve the consumer linked to this API key, to set appropriate headers
  -- 检索链接到此 api 密钥的使用者, 以设置适当的标头
  local consumer, err = cache.get_or_set(cache.consumer_key(credential.consumer_id),
                                    nil, load_consumer, credential.consumer_id)
  if err then
    return responses.send_HTTP_INTERNAL_SERVER_ERROR(err)
  end
  set_consumer(consumer, credential)
  -- 添加rate-limiting插件

  return true
end

-- string split 
local function string_split(str, p)
  local rt= {}
  string.gsub(str, '[^'..p..']+', function(w) table.insert(rt, w) end )
  return rt
end 

function KeyAuthHandler:access(conf)
  KeyAuthHandler.super.access(self)

  if ngx.ctx.authenticated_credential and conf.anonymous ~= "" then
    -- we're already authenticated, and we're configured for using anonymous, 
    -- hence we're in a logical OR between auth methods and we're already done.
    return
  end

  local api_name = nil
  -- 获取request的 api_name
  if conf.apiname_uri_lastest then
    local uri = ngx.var.uri
    local rt = string_split(uri, '/')
    -- 取最后的productid
    api_name = rt[#rt] 
    ngx.log(ngx.INFO, "api_name: ", api_name)
  end

  local ok, err = do_authentication(conf, api_name)
  if not ok then
    if conf.anonymous ~= "" then
      -- get anonymous user
      local consumer, err = cache.get_or_set(cache.consumer_key(conf.anonymous),
                            nil, load_consumer, conf.anonymous, true)
      if err then
        responses.send_HTTP_INTERNAL_SERVER_ERROR(err)
      end
      set_consumer(consumer, nil)
    else
      return responses.send(err.status, err.message)
    end
  end

end


return KeyAuthHandler
