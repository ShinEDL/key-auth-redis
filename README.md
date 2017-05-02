# key-auth-redis
key-auth(a plugin of kong) with redis

Base on kong 0.10.1 

## 说明
key-auth插件连接redis，加强权限验证能力。



## 数据格式

- redis
	- key:key

## 验证步骤

插件正常查询credential。如果没有credential，根据key查询redis，验证key是否存在，如果存在则可以访问，并生成consumer与key存于kong数据库。

## 待验证

1. 在headers中，是否可以获取key-name?
2. 能否连接多个redis？
3. token超时更换新token