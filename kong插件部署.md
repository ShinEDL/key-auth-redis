## kong 插件部署

### refers
+ https://getkong.org/docs/0.9.x/plugin-development/
+ https://github.com/Mashape/kong-plugin
+ https://github.com/brndmg/kong-plugin-hello-world
+ http://streamdata.io/blog/developing-an-helloworld-kong-plugin/


### 编码:helloworld插件
+ 代码示例在 example/helloworld


### 配置插件

+ 将lua模块(kong/plugins/helloworld)，放到kong的插件目录  
  `/usr/local/share/lua/5.1/kong/plugins/helloworld`

  具体操作
  ```
  docker cp helloworld kong:/usr/local/share/lua/5.1/kong/plugins/
  ```

+ 注册模块到kong，需进入kong容器操作

  修改`/usr/local/lib/luarocks/rocks/kong/0.8.3-0/kong-0.8.3-0.rockspec`, 添加

  ```
  ["kong.plugins.helloworld.handler"] = "kong/plugins/helloworld/handler.lua",
  ["kong.plugins.helloworld.access"] = "kong/plugins/helloworld/access.lua",
  ["kong.plugins.helloworld.schema"] = "kong/plugins/helloworld/schema.lua",
  ```

+ 修改kong的配置文件，并重启，需进入kong容器操作

  修改 `/etc/kong/kong.yml`，在首部加上

  ```
  custom_plugins:
    - helloworld

  ```

+ 测试插件

  访问 `http://localhost:8000/`，检测响应头中是否有 `Hello-World:Hello World!!!`


### 开发记录杂项

+ 进入kong，可以发现有`yum`,`lua`,`luarocks`
```
docker exec -ti kong bash
whereis yum
whereis luarocks
```
