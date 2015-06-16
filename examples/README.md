How You Can Use lua-resty-jwt
=============================

### jwt auth using query and cookie

nginx config
```
location / {
    access_log off;
    default_type text/plain;

    set $jwt_secret "your-own-jwt-secret";
    access_by_lua_file /etc/nginx/lua/guard.lua;

    echo "i am protected by jwt guard";
}
```
[guard.lua](guard.lua)


### jwt auth with kid and store keys in redis
nginx config
```
location / {
    set $redhost "127.0.0.1";
    set $redport 6379;
    # set $reddb 1;
    # set $redauth "your-redis-pass";
    access_by_lua_file /etc/nginx/lua/redjwt.lua;

    echo "i am protected jwt guard";
}
```
[redjwt.lua](redjwt.lua)
