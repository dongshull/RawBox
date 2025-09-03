![](https://raw.githubusercontent.com/dongshull/RawBox/main/Logo/RawBox.png "RawBox Logo")

# RawBox

RawBox 是一个轻量级 Docker 镜像，用于将 NAS 目录转换为类似 GitHub raw 的直链服务。

## 功能特性

- 公开文件直链访问（默认）
- 私密文件访问控制（通过 API Token）
- API 令牌认证
- 用户代理（UA）黑白名单过滤
- 访问日志记录
- 自定义错误页面
- 文本文件直接显示

## 快速开始

### 构建镜像

```bash
docker build -t rawbox/rawbox .
```

### 运行容器

```bash
docker run -d --name rawbox \
  -p 8080:8080 \
  -v /path/to/your/data:/data \
  -e API_TOKENS="token1,token2,token3" \
  rawbox/rawbox
```

### 目录结构

在数据目录中会自动创建以下子目录：

- `public/` - 公开文件目录
- `private/` - 私密文件目录
- `log/` - 访问日志目录
- `error_pages/` - 自定义错误页面目录

### 访问文件

- 公开文件: `http://localhost:8080/filename`
- 私密文件: `http://localhost:8080/filename?api=TOKEN`

## 文本文件显示

RawBox 支持直接在浏览器中显示以下类型的文本文件，就像 GitHub raw 显示一样：

- `.md` - Markdown 文件
- `.list` - 列表文件
- `.yml` - YAML 文件
- `.yaml` - YAML 文件
- `.conf` - 配置文件
- `.txt` - 文本文件
- `.lcf` - 配置文件
- `.lsr` - 脚本文件
- `.ini` - INI 配置文件
- `.json` - JSON 文件

这些文件将以纯文本形式在浏览器中显示，便于直接查看和复制内容。

## 错误状态码

RawBox 可能返回以下 HTTP 状态码：

| 状态码 | 说明 |
|--------|------|
| 200 | 请求成功，文件正常返回 |
| 400 | 请求错误，如路径遍历攻击（包含 `..` 的路径） |
| 401 | 未授权，API Token 无效或缺失 |
| 403 | 禁止访问，用户代理（UA）被拒绝 |
| 404 | 文件未找到 |
| 500 | 服务器内部错误 |

详细说明：
- **200 OK**: 成功找到并返回请求的文件
- **401 Unauthorized**: 访问私有文件时提供的 API Token 无效或缺失
- **403 Forbidden**: 用户代理（User-Agent）被 UA 黑白名单规则拒绝
- **404 Not Found**: 请求的文件在指定目录中不存在
- **500 Internal Server Error**: 服务器处理请求时发生内部错误

每个错误状态码都有对应的自定义错误页面。您可以通过修改 `error_pages/` 目录下的对应 HTML 文件来自定义错误页面：

- `401.html` - 401 Unauthorized 错误页面
- `403.html` - 403 Forbidden 错误页面
- `404.html` - 404 Not Found 错误页面
- `500.html` - 500 Internal Server Error 错误页面

## 日志功能

RawBox 会自动记录所有访问日志到 `log/` 目录中，日志文件按天分割，文件名为 `YYYY-MM-DD-RawBox-log.txt`。

日志格式为：
```
访问时间, 访问IP, 访问的文件路径, 访问者的User-Agent, 服务器返回的状态码
```

示例：
```
2023-09-02 14:30:25, 192.168.1.100, /test.txt, Mozilla/5.0, 200
2023-09-02 14:31:10, 192.168.1.101, /private/data.txt, Mozilla/5.0, 401
```

## 安全部署建议

为了防止暴力枚举攻击，在公网部署时建议添加 fail2ban 或限流中间件来增强安全性。

### 使用 Fail2Ban 防护

Fail2Ban 是一个入侵防护软件框架，可以监控系统日志并自动屏蔽恶意 IP 地址。

1. 安装 Fail2Ban:
   ```bash
   # Ubuntu/Debian
   sudo apt-get install fail2ban
   
   # CentOS/RHEL
   sudo yum install fail2ban
   ```

2. 创建 Fail2Ban 过滤器配置文件 `/etc/fail2ban/filter.d/rawbox.conf`:
   ```ini
   [Definition]
   failregex = ^.*"GET .*api=.*" 401.*$
   ignoreregex =
   ```

3. 创建 Fail2Ban jail 配置 `/etc/fail2ban/jail.d/rawbox.conf`:
   ```ini
   [rawbox]
   enabled = true
   port = 80,443
   filter = rawbox
   logpath = /var/log/nginx/access.log
   maxretry = 5
   bantime = 3600
   findtime = 600
   ```

4. 重启 Fail2Ban:
   ```bash
   sudo systemctl restart fail2ban
   ```

### 使用 Nginx 限流防护

Nginx 提供了限流功能，可以限制请求频率。

1. 在 Nginx 配置文件中添加限流规则:
   ```nginx
   # 在 http 块中定义限流区域
   http {
       # 限制每个 IP 每秒 10 个请求
       limit_req_zone $binary_remote_addr zone=rawbox:10m rate=10r/s;
       
       server {
           listen 80;
           server_name your-domain.com;
           
           # 应用限流规则
           location / {
               limit_req zone=rawbox burst=20 nodelay;
               proxy_pass http://localhost:8080;
               proxy_set_header Host $host;
               proxy_set_header X-Real-IP $remote_addr;
           }
       }
   }
   ```

2. 重新加载 Nginx 配置:
   ```bash
   sudo nginx -s reload
   ```

### 使用 Traefik 限流防护

Traefik 也提供了限流中间件功能。

1. 在 Traefik 配置文件中定义限流中间件:
   ```yaml
   # traefik.yml
   http:
     middlewares:
       ratelimit:
         rateLimit:
           average: 10  # 每秒平均请求数
           burst: 20    # 突发请求数
   ```

2. 在服务配置中应用限流中间件:
   ```yaml
   # docker-compose.yml
   services:
     traefik:
       image: traefik:v2.9
       # ... 其他配置
       volumes:
         - ./traefik.yml:/etc/traefik/traefik.yml
       
     rawbox:
       image: rawbox/rawbox
       # ... 其他配置
       labels:
         - "traefik.enable=true"
         - "traefik.http.routers.rawbox.rule=Host(`your-domain.com`)"
         - "traefik.http.routers.rawbox.middlewares=ratelimit@file"
         - "traefik.http.routers.rawbox.entrypoints=web"
   ```

### 使用 Lucky 反向代理

Lucky 是一个轻量级的反向代理工具，也可以用来为 RawBox 提供限流保护。

1. 安装 Lucky（以 Linux 为例）:
   ```bash
   # 下载 Lucky
   wget https://github.com/lucky-proxy/lucky/releases/latest/download/lucky_linux_amd64.tar.gz
   tar -xzf lucky_linux_amd64.tar.gz
   sudo mv lucky /usr/local/bin/
   ```

2. 创建 Lucky 配置文件 `lucky.conf`:
   ```json
   {
     "listen": [
       {
         "addr": ":80",
         "tls": false,
         "rules": [
           {
             "hosts": ["your-domain.com"],
             "backends": ["http://localhost:8080"]
           }
         ]
       }
     ],
     "middlewares": [
       {
         "name": "ratelimit",
         "type": "rate_limit",
         "config": {
           "requests": 10,
           "window": "1s",
           "burst": 20
         }
       }
     ],
     "routes": [
       {
         "match": {
           "hosts": ["your-domain.com"]
         },
         "middlewares": ["ratelimit"]
       }
     ]
   }
   ```

3. 启动 Lucky:
   ```bash
   lucky -c lucky.conf
   ```

## 配置

### 环境变量

RawBox 支持通过环境变量进行配置：

- `DATA_DIR` - 数据目录路径（默认: ./data）
- `PORT` - 服务监听端口（默认: 8080）
- `API_TOKENS` - API Tokens，多个用逗号分隔
- `UA_WHITELIST` - UA 白名单，多个用逗号分隔
- `UA_BLACKLIST` - UA 黑名单，多个用逗号分隔

### Token 配置

通过环境变量 `API_TOKENS` 设置，多个 token 用逗号分隔。

示例：
```bash
docker run -d --name rawbox \
  -p 8080:8080 \
  -v /path/to/your/data:/data \
  -e API_TOKENS="token1,token2,token3" \
  rawbox/rawbox
```

### UA 过滤规则

通过环境变量 `UA_WHITELIST` 和 `UA_BLACKLIST` 设置，多个规则用逗号分隔。

示例：
```bash
docker run -d --name rawbox \
  -p 8080:8080 \
  -v /path/to/your/data:/data \
  -e API_TOKENS="token1,token2,token3" \
  -e UA_WHITELIST="Mozilla,Chrome" \
  -e UA_BLACKLIST="Bot,Spider" \
  rawbox/rawbox
```

### 端口配置

通过环境变量 `PORT` 设置服务监听端口。

示例：
```bash
docker run -d --name rawbox \
  -p 3000:3000 \
  -v /path/to/your/data:/data \
  -e PORT=3000 \
  -e API_TOKENS="token1,token2,token3" \
  rawbox/rawbox
```

## 构建

```bash
# 本地构建
CGO_ENABLED=0 GOOS=linux go build -ldflags="-s -w" -o rawbox
docker build -t rawbox/rawbox .

# 推送到Docker Hub
docker push rawbox/rawbox
```

## 镜像标签

Docker 镜像有两种标签：

1. **版本标签** - 基于 Git 标签生成，格式为 `vX.Y.Z`
2. **latest 标签** - 始终指向最新的稳定版本

## 版本

- v0.1.0：基础功能实现