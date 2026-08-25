# WebServer

轻量级 Windows 源站 Web Server / Reverse Proxy 管理程序。

当前版本 `1.0.0` 已具备公网 `80/443`、证书 CRUD/SNI 热更新、可信 CDN 真实 IP、
阿里云 A 方式 URL 鉴权、双向流式反向代理、HTTP/HTTPS 上游、Backend 并发过载保护、
可恢复连接池、配置备份、日志控制台和 WebSocket 双向隧道。管理平面仍只监听本机回环地址。

## 当前能力

### 数据平面

- Boost.Asio/Beast 异步 HTTP 与 HTTPS Listener，共享 IO 工作线程池
- HTTP/HTTPS/WebSocket 共用默认 16,384 条活动连接硬上限；超过上限立即关闭新连接，既有连接不受影响
- Listener accept 失败采用 10 ms–1 s 指数退避；单个 handler 抛出异常不会再逃出 Worker 导致 `std::terminate`
- TLS 1.2/1.3、SNI 多证书、ALPN `http/1.1`、SNI/Host 一致性校验
- 按 `协议 + Listener 端口 + Host` 执行精确域名和通配域名 VirtualHost 路由
- 全异步 ProxyTransaction、客户端与 Backend keep-alive、按后端隔离的空闲连接池
- 上游支持 HTTP/HTTPS、IP/DNS 地址、自定义 Host、TLS SNI、证书链/主机名验证及连接测试
- 请求头通过路由/策略后，上传正文以 16 KiB 在 Client 与 Backend 间流式传送，同时读取 Backend 提前响应，不在 RAM 完整聚合
- 响应头到达后立即转发，下载正文复用同一个 16 KiB 传输块且不设 8 MiB 硬上限
- 等待 Backend 配额的事务不分配传输块；WebSocket 确认 `101` 后才分配双向 `32 + 32 KiB` 隧道缓冲
- 连接池在复用前探测半关闭连接；池连接首次零字节写失败时安全重连一次，并在 Idle TTL 到期时主动关闭
- 每站独立限制 Backend 活动请求、等待队列和等待超时；增大活动上限会立即按 FIFO 放行既有队列，队列满或超时返回 `503 + Retry-After`
- WebSocket Upgrade/101 握手转发，握手后进入全双工字节隧道
- Proxy 取消会等待客户端与 Backend 两侧全部异步 I/O 回调完成，再允许 Session 关闭或执行 TLS shutdown
- 移除 hop-by-hop Header，并在可信代理边界内安全重建真实 IP Header
- 每个 HTTP/HTTPS 请求只加载一次只读内存 Snapshot，不查询 SQLite
- keep-alive 连接的下一条请求可使用新配置，在途代理请求继续持有旧 Snapshot
- 站点级策略链：请求拦截、Token Bucket、ACL、Redirect、防盗链、URL Auth、Reverse Proxy
- URL Auth 兼容阿里云鉴权 A 方式，支持全站/指定 URI、主备 KEY、有效期、403 与验签后参数清除；未来时间戳仅容忍 5 分钟时钟偏差
- 禁止 TRACE/TRACK，并限制请求目标为 8 KiB、Header 16 KiB；上传上限可热更新配置，`Content-Length` 在请求头阶段超限时 HTTP/HTTPS 均明确返回 `413 Payload Too Large` 后关闭连接

### 配置持久化

- SQLite 保存站点、域名、Backend、监听意图、TLS 证书/私钥、代理设置、管理员和修订号
- 启动时自动执行幂等 Schema Migration
- `WAL`、`synchronous=FULL`、外键约束和 5 秒 busy timeout
- 站点及域名写入使用事务；域名在数据库中全局唯一
- 所有管理保存和配置恢复先构造完整候选 RuntimeConfig，并预占新增监听端口；验证成功后才提交 SQLite，提交后再一次性发布
- 新数据库自动创建 `example.com → 127.0.0.1:8090` 演示站点
- 所有站点域名、上游 IP/DNS、Host、SNI、端口与开关组合在写入前校验并标准化
- Schema Migration v6 增加站点级上游协议、Host、TLS SNI/验证、连接/响应超时和 Keep-Alive，兼容既有数据库
- Schema Migration v7 增加站点级 URL 鉴权配置，既有站点默认关闭且可直接热更新启用
- JSON 配置备份包含站点、策略、证书/私钥和运行设置；超过 16 MiB 往返上限时导出会明确拒绝，恢复先做结构、重复项、证书和完整运行时校验，再单事务替换并热更新

### Admin Plane

- 独立 `io_context` 和线程，不占用公网 HTTP Worker
- 固定绑定 `127.0.0.1:3312`，并再次检查每条连接的 TCP Peer 是回环地址
- Admin 同时活动连接硬上限为 128，accept 同样退避重试，管理线程也有顶层异常保护
- Vue 3 + TypeScript + Vite 单页后台，构建产物随 EXE 一起部署
- 首次运行创建管理员，不提供默认密码
- 管理员密码使用随机 16 字节盐和 PBKDF2-HMAC-SHA256（310,000 次）
- 256-bit 随机登录 Session，8 小时滑动过期，仅保存在进程内存；主动清理过期项并将活动 Session 总数限制为 4096
- `HttpOnly`、`SameSite=Strict` Cookie，登录失败 5 次后暂时限速
- 管理写请求要求专用 Header；无 CORS 响应，并设置 CSP、禁止 frame 和嗅探等安全 Header
- 网站列表、添加、编辑、删除、启停及 Dashboard 状态
- 证书添加、编辑、删除、启停、域名绑定、默认 Context 和私钥保留更新
- Trusted Proxy CIDR、可排序/增删的真实 IP Header、上传上限、连接池与超时设置
- Access/Error 日志页面，支持最近 100/500/1000 条及域名、IP、状态码、Request ID、路径、级别搜索
- 只读 Listener 页面显示实际协议、绑定地址、端口、网站数与 Listening 状态
- Backend 面板显示每站 Active Connections、Queue Length、Rejected Requests 与 Queue Timeout
- TCP 连接页面实时显示源地址、连接时间/持续时长、状态、Method、URL 与 Referer
- HTTP 实时连接页面显示可信代理解析后的用户 IP、所属网站、连接时间/持续时长、状态、Method、URL 与 Referer；默认汇总全部网站，也可按单个网站筛选
- 网站编辑器提供完整反向代理面板和异步 DNS/TCP/TLS“测试连接”结果，不阻塞 Admin 事件循环
- 系统设置可导出/导入配置备份；管理员账号和内存 Session 不进入备份
- 保存后自动 Hot Reload，也可手动重载当前 SQLite 配置
- 可视化编辑 ACL 多条件、CC 限速、全站/指定 URI URL 鉴权、防盗链与主机/路径重定向规则

### 运行与可观测性

- 可作为控制台程序运行，也可由 Windows Service Control Manager 托管
- SCM `STOP` 与系统 `SHUTDOWN` 均进入同一条幂等优雅关闭路径
- 配置或 TLS 错误导致数据 Listener 无法启动时，服务保留本机 Admin 恢复模式；修复并重启后恢复数据平面
- `access.log` 与 `error.log` 使用独立后台线程写入，不阻塞 Asio Worker
- JSON Lines 格式，默认单文件 20 MiB、保留 10 个轮转文件
- 有界 8192 事件队列；过载时优先保留 Error，并在恢复后记录丢弃计数
- 每个数据平面请求生成 128-bit `X-Request-ID`，同时返回客户端并转发到 Backend
- Access 日志不记录 Cookie、Authorization、请求/响应正文、User-Agent 或 Referer

## 第十二阶段双向流式代理与日志控制台

公网 Session 只使用 `async_read_header` 读取和校验请求头。请求通过 Host 路由、ACL、限速等策略后，
`ProxyTransaction` 取得 Backend 配额后才按需分配传输块并从同一个 Beast `buffer_body` Parser 读取正文；
每次最多读取 16 KiB，完成
一次 Backend 写入后再读取下一块，从而形成自然背压。同时在请求头写入 Backend 后立刻并发读取响应头，
因此 Backend 可在上传尚未完成时返回 401、403 或 413；代理停止继续上传、原样转发响应并关闭未排空的客户端连接。
正常请求仍复用单个 16 KiB 块；仅在提前响应与上传写入短暂重叠时按需增加一个 16 KiB 响应块。固定 `Content-Length` 与 chunked 请求都会保留
正确 framing，`Expect: 100-continue` 由代理在策略通过后响应。上传上限仍由热更新设置控制。
若固定 `Content-Length` 在 `async_read_header` 阶段已经超过上传上限，普通 HTTP 与 TLS Session
都会异步写回 `413 Payload Too Large`、设置 `Connection: close`，再关闭连接，不再把
`http::error::body_limit` 当作普通读错误直接断开。

Client Header、Client Body、Client Write 与 Backend Idle I/O Timeout 在系统设置中配置；Backend
Connect 与 Response Header Timeout 在每个网站的反向代理面板独立配置。所有值均保存到 SQLite，
范围为 1–86400 秒；Body/Idle 采用活动间隔语义，
持续有数据的慢速大文件不会因为总传输时间超过固定常量而失败。Backend 空闲连接另有 TTL。

后台“日志”页面读取 JSONL 日志及轮转文件，结果倒序显示。Access 可按域名、IP、状态码、Request ID
和路径组合过滤；Error 可按 warning/error/critical、Request ID、组件或消息过滤。API 每次最多返回
1000 条，单行及扫描量均有上限，且仍要求本机管理员 Session。

真实 IP 的默认优先级为 `EO-Connecting-IP`、`CF-Connecting-IP`、`True-Client-IP`、
`X-Forwarded-For`。只有 TCP Peer 命中 Trusted Proxy CIDR 时这些 Header 才生效；前三类只接受单 IP，
XFF 按可信代理链解析。后台可以调整顺序、删除或添加自定义单 IP Header。

`backend_pool_size` 仍只表示“每个后端最多保留多少空闲连接”。活动并发由每站独立的
`backend_max_active_connections` 控制，达到上限后最多排队 `backend_max_queue` 个请求，并在
`backend_queue_timeout_seconds` 后返回 503。配额在连接池获取或新建连接之前取得，普通请求、
流式上传下载和 WebSocket 都在完成、失败或取消时统一释放。

## 第十三阶段备份、Listener 与 Backend 过载保护

“监听端口”页面是运行态只读视图。Listener 仍由网站的 HTTP/HTTPS 开关和端口自动创建、复用和
回收；页面从 `ServerCore` 的活动 Listener 读取实际绑定结果，不提供第二套容易冲突的端口配置。

配置导出使用带格式版本号的 JSON，包含网站、域名、ACL/CC/URL Auth/防盗链/Redirect、Backend、监听意图、
TLS 证书与私钥、Trusted Proxy、真实 IP Header、上传/连接池/超时设置。导入不会覆盖管理员账号或
登录 Session；文件先经过大小、结构、域名、端口、策略、证书私钥匹配、SNI 覆盖和全局路由冲突
校验，通过后才在一个 SQLite 事务中替换配置并触发 Hot Reload。备份含私钥，必须加密存放。

Backend Limiter 按稳定的站点 ID 共享 HTTP/HTTPS 配额，并使用 FIFO 等待队列。等待中的请求尚未
读取上传正文、分配传输缓冲、获取空闲连接或连接 Backend；队列超时或服务停止会撤销排队项。运行指标区分活动数、
队列长度、累计拒绝和等待超时，便于判断 PHP/Apache/Nginx 是否已达到保护阈值。站点删除后，其 Limiter 状态会
标记退役；最后一个活动 permit 或排队项结束后自动删除，不随历史站点 ID 无限累积，也不会中断在途请求。

## 第十四阶段 HTTPS 上游

每个网站可独立选择 HTTP 或 HTTPS 上游，上游地址既可为 IP，也可为 DNS 主机名。`Host = 自动` 时
保持客户端 Host，选择自定义后会覆盖转发请求的 Host。HTTPS 的 TLS SNI 可单独填写；留空时优先使用
自定义 Host，否则使用上游地址。启用“验证上游证书”后，握手同时验证证书信任链与 SNI 主机名；
Windows 构建会把系统 ROOT 证书库装载到 OpenSSL 客户端上下文。

连接超时、响应头超时和 Backend Keep-Alive 由网站独立配置。连接池按协议、目标、Host、SNI 与验证
策略隔离，因此不会跨 TLS 身份复用连接；每条空闲连接记录独立到期时刻，由主动清理器到点关闭，即使后续
没有新请求也不会滞留。HTTPS 上游同样支持流式上传/下载和 WebSocket 隧道。
“测试连接”使用当前未保存表单执行 DNS、TCP 和可选 TLS 握手，返回实际远端地址、耗时、证书验证状态
或失败原因，不会修改运行配置。

## 第十阶段 Windows Service 与日志

以管理员权限安装服务：

```bat
out\build\windows-vs2022-x64\Release\WebServer.exe --install-service
sc.exe start WebServer
```

安装项使用带引号的绝对 EXE 路径并附加 `--service`，启动类型为延迟自动启动；异常退出后按
5 秒、15 秒、60 秒间隔重启，失败计数每天重置。服务运行时不依赖当前工作目录，证书、SQLite、
后台资源和日志都按 EXE 所在目录解析。也可从 PowerShell 执行
`scripts\install-service.ps1`。

停止并卸载：

```bat
sc.exe stop WebServer
out\build\windows-vs2022-x64\Release\WebServer.exe --uninstall-service
```

卸载命令会先请求停止，最多等待 30 秒，再将服务标记删除；PowerShell 对应脚本为
`scripts\uninstall-service.ps1`。

日志位于 `<WebServer.exe 目录>\logs\`，每行都是一个独立 JSON 对象；Access 只记录数据平面，
不会记录本机管理端的认证请求。Access 字段包含 UTC
时间、请求 ID、TCP Peer IP、协议、Listener 端口、规范化 Host、Method、不含查询字符串的
Path、状态码、响应正文长度、处理耗时和配置修订号。查询参数值、认证 Header、Cookie 与正文
不会写入日志。Error 日志记录组件、级别、消息和可选请求 ID；Backend 连接/超时、Listener、
TLS、Admin、配置重载和进程生命周期错误都进入这里。

稳定性测试使用 8 个并发 keep-alive 客户端发送 601 个成功代理请求及 1 个 Backend 故障请求，
并在请求进行期间连续发布 24 个 Runtime Snapshot；测试同时校验响应、请求 ID、Backend
转发、日志无丢失、查询参数脱敏、错误关联和停止时空闲连接关闭。长期重复测试可运行：

```powershell
.\scripts\run-soak-tests.ps1 -Iterations 100
```

## 第九阶段访问策略

每个网站拥有独立策略，执行顺序如下：

```text
Request Intercept → IP/CIDR Deny → Rate Limit → Remaining ACL → Force HTTPS → Redirect → Hotlink → URL Auth → Backend Limiter → Proxy
```

ACL 支持 IP、URI、Host、Method、User-Agent、Referer 和任意指定 Header；操作符支持
等于、不等于、包含、不包含、开头、结尾和 Regex，IP 还支持 IPv4/IPv6 的 `in_cidr` 与
`not_in_cidr`。一条规则内最多 8 个 AND 条件，规则按界面顺序执行；`Allow` 停止后续 ACL
匹配，`Deny/Return` 可返回 403、404 或 429，Redirect 可返回 301、302、307 或 308。只包含
IP 精确匹配及 `in_cidr`/`not_in_cidr` 条件的 `Deny` 是前置硬拒绝规则，不会占用限速表；其余规则仍按界面顺序执行。
所有 Regex 和 CIDR 在构建候选 Snapshot 时预编译/预解析，非法表达式或网段不会发布。Regex
使用保证线性时间的 RE2；为避免产生错误安全假设，RE2 不支持的回溯特性（例如反向引用和环视）会在保存前明确拒绝。

CC 防护使用按 TCP Peer IP 隔离的 Token Bucket，支持 1–3600 秒窗口、请求上限和最长一天
的临时封禁，超限返回 `429` 与 `Retry-After`。状态表设有容量上限并周期清理空闲条目；满表时按
LRU 淘汰最久未访问的状态并接纳新 IP，不再把所有陌生 IP 误判为 429。
真实 IP 解析遵循明确的可信边界：TCP Peer 不命中 Trusted Proxy CIDR 时，所有真实 IP Header
都会被忽略；命中后按后台定义的优先级选择首个合法 Header，XFF 从右向左剥离可信代理。得到的客户端地址同时用于 ACL、
限速、日志、`X-Real-IP` 和重新生成的 `X-Forwarded-For`。

防盗链按请求路径扩展名启用，本站精确/通配域名自动加入 Referer 允许列表，也可添加额外
域名；空 Referer 可单独允许，拒绝动作可选择 403 或 302 跳转。Redirect 支持可选来源 Host、
精确/前缀路径、保留路径/查询参数及 301/302/307/308。HTTP 强制 HTTPS 会保留 Host、目标
路径和非默认 HTTPS 端口。

URL Auth 放在会产生响应的重定向/防盗链策略之后、Backend Limiter 之前，避免 HTTP→HTTPS 或
自定义 Redirect 提前消耗签名。A 方式请求格式为
`/Filename?auth_key=timestamp-rand-uid-md5hash`，签名原文为
`URI-timestamp-rand-uid-PrivateKey`。时间戳是 10 位 Unix 秒；有效期范围为 1–31536000 秒，
默认 1800 秒；主 KEY 或备 KEY 任意一个匹配即可。KEY 使用阿里云兼容的 6–128 位字母数字格式。
保护范围可选择全站，或最多 200 条 URI 精确/前缀规则。缺少、重复、格式错误、过期或签名不一致的
`auth_key` 统一返回 403；成功后移除保留签名参数 `auth_key`、`sign`、`time`，其余业务查询参数
保持原顺序交给 Backend。未受保护的 URI 不会清理或改写查询参数。

## 第八阶段 Hot Reload

SQLite 与数据平面已经严格分离：

```text
启动：SQLite → Validate → RuntimeConfig → Atomic Store → HTTP/HTTPS Worker

请求：HTTP Session → Load Snapshot → Listener + Host Router → Reverse Proxy

管理：Vue → Admin API → Build Candidate → Validate/Preflight → SQLite Tx → Atomic Publish
```

Admin 保存网站后会全量重建候选配置。域名、后端、端口、证书覆盖和跨协议端口冲突全部
通过校验，且新增 Listener 完成绑定后，才提交 SQLite 事务并以 release/acquire 语义原子发布。新请求立刻
使用新 Backend；在途请求通过 `shared_ptr<const RuntimeConfig>` 安全保留旧配置，最后一个
使用者结束后自动释放。

Listener 按端口集合执行 Diff：新增端口只启动对应 Listener，删除端口停止接收新连接并
让已有连接排空，其他端口不受影响；排空后的 retired Listener 会立刻从运行时容器删除。
校验或端口绑定失败时，SQLite 与运行态 Snapshot 都保持原修订，不会留下“接口返回失败但坏配置已写入”的状态。

TLS Context 也属于 Snapshot。后台可上传或粘贴 CRT/PEM 证书链与 KEY、绑定精确或通配域名，
并设置默认证书。每次保存都会校验有效期、域名覆盖和私钥匹配，再创建全新 SNI Context；
新 TLS 连接立即使用新证书，旧连接安全持有旧 Context 直到结束。列表接口不会回显私钥。

## Admin API

未认证接口：

```text
GET  /api/auth/setup-state
POST /api/auth/setup
POST /api/auth/login
```

认证后接口：

```text
POST   /api/auth/logout
GET    /api/status
POST   /api/runtime/reload
GET    /api/sites
POST   /api/sites
PUT    /api/sites/{id}
DELETE /api/sites/{id}
GET    /api/certificates
POST   /api/certificates
PUT    /api/certificates/{id}
DELETE /api/certificates/{id}
GET    /api/settings
PUT    /api/settings
GET    /api/listeners
GET    /api/connections
GET    /api/backends/metrics
POST   /api/backends/test
GET    /api/config/backup
POST   /api/config/restore
GET    /api/logs/access?limit=100&host=&ip=&status=&request_id=&path=
GET    /api/logs/error?limit=100&level=warning&request_id=&search=
```

管理请求正文限制为 16 MiB，Header 限制为 16 KiB。Admin API 和静态后台都只在回环
Listener 上提供。

## 默认运行位置

```text
HTTP       http://0.0.0.0:80
HTTPS      https://0.0.0.0:443
Admin      http://127.0.0.1:3312
SQLite     <WebServer.exe 目录>\data\webserver.db
Admin UI   <WebServer.exe 目录>\admin-ui\
Logs       <WebServer.exe 目录>\logs\access.log / error.log
```

首次打开 Admin 地址时，页面会要求创建用户名和至少 12 字符的密码。后台使用本机 HTTP，
因此 Cookie 不设置 `Secure`；若将来允许远程管理，必须先增加独立 HTTPS 管理入口，不能
把 `3312` 直接暴露到公网。

## 环境要求

- Windows Server 2012 R2 或更高版本
- Visual Studio 2022，“使用 C++ 的桌面开发”工作负载
- CMake 3.25 或更高版本
- Git、vcpkg
- 仅重建管理前端时需要 Node.js 20.19+ 或 22.12+

生产依赖由 vcpkg 提供：Boost.Asio、Boost.Beast、Boost.System、OpenSSL、SQLite、
nlohmann/json 和 RE2。日志实现只依赖 C++20 标准库。

## 构建和测试

设置 `VCPKG_ROOT` 后，在项目根目录执行：

```bat
cmake --preset windows-vs2022-x64
cmake --build --preset windows-vs2022-x64-release
ctest --preset windows-vs2022-x64-release
```

生成位置：

```text
out\build\windows-vs2022-x64\Release\WebServer.exe
```

仓库已包含经过类型检查的 `admin-ui/dist`，普通 C++ 构建不要求安装 Node.js。若修改
Vue 源码，可执行：

```bat
cd admin-ui
npm ci
npm run build
cd ..
```

也可在 CMake 配置后运行可选目标：

```bat
cmake --build --preset windows-vs2022-x64-release --target AdminUiBuild
```

CTest 现在包含 27 项；Windows CI 的 Release Build 后会执行完整 CTest，任一失败或没有注册测试都会阻止发布产物：

- `WebServer.Version`：版本 `1.0.0`
- `WebServer.HttpIntegration`：HTTP 代理、Header 安全、keep-alive 和错误映射
- `WebServer.VirtualHostTests`：Host 标准化、精确/通配路由和冲突拒绝
- `WebServer.ConfigDatabaseTests`：Migration、事务 CRUD、持久化、配置修订及启停状态
- `WebServer.RuntimeConfigTests`：端口隔离、原子发布及旧 Snapshot 生命周期
- `WebServer.BackendConcurrencyLimiterTests`：活动连接上限、FIFO 队列、等待超时、拒绝指标及增大上限立即放行
- `WebServer.RequestPolicyTests`：ACL、IPv4/IPv6 CIDR、Regex、Token Bucket、防盗链与 Redirect
- `WebServer.UrlAuthenticatorTests`：阿里云官方 A 方式向量、主备 KEY、有效期、URI 范围与参数清除
- `WebServer.UrlAuthIntegration`：缺失/错误签名返回 403，正确签名清除参数后再回源
- `WebServer.LoggingTests`：JSONL、脱敏、请求 ID、异步队列与大小轮转
- `WebServer.WindowsServiceTests`：SCM 命令行安全引用与平台边界
- `WebServer.PolicyIntegration`：真实 HTTP 策略执行及 keep-alive 热更新
- `WebServer.HotReloadIntegration`：keep-alive Backend 切换与 Listener Diff
- `WebServer.StabilityIntegration`：并发代理、连续 Hot Reload、日志完整性及优雅停止
- `WebServer.AdminApiIntegration`：静态页面、Session、设置、连接信息、结构化日志查询和网站 API
- `WebServer.TlsContextTests`：证书、私钥、域名、默认 Context 和 SNI 约束
- `WebServer.HttpsIntegration`：TLS 1.2+、多证书 SNI、HTTPS 代理及 `421`
- `WebServer.ClientIpResolverTests`：可信 CIDR、自定义 Header 优先级、XFF 链与伪造 Header 拒绝
- `WebServer.WebSocketIntegration`：Upgrade/101 握手、双向帧转发与关闭路径
- `WebServer.ServerResilienceTests`：全局连接硬上限、超限拒绝计数及 Worker handler 异常恢复
- `WebServer.StreamingProxyIntegration`：Backend 连接复用、10 MiB 流式上传、提前 413 响应与超过 8 MiB 的分块下载
- `WebServer.BackendTlsProxyIntegration`：DNS HTTPS 上游、自定义 Host、SNI 与证书验证
- `WebServer.BackendConnectionPoolTests`：TTL 前复用及无后续请求时的主动到期关闭
- `WebServer.ProxyTransactionMemoryTests`：排队事务固定尺寸及 HTTP/WebSocket 缓冲大小回归保护
- `WebServer.ConnectionRegistryTests`：连接字段、状态更新、并发注册和断开清理
- `WebServer.HttpRealtimeAndUploadLimitIntegration`：处理中 HTTP 请求的站点/用户 IP/状态登记与完成清理，以及 HTTP/TLS 请求头阶段上传超限的 413 响应

## 运行

先让 PHPStudy 或其他 HTTP 后端监听 `127.0.0.1:8090`，再启动：

```bat
out\build\windows-vs2022-x64\Release\WebServer.exe
```

生产环境建议安装为 Windows Service；控制台模式主要用于首次配置和调试。服务模式与控制台
模式使用完全相同的 ServerCore、AdminServer、配置和关闭路径。

验证：

```bat
curl.exe -i -H "Host: example.com" http://127.0.0.1/
curl.exe -k -i --resolve example.com:443:127.0.0.1 https://example.com/
start http://127.0.0.1:3312
```

`certs/example.com.crt` 和 `.key` 是本地自签名开发证书，生产部署前必须替换。

## 项目结构

```text
WebServer/
├── admin-ui/         Vue 3 / TypeScript 源码与已构建 dist
├── certs/            开发 TLS 证书
├── cmake/
├── src/
│   ├── admin/        Admin Listener、静态页面、API、认证和 Session
│   ├── app/          生命周期、信号与启动装配
│   ├── config/       配置校验与 SQLite/Runtime 边界
│   ├── core/         数据平面 io_context 与工作线程
│   ├── database/     SQLite RAII、Migration 与 Repository
│   ├── http/         HTTP/TLS Session 与共享 Dispatcher
│   ├── logging/      异步 JSONL Access/Error Log、轮转与请求 ID
│   ├── network/      HTTP/HTTPS Listener
│   ├── policy/       ACL、Rate Limit、防盗链、Redirect 与 URL Auth 策略引擎
│   ├── proxy/        流式 Reverse Proxy、Backend 连接池与 WebSocket 隧道
│   ├── routing/      Host 标准化与 VirtualHost
│   ├── service/      Windows SCM 入口、控制回调与安装/卸载
│   └── tls/          TLS Context 和 SNI
├── scripts/          Service 安装、卸载及稳定性重复测试脚本
└── tests/
```

生产环境请在 Windows 防火墙中只开放所需数据端口；不要把 `3312` 管理端口转发到公网。
