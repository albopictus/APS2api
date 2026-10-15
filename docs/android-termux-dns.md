# Android / Termux DNS 修复

此修改保存在 `albopictus/APS2api` 的 `fix/android-termux-dns` 分支。
保留项目原有 PolyForm Noncommercial License 1.0.0 和 Required Notice。

## 原因与修复

`internal/netx/termux.go` 原本只为标准 `net/http` 提供 Termux DNS。
reCAPTCHA 的 `enterprise.js`、anchor、reload 以及业务请求通过
`transport.NetworkClient` 创建 `tls-client` 会话，并未使用这个 resolver。
因此纯 Go 构建在 Termux 中可能向 `[::1]:53` 查询，即使指定公共 DNS 的
`nslookup` 成功，应用请求仍然失败，最终在 API 层表现为 502。

现在 `netx.NewDialer` 复用已有的 Termux 检测和 nameserver 发现逻辑，
并通过 `tls-client.WithDialer` 注入。不能用 `WithDialContext` 替代这一步，
因为它会覆盖 `tls-client` 的内置 HTTP/SOCKS 代理逻辑。
Chrome profile、cookie jar、证书校验和代理失败时返回错误的行为保留。

Mihomo 的底层 dialer 通过其 `SystemResolver` 解析节点服务器域名，
不经过 `net.Dialer.Resolver`。在包初始化期间，仅当检测到 Termux 且发现
可用 nameserver 时，使用相同服务器列表初始化 Mihomo 的 DNS resolver。
节点域名、TLS SNI、节点拨号选项及双跳代理关系保留；代理目标域名仍交给代理。
不修改进程级 `net.DefaultResolver`。

检查了 `internal/recaptcha/recaptcha.go`：其会话构造已统一经过
`CreateSessionWithoutEntryProxy`，因此通过修复公共传输层获得 DNS 修复。
没有屏蔽 502、伪造 token 或修改 reCAPTCHA 错误判断。

当前版本的模型清单主要来自本地模型注册表；依赖远端 HTTP 的业务、订阅和
节点请求使用相应修复后的传输路径。真实上游可用性还取决于手机网络、代理
和上游服务，DNS 修复不能保证消除所有来源的 502。

## DNS 配置

沿用原来的查找顺序：`$PREFIX/etc/resolv.conf`、`/etc/resolv.conf`，
以及 Android `getprop` 中的 DNS 地址。过滤回环和未指定地址并去重。
不会自动改写设备 DNS 文件或添加固定公共 DNS。
启动日志应包含 `[Net] Termux DNS fallback enabled: ...`。
若提示 `no usable nameserver found`，先检查上述文件和系统属性。
仅对 `nslookup example.com 8.8.8.8` 指定 DNS 不会配置应用的 DNS。

## 测试

```sh
GOMAXPROCS=2 go test -p 1 ./internal/netx ./internal/transport ./internal/recaptcha
GOMAXPROCS=2 go test -p 1 ./...
```

DNS 回归测试使用本地 DNS、HTTP/SOCKS 代理和 HTTP/TLS 目标服务。
传输测试在新进程中模拟 Termux，覆盖实际包初始化、标准 HTTP、tls-client
直连、HTTP/SOCKS、Mihomo HTTP/SOCKS、两种双跳代理、代理失败不直连，
并检查 Chrome ClientHello 中的 GREASE、ALPN、原始 SNI 和证书校验。
代理目标和第二跳域名不得进入本地 DNS。
测试需要一个非回环 IPv4 网卡来模拟可被既有 nameserver 过滤器接受的 DNS
服务器地址；纯回环环境会跳过传输集成测试，底层 DNS 测试仍可运行。

## Android ARM64 构建

项目是命令行程序，没有 APK / Gradle 工程。
Go 的 Android ARM64 支持不依赖 NDK 的纯 Go PIE 构建：

```sh
GOMAXPROCS=2 CGO_ENABLED=0 GOOS=android GOARCH=arm64 \
  go build -p 2 -buildmode=pie -trimpath -ldflags='-s -w' \
  -o vertex-proxy ./cmd/vproxy
```

发行包应同时包含 `LICENSE`、`scripts/start.sh`、使用规则和配置示例。
不要把实际 `config.json`、API Key、密码、数据库、节点或日志放入发行包。

## 安装或升级

在 ARM64 Android 的 Termux 中准备运行环境：

```sh
pkg update
pkg install ca-certificates unzip
termux-setup-storage
```

新安装：把 ZIP 下载到手机的 Download 目录后解压到 Termux 私有目录运行，
不要直接在共享存储中执行二进制：

```sh
mkdir -p ~/aps2api
unzip ~/storage/downloads/vertex-proxy-android-arm64-termux-dns.zip -d ~/aps2api
cd ~/aps2api
chmod 700 vertex-proxy
sh start.sh
```

按首次启动提示确认项目规则，随后访问 `http://127.0.0.1:2156/admin/`。

已有安装：先在原终端用 Ctrl+C 停止程序，把 ZIP 解压到新的临时目录，
只将新 `vertex-proxy` 复制到原安装目录，再设置执行权限并使用原启动方式。
保留原安装目录中的整个 `config/`，不要用示例覆盖现有配置、密钥、模型设置
或数据库。更新包自身不包含用户运行数据。

此构建修复 DNS 路径；最终应在手机上复核启动日志、模型读取、reCAPTCHA
和实际节点出站。桌面本地回归测试不能代替真机网络验收。
