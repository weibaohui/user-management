# 常见问题（FAQ）

> 所有文件级操作的第一原则：**先停 dsh web 再改文件**。user-management 把数据整份缓存在内存里，插件运行期间任何一次写盘（哪怕只是某人登录了一次）都会用内存副本覆盖你手改的文件。停法：`kill -9 $(lsof -tiTCP:19080 -sTCP:LISTEN)`（launchd 会自动拉起新进程），改完文件即已完成——新进程启动时读取的就是你改过的版本。

## 忘记管理员密码 / 用户名怎么办

按代价从小到大三级处理：

### 情况 A：还有一个可用的管理员

让 TA 在 **设置 → 用户管理 → 用户** 里对你「重置密码」——生成随机临时密码（仅展示一次，立即保存），你用临时密码登录后尽快改成自己的密码。忘记的只是用户名的话，问 TA 在用户列表里看一眼即可（用户名是明文存的）。

### 情况 B：只有一个管理员（就是你），账号还能登录但忘了密码

无法找回（密码是 scrypt 加盐哈希，不可逆），只能"重建账号"：

```bash
# 1. 停 dsh web（见顶部原则）
kill -9 $(lsof -tiTCP:19080 -sTCP:LISTEN)
# 2. 编辑 ~/.dsh/user-management/users.json，删掉你这个用户的整个 { ... } 条目
#    （先看清 username 字段确认删的是自己）
# 3. 启动后用原用户名重新注册
```

注意：**重建后角色是普通用户**——继续情况 C 把 role 改回 admin。

### 情况 C：把某个账号（重新）提升为管理员

```bash
kill -9 $(lsof -tiTCP:19080 -sTCP:LISTEN)
# 编辑 ~/.dsh/user-management/users.json，找到目标用户，把
#   "role": "user"
# 改成
#   "role": "admin"
# 保存，重启完成
```

### 情况 D：什么都不记得了，推倒重来（清空所有用户）

```bash
kill -9 $(lsof -tiTCP:19080 -sTCP:LISTEN)
rm ~/.dsh/user-management/users.json ~/.dsh/user-management/sessions.json
# 重启后系统回到零用户状态，第一个注册的账号成为管理员
```

副作用：所有用户消失、所有人被登出；封禁列表、审计记录不受影响。

## 把 IP 封错了 / 需要解封

- 界面路径：**设置 → 用户管理 → IP 封禁** → 该行「解封」。
- 完全进不来时的兜底：停 dsh web → 编辑（或直接删除）`~/.dsh/user-management/bans.json` → 重启。
- 插件自带两道防误封：回环地址（127.x、::1）服务端直接拒绝；封禁"你当前请求所用的 IP"会被拒绝。所以正常操作不会把自己锁死。

## 浏览器一直弹证书警告

自签证书的警告**只能靠导入信任链消除**，SAN 再全也一样弹。路径：**设置 → 用户管理 → HTTPS 证书** → 下载 PEM（Windows 用 DER）→ 核对指纹 → 复制对应系统的导入命令执行。导入一次永久有效。临时用可以 `curl -k` 跳过校验。公网 IP 部署想要零警告，可用 Let's Encrypt 给 `<ip>.sslip.io` 签真证书（配置 `sites[].cert/key`）；Tailscale 用户优先 `tailscale cert` + ts.net 域名。

## 为什么直连 dsh web 端口（19080/3080）没有登录墙

v0.4 起门禁由本插件**自带的 HTTPS 网关**（默认 `https://<IP>:19843`）承担，不是宿主的 19080。直连 19080 等于绕过网关——**请保证 dsh web 只监听 loopback**（127.0.0.1），对外只暴露 19843。本机 `dsh web` 若被改绑到 0.0.0.0:19080，等于没有认证裸奔。

## 登录后很快又被要求登录

- 必须通过网关的 HTTPS 地址访问（cookie 带 `Secure` 标志，浏览器只在 HTTPS 下收发）——用 `http://` 访问根本登录不上
- 改密码、被重置密码、被降级角色都会踢掉你的**其他**会话（当前浏览器不受影响）
- 会话 7 天滑动过期；dsh 重启不掉线（会话落盘在 `sessions.json`）

## 重置密码的临时密码没记下来

临时密码只在弹窗里显示一次，丢了就再点一次「重置密码」生成新的——每次重置都会作废该用户全部旧会话，旧临时密码同时失效。

## 其他插件怎么知道当前请求是哪个用户

消费 cordis 服务 `user-management`（`resolveRequest(req)` / `resolveToken(token)`），浏览器端直接 `fetch('/user-management/api/session')`。完整示例见 README 的「给其他插件：解析请求的用户身份」章节。

## 操作日志 / 审计文件太大了

自动滚动：登录记录保留最近 2000 条、操作日志 5000 条，超限自动裁掉最旧的。手动清空：管理员在「操作日志」页点「清空」（或逐条删除），该操作本身也会留痕。紧急瘦身可停 dsh web 后删除 `activity.jsonl` / `audit.jsonl`。

## 网关没起来 / 端口被占用

```bash
# 谁占着 19843：
lsof -iTCP:19843
# 启动日志（用户管理所有 [user-management] 前缀的输出都在这里）：
grep user-management ~/.dsh/logs/web.out.log ~/.dsh/logs/web.err.log
```

- `EADDRINUSE`：19843 被别的进程（或另一个 dsh 实例）占了——杀掉占用者，或在 `~/.dsh/settings.yaml` 的 `user-management:` 段改 `port`
- 配置了 `enabled: false` 网关不会启动
- 改了 hosts/证书配置不生效：删除 `~/.dsh/user-management/certs/` 下的旧证书文件再重启（旧证书按指纹稳定复用，不会自动重签）

## 升级 dsh 后网关行为异常

网关是独立监听器，不依赖宿主内部结构，升级宿主一般无感。若异常：先看 `~/.dsh/logs/web.err.log` 里 `[user-management]` 的报错，再到 [GitHub Issues](https://github.com/weibaohui/user-management/issues) 反馈（附日志）。
