# @weibaohui/user-management

[![DSH plugin](https://img.shields.io/badge/dsh-plugin-green)](https://github.com/topics/dsh-plugin)
[![npm version](https://img.shields.io/npm/v/@weibaohui/user-management)](https://www.npmjs.com/package/@weibaohui/user-management)

**用户管理 + 登录门禁**：给 dsh web 加一道登录验证——未登录访问任何页面自动跳到登录/注册页，API 与 WebSocket 一律 401；内置管理员/普通用户两级角色，管理员管所有用户（删除、重置密码、角色调整）并查看登录记录、访问记录、操作日志，普通用户只能查看和修改自己的信息。

![demo](docs/demo.gif)

## 核心功能

- **全局登录门禁**：未登录的页面访问 302 跳转 `/login`，未登录的 API 请求、WebSocket 升级直接 401；登录页为插件自带的独立页面（登录 / 注册双 Tab），不依赖宿主前端，深浅色自适应
- **首个注册者即管理员**：系统内没有任何账号时，第一个注册的账号自动成为管理员，此后注册的都是普通用户
- **用户管理（仅管理员）**：用户列表（角色 / 创建时间 / 最后登录）、**新增用户（可选管理员或普通用户角色）**、删除用户、重置密码（生成随机临时密码，仅展示一次）、提升 / 降级角色、**禁用 / 启用账号**（禁用立即踢出会话并拒绝登录）；最后一个管理员不可删、不可降、不可禁
- **三本审计账**：登录记录（登录 / 登录失败 / 登出 / 改密 / 注册 / 重置密码 / 角色变更 / 删除 / 禁用 / 封禁等）、访问记录（页面级访问）、操作日志（经过门禁的每一次 API 调用与 WebSocket 连接，含方法 / 路径 / 响应状态 / 来源 IP），均支持按用户、类型、路径、状态过滤
- **IP 封禁**：管理员可将来源 IP 加入封禁列表——命中地址在会话校验之前就被 403 拒绝（登录页也看不到）；服务端拒绝封禁当前请求所用的 IP，防止把自己锁在门外
- **自助服务（所有登录用户）**：查看自己的信息、修改密码（点击左上角头像/用户名 → 修改密码，改密后其他会话全部登出）、查看自己的登录记录
- **会话持久**：7 天滑动过期，dsh 重启不掉线；HttpOnly Cookie，密码 scrypt 加盐哈希，零第三方依赖

## 安装

```bash
dsh plugin --profile web add @weibaohui/user-management -w
```

装完重启 `dsh web` 即生效。

## 使用

1. 首次访问 Web UI 会自动进入注册页——**第一个注册的账号就是管理员**
2. 管理入口：Web UI → **设置页 → 用户管理**
3. 管理员：用户表（新增用户 / 重置密码 / 角色调整 / 禁用启用 / 删除）+ 登录记录 / 访问记录 / 操作日志 / IP 封禁四个管理页
4. 普通用户：个人信息卡 + 修改密码 + 自己的登录记录
5. 数据与审计文件都在 `~/.dsh/user-management/`（`users.json` / `sessions.json` / `activity.jsonl` / `audit.jsonl` / `bans.json`，0600 权限，原子写；审计账本滚动保留最近 5000 条）
6. **IP 封禁按连接源地址（`remoteAddress`）判定**：若部署在反向代理之后，看到的是代理的 IP——需要按真实客户端 IP 封禁时请勿加代理层直连使用

## Remote Gateway 配置

v0.4 起，本插件自带 HTTPS 远程访问网关：dsh web 留在 loopback（`127.0.0.1:3080`），网关（独立 `node:https` 监听器）反代到它——**网关是唯一对外入口，认证不可绕过**。配置走 `~/.dsh/settings.yaml` 的 `user-management:` 段（也支持设置页热生效）。

### 字段

| 字段 | 默认 | 说明 |
|---|---|---|
| `enabled` | `true` | 关掉则不启动网关监听器 |
| `listenHost` | `0.0.0.0` | 网关监听地址；`127.0.0.1` 仅本机可达 |
| `port` | `19843` | 网关 HTTPS 端口 |
| `sites[]` | `[]`（=自动） | 站点白名单 + 证书；空 = 自动枚举本机所有 IP，并附带每个 IP 的 `sslip.io` / `nip.io` 通配 DNS 别名 |
| `sites[].hosts` | — | Host 白名单（域名/IP，支持 `*.example.com` 通配） |
| `sites[].cert` / `sites[].key` | `''` | PEM 文件路径（fullchain + privkey）；不配则按 hosts 自签 |
| `title` | `DSH 控制台` | 登录页标题 |
| `sessionDays` / `loginFailLimit` / `lockoutSeconds` / `maxBodyBytes` | `7` / `5` / `60` / `16384` | 预留字段（当前未接线：会话由 store 管、登录失败靠管理员 IP 封禁、body 上限在 API 内） |

### 场景 1：零配置（推荐 · 私网）

不配 `sites` → 网关自动枚举本机所有非 loopback IP（IPv4 + IPv6，含 Tailscale）填进 hosts，并签发 **100 年自签证书**（SAN 覆盖这些 IP + localhost）；`listenHost` 默认 `0.0.0.0`。打开 `https://<本机任意 IP>:19843` → 信任自签证书 → 注册/登录（**首个访问者即管理员**）。

### 场景 2：域名 + 证书

```yaml
user-management:
  listenHost: '0.0.0.0'
  port: 19843
  sites:
    - hosts: ['dsh.example.com']
      cert: '/etc/letsencrypt/live/dsh.example.com/fullchain.pem'
      key:  '/etc/letsencrypt/live/dsh.example.com/privkey.pem'
```

- `cert` / `key` 是 PEM 文件路径（fullchain + privkey，如 `certbot certonly -d <域名>` 申请）；配了就加载你的证书，不配则按 hosts 自签。
- 多域名走多项 `sites`（每项自己的 `hosts` + `cert` + `key`），网关按 SNI 选证书。

### 安全边界

- **零配置下首个访问者即管理员**——仅适用于可信私网（Tailscale 等）；公网暴露前请：配 `sites` 白名单 + 用域名证书 + 先在 loopback（`https://127.0.0.1:19843`）注册首个 admin 再对外。
- 自签证书 100 年有效，持久化在 `~/.dsh/user-management/certs/`；**改了 hosts/SAN 后删旧证书文件重启才会重签**（否则复用旧证书保指纹稳定）。
- dsh web 始终留在 loopback，网关是唯一对外入口——直连 3080 绕不过认证。

## 安全边界（务必阅读）

- **门禁是"进门"级别**：进门之后，所有登录用户看到的是同一个 dsh 实例的会话与数据——本插件做的是"谁能访问"，不是多用户数据隔离
- **拦截机制**：v0.4 起门禁是独立 HTTPS 网关监听器（`node:https`，见上文「Remote Gateway 配置」）——所有请求先过网关的会话校验（未登录 document 跳 `/login`，API/WS 返 401），通过后才反代到 loopback dsh web；不再依赖宿主 `webServer.server` 监听器重排（旧版 0.3 的 attachGate + 降级路由级网关已移除）
- **开放注册**：注册始终开放（新账号均为普通用户），请勿将 dsh web 暴露给不受信任的网络
- **证书下载与信任引导**：网关免登录提供 `GET /user-management/api/cert`（PEM，`?format=der` 得 Windows 用的 .cer）与 `GET /user-management/api/cert-info`（SHA-256 指纹 / 有效期 / 覆盖名称）。设置页「HTTPS 证书」卡片一键下载 + 复制各系统导入命令。自签证书不会因 SAN 完整而不弹警告——**消除警告靠导入信任链**（导入后 IP / sslip.io / nip.io 三种访问方式全部干净）；公网 IP 可用 Let's Encrypt 给 `<ip>.sslip.io` 签真证书实现真正零警告；**Tailscale 用户优先用 `tailscale cert` + `机器名.尾网名.ts.net`**（真 CA 证书、零警告），尾网 IP 的 SAN 别名仅作兜底
- **审计口径**：操作日志不记录请求体内容与静态资源；被门禁拒绝的请求（401/302）不记录，防止扫描刷屏；临时密码、明文密码永不落盘、不进日志

## 联系我 :飞书群

![link](https://foruda.gitee.com/images/1774880015525784725/4fd67005_77493.png "link")
