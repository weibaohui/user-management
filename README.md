# @weibaohui/user-management

[![npm version](https://img.shields.io/npm/v/@weibaohui/user-management.svg)](https://www.npmjs.com/package/@weibaohui/user-management)
[![CI](https://github.com/weibaohui/user-management/actions/workflows/publish.yml/badge.svg)](https://github.com/weibaohui/user-management/actions/workflows/publish.yml)
[![license](https://img.shields.io/npm/l/@weibaohui/user-management.svg)](https://github.com/weibaohui/user-management/blob/main/LICENSE)

dsh 插件 · 用户管理：给 dsh web 加一道登录门禁——未登录访问任何页面会跳到登录页，API 与 WebSocket 直接 401；登录后可在设置页管理用户（列表 / 删除 / 重置密码 / 角色调整）并查看登录记录与访问记录。内置两级角色：**管理员管所有用户，普通用户只能查看和修改自己的信息**。

## 核心功能

- **全局登录门禁**：未登录的页面访问 302 跳转 `/login`；未登录的 API 请求、WebSocket 升级一律 401。登录页为插件自带的独立页面（登录 / 注册双 Tab），不依赖宿主前端，深浅色自适应。
- **首个注册者即管理员**：系统内没有任何账号时，第一个注册的账号自动成为管理员；此后注册的都是普通用户。
- **用户管理（仅管理员）**：用户列表（角色 / 创建时间 / 最后登录）、删除用户、重置密码（生成随机临时密码，仅展示一次）、提升 / 降级角色。
- **记录审计**：登录记录（登录 / 登录失败 / 登出 / 改密 / 注册 / 重置密码 / 角色变更 / 删除）与访问记录（页面级访问），支持按用户名、类型过滤。普通用户只能看到自己的登录类记录。
- **操作日志（审计）**：独立 `audit.jsonl` 账本记录每个登录用户经过门禁的全部 API 调用与 WebSocket 连接——时间、用户、方法、路径、响应状态、来源 IP（宿主 RPC 的操作语义在 URL 路径里，如 `POST /api/<endpoint>`，无需解析请求体）。静态资源与页面导航不记（页面导航在访问记录里）。滚动保留最近 5000 条，仅管理员可查，支持按用户 / 方法 / 路径 / 状态过滤。
- **自助服务（所有登录用户）**：查看自己的信息、修改密码（改密后其他会话全部登出）。
- **会话持久**：7 天滑动过期，dsh 重启不掉线；HttpOnly Cookie。

## 安全模型（请务必阅读）

- **门禁是"进门"级别**：进门之后，所有登录用户看到的是**同一个 dsh 实例的会话与数据**——本插件做的是"谁能访问"，不是多用户数据隔离。请勿把普通用户身份当作数据边界。
- **硬拦截模式（默认）**：宿主路由表没有中间件机制，且 `/api`、`/plugins` 前缀已被占用；插件通过公开的 `webServer.server`（node:http Server 实例）重排 `request` / `upgrade` 监听器实现真·全局拦截。这是对公开字段的非常规使用，**dsh 大版本升级后可能失效**。
- **降级模式**：若 server 实例不可达，自动退化为路由级网关（`/` 前缀包裹静态兜底）。此模式有两个盲区：`/api`（由宿主自带的 Host/Origin 信任检查兜底）与 `/plugins`。启动日志会明确提示 `degraded to route-level gate`。
- **凭据存储**：密码经 scrypt 加盐哈希；用户与会话数据落盘在 `$DSH_HOME/user-management/`（`users.json`、`sessions.json`、`activity.jsonl`、`audit.jsonl`，0600 权限，原子写）。临时密码、明文密码、请求体内容永不落盘、不进日志。
- **开放注册**：注册始终开放（新账号均为普通用户）。若不希望任何人注册，请勿将 dsh web 暴露给不受信任的网络。
- **访问记录口径**：记录页面文档加载与安全事件，不记录静态资源与 API 轮询；账本滚动保留最近 2000 条。

## 安装

```bash
dsh plugin add @weibaohui/user-management
```

或手动安装（web profile）：`package.json` 依赖加 `"link:"`/`^0.1.0` → `node_modules` 建软链 → `dsh.profile.bundles` 数组加入包名 → 重启 dsh web。

安装重启后访问 `http://<host>:19080/`：首次会进入注册页，注册的第一个账号即管理员；管理界面在 **设置 → 用户管理**。

## 开发

```bash
npm install
npm test           # node --test（后端 + 门禁 + API 权限矩阵 + 前端契约）
npm run build:client
npm run check
```

## License

MIT
