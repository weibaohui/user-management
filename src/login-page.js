'use strict'

/**
 * Standalone login/register page served at `/login`.
 *
 * Deliberately independent of the host SPA (which the gate blocks until
 * authenticated): one self-contained HTML string, no external assets, dark/
 * light adaptive. Talks to /user-management/api like everything else.
 */

function esc(value) {
  return String(value).replace(/[&<>"']/g, (ch) => ({ '&': '&amp;', '<': '&lt;', '>': '&gt;', '"': '&quot;', "'": '&#39;' }[ch]))
}

const PAGE_STYLES = `
:root { color-scheme: light dark; }
* { box-sizing: border-box; }
body {
  margin: 0; min-height: 100vh; display: flex; align-items: center; justify-content: center;
  font-family: -apple-system, BlinkMacSystemFont, "Segoe UI", "PingFang SC", "Hiragino Sans GB", "Microsoft YaHei", sans-serif;
  background: #f5f6f8; color: #1f2329;
}
@media (prefers-color-scheme: dark) {
  body { background: #16181c; color: #e8eaed; }
}
.card {
  width: 360px; max-width: calc(100vw - 32px); padding: 32px 28px 24px;
  border-radius: 14px; background: #ffffff; border: 1px solid rgba(0,0,0,.08);
  box-shadow: 0 8px 30px rgba(0,0,0,.08);
}
@media (prefers-color-scheme: dark) {
  .card { background: #22252b; border-color: rgba(255,255,255,.08); box-shadow: 0 8px 30px rgba(0,0,0,.4); }
}
h1 { font-size: 18px; margin: 0 0 4px; text-align: center; }
.sub { font-size: 12px; opacity: .6; text-align: center; margin: 0 0 20px; }
.tabs { display: flex; gap: 4px; background: rgba(127,127,127,.12); border-radius: 8px; padding: 3px; margin-bottom: 18px; }
.tabs button {
  flex: 1; border: 0; background: transparent; color: inherit; font-size: 13px;
  padding: 7px 0; border-radius: 6px; cursor: pointer;
}
.tabs button.active { background: #ffffff; box-shadow: 0 1px 3px rgba(0,0,0,.15); }
@media (prefers-color-scheme: dark) { .tabs button.active { background: #3a3f47; } }
label { display: block; font-size: 12px; opacity: .75; margin: 12px 0 4px; }
input {
  width: 100%; padding: 9px 11px; font-size: 14px; border-radius: 8px;
  border: 1px solid rgba(127,127,127,.35); background: transparent; color: inherit; outline: none;
}
input:focus { border-color: #4c6ef5; }
.err { min-height: 18px; font-size: 12px; color: #e03131; margin: 10px 0 2px; white-space: pre-wrap; }
.submit {
  width: 100%; margin-top: 10px; padding: 10px 0; font-size: 14px; border: 0; border-radius: 8px;
  background: #4c6ef5; color: #fff; cursor: pointer;
}
.submit:disabled { opacity: .55; cursor: default; }
.hint { font-size: 12px; color: #f08c00; margin-top: 12px; text-align: center; }
.foot { margin-top: 16px; font-size: 11px; opacity: .45; text-align: center; }
`

const PAGE_SCRIPT = `
(function () {
  var hasUsers = __HAS_USERS__;
  var loginForm = document.getElementById('login-form');
  var registerForm = document.getElementById('register-form');
  var err = document.getElementById('err');
  function show(tab) {
    loginForm.style.display = tab === 'login' ? '' : 'none';
    registerForm.style.display = tab === 'register' ? '' : 'none';
    document.getElementById('tab-login').classList.toggle('active', tab === 'login');
    document.getElementById('tab-register').classList.toggle('active', tab === 'register');
    err.textContent = '';
  }
  document.getElementById('tab-login').addEventListener('click', function () { show('login') });
  document.getElementById('tab-register').addEventListener('click', function () { show('register') });
  function submit(form, path, body) {
    var button = form.querySelector('.submit');
    button.disabled = true;
    err.textContent = '';
    fetch(path, {
      method: 'POST',
      headers: { 'content-type': 'application/json' },
      body: JSON.stringify(body),
    }).then(function (res) {
      return res.json().catch(function () { return {} }).then(function (data) { return { ok: res.ok, data: data } });
    }).then(function (result) {
      if (result.ok) { location.href = '/'; return; }
      err.textContent = (result.data && result.data.error) || '请求失败';
      button.disabled = false;
    }).catch(function () {
      err.textContent = '网络错误';
      button.disabled = false;
    });
  }
  loginForm.addEventListener('submit', function (e) {
    e.preventDefault();
    submit(loginForm, '/user-management/api/login', {
      username: document.getElementById('login-username').value.trim(),
      password: document.getElementById('login-password').value,
    });
  });
  registerForm.addEventListener('submit', function (e) {
    e.preventDefault();
    var password = document.getElementById('reg-password').value;
    if (password !== document.getElementById('reg-password2').value) {
      err.textContent = '两次输入的密码不一致';
      return;
    }
    submit(registerForm, '/user-management/api/register', {
      username: document.getElementById('reg-username').value.trim(),
      password: password,
    });
  });
  if (!hasUsers) {
    document.getElementById('first-hint').style.display = '';
    show('register');
  }
})();
`

/**
 * Render the login page. `hasUsers=false` (fresh system) flips the default
 * tab to register and reveals the first-user-becomes-admin hint.
 */
function renderLoginPage({ hasUsers, title = 'DSH 控制台' } = {}) {
  return '<!doctype html>\n<html lang="zh-CN">\n<head>\n<meta charset="utf-8">\n' +
    '<meta name="viewport" content="width=device-width, initial-scale=1">\n' +
    `<title>${esc(title)} · 登录</title>\n` +
    `<style>${PAGE_STYLES}</style>\n</head>\n<body>\n` +
    '<div class="card">\n' +
    `<h1>${esc(title)}</h1>\n<p class="sub">登录后继续访问</p>\n` +
    '<div class="tabs">' +
    '<button type="button" id="tab-login" class="active">登录</button>' +
    '<button type="button" id="tab-register">注册</button></div>\n' +
    '<form id="login-form">\n' +
    '<label for="login-username">用户名</label>\n<input id="login-username" autocomplete="username" required>\n' +
    '<label for="login-password">密码</label>\n<input id="login-password" type="password" autocomplete="current-password" required>\n' +
    '<div class="err" id="err"></div>\n' +
    '<button class="submit" type="submit">登录</button>\n</form>\n' +
    '<form id="register-form" style="display:none">\n' +
    '<label for="reg-username">用户名</label>\n<input id="reg-username" autocomplete="username" required>\n' +
    '<label for="reg-password">密码（至少 6 位）</label>\n<input id="reg-password" type="password" autocomplete="new-password" required>\n' +
    '<label for="reg-password2">确认密码</label>\n<input id="reg-password2" type="password" autocomplete="new-password" required>\n' +
    '<div class="err"></div>\n' +
    '<button class="submit" type="submit">注册并登录</button>\n' +
    `<div class="hint" id="first-hint" style="display:none">当前还没有任何账号，首个注册的账号将成为管理员</div>\n</form>\n` +
    '<div class="foot">dsh 插件 · user-management</div>\n' +
    '</div>\n' +
    `<script>${PAGE_SCRIPT.replace('__HAS_USERS__', hasUsers ? 'true' : 'false')}</script>\n` +
    '</body>\n</html>\n'
}

module.exports = { renderLoginPage }
