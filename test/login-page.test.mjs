// Login page contract: per-form error targets, native password length gate.
import { test } from 'node:test'
import assert from 'node:assert/strict'
import { createRequire } from 'node:module'

const require = createRequire(import.meta.url)
const { renderLoginPage } = require('../src/login-page.js')

test('login page renders both tabs with per-form error regions', () => {
  const html = renderLoginPage({ hasUsers: true })
  assert.ok(html.includes('id="login-form"'))
  assert.ok(html.includes('id="register-form"'))
  // two independent error regions, resolved via form.querySelector('.err')
  assert.equal(html.split('<div class="err"></div>').length - 1, 2)
  assert.ok(html.includes("form.querySelector('.err')"), 'errors are written to the submitting form’s region')
  assert.ok(!html.includes("getElementById('err')"), 'no shared error element (would hide register errors)')
})

test('fresh system flips to register with the first-admin hint', () => {
  const fresh = renderLoginPage({ hasUsers: false })
  assert.ok(fresh.includes('var hasUsers = false;'))
  assert.ok(fresh.includes('首个注册的账号将成为管理员'))
  const used = renderLoginPage({ hasUsers: true })
  assert.ok(used.includes('var hasUsers = true;'))
})

test('register password input carries native minlength', () => {
  const html = renderLoginPage({ hasUsers: false })
  assert.ok(html.includes('minlength="6"'), 'browser validates length before the server round-trip')
})
