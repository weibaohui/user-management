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

test('otp field is hidden until the server asks for it (otpRequired handshake)', () => {
  const html = renderLoginPage({ hasUsers: true })
  assert.ok(html.includes('id="login-otp"'), 'otp input exists')
  assert.ok(html.includes('autocomplete="one-time-code"'), 'OTP autofill hint for authenticator browsers')
  assert.ok(html.includes('maxlength="6"'), '6-digit cap')
  // hidden by default — revealing it is gated on the login response's otpRequired
  assert.ok(html.includes('id="login-otp-label" style="display:none"'))
  assert.ok(html.includes("id=\"login-otp\" inputmode=\"numeric\" autocomplete=\"one-time-code\" maxlength=\"6\" placeholder=\"6 位动态码\" style=\"display:none\""))
  assert.ok(html.includes('otpRequired'), 'script reacts to the otpRequired flag')
  assert.ok(html.includes("otp: otpShown ?"), 'login submit carries the code only after the field is shown')
  assert.ok(!html.includes('reg-otp'), 'register form stays OTP-free')
})

test('login page remembers the last successful username via localStorage', () => {
  const html = renderLoginPage({ hasUsers: true })
  assert.ok(html.includes("localStorage.setItem('um-last-username'"), 'saved on successful login')
  assert.ok(html.includes("localStorage.getItem('um-last-username'"), 'prefilled on the next visit')
  assert.ok(html.includes("getElementById('login-username').value = remembered"), 'restored into the username field')
})
