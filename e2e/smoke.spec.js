const { test, expect } = require('@playwright/test');

const ADMIN_PASSWORD = process.env.E2E_PASSWORD || 'e2e-test-password-123';

async function login(page) {
  await page.goto('/');
  const passwordInput = page.getByPlaceholder('输入密码');
  await expect(passwordInput).toBeVisible();
  await passwordInput.fill(ADMIN_PASSWORD);
  await page.getByRole('button', { name: '登录' }).click();
  // Successful login swaps the login form for the app shell + dashboard.
  await expect(passwordInput).toBeHidden();
  await expect(page.getByText('订阅总数')).toBeVisible();
}

test('login page renders and authenticates with the initial admin password', async ({ page }) => {
  await page.goto('/');

  await expect(page.getByPlaceholder('输入密码')).toBeVisible();
  await expect(page.getByRole('button', { name: '登录' })).toBeVisible();

  await page.getByPlaceholder('输入密码').fill(ADMIN_PASSWORD);
  await page.getByRole('button', { name: '登录' }).click();

  // Redirected to the dashboard (SPA route "/") after a successful login.
  await expect(page).toHaveURL(/\/$/);
  await expect(page.getByText('订阅总数')).toBeVisible();
});

test('dashboard renders the stat cards', async ({ page }) => {
  await login(page);

  for (const statTitle of ['订阅总数', '节点统计', '用户总数', '最低延迟']) {
    await expect(page.getByText(statTitle, { exact: true })).toBeVisible();
  }
});

test('nodes page loads without console errors', async ({ page }) => {
  const consoleErrors = [];
  page.on('console', (message) => {
    if (message.type() === 'error') {
      consoleErrors.push(message.text());
    }
  });
  page.on('pageerror', (error) => {
    consoleErrors.push(String(error));
  });

  await login(page);
  await page.getByRole('link', { name: '节点管理' }).click();
  await expect(page.getByText('暂无节点，请先添加订阅或自建节点')).toBeVisible();

  expect(consoleErrors).toEqual([]);
});
