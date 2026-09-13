/** @type {import('@playwright/test').PlaywrightTestConfig} */
const { defineConfig, devices } = require('@playwright/test');
const fs = require('fs');
const path = require('path');

const REPO_ROOT = path.join(__dirname, '..');
const PORT = 8765;

// Prefer the repo venv on Windows (it has the backend deps); on Linux CI the
// `python` provided by actions/setup-python already has requirements installed.
const defaultPython =
  process.platform === 'win32'
    ? path.join(REPO_ROOT, '.venv', 'Scripts', 'python.exe')
    : 'python';
const python = process.env.E2E_PYTHON || (fs.existsSync(defaultPython) ? defaultPython : 'python');

module.exports = defineConfig({
  testDir: __dirname,
  testMatch: /.*\.spec\.js/,
  fullyParallel: false,
  workers: 1,
  timeout: 60_000,
  expect: { timeout: 15_000 },
  retries: process.env.CI ? 1 : 0,
  reporter: process.env.CI ? [['list'], ['html', { open: 'never' }]] : 'list',
  use: {
    baseURL: `http://127.0.0.1:${PORT}`,
    trace: 'retain-on-failure',
  },
  projects: [
    {
      name: 'chromium',
      use: { ...devices['Desktop Chrome'] },
    },
  ],
  webServer: {
    // launch.py builds the SPA if submerger/dist is missing, then starts the
    // real backend (uvicorn) with a throwaway temp DATA_DIR and a seeded
    // INITIAL_ADMIN_PASSWORD. It never touches the developer's data/ directory.
    command: `${python} e2e/launch.py`,
    cwd: REPO_ROOT,
    url: `http://127.0.0.1:${PORT}/health`,
    reuseExistingServer: !process.env.CI,
    timeout: 240_000,
    stdout: 'pipe',
    stderr: 'pipe',
  },
});
