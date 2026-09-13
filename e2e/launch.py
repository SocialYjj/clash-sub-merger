"""E2E launcher: build the SPA when needed, then serve the backend.

Used by Playwright's webServer (see e2e/playwright.config.js). It always runs
the real backend against a throwaway temp DATA_DIR with a seeded initial admin
password, so E2E runs can never touch a developer's or deployment's data.

Env overrides: E2E_PORT, E2E_PASSWORD, E2E_SKIP_FRONTEND_BUILD=1.
"""

import os
import subprocess
import sys
import tempfile
from pathlib import Path

REPO_ROOT = Path(__file__).resolve().parent.parent
FRONTEND_DIR = REPO_ROOT / "submerger"
FRONTEND_DIST_INDEX = FRONTEND_DIR / "dist" / "index.html"

PORT = int(os.environ.get("E2E_PORT", "8765"))
ADMIN_PASSWORD = os.environ.get("E2E_PASSWORD", "e2e-test-password-123")


def ensure_frontend_build() -> None:
    """Build the SPA if its dist output is missing (required for the UI routes)."""
    if FRONTEND_DIST_INDEX.exists():
        return
    if os.environ.get("E2E_SKIP_FRONTEND_BUILD") == "1":
        raise RuntimeError(
            f"Frontend build not found at {FRONTEND_DIST_INDEX} and E2E_SKIP_FRONTEND_BUILD=1. "
            "Run `npm run build` in submerger/ first."
        )
    npm = "npm.cmd" if os.name == "nt" else "npm"
    print(f"[e2e] Building frontend in {FRONTEND_DIR} ...", flush=True)
    subprocess.run([npm, "run", "build"], cwd=FRONTEND_DIR, check=True)


def main() -> None:
    ensure_frontend_build()

    data_dir = tempfile.mkdtemp(prefix="submerger-e2e-")
    print(f"[e2e] Using temporary DATA_DIR: {data_dir}", flush=True)

    # Must be set before importing the app: core.config reads the environment
    # at import time. These also win over any developer .env because
    # dotenv does not override variables that already exist.
    os.environ["DATA_DIR"] = data_dir
    os.environ["STORAGE_BACKEND"] = "sqlite"
    os.environ["INITIAL_ADMIN_PASSWORD"] = ADMIN_PASSWORD
    os.environ["HOST"] = "127.0.0.1"
    os.environ["PORT"] = str(PORT)
    os.environ["GO_SPEEDTEST_ENABLED"] = "false"

    sys.path.insert(0, str(REPO_ROOT))

    import uvicorn  # noqa: E402

    import server  # noqa: E402

    print(f"[e2e] Starting backend on http://127.0.0.1:{PORT}", flush=True)
    uvicorn.run(server.app, host="127.0.0.1", port=PORT, access_log=False, log_level="warning")


if __name__ == "__main__":
    main()
