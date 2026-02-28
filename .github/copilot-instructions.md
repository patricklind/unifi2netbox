<!-- Copilot / AI agent instructions for contributors and coding agents -->
# Copilot instructions for unifi2netbox

Purpose: give an AI coding agent the minimal, actionable knowledge to be productive in this repository.

- **Big picture**
  - One-way sync: UniFi -> NetBox; orchestrated from `main.py` which coordinates site/device iteration and NetBox API calls.
  - UniFi API wrappers and helpers live in `unifi/` (notably `unifi/unifi.py`, `unifi/resources.py`, `unifi/device.py`, `unifi/sites.py`).
  - NetBox interactions use `pynetbox` from `main.py` and helper functions (e.g., VRF helpers in `main.py`).
  - Device model enrichment uses `data/ubiquiti_device_specs.json` plus some hardcoded mappings in `main.py`.

- **Important files to inspect first**
  - `main.py` — orchestration, caching, concurrency, VRF and NetBox rules, cleanup behavior.
  - `unifi/unifi.py` — UniFi connection handling: Integration API vs session login, retries, timeouts, session persistence (`SESSION_FILE`).
  - `unifi/resources.py` — BaseResource pattern; how resources build URLs and normalize responses.
  - `unifi/device.py` — device-specific resource wrapper (shows integration vs legacy API branching).
  - `config/config.yaml.SAMPLE` and `config/site_mapping.yaml` — canonical config keys and site-mapping behavior.
  - `tests/` — unit tests and fixtures show expected inputs/outputs (see `tests/conftest.py`).

- **Design & patterns**
  - Two UniFi modes: "integration" (API key, prefers integration endpoints) and "legacy" (session login). `Unifi` chooses integration when `UNIFI_API_KEY` validates.
  - `unifi/resources.BaseResource` centralizes URL building and common CRUD (`all`, `get`, `create`, `update`, `delete`). Follow its conventions when adding new endpoints.
  - `main.py` uses many thread-safe caches protected by `threading.Lock` objects (VRFs, tags, VLANs). Be careful when modifying cache access — respect existing locks.
  - Concurrency is configurable via env vars: `MAX_CONTROLLER_THREADS`, `MAX_SITE_THREADS`, `MAX_DEVICE_THREADS` — tests assume multi-thread-friendly behavior.

- **Critical workflows (how to run & debug)**
  - Local dev / tests:
    - Install deps: `pip install -r requirements.txt` (virtualenv recommended).
    - Run tests: `pytest tests/ -v`.
  - Docker: `docker compose up --build -d` (see `docker-compose.yml` and `Dockerfile`).
  - LXC helper: scripts in `lxc/` (`create-lxc.sh`, `install.sh`) show systemd install and service layout.
  - Logs: runtime logs are written to `logs/` by `main.py`; enable DEBUG in environment or modify `setup_logging` for local debugging.

- **Important env/config keys** (used by code directly)
  - UniFi: `UNIFI_URLS`, `UNIFI_API_KEY`, `UNIFI_USERNAME`, `UNIFI_PASSWORD`, `UNIFI_MFA_SECRET`, `UNIFI_VERIFY_SSL`, `UNIFI_REQUEST_TIMEOUT`.
  - NetBox: `NETBOX_URL`, `NETBOX_TOKEN`, `NETBOX_TENANT`, `NETBOX_VRF_MODE`, `NETBOX_VERIFY_SSL`, `NETBOX_CLEANUP` (dangerous — destructive cleanup).
  - Sync toggles: `SYNC_INTERFACES`, `SYNC_VLANS`, `SYNC_WLANS`, `SYNC_CABLES`, `SYNC_STALE_CLEANUP`, `SYNC_INTERVAL` (0 = run-once).

- **Project-specific conventions**
  - Configuration precedence: environment variables override `config/config.yaml` values.
  - When integrating new UniFi endpoints, prefer adding a `Resource` subclass that follows `BaseResource` URL building.
  - Use the NetBox API `OPTIONS` schema (see `get_postable_fields`) to determine which fields can be posted.
  - The code prefers selecting the oldest matching NetBox object when duplicates exist (see VRF selection in `main.py`).

- **Safety notes for agents**
  - `NETBOX_CLEANUP` can delete NetBox data. Search for `NETBOX_CLEANUP` in `main.py` and tests before touching cleanup logic.
  - Network/API retries and backoffs are explicitly implemented in `unifi/unifi.py` — avoid duplicating retry logic without understanding existing behavior.

- **Examples (quick reference)**
  - To find how devices are listed: inspect `unifi/device.Device.all()` which uses `unifi.make_request()` via `BaseResource.all()`.
  - To change VRF behaviour: `get_vrf_for_site()` in `main.py` reads `NETBOX_VRF_MODE` and calls `get_or_create_vrf()` / `get_existing_vrf()`.

If anything is unclear or you'd like me to expand specific sections (for example: testing tips, more endpoint examples, or a short contributor HOWTO), tell me which area to expand. 
