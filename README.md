# unifi2netbox

Synchronizes devices, interfaces, VLANs, WLANs, uplink cables, and device type specifications from one or more UniFi Controllers into NetBox.

NetBox is kept as the authoritative inventory while UniFi provides the operational data. Synchronization direction: **UniFi → NetBox** (no data is written back to UniFi).

---

## Table of Contents

- [Features](#features)
- [Quick Start](#quick-start)
- [Configuration](#configuration)
- [Community Device Specs](#community-device-specs)
- [NetBox Cleanup](#netbox-cleanup)
- [Continuous Sync](#continuous-sync)
- [Supported Hardware](#supported-hardware)
- [Architecture](#architecture)
- [Testing](#testing)
- [Documentation](#documentation)
- [Contributing](#contributing)
- [License](#license)

---

## Features

| Feature | Description |
|---|---|
| **Device Sync** | Creates and updates devices with serial, MAC, firmware, IP, model, site |
| **Interface Sync** | Physical ports, radio interfaces, speed, PoE mode, MAC |
| **Device Type Specs** | Auto-populates port templates, console/power ports from 173+ Ubiquiti models |
| **VLAN / WLAN Sync** | Imports UniFi networks and wireless SSIDs into NetBox |
| **Cable Sync** | Maps uplink cables between devices |
| **DHCP Auto-Discovery** | Detects DHCP ranges from UniFi and assigns static IPs |
| **VRF Support** | Optional VRF per site (existing, create, or none) |
| **Cleanup** | Deletes stale devices, orphan interfaces/IPs/cables, unused device types |
| **Continuous Sync** | Runs every N seconds (configurable, default 10 min) |
| **Multi-Controller** | Supports multiple UniFi controllers in parallel |
| **Dual API** | Works with both Integration API (v1) and Legacy API (username/password) |

---

## Quick Start

### Docker (recommended)

```bash
cp .env.example .env
# Edit .env with your UniFi and NetBox credentials
docker compose up --build
```

The container syncs continuously every 10 minutes by default (`SYNC_INTERVAL=600`).

### LXC / Proxmox

```bash
bash lxc/create-lxc.sh [CTID]
# Edit /opt/unifi2netbox/.env inside the container
systemctl start unifi2netbox
```

### Bare-metal / VM

```bash
sudo bash lxc/install.sh
# Edit /opt/unifi2netbox/.env
systemctl start unifi2netbox
```

---

## Configuration

Configuration comes from environment variables (`.env`) with optional YAML override (`config/config.yaml`). Environment variables take precedence.

See [`.env.example`](.env.example) for a fully commented reference of all 37 environment variables.

For detailed configuration documentation, see [docs/configuration.md](docs/configuration.md).

### Essential Variables

| Variable | Required | Description |
|---|---|---|
| `UNIFI_URLS` | Yes | Controller URL(s) |
| `UNIFI_API_KEY` | * | API key (Integration API) |
| `UNIFI_USERNAME` / `UNIFI_PASSWORD` | * | Credentials (Legacy API) |
| `NETBOX_URL` | Yes | NetBox base URL |
| `NETBOX_TOKEN` | Yes | NetBox API token |
| `NETBOX_TENANT` | Yes | Tenant name |

\* Either API key or username/password is required.

### Feature Toggles

| Variable | Default | Description |
|---|---|---|
| `SYNC_INTERFACES` | `true` | Sync physical ports and radios |
| `SYNC_VLANS` | `true` | Sync VLANs from UniFi networks |
| `SYNC_WLANS` | `true` | Sync wireless SSIDs |
| `SYNC_CABLES` | `true` | Sync uplink cables |
| `SYNC_STALE_CLEANUP` | `true` | Mark missing devices offline |
| `NETBOX_CLEANUP` | `false` | **Destructive** cleanup of stale data |
| `SYNC_INTERVAL` | `600` | Seconds between sync runs (0 = once) |

---

## Community Device Specs

unifi2netbox includes a bundled hardware database of **173 Ubiquiti device types** sourced from the [netbox-community/devicetype-library](https://github.com/netbox-community/devicetype-library).

For each known device, the following is automatically populated:

- Interface templates with correct types (1000base-t, 10gbase-x-sfpp, etc.)
- PoE mode and type per port
- Console port templates (RJ-45)
- Power port templates with max/allocated draw
- Part number, U height, airflow, weight
- Full depth and rack-mount info

The community specs are merged with a hardcoded database (`UNIFI_MODEL_SPECS`) of ~47 models. Hardcoded values always take precedence, ensuring manual overrides are preserved.

**New devices**: When an unknown UniFi device appears, unifi2netbox automatically creates a rich device type from the community database if a match is found.

See [docs/device-specs.md](docs/device-specs.md) for details on the merge logic and how to add custom specs.

---

## NetBox Cleanup

> **Warning**: This feature permanently deletes data from NetBox. Test thoroughly before enabling in production.

Enable with `NETBOX_CLEANUP=true`. The cleanup phase runs after each sync and removes:

| What | Description |
|---|---|
| **Stale devices** | Devices in NetBox not found in UniFi (after grace period) |
| **Garbage interfaces** | Interfaces with `?` in the name |
| **Orphan IPs** | IP addresses with no assigned object |
| **Orphan cables** | Cables with missing terminations |
| **Unused device types** | Device types with zero devices assigned |

The grace period (`CLEANUP_STALE_DAYS`, default 30) prevents deletion of temporarily offline devices. Set to `0` for immediate cleanup.

See [docs/cleanup.md](docs/cleanup.md) for safety guidelines and best practices.

---

## Continuous Sync

The `SYNC_INTERVAL` variable controls how often the sync loop runs:

| Value | Behavior |
|---|---|
| `0` | Run once and exit (for cron or systemd timer) |
| `600` | Every 10 minutes (recommended for Docker) |
| `300` | Every 5 minutes |
| `3600` | Every hour |

Between runs, per-run caches are cleared to ensure fresh data.

---

## Supported Hardware

The bundled database covers **173 Ubiquiti models** including switches, gateways, access points, and UISP/airMAX devices.

The hardcoded specs (`UNIFI_MODEL_SPECS`) include detailed port definitions for ~47 commonly deployed models. All 173 models from the community library get full interface/console/power port templates.

Devices not in either database are still synced — they just won't have pre-configured templates.

See [docs/device-specs.md](docs/device-specs.md) for the full list.

---

## Architecture

```
UniFi Controller(s)
  ↓ (Integration API v1 or Legacy API)
UniFi API wrapper (unifi/)
  ↓
Normalization & Mapping (main.py)
  ↓ (pynetbox)
NetBox API
```

### Threading Model

```
Controller Pool (MAX_CONTROLLER_THREADS=5)
  └── Site Pool (MAX_SITE_THREADS=8)
        └── Device Pool (MAX_DEVICE_THREADS=8)
```

All thread limits are configurable via environment variables. HTTP connection pool: 50 connections. Thread-safe caches with dedicated locks for VRFs, custom fields, tags, VLANs, cables, and device type specs.

### File Structure

| File / Directory | Purpose |
|---|---|
| `main.py` | Core orchestration, sync, cleanup (~3000 lines) |
| `unifi/` | UniFi API abstraction (Integration + Legacy) |
| `config/` | YAML configuration and site mapping |
| `data/` | Bundled community device specs (JSON) |
| `tests/` | pytest test suite |
| `lxc/` | LXC/Proxmox deployment scripts |
| `docs/` | Extended documentation |
| `.gitea/workflows/` | CI/CD pipeline |

See [docs/architecture.md](docs/architecture.md) for deep-dive into threading, caching, and API flows.

---

## Testing

Run the test suite:

```bash
pip install -r requirements.txt
pytest tests/ -v
```

48 tests covering:
- Device helper functions (name, serial, MAC, IP extraction)
- Community device specs (loading, lookup, merge)
- Cleanup configuration (env var parsing)

---

## Documentation

- **[Configuration Reference](docs/configuration.md)** — all 37 env vars with examples
- **[Cleanup Guide](docs/cleanup.md)** — safety guidelines for destructive cleanup
- **[Device Specs](docs/device-specs.md)** — community specs, merge logic, custom models
- **[Architecture](docs/architecture.md)** — threading, caching, API compatibility
- **[Troubleshooting](docs/troubleshooting.md)** — common issues and solutions
- **[FAQ](docs/faq.md)** — frequently asked questions
- **[Changelog](CHANGELOG.md)** — version history

---

## Contributing

1. Fork the repository
2. Create a feature branch
3. Write tests for new functionality
4. Ensure `pytest tests/ -v` passes
5. Submit a pull request

The CI pipeline (Gitea Actions) runs syntax checks, tests, and Docker build on every push.

---

## License

[MIT License](LICENSE)

---

> **Disclaimer**: This tool performs direct write operations in NetBox via API. Validate configuration and test thoroughly before production use.
