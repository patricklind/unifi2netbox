# Changelog

All notable changes to this project are documented in this file.

---

## [Unreleased]

### Added
- Complete documentation overhaul (README, docs/, CHANGELOG, wiki)
- Improved `.env.example` with grouped sections and safety warnings

---

## 2025-02-12

### Added
- **Unit test suite** — 48 pytest tests for helpers, device specs, and cleanup
- **CI/CD pipeline** — Gitea Actions workflow (lint, test, Docker build)
- **Configurable threading** — `MAX_CONTROLLER_THREADS`, `MAX_SITE_THREADS`, `MAX_DEVICE_THREADS` now read from env vars

### Removed
- `README-old.md` (obsolete, replaced by current README)

### Fixed
- `.gitignore` — added `client-privatekey` and `client-publickey`

---

## 2025-02-11

### Added
- **Community device specs** — 173 Ubiquiti device types from [netbox-community/devicetype-library](https://github.com/netbox-community/devicetype-library), bundled as `data/ubiquiti_device_specs.json`
- **Generic template sync** — `_sync_templates()` for interface, console-port, and power-port templates
- **NetBox cleanup** — 5 cleanup functions controlled by `NETBOX_CLEANUP` env var:
  - Stale devices (with configurable grace period via `CLEANUP_STALE_DAYS`)
  - Garbage interfaces (names containing `?`)
  - Orphan IP addresses (unassigned)
  - Orphan cables (missing terminations)
  - Unused device types (zero devices)
- **Auto-create device types** — new UniFi products automatically get rich device types from community database
- **Continuous sync loop** — `SYNC_INTERVAL` env var (default: 600s / 10 minutes)
- Community specs merge: hardcoded `UNIFI_MODEL_SPECS` overlay on community data
- Case-insensitive part number lookup for community specs

### Fixed
- Resolved 7 unresolved git merge conflicts in main.py (from DHCP commit)
- Case-insensitive part number mismatch (e.g. `USW-Pro-48-PoE` vs `USW-PRO-48-POE`)

---

## 2025-02-10

### Added
- **DHCP auto-discovery** — automatically detects DHCP ranges from UniFi network configs (`dhcpd_enabled` + `ip_subnet`)
- Manual `DHCP_RANGES` merged with auto-discovered ranges
- `DHCP_AUTO_DISCOVER` env var (default: `true`)
- Legacy API fallback for network config fetching

---

## 2025-02-09

### Added
- **Device type specs database** — built-in `UNIFI_MODEL_SPECS` with ~47 UniFi models
- Interface template sync from specs (auto-creates port templates)
- Part number, U height, PoE budget sync to device types
- Duplicate template cleanup

### Changed
- Removed unused UniFi classes, anonymized and secured repo
- Fixed tag race condition in concurrent operations

---

## 2025-02-08

### Added
- Cable sync between devices (uplink detection)
- Offline device cleanup (mark as offline)
- Stale device detection per site

### Improved
- Reliability improvements for concurrent API calls

---

## Earlier

### Added
- Initial UniFi to NetBox synchronization
- Device, interface, VLAN, WLAN sync
- VRF support with multiple modes
- Multi-controller support with threading
- UniFi Integration API v1 and Legacy API support
- Docker, LXC/Proxmox, and bare-metal deployment
- Custom field sync (MAC, firmware, uptime, last seen)
- Site mapping (UniFi → NetBox site names)
- Configurable device roles
- Serial number handling modes (mac, unifi, id, none)
