# Architecture

## Overview

```
UniFi Controller(s)
  ↓ (Integration API v1 or Legacy API)
UniFi API wrapper (unifi/)
  ↓
Normalization & Mapping (main.py)
  ↓ (pynetbox)
NetBox API
  ↓
[Optional] Cleanup Phase
```

---

## API Compatibility

unifi2netbox supports two UniFi API modes:

### Integration API v1 (recommended)

- Uses API key authentication (`X-API-KEY` header)
- URL format: `https://controller/proxy/network/integration/v1`
- Returns structured JSON with consistent field names
- Device detail endpoint for per-port data

### Legacy API

- Uses username/password authentication with session cookies
- Optional MFA/TOTP support
- URL format: `https://controller:8443`
- Returns different data format (`port_table`, `radio_table`)
- Network config fetched via `networkconf` endpoint

The API mode is auto-detected from the URL path. Both modes produce the same normalized data for NetBox sync.

---

## Threading Model

```
Main Thread
  └── Controller Pool (MAX_CONTROLLER_THREADS=5)
        └── Site Pool (MAX_SITE_THREADS=8)
              └── Device Pool (MAX_DEVICE_THREADS=8)
```

### Thread Pools

| Pool | Default | Scope |
|---|---|---|
| Controller | 5 threads | One thread per UniFi controller URL |
| Site | 8 threads | One thread per UniFi site (per controller) |
| Device | 8 threads | One thread per device (per site) |

### Maximum Concurrent Operations

With defaults: 5 × 8 × 8 = **320 concurrent device operations**.

Reduce thread counts for:
- Smaller environments (fewer devices)
- Rate-limited APIs
- Resource-constrained hosts

---

## Thread-Safe Caches

| Cache | Lock | Purpose |
|---|---|---|
| `vrf_cache` | `vrf_cache_lock` + per-VRF locks | Prevent duplicate VRF creation |
| `_custom_field_cache` | `_custom_field_lock` | Cache custom field objects |
| `_tag_cache` | `_tag_lock` | Cache tag objects |
| `_vlan_cache` | `_vlan_lock` | Cache VLAN objects |
| `_cable_lock` | (global) | Serialize cable creation |
| `_device_type_specs_done` | `_device_type_specs_lock` | Process each device type once |
| `postable_fields_cache` | `postable_fields_lock` | Cache valid API fields per endpoint |
| `_cleanup_serials_by_site` | `_cleanup_serials_lock` | Track serials for cleanup phase |

---

## Sync Flow

### Per Device

1. Extract device info (name, model, MAC, IP, serial)
2. Skip if offline/disconnected
3. Determine device role from features/type
4. Get or create VRF (if configured)
5. Get or create device type (with community specs)
6. Ensure device type specs (templates, part number, etc.)
7. Get or create device in NetBox
8. Update device fields (name, model, firmware, status)
9. Sync custom fields (MAC, firmware, uptime, last seen)
10. Sync IP address (with DHCP-to-static conversion)
11. Sync interfaces (if enabled)

### Per Site (after devices)

12. Sync uplink cables (if enabled)

### After All Sites

13. Run cleanup phase (if enabled)

---

## Connection Pool

NetBox API client uses a custom HTTP session with:
- 50 connection pool size (connections + max size)
- SSL verification disabled by default
- `threading=True` on pynetbox client

---

## Data Flow: Device Type Specs

```
UNIFI_MODEL_SPECS (hardcoded, ~47 models)
  + community specs JSON (173 models)
    ↓ _resolve_device_specs() merges both
    ↓ ensure_device_type_specs() applies to NetBox
    ↓ _sync_templates() syncs interface/console/power port templates
```

---

## Sync Loop

```
while True:
    Clear per-run caches
    Process all controllers (parallel)
      → Process all sites (parallel)
        → Process all devices (parallel)
    Run cleanup phase
    Sleep SYNC_INTERVAL seconds
    (break if SYNC_INTERVAL == 0)
```
