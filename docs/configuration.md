# Configuration Reference

unifi2netbox uses environment variables (`.env`) as primary configuration, with optional YAML override (`config/config.yaml`). Environment variables always take precedence.

---

## UniFi Connection

| Variable | Required | Default | Description |
|---|---|---|---|
| `UNIFI_URLS` | Yes | — | Controller URL(s). Comma-separated or JSON array. |
| `UNIFI_API_KEY` | * | — | API key for Integration API (recommended). |
| `UNIFI_API_KEY_HEADER` | No | `X-API-KEY` | Custom header name for API key. |
| `UNIFI_USERNAME` | * | — | Username for Legacy API login. |
| `UNIFI_PASSWORD` | * | — | Password for Legacy API login. |
| `UNIFI_MFA_SECRET` | No | — | TOTP secret for 2FA (Legacy API only). |

\* Either `UNIFI_API_KEY` or `UNIFI_USERNAME`/`UNIFI_PASSWORD` is required.

### URL Format

**Integration API** (recommended):
```
UNIFI_URLS=https://controller.example.com/proxy/network/integration/v1
```

**Legacy API**:
```
UNIFI_URLS=https://controller.example.com:8443
```

**Multiple controllers**:
```
UNIFI_URLS=https://ctrl1.example.com/proxy/network/integration/v1,https://ctrl2.example.com/proxy/network/integration/v1
```

---

## NetBox Connection

| Variable | Required | Default | Description |
|---|---|---|---|
| `NETBOX_URL` | Yes | — | NetBox base URL (e.g. `https://netbox.example.com`). |
| `NETBOX_TOKEN` | Yes | — | API token with write access to DCIM, IPAM, Tenancy. |
| `NETBOX_TENANT` | Yes | — | Tenant name. All devices/IPs are assigned to this tenant. |
| `NETBOX_DEVICE_STATUS` | No | `offline` | Default status for newly created devices. |

---

## Serial Number Handling

| Variable | Required | Default | Description |
|---|---|---|---|
| `NETBOX_SERIAL_MODE` | No | `mac` | How the NetBox serial field is populated. |

| Mode | Behavior |
|---|---|
| `mac` (default) | UniFi serial → MAC (uppercase, no colons) → device ID |
| `unifi` | Only UniFi serial (may be empty if device has none) |
| `id` | UniFi serial → device ID (UUID) |
| `none` | Do not set serial field at all |

---

## VRF Handling

| Variable | Required | Default | Description |
|---|---|---|---|
| `NETBOX_VRF_MODE` | No | `existing` | How VRFs are managed per site. |

| Mode | VRF exists | VRF missing |
|---|---|---|
| `none` | Not used | Not used |
| `existing` (default) | Used | Ignored (no VRF) |
| `create` | Used | Created automatically (named after site) |

---

## Device Role Mapping

Individual variables:

| Variable | Default |
|---|---|
| `NETBOX_ROLE_WIRELESS` | `Wireless AP` |
| `NETBOX_ROLE_LAN` | `Switch` |
| `NETBOX_ROLE_GATEWAY` | `Gateway Firewall` |
| `NETBOX_ROLE_ROUTER` | `Router` |
| `NETBOX_ROLE_UNKNOWN` | `Network Device` |

Or as JSON (overrides individual vars):
```
NETBOX_ROLES={"WIRELESS":"Wireless AP","LAN":"Switch","GATEWAY":"Gateway Firewall","ROUTER":"Router","UNKNOWN":"Network Device"}
```

Roles are auto-created in NetBox if they do not exist.

---

## Site Mapping

| Variable | Default | Description |
|---|---|---|
| `UNIFI_USE_SITE_MAPPING` | `false` | Enable site name mapping. |
| `UNIFI_SITE_MAPPINGS` | — | JSON map of UniFi → NetBox site names. |

Also supports YAML file: `config/site_mapping.yaml`.

---

## DHCP / Static IP

| Variable | Default | Description |
|---|---|---|
| `DHCP_AUTO_DISCOVER` | `true` | Auto-detect DHCP ranges from UniFi network configs. |
| `DHCP_RANGES` | — | Manual CIDR ranges (comma-separated). Merged with auto-discovered. |

When a device's IP falls in a DHCP range, unifi2netbox finds an available static IP from the same prefix (outside the pool), verifies it via ping, and assigns it.

---

## Feature Toggles

| Variable | Default | Description |
|---|---|---|
| `SYNC_INTERFACES` | `true` | Sync physical ports and radio interfaces. |
| `SYNC_VLANS` | `true` | Sync VLANs from UniFi networks. |
| `SYNC_WLANS` | `true` | Sync wireless network definitions. |
| `SYNC_CABLES` | `true` | Sync uplink cables between devices. |
| `SYNC_STALE_CLEANUP` | `true` | Mark devices missing from UniFi as offline. |

---

## Threading

| Variable | Default | Description |
|---|---|---|
| `MAX_CONTROLLER_THREADS` | `5` | Concurrent controllers. |
| `MAX_SITE_THREADS` | `8` | Concurrent sites per controller. |
| `MAX_DEVICE_THREADS` | `8` | Concurrent devices per site. |

Reduce for smaller environments or if hitting API rate limits.

---

## Cleanup

| Variable | Default | Description |
|---|---|---|
| `NETBOX_CLEANUP` | `false` | Enable destructive cleanup after sync. |
| `CLEANUP_STALE_DAYS` | `30` | Grace period before stale device deletion. |

See [cleanup.md](cleanup.md) for details.

---

## Sync Interval

| Variable | Default | Description |
|---|---|---|
| `SYNC_INTERVAL` | `600` | Seconds between sync runs. `0` = run once and exit. |

---

## HTTP Tuning

| Variable | Default | Description |
|---|---|---|
| `UNIFI_REQUEST_TIMEOUT` | `15` | HTTP request timeout (seconds). |
| `UNIFI_HTTP_RETRIES` | `3` | Number of retry attempts. |
| `UNIFI_RETRY_BACKOFF_BASE` | `1.0` | Initial retry delay (seconds). |
| `UNIFI_RETRY_BACKOFF_MAX` | `30.0` | Maximum retry delay (seconds). |

---

## YAML Configuration

File: `config/config.yaml`

```yaml
UNIFI:
  URLS:
    - "https://unifi1.example.com"
  USE_SITE_MAPPING: false
  SITE_MAPPINGS:
    "Default": "Main Office"

NETBOX:
  URL: "https://netbox.example.com"
  TENANT: "My Organization"
  ROLES:
    GATEWAY: "Gateway"
    LAN: "Switch"
    WIRELESS: "Access Point"
    UNKNOWN: "Other"
```

Environment variables take precedence over YAML values.
