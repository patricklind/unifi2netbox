# Configuration Reference

Runtime config is built from:
- `config/config.yaml` (optional)
- environment variables

Environment variables always override YAML values.

## Required Settings

| Variable | Required | Default in code | Notes |
|---|---|---|---|
| `UNIFI_URLS` | Yes | — | Comma-separated list or JSON array |
| `NETBOX_URL` | Yes | — | NetBox base URL |
| `NETBOX_TOKEN` | Yes | — | NetBox API token |
| `NETBOX_TENANT` | Yes | — | Existing tenant name |
| `UNIFI_API_KEY` | * | — | Preferred auth mode |
| `UNIFI_USERNAME` + `UNIFI_PASSWORD` | * | — | Fallback auth mode |

\* Provide either API key or username/password.

## UniFi API Settings

| Variable | Required | Default in code | Description |
|---|---|---|---|
| `UNIFI_API_KEY_HEADER` | No | auto-probe | Custom API key header; if omitted, standard headers are probed |
| `UNIFI_MFA_SECRET` | No | unset | Optional TOTP for session login |
| `UNIFI_VERIFY_SSL` | No | `true` | Verify UniFi TLS certificates |
| `UNIFI_PERSIST_SESSION` | No | `true` | Persist UniFi session cache to `~/.unifi_session.json` |
| `UNIFI_REQUEST_TIMEOUT` | No | `15` | Request timeout in seconds |
| `UNIFI_HTTP_RETRIES` | No | `3` | Retry attempts for transient failures |
| `UNIFI_RETRY_BACKOFF_BASE` | No | `1.0` | Exponential backoff base delay (seconds) |
| `UNIFI_RETRY_BACKOFF_MAX` | No | `30.0` | Max backoff delay (seconds) |

### URL format examples

Integration API:
```bash
UNIFI_URLS=https://controller.example.com/proxy/network/integration/v1
```

Integration API (alternate path):
```bash
UNIFI_URLS=https://controller.example.com/integration/v1
```

Base URL (integration base is auto-probed):
```bash
UNIFI_URLS=https://controller.example.com
```

Legacy/session login:
```bash
UNIFI_URLS=https://controller.example.com:8443
```

Multiple controllers:
```bash
UNIFI_URLS=https://ctrl1.example.com/proxy/network/integration/v1,https://ctrl2.example.com:8443
```

## NetBox Settings

| Variable | Required | Default in code | Description |
|---|---|---|---|
| `NETBOX_DEVICE_STATUS` | No | `offline` | Status for newly created devices |
| `NETBOX_VERIFY_SSL` | No | `true` | Verify NetBox TLS certificates |
| `NETBOX_SERIAL_MODE` | No | `mac` | `mac`, `unifi`, `id`, `none` |
| `NETBOX_VRF_MODE` | No | `existing` | `none`, `existing`, `create` |

### Device roles

Configure either:
- individual vars:
  - `NETBOX_ROLE_WIRELESS`
  - `NETBOX_ROLE_LAN`
  - `NETBOX_ROLE_GATEWAY`
  - `NETBOX_ROLE_ROUTER`
  - `NETBOX_ROLE_UNKNOWN`
- or JSON mapping:
  - `NETBOX_ROLES={"WIRELESS":"Wireless AP","LAN":"Switch",...}`

`NETBOX_ROLES` overrides individual role vars.

## Site Mapping

| Variable | Required | Default in code | Description |
|---|---|---|---|
| `UNIFI_USE_SITE_MAPPING` | No | `false` | Enable UniFi->NetBox name mapping |
| `UNIFI_SITE_MAPPINGS` | No | unset | JSON or `key=value` pairs |

YAML mapping file is also supported: `config/site_mapping.yaml`.

## DHCP / Static IP Behavior

| Variable | Required | Default in code | Description |
|---|---|---|---|
| `DHCP_AUTO_DISCOVER` | No | `true` | Discover DHCP ranges from UniFi network configs |
| `DHCP_RANGES` | No | empty | Manual CIDRs, merged with discovered ranges |

When a device IP is in a DHCP range, static replacement logic may assign a free IP from the same prefix (except gateways).

## Feature Toggles

| Variable | Default in code | Description |
|---|---|---|
| `SYNC_INTERFACES` | `true` | Sync physical ports and radios |
| `SYNC_VLANS` | `true` | Sync VLANs |
| `SYNC_WLANS` | `true` | Sync WLANs |
| `SYNC_CABLES` | `true` | Sync uplink cables |
| `SYNC_STALE_CLEANUP` | `true` | Mark missing devices offline |

## Threading

| Variable | Default in code |
|---|---|
| `MAX_CONTROLLER_THREADS` | `5` |
| `MAX_SITE_THREADS` | `8` |
| `MAX_DEVICE_THREADS` | `8` |

## Cleanup

| Variable | Default in code | Description |
|---|---|---|
| `NETBOX_CLEANUP` | `false` | Enable destructive cleanup phase |
| `CLEANUP_STALE_DAYS` | `30` | Grace period before stale device deletion |

## Sync Interval

| Variable | Default in code | Description |
|---|---|---|
| `SYNC_INTERVAL` | `0` | `0` = run once and exit; `>0` = continuous loop |

Note: `.env.example` sets `SYNC_INTERVAL=600` as an operational default for Docker deployments.

## YAML Example (`config/config.yaml`)

```yaml
UNIFI:
  URLS:
    - "https://controller.example.com/proxy/network/integration/v1"
  USE_SITE_MAPPING: false
  SITE_MAPPINGS:
    "Default": "Main Office"

NETBOX:
  URL: "https://netbox.example.com"
  TENANT: "My Organization"
  ROLES:
    WIRELESS: "Wireless AP"
    LAN: "Switch"
    GATEWAY: "Gateway Firewall"
    ROUTER: "Router"
    UNKNOWN: "Network Device"
```
