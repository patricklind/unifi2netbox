# unifi2netbox

unifi2netbox synchronizes devices from one or more UniFi Controllers
into NetBox using the NetBox API.

The project is designed to keep NetBox as the source of truth for
infrastructure inventory while UniFi acts as the real-time data source
for network equipment.

------------------------------------------------------------------------

## Features

-   Device synchronization from UniFi → NetBox
-   Multi-controller support
-   Multi-tenant support
-   Automatic creation of:
    -   Manufacturer (Ubiquity)
    -   Device Roles
-   Optional VLAN synchronization
-   Optional WLAN synchronization
-   Uplink cable synchronization
-   Stale device detection (marked as offline)
-   Parallel processing of:
    -   Controllers
    -   Sites
    -   Devices

------------------------------------------------------------------------

## Architecture

Flow:

UniFi Controller API\
↓\
UniFi API wrapper\
↓\
Mapping / Transformation\
↓\
NetBox API (pynetbox)

Synchronization is unidirectional:

UniFi → NetBox

No data is written back to UniFi.

------------------------------------------------------------------------

## Requirements

-   Python 3.10+
-   NetBox with API token
-   UniFi Controller with API access

------------------------------------------------------------------------

## Installation

``` bash
git clone <repo>
cd unifi2netbox
python -m venv venv
source venv/bin/activate
pip install -r requirements.txt
```

Alternatively using Docker:

``` bash
docker compose up
```

------------------------------------------------------------------------

## Configuration

Configuration is handled through environment variables and YAML.

### Required Environment Variables

    NETBOX_URL=
    NETBOX_TOKEN=
    NETBOX_TENANT=
    UNIFI_URLS=

Either:

    UNIFI_API_KEY=

or:

    UNIFI_USERNAME=
    UNIFI_PASSWORD=

### YAML Example

``` yaml
NETBOX:
  ROLES:
    WIRELESS: AP
    SWITCH: Switch
    GATEWAY: Router

SYNC_VLANS: true
SYNC_WLANS: true
SYNC_STALE_CLEANUP: true

MAX_CONTROLLER_THREADS: 5
MAX_SITE_THREADS: 10
MAX_DEVICE_THREADS: 20
```

------------------------------------------------------------------------

## Runtime Flow

1.  Load configuration
2.  Initialize NetBox session
3.  Ensure manufacturer and device roles exist
4.  Fetch NetBox sites
5.  Start controller threads
6.  For each site:
    -   Sync VLANs
    -   Sync WLANs
    -   Sync devices
    -   Sync uplink cables
    -   Mark stale devices

------------------------------------------------------------------------

## IP Handling

-   Prefix lookup performed in NetBox
-   Subnet mask derived from matched prefix
-   Management IP assigned to interface `vlan.1`
-   If IP changes, the old IP object is deleted and a new one is created

Note: The management interface name `vlan.1` is currently hardcoded.

------------------------------------------------------------------------

## Stale Cleanup

If enabled:

-   Devices existing in NetBox but not present in UniFi
-   Are marked as `offline`
-   Devices are not deleted

------------------------------------------------------------------------

## Limitations

-   SSL verification is disabled by default
-   No transactional rollback
-   Management interface name is hardcoded
-   API rate limiting may occur with high thread values

------------------------------------------------------------------------

## Logging

Verbose mode:

``` bash
python main.py -v
```

Default log level: INFO

------------------------------------------------------------------------

## Recommended Usage

-   Run as a scheduled job (cron or similar)
-   Limit thread counts in large environments
-   Test against a staging NetBox instance before production deployment

------------------------------------------------------------------------

## Disclaimer

This script performs direct modifications in NetBox via API.\
Test thoroughly before running in production environments.
