# unifi2netbox

unifi2netbox synchronizes devices, VLANs, WLANs, and uplink
relationships from one or more UniFi Controllers into NetBox using the
NetBox API.

The application is designed to keep NetBox as the authoritative
inventory system while UniFi acts as the operational data source.

Synchronization direction:

UniFi → NetBox

No data is written back to UniFi.

------------------------------------------------------------------------

# Table of Contents

-   Architecture Overview
-   Complete Configuration Reference
-   .env.example Reference
-   YAML Configuration Reference
-   Full Runtime Flow
-   Threading Model
-   VLAN / WLAN Synchronization
-   Device Synchronization Logic
-   IP Address Handling
-   Uplink Cable Synchronization
-   Stale Device Handling
-   Data Safety Considerations
-   Performance Considerations
-   Logging
-   Deployment Recommendations

------------------------------------------------------------------------

# Architecture Overview

Runtime pipeline:

UniFi Controller API\
↓\
UniFi API wrapper (unifi/)\
↓\
Normalization / Mapping Layer\
↓\
NetBox API (pynetbox)

Core components:

-   main.py --- orchestration layer
-   unifi/ --- UniFi API abstraction layer
-   config/ --- YAML configuration
-   Environment variables (.env)
-   Thread pool execution model

------------------------------------------------------------------------

# Complete Configuration Reference

Configuration is divided into:

1.  Environment variables (.env)
2.  YAML configuration file
3.  Runtime arguments

Both layers are required for proper execution.

------------------------------------------------------------------------

# .env.example Reference

The following environment variables are expected:

## NetBox Configuration

NETBOX_URL= NETBOX_TOKEN= NETBOX_TENANT=

NETBOX_URL\
Base URL of the NetBox instance (e.g., https://netbox.example.com)

NETBOX_TOKEN\
API token with write access to: - DCIM - IPAM - Tenancy

NETBOX_TENANT\
Tenant name used when assigning devices and IP addresses.

------------------------------------------------------------------------

## UniFi Configuration

UNIFI_URLS=

Comma-separated list of controller URLs.

Example: UNIFI_URLS=https://unifi1.local,https://unifi2.local

Authentication (choose one):

Option 1: UNIFI_API_KEY=

Option 2: UNIFI_USERNAME= UNIFI_PASSWORD=

------------------------------------------------------------------------

## Optional / Advanced Variables

SSL verification is disabled by default inside the HTTP session.

If modifying code, SSL behavior can be enforced by enabling request
verification.

------------------------------------------------------------------------

# YAML Configuration Reference

Example structure:

NETBOX: ROLES: WIRELESS: AP SWITCH: Switch GATEWAY: Router

SYNC_VLANS: true SYNC_WLANS: true SYNC_STALE_CLEANUP: true

MAX_CONTROLLER_THREADS: 5 MAX_SITE_THREADS: 10 MAX_DEVICE_THREADS: 20

------------------------------------------------------------------------

## NETBOX.ROLES

Maps UniFi device types to NetBox device roles.

Keys: - WIRELESS - SWITCH - GATEWAY

Values: Existing or auto-created NetBox role names.

Roles are auto-created if missing.

------------------------------------------------------------------------

## SYNC_VLANS

If true: - UniFi networks are synchronized into NetBox VLAN objects.

If false: - VLAN synchronization is skipped.

------------------------------------------------------------------------

## SYNC_WLANS

If true: - UniFi WLAN definitions are synchronized.

If false: - WLAN synchronization is skipped.

------------------------------------------------------------------------

## SYNC_STALE_CLEANUP

If true: - Devices present in NetBox but missing in UniFi - Are marked
as status: offline

Devices are NOT deleted.

------------------------------------------------------------------------

## Threading Parameters

MAX_CONTROLLER_THREADS\
Parallel controllers

MAX_SITE_THREADS\
Parallel sites per controller

MAX_DEVICE_THREADS\
Parallel devices per site

Improper tuning can result in: - API rate limiting - High memory usage -
Connection pool exhaustion

------------------------------------------------------------------------

# Full Runtime Flow

1.  Load environment variables
2.  Load YAML configuration
3.  Initialize HTTP session (custom connection pool)
4.  Initialize NetBox API client (pynetbox, threading enabled)
5.  Ensure manufacturer exists (Ubiquity)
6.  Ensure tenant exists
7.  Ensure device roles exist
8.  Fetch all NetBox sites
9.  Start controller thread pool

For each controller: Fetch sites For each matching site: Optionally sync
VLANs Optionally sync WLANs Sync devices Sync uplink cables Optionally
mark stale devices

------------------------------------------------------------------------

# Threading Model

Hierarchy:

Controller Thread └── Site Thread └── Device Thread

Custom HTTPAdapter pool size: 50 connections.

NetBox client uses threading=True to allow concurrent API calls.

------------------------------------------------------------------------

# VLAN / WLAN Synchronization

If enabled:

-   UniFi networks are mapped to NetBox VLAN objects.
-   UniFi WLAN definitions are imported depending on implementation in
    unifi/wlanconf.py.
-   Existing VLANs are looked up before creation.
-   No destructive deletion is performed.

------------------------------------------------------------------------

# Device Synchronization Logic

For each UniFi device:

1.  Extract:
    -   Serial
    -   MAC
    -   Model
    -   Firmware
    -   IP
    -   Site
2.  Match NetBox device by:
    -   Serial (primary)
    -   Custom field unifi_mac (secondary)
3.  If device exists:
    -   Update fields
4.  If device does not exist:
    -   Create new device

Manufacturer auto-ensured: Ubiquity

------------------------------------------------------------------------

# IP Address Handling

Process:

1.  Lookup prefix in NetBox using contains filter
2.  If VRF present → filter by VRF
3.  Derive subnet mask from matched prefix
4.  Construct IP/CIDR string
5.  If IP changed:
    -   Delete old IP object
    -   Create new IP object
6.  Assign to interface vlan.1
7.  Set as primary_ip4

Important: Management interface name is hardcoded as vlan.1.

------------------------------------------------------------------------

# Uplink Cable Synchronization

After device creation:

1.  Build dictionary:
    -   serial → device
    -   unifi_mac → device
2.  Inspect UniFi uplink data
3.  Create NetBox cable objects between interfaces

No automatic removal of old cables unless handled explicitly in sync
logic.

------------------------------------------------------------------------

# Stale Device Handling

If SYNC_STALE_CLEANUP is true:

Devices in NetBox but missing in UniFi:

→ status set to offline

No deletion occurs.

------------------------------------------------------------------------

# Data Safety Considerations

-   Old IP objects are deleted if IP changes.
-   No rollback if API call partially fails.
-   Script assumes valid prefix structure in NetBox.
-   SSL verification disabled in default HTTP session.
-   Hardcoded interface naming assumption.

------------------------------------------------------------------------

# Performance Considerations

High-scale deployments should:

-   Reduce MAX_DEVICE_THREADS
-   Monitor NetBox API latency
-   Ensure sufficient API rate limits
-   Increase HTTP connection pool if necessary

Large environments (\>1000 devices): Testing recommended before
production deployment.

------------------------------------------------------------------------

# Logging

Standard log level: INFO

Verbose mode:

python main.py -v

Logs include: - Created devices - Updated devices - VLAN/WLAN sync
status - Cable sync actions - Stale device marking - API errors

------------------------------------------------------------------------

# Deployment Recommendations

-   Run as scheduled task (cron, systemd timer, or container scheduler)
-   Use staging NetBox instance for testing
-   Monitor API response times
-   Avoid excessive thread counts
-   Enable proper SSL verification in production

------------------------------------------------------------------------

# Disclaimer

This script performs direct write operations in NetBox via API.

Validate configuration and test thoroughly before production use.
