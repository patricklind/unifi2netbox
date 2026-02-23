# Frequently Asked Questions

## General

### Does this tool write anything back to UniFi?

No. Synchronization is one-way: **UniFi → NetBox**. The tool never modifies UniFi configuration.

### Which UniFi API should I use?

**Integration API v1** is recommended. It uses API key authentication and provides structured data. Legacy API (username/password) is supported as a fallback for older controllers.

### How do I run against a legacy UniFi controller?

Use a controller base URL (for example `https://controller.example.com:8443`) and set:
```
UNIFI_USERNAME=...
UNIFI_PASSWORD=...
```
If `UNIFI_API_KEY` is also set and Integration API probing fails, the client falls back to legacy session login.

### What happens to offline devices?

By default, offline/disconnected devices are **skipped** during sync (not created). Existing devices that go offline are marked as `status: offline` when `SYNC_STALE_CLEANUP=true`.

With `NETBOX_CLEANUP=true`, devices offline for longer than `CLEANUP_STALE_DAYS` are permanently deleted.

---

## Configuration

### Can I sync from multiple UniFi controllers?

Yes. Set `UNIFI_URLS` to a comma-separated list or JSON array:
```
UNIFI_URLS=https://ctrl1.example.com/...,https://ctrl2.example.com/...
```

Controllers are processed in parallel.

### What if UniFi site names don't match NetBox sites?

Use site mapping:
```
UNIFI_USE_SITE_MAPPING=true
UNIFI_SITE_MAPPINGS={"UniFi Site Name":"NetBox Site Name"}
```

Or use `config/site_mapping.yaml`.

### Is it possible to set a specific tenant that imports from UniFi should be placed under?

Yes. Set `NETBOX_IMPORT_TENANT` (or `NETBOX_TENANT`) to an existing NetBox tenant name.
If both are set, `NETBOX_IMPORT_TENANT` is used.

### Is it possible to set a default VRF for imported IP addresses?

Yes. Set:
```
NETBOX_VRF_MODE=existing|create
NETBOX_DEFAULT_VRF=Shared VRF Name
```
`NETBOX_DEFAULT_VRF` overrides site-based VRF naming and applies one VRF name across imports.
With `NETBOX_VRF_MODE=existing`, the VRF must already exist. With `create`, it will be created if missing.

### How do I run the sync only once (not continuously)?

Set `SYNC_INTERVAL=0`. The tool will run one sync cycle and exit. Useful for cron jobs or systemd timers.

### How do I add a device model that isn't recognized?

The model will still be synced — it just won't have pre-configured interface templates. To add specs, either:

1. Check if the model exists in the [community library](https://github.com/netbox-community/devicetype-library) and update `data/ubiquiti_device_specs.json`
2. Add an entry to `UNIFI_MODEL_SPECS` in `main.py`

---

## Cleanup

### Is cleanup safe to enable?

It permanently deletes data. Start with `CLEANUP_STALE_DAYS=9999` to see what would be affected, then lower gradually. Always test in staging first.

### What does cleanup NOT delete?

Sites, tenants, manufacturers, device roles, VRFs, prefixes, VLANs, WLANs, custom fields, and tags are never deleted.

### Can I run cleanup without continuous sync?

Yes. Set `SYNC_INTERVAL=0` and `NETBOX_CLEANUP=true`. The tool runs one sync + cleanup cycle and exits.

---

## Docker

### How do I view logs?

```bash
docker compose logs -f
```

### How do I update the container?

```bash
git pull
docker compose up --build -d
```

### Can I use Docker Compose with multiple environments?

Yes. Create separate `.env` files and use:
```bash
docker compose --env-file .env.production up -d
```

---

## Troubleshooting

### Why are some interfaces named with `?`?

This happens when the UniFi API returns malformed port data. These interfaces are automatically cleaned up when `NETBOX_CLEANUP=true`.

### Why do I see duplicate VRFs?

Thread-safe locking prevents new duplicates. If duplicates already exist from before, the tool uses the oldest (lowest ID). Clean up extras manually in NetBox.

### The tool seems slow — how do I speed it up?

- Increase thread counts (if API can handle it)
- Reduce `UNIFI_REQUEST_TIMEOUT` if your network is fast
- Disable features you don't need (`SYNC_CABLES=false`, etc.)
