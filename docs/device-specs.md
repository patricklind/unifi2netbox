# Device Type Specs

unifi2netbox maintains two sources of device type specifications that are merged at runtime.

---

## Data Sources

### 1. Community Library (173 models)

Bundled as `data/ubiquiti_device_specs.json` (304 KB), sourced from the [netbox-community/devicetype-library](https://github.com/netbox-community/devicetype-library).

Each entry contains:
- Model name and slug
- Part number
- U height, is_full_depth, airflow
- Weight and weight unit
- Interface templates (with PoE mode/type, management-only flag)
- Console port templates
- Power port templates (with max/allocated draw)
- Module bays and device bays

### 2. Hardcoded Specs (~47 models)

Defined in `UNIFI_MODEL_SPECS` in `main.py`. These contain:
- Part number
- U height
- Port definitions (name pattern, type, count)
- PoE budget

---

## Merge Logic

When a device type is processed, `_resolve_device_specs(model)` merges both sources:

1. Look up the model in `UNIFI_MODEL_SPECS` (hardcoded)
2. Get the part number from hardcoded specs
3. Look up community specs by part number (case-insensitive)
4. If no match: try model code as part number
5. If no match: try model name in community `by_model` index
6. Merge: community as base, hardcoded as overlay

**Hardcoded values always win** — this ensures manual corrections are preserved.

### Example

For model `US48PRO`:
- Hardcoded: `part_number: USW-Pro-48-PoE`, `ports: [48x GbE + 4x SFP+]`, `poe_budget: 600`
- Community (`USW-PRO-48-POE`): `interfaces: [detailed per-port PoE]`, `console_ports`, `power_ports`, `weight`, `airflow`
- Merged result: has both detailed per-port PoE from community AND poe_budget from hardcoded

---

## Template Sync

The generic `_sync_templates()` function handles three template types:

| Type | NetBox Endpoint | Fields |
|---|---|---|
| Interface | `dcim.interface_templates` | name, type, poe_mode, poe_type, mgmt_only |
| Console Port | `dcim.console_port_templates` | name, type |
| Power Port | `dcim.power_port_templates` | name, type, maximum_draw, allocated_draw |

Templates are compared as sets. If the expected set differs from existing templates, **all templates are deleted and recreated**. This ensures consistency and handles renames.

Each device type is processed only once per sync run (thread-safe via `_device_type_specs_done` set).

---

## Auto-Create Device Types

When a new UniFi device appears with an unknown model:

1. `_resolve_device_specs(model)` is called
2. If specs are found, the device type is created with:
   - Community slug (or auto-generated)
   - Part number, U height, is_full_depth
   - Airflow, weight, weight_unit
3. After creation, `ensure_device_type_specs()` populates all templates

This means new Ubiquiti products are automatically created with rich specs — no manual intervention needed.

---

## Updating the Community Database

To refresh the bundled specs from the latest community library:

```bash
# Clone the community library
git clone https://github.com/netbox-community/devicetype-library /tmp/dtl

# Run the bundling script (requires pyyaml)
python3 -c "
import yaml, json, os, glob

by_part, by_model = {}, {}
for f in sorted(glob.glob('/tmp/dtl/device-types/Ubiquiti/*.yaml')):
    with open(f) as fh:
        spec = yaml.safe_load(fh)
    pn = spec.get('part_number', '')
    if pn:
        by_part[pn] = spec
    mn = spec.get('model', '')
    if mn:
        by_model[mn] = spec

with open('data/ubiquiti_device_specs.json', 'w') as fh:
    json.dump({'by_part': by_part, 'by_model': by_model}, fh, separators=(',', ':'))
print(f'Bundled {len(by_part)} by part, {len(by_model)} by model')
"
```

Then rebuild the Docker image to include the updated JSON.
