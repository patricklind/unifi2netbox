# Device Type Specs

Device type enrichment combines two sources at runtime:

1. `UNIFI_MODEL_SPECS` in `unifi/model_specs.py` (**46 hardcoded models**)
2. `data/ubiquiti_device_specs.json` (community bundle):
   - **173** entries indexed by model (`by_model`)
   - **166** entries indexed by part number (`by_part`)

## Merge Strategy

`_resolve_device_specs(model)`:

1. Load hardcoded spec by model key (if present)
2. Try community lookup by:
   - hardcoded `part_number`
   - model string as fallback part number
   - model lookup in `by_model`
3. Merge with precedence:
   - community fields as base
   - hardcoded fields override

This keeps curated overrides intact while inheriting rich template data from community specs.

## Synced Template Types

`_sync_templates()` in `main.py` handles:

- interface templates (`dcim.interface_templates`)
- console port templates (`dcim.console_port_templates`)
- power port templates (`dcim.power_port_templates`)

If expected template set differs from existing templates, current templates are replaced for that device type.

## Auto-Create Device Types

When UniFi reports an unknown model:

1. `_resolve_device_specs(model)` is called
2. If specs exist, a NetBox device type is created
3. `ensure_device_type_specs()` applies template sync and metadata fields

If no spec is found, devices still sync, but without enriched template definitions.
