from __future__ import annotations

import json
from dotenv import load_dotenv
from slugify import slugify
import os
import re
import requests
import subprocess
import warnings
import logging
import pynetbox
import ipaddress
import yaml
import threading
from concurrent.futures import ThreadPoolExecutor, as_completed
from urllib3.exceptions import InsecureRequestWarning
# Import the unifi module instead of defining the Unifi class
from unifi.unifi import Unifi
# Suppress only the InsecureRequestWarning
warnings.simplefilter("ignore", InsecureRequestWarning)

load_dotenv()
logger = logging.getLogger(__name__)

# Threading limits (configurable via env vars)
MAX_CONTROLLER_THREADS = int(os.getenv("MAX_CONTROLLER_THREADS", "5"))
MAX_SITE_THREADS = int(os.getenv("MAX_SITE_THREADS", "8"))
MAX_DEVICE_THREADS = int(os.getenv("MAX_DEVICE_THREADS", "8"))

# Populated at runtime from NETBOX roles in env/config
netbox_device_roles = {}
postable_fields_cache = {}
postable_fields_lock = threading.Lock()
vrf_cache = {}
vrf_cache_lock = threading.Lock()
vrf_locks = {}
vrf_locks_lock = threading.Lock()
# Caches for custom fields, tags, VLANs (thread-safe)
_custom_field_cache = {}
_custom_field_lock = threading.Lock()
_tag_cache = {}
_tag_lock = threading.Lock()
_vlan_cache = {}
_vlan_lock = threading.Lock()
_cable_lock = threading.Lock()
_dhcp_ranges_cache = None
_dhcp_ranges_lock = threading.Lock()
_assigned_static_ips = set()
_assigned_static_ips_lock = threading.Lock()
_unifi_dhcp_ranges = {}                # site_id -> list of IPv4Network
_unifi_dhcp_ranges_lock = threading.Lock()
_unifi_network_info = {}               # site_id -> list of dicts: {network, gateway, dns}
_unifi_network_info_lock = threading.Lock()
_cleanup_serials_by_site = {}          # site_id -> set of UniFi serials (for cleanup)
_cleanup_serials_lock = threading.Lock()


def _normalize_vrf_name(vrf_name: str) -> str:
    """
    Normalize VRF names so lookups are stable and do not create near-duplicates.
    """
    if vrf_name is None:
        return ""
    # Strip and collapse repeated whitespace.
    return " ".join(str(vrf_name).strip().split())


def _vrf_cache_key(vrf_name: str) -> str:
    return _normalize_vrf_name(vrf_name).casefold()


def _find_vrfs_by_name(nb, vrf_name: str):
    """
    Find matching VRFs by name.

    Starts with exact-name API filter for efficiency.
    Falls back to normalized case-insensitive scan to avoid duplicates when
    historical data has casing/whitespace drift.
    """
    normalized = _normalize_vrf_name(vrf_name)
    if not normalized:
        return []

    exact = list(nb.ipam.vrfs.filter(name=normalized))
    if exact:
        return exact

    wanted_key = _vrf_cache_key(normalized)
    matches = []
    try:
        for candidate in nb.ipam.vrfs.all():
            candidate_name = getattr(candidate, "name", "")
            if _vrf_cache_key(candidate_name) == wanted_key:
                matches.append(candidate)
    except Exception as e:
        logger.debug(f"Failed VRF fallback scan for '{normalized}': {e}")

    return matches


def _get_vrf_lock(vrf_name: str) -> threading.Lock:
    cache_key = _vrf_cache_key(vrf_name)
    with vrf_locks_lock:
        lock = vrf_locks.get(cache_key)
        if lock is None:
            lock = threading.Lock()
            vrf_locks[cache_key] = lock
    return lock


def get_or_create_vrf(nb, vrf_name: str):
    """
    Get or create a VRF by name in a concurrency-safe way.

    NetBox does not enforce VRF name uniqueness, so without a lock multiple
    threads can create duplicates when processing devices in parallel.
    """
    normalized_name = _normalize_vrf_name(vrf_name)
    if not normalized_name:
        return None
    cache_key = _vrf_cache_key(normalized_name)

    with vrf_cache_lock:
        cached = vrf_cache.get(cache_key)
    if cached is not None:
        return cached

    with _get_vrf_lock(normalized_name):
        with vrf_cache_lock:
            cached = vrf_cache.get(cache_key)
        if cached is not None:
            return cached

        existing = _find_vrfs_by_name(nb, normalized_name)
        vrf = None
        if existing:
            # Pick the oldest (lowest id) to keep behavior stable when duplicates already exist.
            vrf = sorted(existing, key=lambda item: item.id or 0)[0]
            if len(existing) > 1:
                logger.warning(
                    f"Multiple VRFs with name {normalized_name} found. Using ID {vrf.id}."
                )
        else:
            logger.debug(f"VRF {normalized_name} not found, creating new VRF")
            try:
                vrf = nb.ipam.vrfs.create({"name": normalized_name})
                if vrf is not None:
                    logger.info(f"VRF {normalized_name} with ID {vrf.id} successfully added to NetBox.")
            except pynetbox.core.query.RequestError as e:
                logger.warning(f"Failed to create VRF {normalized_name}: {e}. Trying to refetch.")
                existing = _find_vrfs_by_name(nb, normalized_name)
                if existing:
                    vrf = sorted(existing, key=lambda item: item.id or 0)[0]

        if vrf is not None:
            with vrf_cache_lock:
                vrf_cache[cache_key] = vrf
        return vrf


def get_existing_vrf(nb, vrf_name: str):
    """Get a VRF by name (do not create)."""
    normalized_name = _normalize_vrf_name(vrf_name)
    if not normalized_name:
        return None
    cache_key = _vrf_cache_key(normalized_name)
    with vrf_cache_lock:
        cached = vrf_cache.get(cache_key)
    if cached is not None:
        return cached

    with _get_vrf_lock(normalized_name):
        with vrf_cache_lock:
            cached = vrf_cache.get(cache_key)
        if cached is not None:
            return cached

        existing = _find_vrfs_by_name(nb, normalized_name)
        if not existing:
            return None
        vrf = sorted(existing, key=lambda item: item.id or 0)[0]
        if len(existing) > 1:
            logger.warning(f"Multiple VRFs with name {normalized_name} found. Using ID {vrf.id}.")
        with vrf_cache_lock:
            vrf_cache[cache_key] = vrf
        return vrf


def get_vrf_for_site(nb, site_name: str):
    """
    Decide VRF behavior based on env.

    NETBOX_VRF_MODE:
      - none/disabled/off: do not use VRF at all
      - existing/get: use VRF if it exists, never create
      - create/site (legacy behavior): create VRF if missing
    """
    site_name = _normalize_vrf_name(site_name)
    mode = (os.getenv("NETBOX_VRF_MODE") or "existing").strip().lower()
    if mode in {"none", "disabled", "off"}:
        return None, mode

    # VRF name == site name (no prefix, no "vrf_").
    if not site_name:
        return None, mode

    if mode in {"create", "site"}:
        vrf = get_or_create_vrf(nb, site_name)
        return vrf, mode

    if mode in {"existing", "get"}:
        vrf = get_existing_vrf(nb, site_name)
        return vrf, mode

    logger.warning(f"Unknown NETBOX_VRF_MODE='{mode}'. Falling back to 'existing'.")
    vrf = get_existing_vrf(nb, site_name)
    return vrf, "existing"

def get_postable_fields(base_url, token, url_path):
    """
    Retrieves the POST-able fields for NetBox path.
    """
    normalized_base = base_url.rstrip("/")
    normalized_path = url_path.strip("/")
    cache_key = (normalized_base, normalized_path)
    with postable_fields_lock:
        cached_fields = postable_fields_cache.get(cache_key)
    if cached_fields is not None:
        logger.debug(f"Using cached POST-able fields for NetBox path: {normalized_path}")
        return cached_fields

    url = f"{normalized_base}/api/{normalized_path}/"
    logger.debug(f"Retrieving POST-able fields from NetBox API: {url}")
    headers = {
        "Authorization": f"Token {token}",
        "Content-Type": "application/json",
    }
    response = requests.options(
        url,
        headers=headers,
        verify=_netbox_verify_ssl(),
        timeout=15,
    )
    response.raise_for_status()  # Raise an error if the response is not successful

    # Extract the available POST fields from the API schema
    fields = response.json().get("actions", {}).get("POST", {})
    with postable_fields_lock:
        postable_fields_cache[cache_key] = fields
    logger.debug(f"Retrieved {len(fields)} POST-able fields from NetBox API")
    return fields

def load_site_mapping(config=None):
    """
    Load site mapping from configuration or YAML file.
    Returns a dictionary mapping UniFi site names to NetBox site names.
    
    :param config: Configuration dictionary loaded from config.yaml
    :return: Dictionary mapping UniFi site names to NetBox site names
    """
    # Initialize with empty mapping
    site_mapping = {}
    
    # First check if config has site mappings defined directly
    if config and 'UNIFI' in config and 'SITE_MAPPINGS' in config['UNIFI']:
        logger.debug("Loading site mappings from config.yaml")
        config_mappings = config['UNIFI']['SITE_MAPPINGS']
        if config_mappings:
            site_mapping.update(config_mappings)
            logger.debug(f"Loaded {len(config_mappings)} site mappings from config.yaml")
    
    # Check if we should use the external mapping file
    use_file_mapping = False
    if config and 'UNIFI' in config and 'USE_SITE_MAPPING' in config['UNIFI']:
        use_file_mapping = config['UNIFI']['USE_SITE_MAPPING']
        
    if use_file_mapping:
        site_mapping_path = os.path.join(os.path.dirname(os.path.abspath(__file__)), 'config', 'site_mapping.yaml')
        logger.debug(f"Loading site mapping from file: {site_mapping_path}")
        
        # Check if file exists, if not create a default one
        if not os.path.exists(site_mapping_path):
            logger.warning(f"Site mapping file not found at {site_mapping_path}. Creating a default one.")
            os.makedirs(os.path.dirname(site_mapping_path), exist_ok=True)
            with open(site_mapping_path, 'w') as f:
                f.write("# Site mapping configuration\n")
                f.write("# Format: unifi_site_name: netbox_site_name\n")
                f.write("\"Default\": \"Default\"\n")
            
        try:
            with open(site_mapping_path, 'r') as f:
                file_mapping = yaml.safe_load(f) or {}
                logger.debug(f"Loaded {len(file_mapping)} mappings from site_mapping.yaml")
                # Update the mapping with file values (config values take precedence)
                for key, value in file_mapping.items():
                    if key not in site_mapping:  # Don't overwrite config mappings
                        site_mapping[key] = value
        except Exception as e:
            logger.error(f"Error loading site mapping file: {e}")
    
    logger.debug(f"Final site mapping has {len(site_mapping)} entries")
    return site_mapping

def get_netbox_site_name(unifi_site_name, config=None):
    """
    Get NetBox site name from UniFi site name using the mapping table.
    If no mapping exists, return the original name.
    
    :param unifi_site_name: The UniFi site name to look up
    :param config: Configuration dictionary loaded from config.yaml
    :return: The corresponding NetBox site name or the original name if no mapping exists
    """
    site_mapping = load_site_mapping(config)
    mapped_name = site_mapping.get(unifi_site_name, unifi_site_name)
    if mapped_name != unifi_site_name:
        logger.debug(f"Mapped UniFi site '{unifi_site_name}' to NetBox site '{mapped_name}'")
    return mapped_name

def prepare_netbox_sites(netbox_sites):
    """
    Pre-process NetBox sites for lookup.

    :param netbox_sites: List of NetBox site objects.
    :return: A dictionary mapping NetBox site names to the original NetBox site objects.
    """
    netbox_sites_dict = {}
    for netbox_site in netbox_sites:
        netbox_sites_dict[netbox_site.name] = netbox_site
    return netbox_sites_dict

def match_sites_to_netbox(ubiquity_desc, netbox_sites_dict, config=None):
    """
    Match Ubiquity site to NetBox site using the site mapping configuration.

    :param ubiquity_desc: The description of the Ubiquity site.
    :param netbox_sites_dict: A dictionary mapping NetBox site names to site objects.
    :param config: Configuration dictionary loaded from config.yaml
    :return: The matched NetBox site, or None if no match is found.
    """
    # Get the corresponding NetBox site name from the mapping
    netbox_site_name = get_netbox_site_name(ubiquity_desc, config)
    logger.debug(f'Mapping Ubiquity site: "{ubiquity_desc}" -> "{netbox_site_name}"')
    
    # Look for exact match in NetBox sites
    if netbox_site_name in netbox_sites_dict:
        netbox_site = netbox_sites_dict[netbox_site_name]
        logger.debug(f'Matched Ubiquity site "{ubiquity_desc}" to NetBox site "{netbox_site.name}"')
        return netbox_site
    
    # If site mapping is enabled but no match found, provide more helpful message
    if config and 'UNIFI' in config and ('USE_SITE_MAPPING' in config['UNIFI'] and config['UNIFI']['USE_SITE_MAPPING'] or 
                                        'SITE_MAPPINGS' in config['UNIFI'] and config['UNIFI']['SITE_MAPPINGS']):
        logger.debug(f'No match found for Ubiquity site "{ubiquity_desc}". Add mapping in config.yaml or site_mapping.yaml.')
    else:
        logger.debug(f'No match found for Ubiquity site "{ubiquity_desc}". Enable site mapping in config.yaml if needed.')
    return None

def setup_logging(min_log_level=logging.INFO):
    """
    Sets up logging to separate files for each log level.
    Only logs from the specified `min_log_level` and above are saved in their respective files.
    Includes console logging for the same log levels.

    :param min_log_level: Minimum log level to log. Defaults to logging.INFO.
    """
    logs_dir = "logs"
    if not os.path.exists(logs_dir):
        os.makedirs(logs_dir)

    if not os.access(logs_dir, os.W_OK):
        raise PermissionError(f"Cannot write to log directory: {logs_dir}")

    # Log files for each level
    log_levels = {
        "DEBUG": logging.DEBUG,
        "INFO": logging.INFO,
        "WARNING": logging.WARNING,
        "ERROR": logging.ERROR,
        "CRITICAL": logging.CRITICAL
    }

    # Create the root logger
    logger = logging.getLogger()
    logger.setLevel(logging.DEBUG)  # Capture all log levels

    # Define a log format
    log_format = logging.Formatter("%(asctime)s - %(levelname)s - %(message)s")

    # Set up file handlers for each log level
    for level_name, level_value in log_levels.items():
        if level_value >= min_log_level:
            log_file = os.path.join(logs_dir, f"{level_name.lower()}.log")
            handler = logging.FileHandler(log_file)
            handler.setLevel(level_value)
            handler.setFormatter(log_format)

            # Add a filter so only logs of this specific level are captured
            handler.addFilter(lambda record, lv=level_value: record.levelno == lv)
            logger.addHandler(handler)

    # Set up console handler for logs at `min_log_level` and above
    console_handler = logging.StreamHandler()
    console_handler.setLevel(min_log_level)
    console_handler.setFormatter(log_format)
    logger.addHandler(console_handler)

    logging.info(f"Logging is set up. Minimum log level: {logging.getLevelName(min_log_level)}")

def _parse_env_bool(raw_value: str | None, default: bool = False) -> bool:
    if raw_value is None:
        return default
    value = str(raw_value).strip().lower()
    if value in {"1", "true", "yes", "on"}:
        return True
    if value in {"0", "false", "no", "off"}:
        return False
    logger.warning(f"Invalid boolean value '{raw_value}'. Using default {default}.")
    return default


def _read_env_int(var_name: str, default: int, minimum: int | None = None) -> int:
    raw_value = os.getenv(var_name)
    if raw_value is None or str(raw_value).strip() == "":
        return default
    try:
        value = int(str(raw_value).strip())
    except (TypeError, ValueError):
        logger.warning(
            f"Invalid integer value for {var_name}: {raw_value}. Using default {default}."
        )
        return default
    if minimum is not None and value < minimum:
        logger.warning(
            f"Value for {var_name} must be >= {minimum}. Using default {default}."
        )
        return default
    return value


def _unifi_verify_ssl() -> bool:
    return _parse_env_bool(os.getenv("UNIFI_VERIFY_SSL"), default=True)


def _netbox_verify_ssl() -> bool:
    return _parse_env_bool(os.getenv("NETBOX_VERIFY_SSL"), default=True)


def _sync_interval_seconds() -> int:
    return _read_env_int("SYNC_INTERVAL", default=0, minimum=0)


def _parse_env_list(var_name: str) -> list[str] | None:
    raw_value = os.getenv(var_name)
    if raw_value is None or not str(raw_value).strip():
        return None

    value = str(raw_value).strip()
    if value.startswith("["):
        try:
            parsed = json.loads(value)
        except json.JSONDecodeError as err:
            raise ValueError(f"{var_name} must be a JSON array or comma-separated list.") from err
        if not isinstance(parsed, list):
            raise ValueError(f"{var_name} JSON value must be an array.")
        return [str(item).strip() for item in parsed if str(item).strip()]

    return [item.strip() for item in value.split(",") if item.strip()]


def _parse_env_dhcp_ranges():
    """Parse DHCP_RANGES env var into a list of ipaddress.IPv4Network objects. Cached."""
    global _dhcp_ranges_cache
    with _dhcp_ranges_lock:
        if _dhcp_ranges_cache is not None:
            return _dhcp_ranges_cache

    raw_ranges = _parse_env_list("DHCP_RANGES")
    if not raw_ranges:
        with _dhcp_ranges_lock:
            _dhcp_ranges_cache = []
        return []

    networks = []
    for r in raw_ranges:
        r = r.strip()
        try:
            networks.append(ipaddress.ip_network(r, strict=False))
        except ValueError:
            logger.warning(f"Invalid DHCP range '{r}' in DHCP_RANGES. Skipping.")

    with _dhcp_ranges_lock:
        _dhcp_ranges_cache = networks
    logger.debug(f"Parsed {len(networks)} env DHCP ranges: {[str(n) for n in networks]}")
    return networks


def _fetch_legacy_networkconf(unifi, site_obj):
    """Fetch network configs via Legacy API (has DHCP fields).

    The Integration API does not return dhcpd_enabled / ip_subnet,
    so we fall back to the Legacy REST endpoint which includes the
    full DHCP server configuration.

    Uses the existing session with API key headers.
    """
    # Determine the site code for Legacy API path
    site_code = (
        getattr(site_obj, "internal_reference", None)
        or getattr(site_obj, "name", None)
        or "default"
    )
    # Build Legacy endpoint — strip integration path to get base host
    base = unifi.base_url
    if "/proxy/network/integration" in base:
        base = base.split("/proxy/network/integration")[0]
    elif "/integration/" in base:
        base = base.split("/integration/")[0]
    url = f"{base}/proxy/network/api/s/{site_code}/rest/networkconf"

    try:
        # Reuse the auth headers discovered during Integration API setup
        headers = {"Content-Type": "application/json", "Accept": "application/json"}
        auth_headers = getattr(unifi, "integration_auth_headers", None) or {}
        headers.update(auth_headers)

        resp = unifi.session.get(
            url,
            headers=headers,
            verify=getattr(unifi, "verify_ssl", _unifi_verify_ssl()),
            timeout=unifi.request_timeout,
        )
        if resp.status_code == 200:
            data = resp.json()
            if isinstance(data, dict) and "data" in data:
                return data["data"]
            if isinstance(data, list):
                return data
        else:
            logger.debug(f"Legacy networkconf returned HTTP {resp.status_code} for site {site_code}")
    except Exception as e:
        logger.debug(f"Legacy networkconf fallback failed for site {site_code}: {e}")
    return None


def extract_dhcp_ranges_from_unifi(site_obj, unifi=None) -> list[ipaddress.IPv4Network]:
    """Extract DHCP ranges from UniFi network configs for a site.

    Returns a list of ipaddress.IPv4Network objects representing
    subnets where DHCP is enabled.

    For Integration API controllers (which lack DHCP fields), falls
    back to the Legacy API endpoint automatically.
    """
    networks_result = []
    try:
        net_configs = site_obj.network_conf.all()
    except Exception as e:
        logger.warning(f"Could not fetch network configs for DHCP range extraction: {e}")
        return networks_result

    # Check if Integration API returned limited data (no dhcpd_enabled field)
    if net_configs and "dhcpd_enabled" not in net_configs[0] and unifi:
        logger.debug("Integration API lacks DHCP fields, falling back to Legacy API")
        legacy_configs = _fetch_legacy_networkconf(unifi, site_obj)
        if legacy_configs:
            net_configs = legacy_configs
        else:
            logger.debug("Legacy API fallback returned no data")
            return networks_result

    network_info_list = []

    for net in net_configs:
        net_name = net.get("name") or net.get("purpose") or "unknown"

        # Check if DHCP server is enabled on this network
        dhcp_enabled = net.get("dhcpd_enabled") or net.get("dhcpdEnabled") or False
        if not dhcp_enabled:
            continue

        # Get the subnet
        subnet = net.get("ip_subnet") or net.get("subnet")
        if not subnet:
            continue

        try:
            network = ipaddress.ip_network(subnet, strict=False)
            networks_result.append(network)
            logger.debug(f"Found DHCP-enabled network '{net_name}': {subnet}")

            # Extract gateway and DNS from network config
            gateway = net.get("gateway_ip") or net.get("gateway") or None
            dns_servers = []
            for key in ("dhcpd_dns_1", "dhcpd_dns_2", "dhcpd_dns_3", "dhcpd_dns_4",
                         "dhcpdDns1", "dhcpdDns2", "dhcpdDns3", "dhcpdDns4"):
                val = net.get(key)
                if val and str(val).strip():
                    dns_servers.append(str(val).strip())
            # Deduplicate while preserving order
            seen_dns = set()
            unique_dns = []
            for d in dns_servers:
                if d not in seen_dns:
                    seen_dns.add(d)
                    unique_dns.append(d)

            network_info_list.append({
                "network": network,
                "gateway": gateway,
                "dns": unique_dns,
                "name": net_name,
            })
            if gateway or unique_dns:
                logger.debug(f"Network '{net_name}': gateway={gateway}, dns={unique_dns}")

        except ValueError:
            logger.warning(f"Invalid subnet '{subnet}' in UniFi network config. Skipping.")

    # Store network info globally for later gateway/DNS lookup
    site_id = getattr(site_obj, "id", None) or getattr(site_obj, "_id", None)
    if site_id and network_info_list:
        with _unifi_network_info_lock:
            _unifi_network_info[site_id] = network_info_list

    return networks_result


def get_all_dhcp_ranges() -> list[ipaddress.IPv4Network]:
    """Return merged DHCP ranges from env var + all discovered UniFi sites."""
    env_ranges = _parse_env_dhcp_ranges()
    with _unifi_dhcp_ranges_lock:
        unifi_ranges = []
        for ranges in _unifi_dhcp_ranges.values():
            unifi_ranges.extend(ranges)

    # Deduplicate by network address
    seen = set()
    merged = []
    for net in env_ranges + unifi_ranges:
        key = str(net)
        if key not in seen:
            seen.add(key)
            merged.append(net)
    return merged


def is_ip_in_dhcp_range(ip_str: str) -> bool:
    """Return True if the given IP string falls within any configured or discovered DHCP range."""
    dhcp_ranges = get_all_dhcp_ranges()
    if not dhcp_ranges:
        return False
    try:
        addr = ipaddress.ip_address(ip_str)
    except ValueError:
        return False
    return any(addr in network for network in dhcp_ranges)


def _get_network_info_for_ip(ip_str: str) -> tuple[str | None, list[str]]:
    """Look up gateway and DNS servers for a given IP from cached UniFi network configs.

    Returns (gateway, dns_servers) tuple.  Both may be None/empty if not found.
    Falls back to env vars DEFAULT_GATEWAY / DEFAULT_DNS if UniFi data unavailable.
    """
    try:
        addr = ipaddress.ip_address(ip_str)
    except ValueError:
        return None, []

    # Search cached network info from all sites
    with _unifi_network_info_lock:
        for _site_id, info_list in _unifi_network_info.items():
            for info in info_list:
                if addr in info["network"]:
                    return info.get("gateway"), info.get("dns", [])

    # Fallback to env vars
    env_gw = os.getenv("DEFAULT_GATEWAY", "").strip() or None
    env_dns_raw = os.getenv("DEFAULT_DNS", "").strip()
    env_dns = [d.strip() for d in env_dns_raw.split(",") if d.strip()] if env_dns_raw else []
    if env_gw or env_dns:
        logger.debug(f"Using env fallback for {ip_str}: gateway={env_gw}, dns={env_dns}")
    return env_gw, env_dns


def ping_ip(ip_str: str, count: int = 2, timeout: int = 1) -> bool:
    """Ping an IP address. Returns True if host responds (IP in use), False if not."""
    try:
        # Linux (Docker container): -W for timeout in seconds
        cmd = ["ping", "-c", str(count), "-W", str(timeout), ip_str]
        result = subprocess.run(
            cmd,
            stdout=subprocess.DEVNULL,
            stderr=subprocess.DEVNULL,
            timeout=count * timeout + 5,
        )
        return result.returncode == 0
    except (subprocess.TimeoutExpired, Exception) as e:
        logger.debug(f"Ping to {ip_str} failed/timed out: {e}")
        return False


def find_available_static_ip(nb, prefix_obj, vrf, tenant, unifi_device_ips: set[str] | None = None, max_attempts: int = 10) -> str | None:
    """
    Find an available static IP in the given NetBox prefix that:
    1. Is NOT within any configured DHCP range
    2. Is NOT already used by any UniFi device
    3. Is NOT already in NetBox
    4. Does NOT respond to ping
    Uses NetBox available-ips API. Returns IP string with mask (e.g. '192.168.1.5/24') or None.
    """
    dhcp_ranges = get_all_dhcp_ranges()
    subnet_mask = prefix_obj.prefix.split("/")[1]
    prefix_id = prefix_obj.id
    unifi_ips = unifi_device_ips or set()

    # Use direct HTTP GET to list available IPs without creating them
    netbox_url = os.getenv("NETBOX_URL", "").rstrip("/")
    netbox_token = os.getenv("NETBOX_TOKEN", "")
    url = f"{netbox_url}/api/ipam/prefixes/{prefix_id}/available-ips/"
    headers = {"Authorization": f"Token {netbox_token}", "Accept": "application/json"}

    try:
        resp = requests.get(
            url,
            headers=headers,
            params={"limit": max_attempts * 5},
            verify=_netbox_verify_ssl(),
            timeout=10,
        )
        resp.raise_for_status()
        candidates = resp.json()
    except Exception as e:
        logger.error(f"Failed to query available IPs for prefix {prefix_obj.prefix}: {e}")
        return None

    if not isinstance(candidates, list):
        logger.error(f"Unexpected response from available-ips endpoint: {type(candidates)}")
        return None

    attempts = 0
    for candidate in candidates:
        if attempts >= max_attempts:
            break

        candidate_addr = candidate.get("address", "")
        candidate_ip = candidate_addr.split("/")[0]

        try:
            addr = ipaddress.ip_address(candidate_ip)
        except ValueError:
            continue

        # Skip if candidate is in DHCP range
        if any(addr in net for net in dhcp_ranges):
            continue

        # Skip if already being assigned in this run (thread-safe)
        with _assigned_static_ips_lock:
            if candidate_ip in _assigned_static_ips:
                logger.debug(f"Skipping {candidate_ip} — already being assigned this run")
                continue

        # Skip if any UniFi device already uses this IP
        if candidate_ip in unifi_ips:
            logger.debug(f"Skipping {candidate_ip} — already in use by a UniFi device")
            continue

        attempts += 1

        # Ping check — skip if IP responds
        if ping_ip(candidate_ip):
            logger.warning(f"Candidate IP {candidate_ip} responds to ping — in use, skipping")
            continue

        # Reserve this IP to prevent concurrent assignment
        with _assigned_static_ips_lock:
            if candidate_ip in _assigned_static_ips:
                continue  # Another thread grabbed it while we were pinging
            _assigned_static_ips.add(candidate_ip)

        logger.info(f"Found available static IP: {candidate_ip}/{subnet_mask}")
        return f"{candidate_ip}/{subnet_mask}"

    logger.warning(f"Could not find available static IP in {prefix_obj.prefix} after {attempts} attempts")
    return None


def set_unifi_device_static_ip(unifi, site_obj, device: dict, static_ip: str, subnet_mask: str = "255.255.252.0", gateway: str | None = None, dns_servers: list[str] | None = None) -> bool:
    """
    Set a static IP on a UniFi device via the controller API.
    For Integration API: PATCH /sites/{siteId}/devices/{deviceId}
    For Legacy API: PUT /api/s/{site}/rest/device/{id}
    """
    device_id = device.get("id") or device.get("_id")
    device_name = get_device_name(device)
    if not device_id:
        logger.warning(f"Cannot set static IP on {device_name}: no device ID")
        return False

    site_api_id = getattr(site_obj, "api_id", None) or getattr(site_obj, "_id", None)
    if not site_api_id:
        logger.warning(f"Cannot set static IP on {device_name}: no site API ID")
        return False

    # Determine gateway from prefix if not provided
    if not gateway:
        try:
            network = ipaddress.ip_network(f"{static_ip}/{subnet_mask}", strict=False)
            gateway = str(list(network.hosts())[0])  # First host in subnet
        except Exception as e:
            gateway = static_ip.rsplit(".", 1)[0] + ".1"  # Fallback: x.x.x.1
            logger.debug(f"Could not compute gateway from prefix, using fallback {gateway}: {e}")

    api_style = getattr(unifi, "api_style", "legacy")
    if api_style == "integration":
        url = f"/sites/{site_api_id}/devices/{device_id}"
        ip_config = {
            "mode": "static",
            "ip": static_ip,
            "subnetMask": subnet_mask,
            "gateway": gateway,
        }
        if dns_servers:
            if len(dns_servers) >= 1:
                ip_config["preferredDns"] = dns_servers[0]
            if len(dns_servers) >= 2:
                ip_config["alternateDns"] = dns_servers[1]
        payload = {"ipConfig": ip_config}
        try:
            response = unifi.make_request(url, "PATCH", data=payload)
            if isinstance(response, dict):
                status = response.get("statusCode") or response.get("status")
                if status and int(status) >= 400:
                    logger.warning(f"Failed to set static IP on {device_name} via Integration API: {response.get('message', response)}")
                    return False
            logger.info(f"Set static IP {static_ip} (gw={gateway}, dns={dns_servers}) on UniFi device {device_name}")
            return True
        except Exception as e:
            logger.warning(f"Failed to set static IP on {device_name}: {e}")
            return False
    else:
        # Legacy API: PUT /api/s/{site}/rest/device/{id}
        config_network = {
            "type": "static",
            "ip": static_ip,
            "netmask": subnet_mask,
            "gateway": gateway,
        }
        if dns_servers:
            if len(dns_servers) >= 1:
                config_network["dns1"] = dns_servers[0]
            if len(dns_servers) >= 2:
                config_network["dns2"] = dns_servers[1]
        payload = {"config_network": config_network}
        try:
            site_name = getattr(site_obj, "name", "default")
            url = f"/api/s/{site_name}/rest/device/{device_id}"
            response = unifi.make_request(url, "PUT", data=payload)
            if isinstance(response, dict):
                meta = response.get("meta", {})
                if isinstance(meta, dict) and meta.get("rc") == "ok":
                    logger.info(f"Set static IP {static_ip} (gw={gateway}, dns={dns_servers}) on UniFi device {device_name}")
                    return True
                logger.warning(f"Failed to set static IP on {device_name} via legacy API: {response}")
                return False
            return False
        except Exception as e:
            logger.warning(f"Failed to set static IP on {device_name}: {e}")
            return False


def _parse_env_mapping(var_name: str) -> dict[str, str] | None:
    raw_value = os.getenv(var_name)
    if raw_value is None or not str(raw_value).strip():
        return None

    value = str(raw_value).strip()
    if value.startswith("{"):
        try:
            parsed = json.loads(value)
        except json.JSONDecodeError as err:
            raise ValueError(f"{var_name} must be a JSON object or key=value pairs.") from err
        if not isinstance(parsed, dict):
            raise ValueError(f"{var_name} JSON value must be an object.")
        return {
            str(key).strip(): str(item).strip()
            for key, item in parsed.items()
            if str(key).strip() and str(item).strip()
        }

    mapping = {}
    for pair in re.split(r"[;,]", value):
        pair = pair.strip()
        if not pair:
            continue
        if "=" in pair:
            key, item = pair.split("=", 1)
        elif ":" in pair:
            key, item = pair.split(":", 1)
        else:
            raise ValueError(
                f"{var_name} pair '{pair}' is invalid. Use key=value pairs separated by ',' or ';'."
            )
        key = key.strip()
        item = item.strip()
        if key and item:
            mapping[key] = item
    return mapping


def _load_roles_from_env():
    roles_from_mapping = _parse_env_mapping("NETBOX_ROLES")
    if roles_from_mapping:
        return {str(key).upper(): value for key, value in roles_from_mapping.items()}

    prefix = "NETBOX_ROLE_"
    roles = {}
    for key, value in os.environ.items():
        if not key.startswith(prefix):
            continue
        role_key = key[len(prefix):].strip().upper()
        role_value = str(value).strip()
        if role_key and role_value:
            roles[role_key] = role_value
    return roles or None


def load_config(config_path="config/config.yaml"):
    """
    Reads configuration from YAML if present.
    Returns empty config if file does not exist.
    """
    if not os.path.exists(config_path):
        logger.debug(f"Configuration file not found at {config_path}. Using environment variables.")
        return {}

    with open(config_path, "r") as file:
        try:
            config = yaml.safe_load(file) or {}
        except yaml.YAMLError as e:
            raise Exception(f"Error reading configuration file: {e}")
    if not isinstance(config, dict):
        raise ValueError("Configuration file must contain a top-level mapping.")
    return config


def load_runtime_config(config_path="config/config.yaml"):
    """
    Build runtime config from YAML + environment variables.
    Environment variables take precedence.
    """
    config = load_config(config_path)

    unifi_cfg = dict(config.get("UNIFI") or {})
    netbox_cfg = dict(config.get("NETBOX") or {})

    env_unifi_urls = _parse_env_list("UNIFI_URLS")
    if env_unifi_urls is not None:
        unifi_cfg["URLS"] = env_unifi_urls

    env_use_site_mapping = os.getenv("UNIFI_USE_SITE_MAPPING")
    if env_use_site_mapping is not None:
        unifi_cfg["USE_SITE_MAPPING"] = _parse_env_bool(env_use_site_mapping, default=False)

    env_site_mappings = _parse_env_mapping("UNIFI_SITE_MAPPINGS")
    if env_site_mappings is not None:
        unifi_cfg["SITE_MAPPINGS"] = env_site_mappings

    env_netbox_url = os.getenv("NETBOX_URL")
    if env_netbox_url:
        netbox_cfg["URL"] = env_netbox_url.strip()

    env_netbox_tenant = os.getenv("NETBOX_TENANT")
    if env_netbox_tenant:
        netbox_cfg["TENANT"] = env_netbox_tenant.strip()

    env_netbox_roles = _load_roles_from_env()
    if env_netbox_roles:
        netbox_cfg["ROLES"] = env_netbox_roles

    if isinstance(unifi_cfg.get("URLS"), str):
        unifi_cfg["URLS"] = [item.strip() for item in unifi_cfg["URLS"].split(",") if item.strip()]
    if not isinstance(unifi_cfg.get("URLS"), list):
        unifi_cfg["URLS"] = []
    unifi_cfg["URLS"] = [str(item).strip() for item in unifi_cfg["URLS"] if str(item).strip()]

    site_mappings = unifi_cfg.get("SITE_MAPPINGS")
    if site_mappings is None:
        site_mappings = {}
    if not isinstance(site_mappings, dict):
        raise ValueError("UNIFI.SITE_MAPPINGS must be a mapping.")
    unifi_cfg["SITE_MAPPINGS"] = {
        str(key).strip(): str(value).strip()
        for key, value in site_mappings.items()
        if str(key).strip() and str(value).strip()
    }

    use_site_mapping = unifi_cfg.get("USE_SITE_MAPPING", False)
    if isinstance(use_site_mapping, str):
        use_site_mapping = _parse_env_bool(use_site_mapping, default=False)
    unifi_cfg["USE_SITE_MAPPING"] = bool(use_site_mapping)

    roles_cfg = netbox_cfg.get("ROLES")
    if roles_cfg is None:
        roles_cfg = {}
    if not isinstance(roles_cfg, dict):
        raise ValueError("NETBOX.ROLES must be a mapping.")
    netbox_cfg["ROLES"] = {
        str(key).strip().upper(): str(value).strip()
        for key, value in roles_cfg.items()
        if str(key).strip() and str(value).strip()
    }

    runtime_config = {
        "UNIFI": unifi_cfg,
        "NETBOX": netbox_cfg,
    }
    return runtime_config

def get_device_name(device: dict) -> str:
    return (
        device.get("name")
        or device.get("hostname")
        or device.get("macAddress")
        or device.get("mac")
        or device.get("id")
        or "unknown-device"
    )

def extract_asset_tag(device_name: str | None) -> str | None:
    """Extract ID or AID tag from device name, e.g. 'IT-AULA-AP02-ID3006' -> 'ID3006'."""
    if not device_name:
        return None
    match = re.search(r'[-_]?(A?ID\d+)$', device_name, re.IGNORECASE)
    if match:
        return match.group(1).upper()
    return None


def get_device_mac(device: dict) -> str | None:
    return device.get("mac") or device.get("macAddress")

def get_device_ip(device: dict) -> str | None:
    return device.get("ip") or device.get("ipAddress")

def get_device_serial(device: dict) -> str | None:
    """
    Determine what to put in NetBox's `serial` field.

    Controlled by env:
      - NETBOX_SERIAL_MODE=mac   (default): use device.serial, else MAC, else id
      - NETBOX_SERIAL_MODE=unifi: only use device.serial (no fallback)
      - NETBOX_SERIAL_MODE=id    : use device.serial, else id
      - NETBOX_SERIAL_MODE=none  : do not set serial in NetBox
    """
    def _normalize_serial(value):
        if value is None:
            return None
        text = str(value).strip()
        if not text:
            return None
        # If this is a MAC address (with separators) or 12 hex characters, normalize to compact uppercase.
        if re.fullmatch(r"(?i)([0-9a-f]{2}[:-]){5}[0-9a-f]{2}", text) or re.fullmatch(r"(?i)[0-9a-f]{12}", text):
            return re.sub(r"[^0-9A-Fa-f]", "", text).upper()
        return text

    mode = (os.getenv("NETBOX_SERIAL_MODE") or "mac").strip().lower()
    if mode == "none":
        return None
    if mode in {"unifi", "serial"}:
        return _normalize_serial(device.get("serial"))
    if mode == "id":
        return _normalize_serial(device.get("serial") or device.get("id"))
    # default: mac
    return _normalize_serial(device.get("serial") or get_device_mac(device) or device.get("id"))

def is_access_point_device(device: dict) -> bool:
    ap_flag = device.get("is_access_point")
    if isinstance(ap_flag, bool):
        return ap_flag
    features = device.get("features")
    if isinstance(features, list):
        return "accessPoint" in features
    if isinstance(features, dict):
        return "accessPoint" in features
    interfaces = device.get("interfaces")
    if isinstance(interfaces, dict):
        return bool(interfaces.get("radios"))
    if isinstance(interfaces, list):
        # Check if any item in the list looks like a radio
        return any(
            isinstance(iface, dict) and (
                iface.get("radio") is not None
                or iface.get("band")
                or iface.get("channel")
                or (iface.get("name") or "").lower().startswith("radio")
            )
            for iface in interfaces
        )
    return False

def ensure_custom_field(nb, name, cf_type="text", content_types=None, label=None):
    """Ensure a custom field exists in NetBox. Create if missing. Returns the CF object."""
    with _custom_field_lock:
        if name in _custom_field_cache:
            return _custom_field_cache[name]
    cf = None
    try:
        cfs = list(nb.extras.custom_fields.filter(name=name))
        if cfs:
            cf = cfs[0]
        else:
            try:
                cf = nb.extras.custom_fields.create({
                    "name": name,
                    "type": cf_type,
                    "object_types": content_types or ["dcim.device"],
                    "label": label or name.replace("_", " ").title(),
                    "filter_logic": "loose",
                })
                if cf:
                    logger.info(f"Created custom field '{name}' in NetBox.")
            except Exception:
                # Race condition: another thread created it; retry filter
                cfs = list(nb.extras.custom_fields.filter(name=name))
                if cfs:
                    cf = cfs[0]
    except Exception as e:
        logger.warning(f"Could not ensure custom field '{name}': {e}")
    with _custom_field_lock:
        _custom_field_cache[name] = cf
    return cf


def ensure_tag(nb, name, slug=None, color=None):
    """Ensure a tag exists in NetBox. Returns the tag object.

    Uses double-check locking to prevent duplicate tag creation
    when multiple threads request the same tag concurrently.
    """
    slug = slug or slugify(name)
    # Fast path: check cache without blocking
    with _tag_lock:
        if slug in _tag_cache:
            return _tag_cache[slug]

    # Slow path: hold lock for the entire get-or-create to close TOCTOU window
    with _tag_lock:
        # Double-check after acquiring lock
        if slug in _tag_cache:
            return _tag_cache[slug]

        tag = None
        try:
            tag = nb.extras.tags.get(slug=slug)
            if not tag:
                payload = {"name": name, "slug": slug}
                if color:
                    payload["color"] = color
                tag = nb.extras.tags.create(payload)
                if tag:
                    logger.info(f"Created tag '{name}' in NetBox.")
        except pynetbox.core.query.RequestError:
            # Race condition: another thread created it between get and create
            tag = nb.extras.tags.get(slug=slug)

        if tag:
            _tag_cache[slug] = tag
        else:
            logger.warning(f"Could not ensure tag '{name}' in NetBox")
        return tag


def sync_device_state(nb, nb_device, device):
    """Sync UniFi device state to NetBox device status (active/offline)."""
    state = (device.get("state") or device.get("status") or "").upper()
    if state in ("ONLINE", "CONNECTED", "1"):
        desired = "active"
    elif state in ("OFFLINE", "DISCONNECTED", "0"):
        desired = "offline"
    else:
        return  # Unknown state, don't change

    current = None
    if nb_device.status:
        current = nb_device.status.value if isinstance(nb_device.status, dict) or hasattr(nb_device.status, 'value') else str(nb_device.status)
        if hasattr(nb_device.status, 'value'):
            current = nb_device.status.value
    if current != desired:
        nb_device.status = desired
        nb_device.save()
        logger.info(f"Updated {nb_device.name} status: {current} -> {desired}")


def sync_device_custom_fields(nb, nb_device, device):
    """Sync firmware version, uptime, MAC, and last seen from UniFi to NetBox custom fields."""
    # Ensure custom fields exist
    ensure_custom_field(nb, "unifi_firmware", cf_type="text", label="UniFi Firmware")
    ensure_custom_field(nb, "unifi_uptime", cf_type="integer", label="UniFi Uptime (sec)")
    ensure_custom_field(nb, "unifi_mac", cf_type="text", label="UniFi MAC")
    ensure_custom_field(nb, "unifi_last_seen", cf_type="text", label="UniFi Last Seen")

    firmware = device.get("firmwareVersion") or device.get("version") or device.get("fw_version")
    uptime = device.get("uptimeSec") or device.get("uptime") or device.get("_uptime")
    mac = device.get("macAddress") or device.get("mac")
    last_seen = device.get("lastSeen") or device.get("last_seen")

    cf = dict(nb_device.custom_fields or {})
    changed = False

    if firmware and cf.get("unifi_firmware") != firmware:
        cf["unifi_firmware"] = firmware
        changed = True
    if uptime is not None:
        try:
            uptime_int = int(uptime)
            if cf.get("unifi_uptime") != uptime_int:
                cf["unifi_uptime"] = uptime_int
                changed = True
        except (ValueError, TypeError):
            pass
    if mac and cf.get("unifi_mac") != mac:
        cf["unifi_mac"] = mac
        changed = True
    # Last seen: store as ISO timestamp or raw value
    if last_seen:
        last_seen_str = str(last_seen)
        # Convert epoch seconds to readable format
        if last_seen_str.isdigit() and len(last_seen_str) >= 10:
            try:
                from datetime import datetime, timezone
                last_seen_str = datetime.fromtimestamp(int(last_seen_str), tz=timezone.utc).isoformat()
            except (ValueError, OSError):
                pass
        if cf.get("unifi_last_seen") != last_seen_str:
            cf["unifi_last_seen"] = last_seen_str
            changed = True

    if changed:
        nb_device.custom_fields = cf
        nb_device.save()
        logger.debug(f"Updated custom fields for {nb_device.name}")


def sync_uplink_cable(nb, nb_device, device, all_nb_devices_by_mac):
    """Create cable between device uplink port and upstream device if both exist in NetBox.
    For offline devices: remove existing cables instead of creating new ones."""
    device_name = get_device_name(device)

    # Check if device is offline — remove cables and skip
    device_state = (device.get("state") or device.get("status") or "").upper()
    if device_state in ("OFFLINE", "DISCONNECTED", "0"):
        # Remove all cables from this device's interfaces
        try:
            ifaces = list(nb.dcim.interfaces.filter(device_id=nb_device.id))
            for iface in ifaces:
                if iface.cable:
                    try:
                        cable_id = iface.cable.id if hasattr(iface.cable, 'id') else iface.cable
                        cable_obj = nb.dcim.cables.get(cable_id)
                        if cable_obj:
                            cable_obj.delete()
                            logger.info(f"Removed cable from offline device {device_name}:{iface.name}")
                    except Exception as e:
                        logger.debug(f"Could not remove cable from {device_name}:{iface.name}: {e}")
        except Exception as e:
            logger.debug(f"Could not check cables for offline device {device_name}: {e}")
        return

    # Integration API: uplink.deviceId; Legacy: uplink_mac or uplink.mac
    # Prefer _detail_uplink (from device detail API) over the list-level uplink
    uplink = device.get("_detail_uplink") or device.get("uplink") or {}
    logger.debug(f"Cable sync for {device_name}: uplink keys={list(uplink.keys()) if uplink else 'none'}, uplink={uplink}")
    upstream_device_id = uplink.get("deviceId") or uplink.get("device_id")
    upstream_mac = uplink.get("uplink_mac") or uplink.get("mac") or uplink.get("macAddress")
    uplink_port_name = uplink.get("name") or uplink.get("uplink_port") or uplink.get("port_name") or uplink.get("portName")
    upstream_port_name = uplink.get("uplink_remote_port") or uplink.get("remotePort") or uplink.get("port_name")

    if not upstream_device_id and not upstream_mac:
        logger.debug(f"Cable sync for {device_name}: no upstream deviceId or MAC in uplink data")
        return

    logger.debug(f"Cable sync for {device_name}: upstream_device_id={upstream_device_id}, upstream_mac={upstream_mac}, uplink_port={uplink_port_name}, upstream_port={upstream_port_name}")

    # Find upstream device in NetBox (O(1) lookup via dict)
    upstream_nb = None
    if upstream_mac:
        normalized_mac = upstream_mac.upper().replace(":", "").replace("-", "")
        upstream_nb = all_nb_devices_by_mac.get(normalized_mac)
        if not upstream_nb:
            logger.debug(f"Cable sync for {device_name}: upstream MAC {normalized_mac} not found in lookup (keys: {list(all_nb_devices_by_mac.keys())[:5]}...)")
    if not upstream_nb and upstream_device_id:
        # Try UUID-based lookup (Integration API stores device UUIDs)
        upstream_nb = all_nb_devices_by_mac.get(str(upstream_device_id))
        if not upstream_nb:
            logger.debug(f"Cable sync for {device_name}: upstream UUID {upstream_device_id} not found in lookup")

    if not upstream_nb:
        logger.debug(f"Cable sync for {device_name}: upstream device not found in NetBox")
        return

    logger.debug(f"Cable sync for {device_name}: found upstream device {upstream_nb.name}")

    # Find the uplink interface on our device
    our_iface = None
    if uplink_port_name:
        our_iface = nb.dcim.interfaces.get(device_id=nb_device.id, name=uplink_port_name)
    if not our_iface:
        # Try to find any interface marked as uplink
        all_ifaces = list(nb.dcim.interfaces.filter(device_id=nb_device.id))
        # Filter to only cabled (ethernet/physical) interfaces — exclude wireless types
        iface_types = [(i.name, str(i.type.value) if i.type else "none") for i in all_ifaces]
        logger.debug(f"Cable sync for {device_name}: all interfaces: {iface_types}")
        wired_ifaces = [i for i in all_ifaces if i.type and i.type.value not in ("virtual", "lag") and not str(i.type.value).startswith("ieee802.11")]
        for iface in wired_ifaces:
            if iface.description and "uplink" in iface.description.lower():
                our_iface = iface
                break
        # Last resort: use the last physical port (commonly uplink on switches)
        if not our_iface and wired_ifaces:
            physical_ifaces = [i for i in wired_ifaces if i.type and i.type.value not in ("virtual", "lag")]
            if physical_ifaces:
                our_iface = physical_ifaces[-1]
        # For APs with no wired interfaces, create an eth0 interface for uplink
        if not our_iface and not wired_ifaces:
            try:
                our_iface = nb.dcim.interfaces.create({
                    "device": nb_device.id,
                    "name": "eth0",
                    "type": "1000base-t",
                    "description": "Uplink (auto-created)",
                })
                if our_iface:
                    logger.info(f"Created eth0 uplink interface for {device_name}")
            except pynetbox.core.query.RequestError as e:
                logger.debug(f"Could not create eth0 for {device_name}: {e}")

    if not our_iface:
        logger.debug(f"Cable sync for {device_name}: no suitable uplink interface found on device (port_name={uplink_port_name})")
        return

    # Check if cable already exists on this interface
    if our_iface.cable:
        logger.debug(f"Cable sync for {device_name}: cable already exists on {our_iface.name}")
        return

    # Find a port on upstream device to connect to
    upstream_iface = None
    upstream_ifaces = list(nb.dcim.interfaces.filter(device_id=upstream_nb.id))
    # Prefer matching the remote port name from uplink data
    if upstream_port_name:
        for iface in upstream_ifaces:
            if iface.name == upstream_port_name and not iface.cable:
                upstream_iface = iface
                break
    # Fallback: any unconnected physical port
    if not upstream_iface:
        for iface in upstream_ifaces:
            if not iface.cable and iface.type and iface.type.value not in ("virtual", "lag"):
                upstream_iface = iface
                break

    if not upstream_iface:
        logger.debug(f"Cable sync for {device_name}: no available interface on upstream device {upstream_nb.name} (upstream_port={upstream_port_name})")
        return

    with _cable_lock:
        try:
            cable = nb.dcim.cables.create({
                "a_terminations": [{"object_type": "dcim.interface", "object_id": our_iface.id}],
                "b_terminations": [{"object_type": "dcim.interface", "object_id": upstream_iface.id}],
                "status": "connected",
            })
            if cable:
                logger.info(f"Created cable: {device_name}:{our_iface.name} <-> {upstream_nb.name}:{upstream_iface.name}")
        except pynetbox.core.query.RequestError as e:
            logger.warning(f"Could not create cable for {device_name}: {e}")


def sync_site_vlans(nb, site_obj, nb_site, tenant):
    """Sync VLANs from UniFi network configs to NetBox."""
    try:
        networks = site_obj.network_conf.all()
    except Exception as e:
        logger.warning(f"Could not fetch networks for site {nb_site.name}: {e}")
        return

    if not networks:
        return

    # Ensure a VLAN group exists for the site
    vlan_group = None
    try:
        vlan_group = nb.ipam.vlan_groups.get(slug=slugify(nb_site.name))
        if not vlan_group:
            vlan_group = nb.ipam.vlan_groups.create({
                "name": nb_site.name,
                "slug": slugify(nb_site.name),
                "scope_type": "dcim.site",
                "scope_id": nb_site.id,
            })
            if vlan_group:
                logger.info(f"Created VLAN group '{nb_site.name}' for site.")
    except pynetbox.core.query.RequestError as e:
        logger.warning(f"Could not create VLAN group for {nb_site.name}: {e}")
        # Try without scope (older NetBox)
        try:
            vlan_group = nb.ipam.vlan_groups.get(slug=slugify(nb_site.name))
            if not vlan_group:
                vlan_group = nb.ipam.vlan_groups.create({
                    "name": nb_site.name,
                    "slug": slugify(nb_site.name),
                })
        except Exception as e:
            logger.debug(f"VLAN group fallback for {nb_site.name}: {e}")

    for net in networks:
        vlan_id = net.get("vlanId") or net.get("vlan") or net.get("vlan_id")
        net_name = net.get("name") or net.get("purpose") or "Unknown"
        enabled = net.get("enabled", True)

        if not vlan_id:
            continue

        try:
            vlan_id = int(vlan_id)
        except (ValueError, TypeError):
            continue

        vlan_key = f"{nb_site.id}_{vlan_id}"
        with _vlan_lock:
            if vlan_key in _vlan_cache:
                continue

        # Check if VLAN exists
        vlan_filters = {"vid": vlan_id, "site_id": nb_site.id}
        existing = nb.ipam.vlans.get(**vlan_filters)
        if not existing and vlan_group:
            vlan_filters = {"vid": vlan_id, "group_id": vlan_group.id}
            existing = nb.ipam.vlans.get(**vlan_filters)

        if not existing:
            try:
                vlan_payload = {
                    "name": net_name,
                    "vid": vlan_id,
                    "site": nb_site.id,
                    "tenant": tenant.id,
                    "status": "active" if enabled else "reserved",
                }
                if vlan_group:
                    vlan_payload["group"] = vlan_group.id
                new_vlan = nb.ipam.vlans.create(vlan_payload)
                if new_vlan:
                    logger.info(f"Created VLAN {vlan_id} ({net_name}) at site {nb_site.name}")
                    with _vlan_lock:
                        _vlan_cache[vlan_key] = new_vlan
            except pynetbox.core.query.RequestError as e:
                logger.warning(f"Could not create VLAN {vlan_id} ({net_name}): {e}")
        else:
            with _vlan_lock:
                _vlan_cache[vlan_key] = existing
            # Update name if changed
            if existing.name != net_name:
                try:
                    existing.name = net_name
                    existing.save()
                    logger.debug(f"Updated VLAN {vlan_id} name to '{net_name}'")
                except Exception as e:
                    logger.warning(f"Failed to update VLAN {vlan_id} name: {e}")


def sync_site_wlans(nb, site_obj, nb_site, tenant):
    """Sync WiFi SSIDs from UniFi to NetBox wireless LANs."""
    try:
        wlans = site_obj.wlan_conf.all()
    except Exception as e:
        logger.warning(f"Could not fetch WLANs for site {nb_site.name}: {e}")
        return

    if not wlans:
        return

    # Ensure a wireless LAN group for the site
    wlan_group = None
    try:
        wlan_group = nb.wireless.wireless_lan_groups.get(slug=slugify(nb_site.name))
        if not wlan_group:
            wlan_group = nb.wireless.wireless_lan_groups.create({
                "name": nb_site.name,
                "slug": slugify(nb_site.name),
            })
            if wlan_group:
                logger.info(f"Created wireless LAN group '{nb_site.name}'.")
    except Exception as e:
        logger.debug(f"Wireless LAN groups not available: {e}")

    for wlan in wlans:
        ssid = wlan.get("name") or wlan.get("x_passphrase") or "Unknown"
        enabled = wlan.get("enabled", True)
        security = wlan.get("security") or wlan.get("wpa_mode") or ""
        # Integration API: securityConfiguration.type
        sec_config = wlan.get("securityConfiguration") or {}
        if isinstance(sec_config, dict):
            security = security or sec_config.get("type") or ""

        # Map security to NetBox auth_type (NetBox 4.x: open, wep, wpa-personal, wpa-enterprise)
        sec_lower = str(security).lower()
        if "enterprise" in sec_lower:
            auth_type = "wpa-enterprise"
        elif "wpa" in sec_lower or "sae" in sec_lower or "psk" in sec_lower:
            auth_type = "wpa-personal"
        elif "wep" in sec_lower:
            auth_type = "wep"
        elif "open" in sec_lower or "none" in sec_lower:
            auth_type = "open"
        else:
            auth_type = "wpa-personal"

        # Check if wireless LAN exists for this group (site)
        existing = None
        try:
            filters = {"ssid": ssid}
            if wlan_group:
                filters["group_id"] = wlan_group.id
            matches = list(nb.wireless.wireless_lans.filter(**filters))
            if matches:
                existing = matches[0]
        except Exception as e:
            logger.debug(f"Could not check existing wireless LAN '{ssid}': {e}")

        if not existing:
            try:
                wlan_payload = {
                    "ssid": ssid,
                    "status": "active" if enabled else "disabled",
                    "auth_type": auth_type,
                    "tenant": tenant.id,
                }
                if wlan_group:
                    wlan_payload["group"] = wlan_group.id
                new_wlan = nb.wireless.wireless_lans.create(wlan_payload)
                if new_wlan:
                    logger.info(f"Created wireless LAN '{ssid}' at site {nb_site.name}")
            except pynetbox.core.query.RequestError as e:
                logger.warning(f"Could not create wireless LAN '{ssid}': {e}")
        else:
            # Update if changed
            changed = False
            desired_status = "active" if enabled else "disabled"
            if hasattr(existing, 'status') and existing.status:
                current_status = existing.status.value if hasattr(existing.status, 'value') else str(existing.status)
                if current_status != desired_status:
                    existing.status = desired_status
                    changed = True
            if changed:
                try:
                    existing.save()
                    logger.debug(f"Updated wireless LAN '{ssid}'")
                except Exception as e:
                    logger.warning(f"Failed to update wireless LAN '{ssid}': {e}")


def map_unifi_port_to_netbox_type(port, api_style="integration"):
    """Map a UniFi port dict to a NetBox interface type string."""
    if api_style == "legacy":
        media = (port.get("media") or "").upper()
        speed = port.get("speed", 0) or 0
        if media == "SFP+":
            return "10gbase-x-sfpp"
        if media == "SFP":
            return "1000base-x-sfp"
        if speed >= 10000:
            return "10gbase-t"
        if speed >= 2500:
            return "2.5gbase-t"
        return "1000base-t"
    # Integration API
    max_speed = port.get("maxSpeed") or port.get("speed") or 0
    connector = (port.get("connector") or "").lower()
    if "sfp" in connector:
        if max_speed >= 10000:
            return "10gbase-x-sfpp"
        return "1000base-x-sfp"
    if max_speed >= 10000:
        return "10gbase-t"
    if max_speed >= 2500:
        return "2.5gbase-t"
    return "1000base-t"


def map_unifi_radio_to_netbox_type(radio):
    """Map a UniFi radio to a NetBox wireless interface type."""
    band = str(radio.get("band") or radio.get("radio") or "").lower()
    if "6e" in band or "6ghz" in band or "6g" in band:
        return "ieee802.11ax"
    if "5g" in band or "na" in band:
        return "ieee802.11ac"
    if "2g" in band or "ng" in band:
        return "ieee802.11n"
    return "ieee802.11ax"


def normalize_port_data(device, api_style="integration"):
    """Extract and normalize port data from device dict into a common format."""
    ports = []
    if api_style == "integration":
        interfaces = device.get("interfaces")
        if isinstance(interfaces, dict):
            raw_ports = interfaces.get("ports") or []
        elif isinstance(interfaces, list):
            # Integration API v1 may return interfaces as a flat list;
            # filter to port-type entries (non-radio, or entries with portIdx/connector)
            raw_ports = [
                iface for iface in interfaces
                if isinstance(iface, dict) and (
                    iface.get("portIdx") is not None
                    or iface.get("connector")
                    or iface.get("maxSpeed")
                    or iface.get("type", "").lower() in ("ethernet", "sfp", "sfp+", "port")
                    or (iface.get("name") or "").lower().startswith("port")
                )
            ]
        else:
            raw_ports = []
    else:
        raw_ports = device.get("port_table") or []

    for port in raw_ports:
        if api_style == "integration":
            name = port.get("name") or f"Port {port.get('portIdx', '?')}"
            speed_mbps = port.get("maxSpeed") or port.get("speed") or 0
            enabled = port.get("enabled", True) if "enabled" in port else port.get("up", True)
            poe = port.get("poeMode") or port.get("poe_mode")
            mac = port.get("macAddress") or port.get("mac")
            is_uplink = port.get("isUplink", False)
        else:
            name = port.get("name") or f"Port {port.get('port_idx', '?')}"
            speed_mbps = port.get("speed") or 0
            enabled = port.get("up", True)
            poe = port.get("poe_mode")
            mac = port.get("mac")
            is_uplink = port.get("is_uplink", False)

        # Skip ports without real data (missing index/name)
        if "?" in name:
            continue

        nb_type = map_unifi_port_to_netbox_type(port, api_style)
        speed_kbps = int(speed_mbps) * 1000 if speed_mbps else None

        nb_poe_mode = None
        if poe:
            poe_str = str(poe).lower()
            if poe_str in ("auto", "pasv24", "passthrough", "on"):
                nb_poe_mode = "pse"

        ports.append({
            "name": name,
            "type": nb_type,
            "speed_kbps": speed_kbps,
            "enabled": bool(enabled),
            "poe_mode": nb_poe_mode,
            "mac_address": mac,
            "is_uplink": bool(is_uplink),
            "description": "Uplink" if is_uplink else "",
        })
    return ports


def normalize_radio_data(device, api_style="integration"):
    """Extract and normalize radio data from device dict."""
    radios = []
    if api_style == "integration":
        interfaces = device.get("interfaces")
        if isinstance(interfaces, dict):
            raw_radios = interfaces.get("radios") or []
        elif isinstance(interfaces, list):
            # Integration API v1 may return interfaces as a flat list;
            # filter to radio-type entries
            raw_radios = [
                iface for iface in interfaces
                if isinstance(iface, dict) and (
                    iface.get("radio") is not None
                    or iface.get("band")
                    or iface.get("channel")
                    or iface.get("type", "").lower() in ("radio", "wireless")
                    or (iface.get("name") or "").lower().startswith("radio")
                )
            ]
        else:
            raw_radios = []
    else:
        raw_radios = device.get("radio_table") or []

    for radio in raw_radios:
        name = radio.get("name") or f"radio{radio.get('radio', '?')}"
        # Skip radios without real data (missing index/name)
        if "?" in name:
            continue
        nb_type = map_unifi_radio_to_netbox_type(radio)
        # Build rich description: band, channel, tx power
        desc_parts = []
        band = radio.get("band") or radio.get("radio") or ""
        if band:
            desc_parts.append(str(band).upper())
        channel = radio.get("channel")
        if channel:
            desc_parts.append(f"Ch {channel}")
        tx_power = radio.get("txPower") or radio.get("tx_power") or radio.get("tx_power_mode")
        if tx_power:
            desc_parts.append(f"TX {tx_power}dBm" if str(tx_power).isdigit() else f"TX {tx_power}")
        radios.append({
            "name": name,
            "type": nb_type,
            "enabled": True,
            "description": " | ".join(desc_parts) if desc_parts else "",
        })
    return radios


def _fetch_integration_device_detail(unifi, site_obj, device_id):
    """Fetch full device detail via Integration API /devices/{id} which includes port_table."""
    try:
        site_api_id = getattr(site_obj, "api_id", site_obj.name)
        url = f"/sites/{site_api_id}/devices/{device_id}"
        response = unifi.make_request(url, "GET")
        logger.debug(f"Device detail response type: {type(response)}, "
                     f"keys: {list(response.keys()) if isinstance(response, dict) else 'N/A'}")
        if isinstance(response, dict):
            # Detect error responses from the API
            if "statusCode" in response:
                status = int(response.get("statusCode", 0))
                if status >= 400:
                    logger.debug(f"Device detail API error for {device_id}: "
                                 f"{response.get('message', 'unknown error')} (status {status})")
                    return None
            data = response.get("data", response)
            if isinstance(data, dict):
                # Also check if data itself is an error response
                if "statusCode" in data and int(data.get("statusCode", 0)) >= 400:
                    return None
                return data
            if isinstance(data, list) and data:
                return data[0]
        return None
    except Exception as e:
        logger.debug(f"Could not fetch device detail for {device_id}: {e}")
    return None


def sync_device_interfaces(nb, nb_device, device, api_style="integration", unifi=None, site_obj=None):
    """
    Sync physical port and radio interfaces from UniFi device data to NetBox.
    Upsert: match by device_id + interface name, create if missing, update if changed.
    """
    if not os.getenv("SYNC_INTERFACES", "true").strip().lower() in ("true", "1", "yes"):
        return

    device_name = get_device_name(device)

    # Integration API v1: device list only returns interfaces: ["ports"]/["radios"]
    # as metadata strings. We need to fetch actual port data via a separate API call.
    original_device = device  # Keep reference to original for uplink merge
    interfaces = device.get("interfaces")
    if api_style == "integration" and isinstance(interfaces, list) and unifi and site_obj:
        device_id = device.get("id")
        if device_id:
            detail = _fetch_integration_device_detail(unifi, site_obj, device_id)
            if detail and isinstance(detail, dict):
                detail_ifaces = detail.get("interfaces")
                port_table = detail.get("port_table")
                radio_table = detail.get("radio_table")
                logger.debug(f"Device {device_name} detail: interfaces type={type(detail_ifaces)}, "
                             f"has port_table={port_table is not None}, has radio_table={radio_table is not None}, "
                             f"detail keys={list(detail.keys())[:15]}")
                # If the detail has richer interface data, use it
                if isinstance(detail_ifaces, dict):
                    device = dict(device)
                    device["interfaces"] = detail_ifaces
                elif port_table or radio_table:
                    device = dict(device)
                    if port_table:
                        device["port_table"] = port_table
                    if radio_table:
                        device["radio_table"] = radio_table
                    # Switch to legacy-style parsing since we have port_table/radio_table
                    api_style = "legacy"
                # Merge uplink data from detail into ORIGINAL device dict for cable sync
                detail_uplink = detail.get("uplink")
                if detail_uplink and isinstance(detail_uplink, dict):
                    original_device["_detail_uplink"] = detail_uplink
                    logger.debug(f"Stored uplink detail for {device_name}: {list(detail_uplink.keys())}")
            else:
                logger.debug(f"No detail data returned for {device_name} from Integration API")

    # Fetch all existing interfaces for this device in one call
    existing_interfaces = {
        iface.name: iface
        for iface in nb.dcim.interfaces.filter(device_id=nb_device.id)
    }

    # --- Physical Ports ---
    ports = normalize_port_data(device, api_style)
    for port in ports:
        iface_name = port["name"]
        existing = existing_interfaces.get(iface_name)

        iface_data = {
            "device": nb_device.id,
            "name": iface_name,
            "type": port["type"],
            "enabled": port["enabled"],
        }
        if port.get("speed_kbps"):
            iface_data["speed"] = port["speed_kbps"]
        if port.get("poe_mode"):
            iface_data["poe_mode"] = port["poe_mode"]
        if port.get("description"):
            iface_data["description"] = port["description"]
        if port.get("mac_address"):
            iface_data["mac_address"] = port["mac_address"]

        if existing:
            needs_update = False
            for key, value in iface_data.items():
                if key == "device":
                    continue
                current_val = getattr(existing, key, None)
                if isinstance(current_val, dict):
                    current_val = current_val.get("value")
                if str(current_val) != str(value):
                    needs_update = True
                    break
            if needs_update:
                try:
                    for key, value in iface_data.items():
                        if key != "device":
                            setattr(existing, key, value)
                    existing.save()
                    logger.debug(f"Updated interface {iface_name} on {device_name}")
                except pynetbox.core.query.RequestError as e:
                    logger.warning(f"Failed to update interface {iface_name} on {device_name}: {e}")
        else:
            try:
                new_iface = nb.dcim.interfaces.create(iface_data)
                if new_iface:
                    logger.info(f"Created interface {iface_name} (ID {new_iface.id}) on {device_name}")
            except pynetbox.core.query.RequestError as e:
                logger.warning(f"Failed to create interface {iface_name} on {device_name}: {e}")

    # --- Radio Interfaces (APs only) ---
    if is_access_point_device(device):
        radios = normalize_radio_data(device, api_style)
        for radio in radios:
            iface_name = radio["name"]
            existing = existing_interfaces.get(iface_name)

            iface_data = {
                "device": nb_device.id,
                "name": iface_name,
                "type": radio["type"],
                "enabled": radio["enabled"],
            }
            if radio.get("description"):
                iface_data["description"] = radio["description"]

            if existing:
                needs_update = False
                for key, value in iface_data.items():
                    if key == "device":
                        continue
                    current_val = getattr(existing, key, None)
                    if isinstance(current_val, dict):
                        current_val = current_val.get("value")
                    if str(current_val) != str(value):
                        needs_update = True
                        break
                if needs_update:
                    try:
                        for key, value in iface_data.items():
                            if key != "device":
                                setattr(existing, key, value)
                        existing.save()
                        logger.debug(f"Updated radio {iface_name} on {device_name}")
                    except pynetbox.core.query.RequestError as e:
                        logger.warning(f"Failed to update radio {iface_name} on {device_name}: {e}")
            else:
                try:
                    new_iface = nb.dcim.interfaces.create(iface_data)
                    if new_iface:
                        logger.info(f"Created radio {iface_name} (ID {new_iface.id}) on {device_name}")
                except pynetbox.core.query.RequestError as e:
                    logger.warning(f"Failed to create radio {iface_name} on {device_name}: {e}")

    # Clean up interfaces with '?' in name (leftover from previous runs with missing data)
    for iface_name, iface_obj in existing_interfaces.items():
        if "?" in iface_name:
            try:
                iface_obj.delete()
                logger.info(f"Deleted invalid interface '{iface_name}' from {device_name}")
            except Exception as e:
                logger.warning(f"Failed to delete interface '{iface_name}' from {device_name}: {e}")


def get_device_features(device):
    """Normalize feature information from legacy and integration payloads."""
    features = device.get("features")
    if isinstance(features, list):
        return {str(item) for item in features}
    if isinstance(features, dict):
        return set(features.keys())
    return set()

def infer_role_key_for_device(device):
    """
    Infer a role key from device capabilities/model.
    Supported keys: WIRELESS, LAN, GATEWAY, ROUTER, UNKNOWN.
    """
    if is_access_point_device(device):
        return "WIRELESS"

    features = get_device_features(device)
    model = str(device.get("model", "")).upper()

    if (
        {"gateway", "securityGateway", "routing", "wan"} & features
        or model.startswith(("USG", "UXG", "UDM", "UCG", "UDR", "UX", "UGW"))
        or "GATEWAY" in model
    ):
        return "GATEWAY"

    if "routing" in features or "ROUTER" in model:
        return "ROUTER"

    if {"switching", "switch", "ports"} & features:
        return "LAN"

    return "UNKNOWN"

def select_netbox_role_for_device(device):
    """
    Pick a NetBox role object based on inferred role key and configured fallback order.
    """
    if not netbox_device_roles:
        raise ValueError("No device roles loaded from NETBOX.ROLES")

    inferred_key = infer_role_key_for_device(device)
    if inferred_key in netbox_device_roles:
        return netbox_device_roles[inferred_key], inferred_key

    for fallback_key in ("LAN", "WIRELESS", "GATEWAY", "ROUTER", "UNKNOWN"):
        if fallback_key in netbox_device_roles:
            return netbox_device_roles[fallback_key], fallback_key

    # Final fallback: first configured role
    first_key = next(iter(netbox_device_roles))
    return netbox_device_roles[first_key], first_key


# ──────────────────────────────────────────────────────────────
# UniFi device-type specs database
# Maps UniFi model codes to hardware specifications for NetBox.
# Keys: model string as returned by UniFi API.
# ──────────────────────────────────────────────────────────────
UNIFI_MODEL_SPECS = {
    # ── Switches ──────────────────────────────────────────────
    "US8P60":       {"part_number": "US-8-60W",             "u_height": 0, "ports": [("Port {n}", "1000base-t", 8)], "poe_budget": 60},
    "US 8 60W":     {"part_number": "US-8-60W",             "u_height": 0, "ports": [("Port {n}", "1000base-t", 8)], "poe_budget": 60},
    "US8P150":      {"part_number": "US-8-150W",            "u_height": 0, "ports": [("Port {n}", "1000base-t", 8), ("SFP {n}", "1000base-x-sfp", 2)], "poe_budget": 150},
    "US 8 PoE 150W":{"part_number": "US-8-150W",            "u_height": 0, "ports": [("Port {n}", "1000base-t", 8), ("SFP {n}", "1000base-x-sfp", 2)], "poe_budget": 150},
    "US68P":        {"part_number": "USW-Lite-8-PoE",       "u_height": 0, "ports": [("Port {n}", "1000base-t", 8)], "poe_budget": 52},
    "USLP8P":       {"part_number": "USW-Lite-8-PoE",       "u_height": 0, "ports": [("Port {n}", "1000base-t", 8)], "poe_budget": 52},
    "US16P150":     {"part_number": "US-16-150W",           "u_height": 1, "ports": [("Port {n}", "1000base-t", 16), ("SFP {n}", "1000base-x-sfp", 2)], "poe_budget": 150},
    "US 16 PoE 150W":{"part_number": "US-16-150W",          "u_height": 1, "ports": [("Port {n}", "1000base-t", 16), ("SFP {n}", "1000base-x-sfp", 2)], "poe_budget": 150},
    "US24P250":     {"part_number": "US-24-250W",           "u_height": 1, "ports": [("Port {n}", "1000base-t", 24), ("SFP {n}", "1000base-x-sfp", 2)], "poe_budget": 250},
    "US 24 PoE 250W":{"part_number": "US-24-250W",          "u_height": 1, "ports": [("Port {n}", "1000base-t", 24), ("SFP {n}", "1000base-x-sfp", 2)], "poe_budget": 250},
    "US48PRO":      {"part_number": "USW-Pro-48-PoE",       "u_height": 1, "ports": [("Port {n}", "1000base-t", 48), ("SFP+ {n}", "10gbase-x-sfpp", 4)], "poe_budget": 600},
    "USW Pro 48 PoE":{"part_number": "USW-Pro-48-PoE",      "u_height": 1, "ports": [("Port {n}", "1000base-t", 48), ("SFP+ {n}", "10gbase-x-sfpp", 4)], "poe_budget": 600},
    "US6XG150":     {"part_number": "US-XG-6POE",           "u_height": 1, "ports": [("Port {n}", "10gbase-t", 4), ("SFP+ {n}", "10gbase-x-sfpp", 2)], "poe_budget": 150},
    "US XG 6 PoE":  {"part_number": "US-XG-6POE",           "u_height": 1, "ports": [("Port {n}", "10gbase-t", 4), ("SFP+ {n}", "10gbase-x-sfpp", 2)], "poe_budget": 150},
    "USMINI":       {"part_number": "USW-Flex-Mini",        "u_height": 0, "ports": [("Port {n}", "1000base-t", 5)], "poe_budget": 0},
    "USW Flex Mini": {"part_number": "USW-Flex-Mini",       "u_height": 0, "ports": [("Port {n}", "1000base-t", 5)], "poe_budget": 0},
    "USXG":         {"part_number": "USW-Aggregation",      "u_height": 1, "ports": [("SFP+ {n}", "10gbase-x-sfpp", 8)], "poe_budget": 0},
    "USW Aggregation":{"part_number": "USW-Aggregation",    "u_height": 1, "ports": [("SFP+ {n}", "10gbase-x-sfpp", 8)], "poe_budget": 0},
    "USAGGPRO":     {"part_number": "USW-Pro-Aggregation",  "u_height": 1, "ports": [("SFP+ {n}", "10gbase-x-sfpp", 28), ("SFP28 {n}", "25gbase-x-sfp28", 4)], "poe_budget": 0},
    "USW Pro Aggregation":{"part_number": "USW-Pro-Aggregation","u_height": 1, "ports": [("SFP+ {n}", "10gbase-x-sfpp", 28), ("SFP28 {n}", "25gbase-x-sfp28", 4)], "poe_budget": 0},
    "USL8A":        {"part_number": "USW-Lite-8",           "u_height": 0, "ports": [("Port {n}", "1000base-t", 8)], "poe_budget": 0},
    "USPM16P":      {"part_number": "USW-Pro-Max-16-PoE",   "u_height": 0, "ports": [("Port {n}", "2.5gbase-t", 16), ("SFP+ {n}", "10gbase-x-sfpp", 2)], "poe_budget": 180},
    "USW Pro Max 16 PoE":{"part_number": "USW-Pro-Max-16-PoE","u_height": 0, "ports": [("Port {n}", "2.5gbase-t", 16), ("SFP+ {n}", "10gbase-x-sfpp", 2)], "poe_budget": 180},
    "USPM24P":      {"part_number": "USW-Pro-Max-24-PoE",   "u_height": 1, "ports": [("Port {n}", "1000base-t", 16), ("Port {n+16}", "2.5gbase-t", 8), ("SFP+ {n}", "10gbase-x-sfpp", 2)], "poe_budget": 400},
    "USW Pro Max 24 PoE":{"part_number": "USW-Pro-Max-24-PoE","u_height": 1, "ports": [("Port {n}", "1000base-t", 16), ("Port {n+16}", "2.5gbase-t", 8), ("SFP+ {n}", "10gbase-x-sfpp", 2)], "poe_budget": 400},
    "USW Pro 8 PoE":{"part_number": "USW-Pro-8-PoE",        "u_height": 0, "ports": [("Port {n}", "1000base-t", 8), ("SFP+ {n}", "10gbase-x-sfpp", 2)], "poe_budget": 120},
    "USW Enterprise 8 PoE":{"part_number": "USW-Enterprise-8-PoE","u_height": 0, "ports": [("Port {n}", "2.5gbase-t", 8), ("SFP+ {n}", "10gbase-x-sfpp", 2)], "poe_budget": 120},
    "US XG 16":     {"part_number": "US-XG-16",             "u_height": 1, "ports": [("Port {n}", "10gbase-t", 4), ("SFP+ {n}", "10gbase-x-sfpp", 12)], "poe_budget": 0},
    # ── Gateways ──────────────────────────────────────────────
    "UXGPRO":       {"part_number": "UXG-Pro",              "u_height": 1, "ports": [("WAN 1", "1000base-t", 1), ("WAN 2", "1000base-t", 1), ("LAN 1", "10gbase-x-sfpp", 1), ("LAN 2", "10gbase-x-sfpp", 1)], "poe_budget": 0},
    "Gateway Pro":  {"part_number": "UXG-Pro",              "u_height": 1, "ports": [("WAN 1", "1000base-t", 1), ("WAN 2", "1000base-t", 1), ("LAN 1", "10gbase-x-sfpp", 1), ("LAN 2", "10gbase-x-sfpp", 1)], "poe_budget": 0},
    # ── Access Points ─────────────────────────────────────────
    "U7LT":         {"part_number": "UAP-AC-Lite",          "u_height": 0, "ports": [("eth0", "1000base-t", 1)], "poe_budget": 0},
    "UAP-AC-Lite":  {"part_number": "UAP-AC-Lite",          "u_height": 0, "ports": [("eth0", "1000base-t", 1)], "poe_budget": 0},
    "U7MSH":        {"part_number": "UAP-AC-M",             "u_height": 0, "ports": [("eth0", "1000base-t", 1)], "poe_budget": 0},
    "AC Mesh":      {"part_number": "UAP-AC-M",             "u_height": 0, "ports": [("eth0", "1000base-t", 1)], "poe_budget": 0},
    "UAL6":         {"part_number": "U6-LR",                "u_height": 0, "ports": [("eth0", "1000base-t", 1)], "poe_budget": 0},
    "U6 Lite":      {"part_number": "U6-Lite",              "u_height": 0, "ports": [("eth0", "1000base-t", 1)], "poe_budget": 0},
    "UFLHD":        {"part_number": "UAP-FlexHD",           "u_height": 0, "ports": [("eth0", "1000base-t", 1)], "poe_budget": 0},
    "FlexHD":       {"part_number": "UAP-FlexHD",           "u_height": 0, "ports": [("eth0", "1000base-t", 1)], "poe_budget": 0},
    # ── UISP / airMAX ────────────────────────────────────────
    "Rocket Prism 5AC Gen2":{"part_number": "RP-5AC-Gen2",  "u_height": 0, "ports": [("eth0", "1000base-t", 1)], "poe_budget": 0},
    "LiteAP AC":    {"part_number": "LAP-120",              "u_height": 0, "ports": [("eth0", "1000base-t", 1)], "poe_budget": 0},
    "LiteBeam 5AC Gen2":{"part_number": "LBE-5AC-Gen2",    "u_height": 0, "ports": [("eth0", "1000base-t", 1)], "poe_budget": 0},
    "Nanostation 5AC":{"part_number": "NS-5AC",             "u_height": 0, "ports": [("eth0", "1000base-t", 1)], "poe_budget": 0},
}


_device_type_specs_done = set()
_device_type_specs_lock = threading.Lock()

# ---------------------------------------------------------------------------
#  Community device-type library (netbox-community/devicetype-library)
# ---------------------------------------------------------------------------
_community_specs = None


def _load_community_specs():
    """Load community device specs from bundled JSON file (lazy, cached)."""
    global _community_specs
    if _community_specs is not None:
        return _community_specs
    json_path = os.path.join(os.path.dirname(os.path.abspath(__file__)), "data", "ubiquiti_device_specs.json")
    if not os.path.exists(json_path):
        logger.warning(f"Community device specs file not found: {json_path}")
        _community_specs = {"by_part": {}, "by_model": {}}
        return _community_specs
    try:
        with open(json_path, "r") as fh:
            _community_specs = json.load(fh)
        logger.info(f"Loaded community device specs: {len(_community_specs.get('by_part', {}))} by part, "
                     f"{len(_community_specs.get('by_model', {}))} by model")
    except Exception as e:
        logger.warning(f"Failed to load community device specs: {e}")
        _community_specs = {"by_part": {}, "by_model": {}}
    return _community_specs


def _lookup_community_specs(part_number=None, model=None):
    """Look up community specs by part number or model name (case-insensitive)."""
    specs = _load_community_specs()
    # Try part_number first
    if part_number:
        hit = specs["by_part"].get(part_number)
        if hit:
            return hit
        # Case-insensitive fallback
        pn_upper = part_number.upper()
        for key, val in specs["by_part"].items():
            if key.upper() == pn_upper:
                return val
    # Try model name
    if model:
        hit = specs["by_model"].get(model)
        if hit:
            return hit
        model_upper = model.upper()
        for key, val in specs["by_model"].items():
            if key.upper() == model_upper:
                return val
    return None


def _resolve_device_specs(model):
    """Resolve full device specs by merging UNIFI_MODEL_SPECS with community library.

    Hardcoded specs overlay community data so manual overrides always win.
    Returns merged dict or None if neither source has data.
    """
    hardcoded = UNIFI_MODEL_SPECS.get(model)
    part_number = hardcoded.get("part_number") if hardcoded else None

    # Look up community specs by part_number or model name
    community = _lookup_community_specs(part_number=part_number, model=model)
    # Fallback: try model code as part_number (e.g. "US48PRO" might match)
    if not community and not part_number:
        community = _lookup_community_specs(part_number=model)

    if not community and not hardcoded:
        return None

    # Merge: community base, hardcoded overlay
    merged = {}
    if community:
        merged.update(community)
    if hardcoded:
        merged.update(hardcoded)
    return merged


# ---------------------------------------------------------------------------
#  Generic template sync (interfaces, console ports, power ports)
# ---------------------------------------------------------------------------

def _sync_templates(nb, nb_device_type, model, template_endpoint, expected, label):
    """Generic sync for interface/console-port/power-port templates.

    *expected* is a list of dicts, each with at least 'name' and 'type'.
    *template_endpoint* is the pynetbox endpoint (e.g. nb.dcim.interface_templates).
    *label* is used for log messages (e.g. "interface", "console-port").
    """
    dt_id = int(nb_device_type.id)
    existing_templates = list(template_endpoint.filter(device_type_id=dt_id))

    # De-duplicate existing
    existing_by_name = {}
    for tmpl in existing_templates:
        key = tmpl.name
        if key not in existing_by_name:
            existing_by_name[key] = tmpl
        else:
            try:
                tmpl.delete()
                logger.debug(f"Deleted duplicate {label} template '{key}' from {model}")
            except Exception:
                pass

    # Build comparison sets
    expected_set = set()
    for e in expected:
        expected_set.add((e["name"], e.get("type", "")))

    existing_set = set()
    for name, tmpl in existing_by_name.items():
        tmpl_type = tmpl.type.value if tmpl.type else ""
        existing_set.add((name, tmpl_type))

    if expected_set == existing_set:
        logger.debug(f"{label.capitalize()} templates for {model} already correct ({len(expected_set)})")
        return

    logger.debug(f"{label.capitalize()} template mismatch for {model}: "
                 f"expected={len(expected_set)}, existing={len(existing_set)}")

    # Delete all and recreate
    for tmpl in existing_by_name.values():
        try:
            tmpl.delete()
        except Exception:
            pass

    for entry in expected:
        create_data = {
            "device_type": dt_id,
            "name": entry["name"],
            "type": entry.get("type", ""),
        }
        # Pass through optional fields
        for opt_field in ("mgmt_only", "poe_mode", "poe_type", "label",
                          "maximum_draw", "allocated_draw"):
            if opt_field in entry and entry[opt_field] is not None:
                create_data[opt_field] = entry[opt_field]
        try:
            template_endpoint.create(create_data)
        except pynetbox.core.query.RequestError:
            pass
    logger.info(f"Synced {len(expected)} {label} templates for {model}")


def ensure_device_type_specs(nb, nb_device_type, model):
    """Ensure a device type has correct specs (part number, u_height, interface templates)
    based on merged UNIFI_MODEL_SPECS + community library. Also syncs console/power port templates."""
    specs = _resolve_device_specs(model)
    if not specs:
        return

    # Serialize all template operations to prevent concurrent API races
    with _device_type_specs_lock:
        if nb_device_type.id in _device_type_specs_done:
            return
        _device_type_specs_done.add(nb_device_type.id)

        _ensure_device_type_specs_inner(nb, nb_device_type, model, specs)


def _ensure_device_type_specs_inner(nb, nb_device_type, model, specs):
    """Inner implementation of device type spec sync (called under lock)."""
    changed = False
    # Update part number and u_height if missing/wrong
    if specs.get("part_number") and (nb_device_type.part_number or "") != specs["part_number"]:
        nb_device_type.part_number = specs["part_number"]
        changed = True
    if specs.get("u_height") is not None and nb_device_type.u_height != specs["u_height"]:
        nb_device_type.u_height = specs["u_height"]
        changed = True
    # is_full_depth
    if specs.get("is_full_depth") is not None and getattr(nb_device_type, "is_full_depth", None) != specs["is_full_depth"]:
        nb_device_type.is_full_depth = specs["is_full_depth"]
        changed = True
    # airflow
    if specs.get("airflow") and getattr(nb_device_type, "airflow", None) != specs["airflow"]:
        nb_device_type.airflow = specs["airflow"]
        changed = True
    # weight
    if specs.get("weight") is not None:
        try:
            w = float(specs["weight"])
            if getattr(nb_device_type, "weight", None) != w:
                nb_device_type.weight = w
                nb_device_type.weight_unit = specs.get("weight_unit", "kg")
                changed = True
        except (ValueError, TypeError):
            pass
    # Add PoE budget as comment if available
    poe = specs.get("poe_budget", 0)
    expected_comments = f"PoE budget: {poe}W" if poe else ""
    if expected_comments and (nb_device_type.comments or "") != expected_comments:
        nb_device_type.comments = expected_comments
        changed = True
    if changed:
        try:
            nb_device_type.save()
            logger.info(f"Updated device type specs for {model}: part#={specs.get('part_number')}, "
                        f"u_height={specs.get('u_height')}, PoE={poe}W")
        except Exception as e:
            logger.warning(f"Failed to update device type specs for {model}: {e}")

    # --- Sync interface templates ---
    expected_ifaces = []
    # Prefer community 'interfaces' list (richer: poe_mode, poe_type, mgmt_only)
    if specs.get("interfaces"):
        for iface in specs["interfaces"]:
            entry = {"name": iface["name"], "type": iface.get("type", "1000base-t")}
            if iface.get("mgmt_only"):
                entry["mgmt_only"] = True
            if iface.get("poe_mode"):
                entry["poe_mode"] = iface["poe_mode"]
            if iface.get("poe_type"):
                entry["poe_type"] = iface["poe_type"]
            expected_ifaces.append(entry)
    elif specs.get("ports"):
        # Fallback to hardcoded ports tuple format
        for port_spec in specs["ports"]:
            pattern, port_type, count = port_spec
            if count == 1 and "{n}" not in pattern and "{n+" not in pattern:
                expected_ifaces.append({"name": pattern, "type": port_type})
            elif "{n+" in pattern:
                import re as _re
                m = _re.search(r'\{n\+(\d+)\}', pattern)
                offset = int(m.group(1)) if m else 0
                base_pattern = _re.sub(r'\{n\+\d+\}', '{}', pattern)
                for i in range(1, count + 1):
                    expected_ifaces.append({"name": base_pattern.format(offset + i), "type": port_type})
            else:
                for i in range(1, count + 1):
                    expected_ifaces.append({"name": pattern.replace("{n}", str(i)), "type": port_type})

    if expected_ifaces:
        _sync_templates(nb, nb_device_type, model, nb.dcim.interface_templates, expected_ifaces, "interface")

    # --- Sync console port templates ---
    if specs.get("console_ports"):
        expected_console = []
        for cp in specs["console_ports"]:
            expected_console.append({"name": cp["name"], "type": cp.get("type", "rj-45")})
        _sync_templates(nb, nb_device_type, model, nb.dcim.console_port_templates, expected_console, "console-port")

    # --- Sync power port templates ---
    if specs.get("power_ports"):
        expected_power = []
        for pp in specs["power_ports"]:
            entry = {"name": pp["name"], "type": pp.get("type", "iec-60320-c14")}
            if pp.get("maximum_draw") is not None:
                entry["maximum_draw"] = pp["maximum_draw"]
            if pp.get("allocated_draw") is not None:
                entry["allocated_draw"] = pp["allocated_draw"]
            expected_power.append(entry)
        _sync_templates(nb, nb_device_type, model, nb.dcim.power_port_templates, expected_power, "power-port")


def process_device(unifi, nb, site, device, nb_ubiquity, tenant, unifi_device_ips=None, unifi_site_obj=None):
    """Process a device and add it to NetBox."""
    try:
        device_name = get_device_name(device)
        device_model = device.get("model") or "Unknown Model"
        device_mac = get_device_mac(device)
        device_ip = get_device_ip(device)
        device_serial = get_device_serial(device)

        # Skip offline/disconnected devices
        device_state = (device.get("state") or device.get("status") or "").upper()
        if device_state in ("OFFLINE", "DISCONNECTED", "0"):
            logger.debug(f"Skipping offline device {device_name}")
            return

        logger.info(f"Processing device {device_name} at site {site}...")
        logger.debug(f"Device details: Model={device_model}, MAC={device_mac}, IP={device_ip}, Serial={device_serial}")

        # Determine device role from configured NETBOX.ROLES mapping
        nb_device_role, selected_role_key = select_netbox_role_for_device(device)
        logger.debug(f"Using role '{selected_role_key}' ({nb_device_role.name}) for device {device_name}")

        if not device_serial:
            logger.warning(f"Missing serial/mac/id for device {device_name}. Skipping...")
            return

        # VRF handling (env-controlled). Default: do not create VRFs.
        vrf, vrf_mode = get_vrf_for_site(nb, site.name)
        if vrf:
            logger.debug(f"Using VRF {vrf.name} (ID {vrf.id}) for site {site.name} (mode={vrf_mode})")
        else:
            logger.debug(f"Running without VRF for site {site.name} (mode={vrf_mode})")

        # Device Type creation
        logger.debug(f"Checking for existing device type: {device_model} (manufacturer ID: {nb_ubiquity.id})")
        nb_device_type = nb.dcim.device_types.get(model=device_model, manufacturer_id=nb_ubiquity.id)
        if not nb_device_type:
            try:
                # Pre-populate from community specs when creating a new device type
                specs = _resolve_device_specs(device_model)
                create_data = {
                    "manufacturer": nb_ubiquity.id,
                    "model": device_model,
                    "slug": (specs or {}).get("slug") or slugify(f'{nb_ubiquity.name}-{device_model}'),
                }
                if specs:
                    if specs.get("part_number"):
                        create_data["part_number"] = specs["part_number"]
                    if specs.get("u_height") is not None:
                        create_data["u_height"] = specs["u_height"]
                    if specs.get("is_full_depth") is not None:
                        create_data["is_full_depth"] = specs["is_full_depth"]
                    if specs.get("airflow"):
                        create_data["airflow"] = specs["airflow"]
                    if specs.get("weight") is not None:
                        try:
                            create_data["weight"] = float(specs["weight"])
                            create_data["weight_unit"] = specs.get("weight_unit", "kg")
                        except (ValueError, TypeError):
                            pass
                nb_device_type = nb.dcim.device_types.create(create_data)
                if nb_device_type:
                    logger.info(f"Device type {device_model} with ID {nb_device_type.id} successfully added to NetBox.")
            except pynetbox.core.query.RequestError as e:
                logger.error(f"Failed to create device type for {device_name} at site {site}: {e}")
                return
        # Ensure device type has correct specs (ports, PoE, part number, etc.)
        ensure_device_type_specs(nb, nb_device_type, device_model)

        # Check for existing device
        logger.debug(f"Checking if device already exists: {device_name} (serial: {device_serial})")
        nb_device = nb.dcim.devices.get(site_id=site.id, serial=device_serial)
        if nb_device:
            logger.info(f"Device {device_name} with serial {device_serial} already exists. Checking IP...")
            # Update device name if changed in UniFi
            if nb_device.name != device_name:
                old_name = nb_device.name
                nb_device.name = device_name
                try:
                    nb_device.save()
                    logger.info(f"Updated device name from '{old_name}' to '{device_name}'")
                except pynetbox.core.query.RequestError as e:
                    logger.warning(f"Failed to update device name to '{device_name}': {e}")
                    nb_device.name = old_name  # Revert on failure
            # Update device type if model changed
            current_type_id = nb_device.device_type.id if nb_device.device_type else None
            if nb_device_type and current_type_id != nb_device_type.id:
                nb_device.device_type = nb_device_type.id
                try:
                    nb_device.save()
                    logger.info(f"Updated device type for {device_name} to {device_model}")
                except pynetbox.core.query.RequestError as e:
                    logger.warning(f"Failed to update device type for {device_name}: {e}")
            # Update asset tag from device name (ID/AID suffix)
            asset_tag = extract_asset_tag(device_name)
            if asset_tag and getattr(nb_device, 'asset_tag', None) != asset_tag:
                nb_device.asset_tag = asset_tag
                try:
                    nb_device.save()
                    logger.info(f"Updated asset tag for {device_name} to {asset_tag}")
                except pynetbox.core.query.RequestError as e:
                    logger.warning(f"Failed to update asset tag for {device_name}: {e}")
        else:
            # Create NetBox Device
            try:
                device_data = {
                        'name': device_name,
                        'device_type': nb_device_type.id,
                        'tenant': tenant.id,
                        'site': site.id,
                        'serial': device_serial
                    }
                asset_tag = extract_asset_tag(device_name)
                if asset_tag:
                    device_data['asset_tag'] = asset_tag

                logger.debug("Getting postable fields for NetBox API")
                available_fields = get_postable_fields(netbox_url, netbox_token, 'dcim/devices')
                logger.debug(f"Available NetBox API fields: {list(available_fields.keys())}")
                if 'role' in available_fields:
                    logger.debug(f"Using 'role' field for device role (ID: {nb_device_role.id})")
                    device_data['role'] = nb_device_role.id
                elif 'device_role' in available_fields:
                    logger.debug(f"Using 'device_role' field for device role (ID: {nb_device_role.id})")
                    device_data['device_role'] = nb_device_role.id
                else:
                    logger.error(f'Could not determine the syntax for the role. Skipping device {device_name}, '
                                    f'{device_serial}.')
                    return None

                # Device status on create (default: offline)
                desired_status = (os.getenv("NETBOX_DEVICE_STATUS") or "offline").strip().lower()
                if desired_status and "status" in available_fields:
                    device_data["status"] = desired_status

                # Add the device to Netbox
                logger.debug(f"Creating device in NetBox with data: {device_data}")
                nb_device = nb.dcim.devices.create(device_data)

                if nb_device:
                    logger.info(f"Device {device_name} serial {device_serial} with ID {nb_device.id} successfully added to NetBox.")
            except pynetbox.core.query.RequestError as e:
                error_message = str(e)
                if "Device name must be unique per site" in error_message:
                    logger.warning(f"Device name {device_name} already exists at site {site}. "
                                   f"Trying with name {device_name}_{device_serial}.")
                    try:
                        device_data['name'] = f"{device_name}_{device_serial}"
                        nb_device = nb.dcim.devices.create(device_data)
                        if nb_device:
                            logger.info(f"Device {device_name} with ID {nb_device.id} successfully added to NetBox.")
                    except pynetbox.core.query.RequestError as e2:
                        logger.exception(f"Failed to create device {device_name} serial {device_serial} at site {site}: {e2}")
                        return
                else:
                    logger.exception(f"Failed to create device {device_name} serial {device_serial} at site {site}: {e}")
                    return

        if nb_device:
            # Ensure "zabbix" tag is present
            zabbix_tag = ensure_tag(nb, "zabbix")
            if zabbix_tag:
                current_tags = [t.id for t in (nb_device.tags or [])]
                if zabbix_tag.id not in current_tags:
                    current_tags.append(zabbix_tag.id)
                    nb_device.tags = current_tags
                    nb_device.save()
                    logger.info(f"Added 'zabbix' tag to device {device_name}.")

            # Sync device state (ONLINE/OFFLINE -> active/offline)
            try:
                sync_device_state(nb, nb_device, device)
            except Exception as e:
                logger.warning(f"Failed to sync state for {device_name}: {e}")

            # Sync custom fields (firmware, uptime, mac)
            try:
                sync_device_custom_fields(nb, nb_device, device)
            except Exception as e:
                logger.warning(f"Failed to sync custom fields for {device_name}: {e}")

            # Sync physical interfaces from UniFi to NetBox
            try:
                api_style = getattr(unifi, "api_style", "legacy") or "legacy"
                sync_device_interfaces(nb, nb_device, device, api_style, unifi=unifi, site_obj=unifi_site_obj)
            except Exception as e:
                logger.warning(f"Failed to sync interfaces for {device_name}: {e}")

        # Add primary IP if available — skip routers/gateways (they manage their own IPs)
        role_key = infer_role_key_for_device(device)
        if role_key in ("GATEWAY", "ROUTER"):
            logger.debug(f"Skipping IP assignment for {device_name} — device is a {role_key}")
            return

        if not device_ip:
            logger.warning(f"Missing IP for device {device_name}. Skipping IP assignment...")
            return
        try:
            ipaddress.ip_address(device_ip)
        except ValueError:
            logger.warning(f"Invalid IP {device_ip} for device {device_name}. Skipping...")
            return

        # --- DHCP-to-static IP reassignment ---
        if is_ip_in_dhcp_range(device_ip):
            # Skip routers/gateways — they manage their own IPs
            role_key = infer_role_key_for_device(device)
            if role_key in ("GATEWAY", "ROUTER"):
                logger.debug(f"Skipping DHCP-to-static for {device_name} — device is a {role_key}")
            else:
                # If device already has a static IP in NetBox, keep it
                if nb_device and nb_device.primary_ip4:
                    existing_ip_obj = nb.ipam.ip_addresses.get(id=nb_device.primary_ip4.id)
                    if existing_ip_obj:
                        existing_ip_str = str(existing_ip_obj.address).split("/")[0]
                        if not is_ip_in_dhcp_range(existing_ip_str):
                            logger.debug(
                                f"Device {device_name} reports DHCP IP {device_ip} but NetBox "
                                f"already has static IP {existing_ip_str}. Keeping existing."
                            )
                            return

                logger.info(f"Device {device_name} has DHCP IP {device_ip}. Finding static IP...")
                # Find prefix containing the DHCP IP
                if vrf:
                    dhcp_prefixes = list(nb.ipam.prefixes.filter(contains=device_ip, vrf_id=vrf.id))
                else:
                    dhcp_prefixes = list(nb.ipam.prefixes.filter(contains=device_ip))

                if dhcp_prefixes:
                    target_prefix = dhcp_prefixes[0]
                    static_ip = find_available_static_ip(nb, target_prefix, vrf, tenant, unifi_device_ips=unifi_device_ips)
                    if static_ip:
                        logger.info(f"Reassigning {device_name} from DHCP {device_ip} to static {static_ip}")
                        new_ip = static_ip.split("/")[0]
                        # Set static IP on UniFi device with gateway + DNS from network config
                        if unifi_site_obj:
                            subnet_mask_bits = int(static_ip.split("/")[1])
                            subnet_mask = str(ipaddress.IPv4Network(f"0.0.0.0/{subnet_mask_bits}").netmask)
                            gw, dns = _get_network_info_for_ip(new_ip)
                            set_unifi_device_static_ip(
                                unifi, unifi_site_obj, device, new_ip,
                                subnet_mask=subnet_mask, gateway=gw, dns_servers=dns
                            )
                        device_ip = new_ip
                    else:
                        logger.warning(f"No available static IP for {device_name}. Keeping DHCP IP {device_ip}.")
                else:
                    logger.warning(f"No prefix found for DHCP IP {device_ip}. Keeping DHCP IP.")
        # --- End DHCP-to-static ---

        # get the prefix that this IP address belongs to
        if vrf:
            prefixes = nb.ipam.prefixes.filter(contains=device_ip, vrf_id=vrf.id)
        else:
            prefixes = nb.ipam.prefixes.filter(contains=device_ip)
        if not prefixes:
            logger.warning(f"No prefix found for IP {device_ip} for device {device_name}. Skipping...")
            return
        for prefix in prefixes:
            # Extract the prefix length (mask) from the prefix
            subnet_mask = prefix.prefix.split('/')[1]
            ip = f'{device_ip}/{subnet_mask}'
            break
        if nb_device:
            # Check if the IP has changed compared to what NetBox has
            old_ip_str = None
            if nb_device.primary_ip4:
                old_ip_obj = nb.ipam.ip_addresses.get(id=nb_device.primary_ip4.id)
                if old_ip_obj:
                    old_ip_str = str(old_ip_obj.address).split("/")[0]
            if old_ip_str and old_ip_str != device_ip:
                logger.info(f"Device {device_name} IP changed: {old_ip_str} -> {device_ip}. Updating NetBox.")
                # Remove old IP assignment
                try:
                    old_ip_obj.delete()
                    logger.info(f"Deleted old IP {old_ip_str} for device {device_name}.")
                except Exception as e:
                    logger.warning(f"Could not delete old IP {old_ip_str} for device {device_name}: {e}")
                nb_device.primary_ip4 = None
                nb_device.save()
            elif old_ip_str and old_ip_str == device_ip:
                logger.debug(f"Device {device_name} IP unchanged ({device_ip}). Skipping IP update.")
                return

            interface = nb.dcim.interfaces.get(device_id=nb_device.id, name="vlan.1")
            if not interface:
                try:
                    iface_payload = {
                        "device": nb_device.id,
                        "name": "vlan.1",
                        "type": "virtual",
                        "enabled": True,
                    }
                    if vrf:
                        iface_payload["vrf_id"] = vrf.id
                    interface = nb.dcim.interfaces.create(**iface_payload)
                    if interface:
                        logger.info(
                            f"Interface vlan.1 for device {device_name} with ID {interface.id} successfully added to NetBox.")
                except pynetbox.core.query.RequestError as e:
                    logger.exception(
                        f"Failed to create interface vlan.1 for device {device_name} at site {site}: {e}")
                    return
            ip_get_filters = {"address": ip, "tenant_id": tenant.id}
            if vrf:
                ip_get_filters["vrf_id"] = vrf.id
            nb_ip = nb.ipam.ip_addresses.get(**ip_get_filters)
            if not nb_ip:
                try:
                    ip_payload = {
                        "assigned_object_id": interface.id,
                        "assigned_object_type": 'dcim.interface',
                        "address": ip,
                        "tenant_id": tenant.id,
                        "status": "active",
                    }
                    if vrf:
                        ip_payload["vrf_id"] = vrf.id
                    nb_ip = nb.ipam.ip_addresses.create(ip_payload)
                    if nb_ip:
                        logger.info(f"IP address {ip} with ID {nb_ip.id} successfully added to NetBox.")
                except pynetbox.core.query.RequestError as e:
                    logger.exception(f"Failed to create IP address {ip} for device {device_name} at site {site}: {e}")
                    return
            if nb_ip:
                nb_device.primary_ip4 = nb_ip.id
                nb_device.save()
                logger.info(f"Device {device_name} primary IP set to {ip}.")

    except Exception as e:
        logger.exception(f"Failed to process device {get_device_name(device)} at site {site}: {e}")

def process_site(unifi, nb, site_obj, site_display_name, nb_site, nb_ubiquity, tenant):
    """
    Process devices for a given site and add them to NetBox.
    Also syncs VLANs, WiFi SSIDs, and uplink cables.
    """
    logger.debug(f"Processing site {site_display_name}...")
    try:
        if site_obj:
            # Sync VLANs from UniFi networks
            if os.getenv("SYNC_VLANS", "true").strip().lower() in ("true", "1", "yes"):
                try:
                    sync_site_vlans(nb, site_obj, nb_site, tenant)
                except Exception as e:
                    logger.warning(f"Failed to sync VLANs for site {site_display_name}: {e}")

            # Sync WiFi SSIDs
            if os.getenv("SYNC_WLANS", "true").strip().lower() in ("true", "1", "yes"):
                try:
                    sync_site_wlans(nb, site_obj, nb_site, tenant)
                except Exception as e:
                    logger.warning(f"Failed to sync WLANs for site {site_display_name}: {e}")

            # Auto-discover DHCP ranges from UniFi network configs
            if os.getenv("DHCP_AUTO_DISCOVER", "true").strip().lower() in ("true", "1", "yes"):
                try:
                    site_dhcp_ranges = extract_dhcp_ranges_from_unifi(site_obj, unifi=unifi)
                    if site_dhcp_ranges:
                        with _unifi_dhcp_ranges_lock:
                            _unifi_dhcp_ranges[nb_site.id] = site_dhcp_ranges
                        logger.info(
                            f"Discovered {len(site_dhcp_ranges)} DHCP range(s) from UniFi "
                            f"for site {site_display_name}: {[str(n) for n in site_dhcp_ranges]}"
                        )
                except Exception as e:
                    logger.warning(f"Failed to extract DHCP ranges for site {site_display_name}: {e}")

            logger.debug(f"Fetching devices for site: {site_display_name}")
            devices = site_obj.device.all()
            logger.debug(f"Found {len(devices)} devices for site {site_display_name}")

            # Collect all UniFi device IPs for DHCP-to-static checks
            unifi_device_ips = set()
            # Also collect serials for cleanup phase
            site_serials = set()
            for d in devices:
                dip = get_device_ip(d)
                if dip:
                    unifi_device_ips.add(dip)
                ds = get_device_serial(d)
                if ds:
                    site_serials.add(ds)
            # Store serials for cleanup
            with _cleanup_serials_lock:
                _cleanup_serials_by_site[nb_site.id] = site_serials

            with ThreadPoolExecutor(max_workers=MAX_DEVICE_THREADS) as executor:
                futures = []
                for device in devices:
                    futures.append(executor.submit(process_device, unifi, nb, nb_site, device, nb_ubiquity, tenant, unifi_device_ips=unifi_device_ips, unifi_site_obj=site_obj))

                for future in as_completed(futures):
                    try:
                        future.result()
                    except Exception as e:
                        logger.error(f"Error processing a device at site {site_display_name}: {e}")

            # Sync uplink cables after all devices are processed
            if os.getenv("SYNC_CABLES", "true").strip().lower() in ("true", "1", "yes"):
                try:
                    # Build a lookup of all NetBox devices by MAC/serial/UUID for this site
                    nb_devices_at_site = nb.dcim.devices.filter(site_id=nb_site.id, tenant_id=tenant.id)
                    all_nb_devices_by_mac = {}
                    for d in nb_devices_at_site:
                        serial = str(d.serial or "").upper().replace(":", "")
                        if serial:
                            all_nb_devices_by_mac[serial] = d
                        # Also index by custom field MAC if available
                        cf = dict(d.custom_fields or {})
                        cf_mac = (cf.get("unifi_mac") or "").upper().replace(":", "")
                        if cf_mac:
                            all_nb_devices_by_mac[cf_mac] = d
                    # Index UniFi device UUIDs for O(1) upstream lookup
                    for unifi_dev in devices:
                        dev_id = unifi_dev.get("id")
                        dev_serial = get_device_serial(unifi_dev)
                        if dev_id and dev_serial and dev_serial in all_nb_devices_by_mac:
                            all_nb_devices_by_mac[str(dev_id)] = all_nb_devices_by_mac[dev_serial]

                    # Ensure all devices have uplink data from device detail API
                    # (sync_device_interfaces only fetches detail for devices with list-type interfaces)
                    api_style = getattr(unifi, "api_style", "legacy") or "legacy"
                    if api_style == "integration":
                        for device in devices:
                            if not device.get("_detail_uplink"):
                                device_id = device.get("id")
                                if device_id:
                                    detail = _fetch_integration_device_detail(unifi, site_obj, device_id)
                                    if detail and isinstance(detail, dict):
                                        detail_uplink = detail.get("uplink")
                                        if detail_uplink and isinstance(detail_uplink, dict):
                                            device["_detail_uplink"] = detail_uplink

                    for device in devices:
                        device_serial = get_device_serial(device)
                        if not device_serial:
                            continue
                        # Use the already-built lookup instead of an extra API call
                        nb_device = all_nb_devices_by_mac.get(device_serial)
                        if nb_device:
                            try:
                                sync_uplink_cable(nb, nb_device, device, all_nb_devices_by_mac)
                            except Exception as e:
                                logger.debug(f"Could not sync uplink cable for {get_device_name(device)}: {e}")
                except Exception as e:
                    logger.warning(f"Failed to sync uplink cables for site {site_display_name}: {e}")

            # Mark stale devices (in NetBox but no longer in UniFi) as offline
            if os.getenv("SYNC_STALE_CLEANUP", "true").strip().lower() in ("true", "1", "yes"):
                try:
                    unifi_serials = set()
                    for d in devices:
                        s = get_device_serial(d)
                        if s:
                            unifi_serials.add(s)
                    nb_devices_at_site = list(nb.dcim.devices.filter(site_id=nb_site.id, tenant_id=tenant.id))
                    for nb_dev in nb_devices_at_site:
                        if nb_dev.serial and nb_dev.serial not in unifi_serials:
                            current_status = nb_dev.status.value if hasattr(nb_dev.status, 'value') else str(nb_dev.status)
                            if current_status != "offline":
                                nb_dev.status = "offline"
                                nb_dev.save()
                                logger.info(f"Marked stale device '{nb_dev.name}' as offline (not in UniFi)")
                except Exception as e:
                    logger.warning(f"Failed to clean up stale devices for site {site_display_name}: {e}")
        else:
            logger.error(f"Site {site_display_name} not found")
    except Exception as e:
        logger.error(f"Failed to process site {site_display_name}: {e}")

def process_controller(unifi_url, unifi_username, unifi_password, unifi_mfa_secret, unifi_api_key, unifi_api_key_header, nb, nb_ubiquity, tenant,
                       netbox_sites_dict, config=None):
    """
    Process all sites and devices for a specific UniFi controller.
    """
    logger.info(f"Processing controller {unifi_url}...")
    logger.debug(f"Initializing UniFi connection to: {unifi_url}")

    try:
        # Create a Unifi instance and authenticate
        unifi = Unifi(
            unifi_url,
            unifi_username,
            unifi_password,
            unifi_mfa_secret,
            api_key=unifi_api_key,
            api_key_header=unifi_api_key_header,
        )
        logger.debug(f"UniFi connection established to: {unifi_url}")
        
        # Get all sites from the controller
        logger.debug(f"Fetching sites from controller: {unifi_url}")
        sites = unifi.sites
        logger.debug(f"Found {len(sites)} sites on controller: {unifi_url}")
        logger.info(f"Found {len(sites)} sites for controller {unifi_url}")

        with ThreadPoolExecutor(max_workers=MAX_SITE_THREADS) as executor:
            futures = []
            for site_name, site_obj in sites.items():
                logger.info(f"Processing site {site_name}...")
                nb_site = match_sites_to_netbox(site_name, netbox_sites_dict, config)

                if not nb_site:
                    logger.warning(f"No match found for Ubiquity site: {site_name}. Skipping...")
                    continue

                futures.append(executor.submit(process_site, unifi, nb, site_obj, site_name, nb_site, nb_ubiquity, tenant))

            # Wait for all site-processing threads to complete
            for future in as_completed(futures):
                future.result()
    except Exception as e:
        logger.error(f"Error processing controller {unifi_url}: {e}")

def process_all_controllers(unifi_url_list, unifi_username, unifi_password, unifi_mfa_secret, unifi_api_key, unifi_api_key_header, nb, nb_ubiquity, tenant,
                            netbox_sites_dict, config=None):
    """
    Process all UniFi controllers in parallel.
    """
    with ThreadPoolExecutor(max_workers=MAX_CONTROLLER_THREADS) as executor:
        future_to_url = {}
        for url in unifi_url_list:
            future = executor.submit(
                process_controller,
                url,
                unifi_username,
                unifi_password,
                unifi_mfa_secret,
                unifi_api_key,
                unifi_api_key_header,
                nb,
                nb_ubiquity,
                tenant,
                netbox_sites_dict,
                config,
            )
            future_to_url[future] = url

        # Wait for all controller-processing threads to complete
        for future in as_completed(future_to_url):
            url = future_to_url[future]
            try:
                future.result()
            except Exception as e:
                logger.exception(f"Error processing one of the UniFi controllers {url}: {e}")
                continue

# ---------------------------------------------------------------------------
#  NetBox Cleanup Functions
# ---------------------------------------------------------------------------

def _is_cleanup_enabled() -> bool:
    """Check if cleanup is enabled via NETBOX_CLEANUP env var."""
    return _parse_env_bool(os.getenv("NETBOX_CLEANUP"), default=False)


def _cleanup_stale_days() -> int:
    """Get the stale device grace period in days."""
    return _read_env_int("CLEANUP_STALE_DAYS", default=30, minimum=0)


def cleanup_stale_devices(nb, nb_site, tenant, unifi_serials):
    """Delete devices at a site that are no longer present in UniFi.

    Only deletes devices that have been offline for longer than CLEANUP_STALE_DAYS.
    When CLEANUP_STALE_DAYS=0, all stale devices are deleted immediately.
    """
    grace_days = _cleanup_stale_days()
    nb_devices = list(nb.dcim.devices.filter(site_id=nb_site.id, tenant_id=tenant.id))
    deleted = 0
    for dev in nb_devices:
        serial = str(dev.serial or "").upper().replace(":", "")
        if not serial:
            continue
        if serial in unifi_serials:
            continue
        # Device not found in UniFi — check grace period
        if grace_days > 0:
            # Use last_updated as proxy for "last seen"
            import datetime
            last_updated = getattr(dev, "last_updated", None)
            if last_updated:
                try:
                    if isinstance(last_updated, str):
                        lu = datetime.datetime.fromisoformat(last_updated.replace("Z", "+00:00"))
                    else:
                        lu = last_updated
                    now = datetime.datetime.now(datetime.timezone.utc)
                    age_days = (now - lu).days
                    if age_days < grace_days:
                        logger.debug(f"Stale device {dev.name} ({serial}) last updated {age_days}d ago, "
                                     f"grace={grace_days}d — skipping")
                        continue
                except Exception:
                    pass
        # Delete the device and its interfaces/IPs
        try:
            dev.delete()
            deleted += 1
            logger.info(f"Cleanup: deleted stale device {dev.name} ({serial}) from site {nb_site.name}")
        except Exception as e:
            logger.warning(f"Cleanup: failed to delete stale device {dev.name}: {e}")
    if deleted:
        logger.info(f"Cleanup: deleted {deleted} stale device(s) from site {nb_site.name}")
    return deleted


def cleanup_orphan_interfaces(nb, nb_site, tenant):
    """Delete garbage interfaces (names containing '?') at a site."""
    nb_devices = list(nb.dcim.devices.filter(site_id=nb_site.id, tenant_id=tenant.id))
    deleted = 0
    for dev in nb_devices:
        ifaces = list(nb.dcim.interfaces.filter(device_id=dev.id))
        for iface in ifaces:
            if "?" in (iface.name or ""):
                try:
                    iface.delete()
                    deleted += 1
                    logger.debug(f"Cleanup: deleted garbage interface '{iface.name}' on {dev.name}")
                except Exception as e:
                    logger.warning(f"Cleanup: failed to delete interface '{iface.name}' on {dev.name}: {e}")
    if deleted:
        logger.info(f"Cleanup: deleted {deleted} garbage interface(s) from site {nb_site.name}")
    return deleted


def cleanup_orphan_ips(nb, tenant):
    """Delete IP addresses that have no assigned object (orphaned)."""
    all_ips = list(nb.ipam.ip_addresses.filter(tenant_id=tenant.id))
    deleted = 0
    for ip in all_ips:
        if ip.assigned_object is None and ip.assigned_object_id is None:
            try:
                ip.delete()
                deleted += 1
                logger.debug(f"Cleanup: deleted orphan IP {ip.address}")
            except Exception as e:
                logger.warning(f"Cleanup: failed to delete orphan IP {ip.address}: {e}")
    if deleted:
        logger.info(f"Cleanup: deleted {deleted} orphan IP(s)")
    return deleted


def cleanup_orphan_cables(nb, nb_site):
    """Delete cables at a site where one or both terminations are missing."""
    try:
        cables = list(nb.dcim.cables.filter(site_id=nb_site.id))
    except Exception:
        cables = list(nb.dcim.cables.all())
    deleted = 0
    for cable in cables:
        a_ok = getattr(cable, "a_terminations", None)
        b_ok = getattr(cable, "b_terminations", None)
        if not a_ok or not b_ok:
            try:
                cable.delete()
                deleted += 1
                logger.debug(f"Cleanup: deleted orphan cable {cable.id}")
            except Exception as e:
                logger.warning(f"Cleanup: failed to delete orphan cable {cable.id}: {e}")
    if deleted:
        logger.info(f"Cleanup: deleted {deleted} orphan cable(s) from site {nb_site.name}")
    return deleted


def cleanup_device_types(nb, nb_ubiquity):
    """Refresh device type specs and delete unused device types (device_count == 0)."""
    all_types = list(nb.dcim.device_types.filter(manufacturer_id=nb_ubiquity.id))
    refreshed = 0
    deleted = 0
    for dt in all_types:
        # Refresh specs from community + hardcoded
        model = dt.model
        specs = _resolve_device_specs(model)
        if specs:
            try:
                _ensure_device_type_specs_inner(nb, dt, model, specs)
                refreshed += 1
            except Exception as e:
                logger.warning(f"Cleanup: failed to refresh specs for device type {model}: {e}")
        # Delete unused device types
        device_count = getattr(dt, "device_count", None)
        if device_count is not None and device_count == 0:
            try:
                dt.delete()
                deleted += 1
                logger.info(f"Cleanup: deleted unused device type {model}")
            except Exception as e:
                logger.warning(f"Cleanup: failed to delete unused device type {model}: {e}")
    logger.info(f"Cleanup: refreshed {refreshed} device type(s), deleted {deleted} unused device type(s)")
    return deleted


def run_netbox_cleanup(nb, nb_ubiquity, tenant, netbox_sites_dict, all_unifi_serials_by_site):
    """Orchestrate all cleanup functions."""
    if not _is_cleanup_enabled():
        logger.debug("NetBox cleanup is disabled (NETBOX_CLEANUP != true)")
        return

    logger.info("=== Starting NetBox cleanup ===")

    # Per-site cleanup
    for site_name, nb_site in netbox_sites_dict.items():
        site_serials = all_unifi_serials_by_site.get(nb_site.id, set())
        try:
            cleanup_stale_devices(nb, nb_site, tenant, site_serials)
        except Exception as e:
            logger.warning(f"Cleanup error (stale devices) at site {site_name}: {e}")
        try:
            cleanup_orphan_interfaces(nb, nb_site, tenant)
        except Exception as e:
            logger.warning(f"Cleanup error (orphan interfaces) at site {site_name}: {e}")
        try:
            cleanup_orphan_cables(nb, nb_site)
        except Exception as e:
            logger.warning(f"Cleanup error (orphan cables) at site {site_name}: {e}")

    # Global cleanup (not per-site)
    try:
        cleanup_orphan_ips(nb, tenant)
    except Exception as e:
        logger.warning(f"Cleanup error (orphan IPs): {e}")

    try:
        cleanup_device_types(nb, nb_ubiquity)
    except Exception as e:
        logger.warning(f"Cleanup error (device types): {e}")

    logger.info("=== NetBox cleanup complete ===")


if __name__ == "__main__":
    # Parse command line arguments
    import argparse
    parser = argparse.ArgumentParser(description='Sync UniFi devices to NetBox')
    parser.add_argument('-v', '--verbose', action='store_true', help='Enable verbose (debug) logging')
    args = parser.parse_args()
    
    # Configure logging with appropriate level based on verbose flag
    log_level = logging.DEBUG if args.verbose else logging.INFO
    setup_logging(log_level)
    
    if args.verbose:
        logger.debug("Verbose logging enabled")
    logger.debug("Loading runtime configuration (config file + environment)")
    try:
        config = load_runtime_config()
    except Exception as e:
        logger.exception(f"Failed to load runtime configuration: {e}")
        raise SystemExit(1)
    logger.debug("Runtime configuration loaded successfully")
    try:
        unifi_url_list = config['UNIFI']['URLS']
    except (KeyError, TypeError):
        logger.error("UniFi URL list is missing. Set UNIFI_URLS in .env or UNIFI.URLS in config.")
        raise SystemExit(1)
    if not unifi_url_list:
        logger.error("UniFi URL list is empty. Set UNIFI_URLS in .env (comma-separated or JSON array).")
        raise SystemExit(1)

    unifi_username = os.getenv('UNIFI_USERNAME')
    unifi_password = os.getenv('UNIFI_PASSWORD')
    unifi_mfa_secret = os.getenv('UNIFI_MFA_SECRET')
    unifi_api_key = os.getenv('UNIFI_API_KEY')
    unifi_api_key_header = os.getenv('UNIFI_API_KEY_HEADER')

    if not unifi_api_key and not (unifi_username and unifi_password):
        logger.error("Missing UniFi credentials. Set UNIFI_API_KEY or UNIFI_USERNAME + UNIFI_PASSWORD.")
        raise SystemExit(1)

    # Connect to Netbox
    try:
        netbox_url = config['NETBOX']['URL']
    except (KeyError, TypeError):
        logger.error("NetBox URL is missing. Set NETBOX_URL in .env or NETBOX.URL in config.")
        raise SystemExit(1)
    if not netbox_url:
        logger.error("NetBox URL is empty. Set NETBOX_URL in .env.")
        raise SystemExit(1)
    netbox_token = os.getenv('NETBOX_TOKEN')
    if not netbox_token:
        logger.error("Netbox token is missing from environment variables.")
        raise SystemExit(1)

    # Create a custom HTTP session as this script will often exceed the default pool size of 10
    session = requests.Session()
    adapter = requests.adapters.HTTPAdapter(pool_connections=50, pool_maxsize=50)

    # Adjust connection pool size
    session.mount("http://", adapter)
    session.mount("https://", adapter)
    session.verify = _netbox_verify_ssl()

    logger.debug(f"Initializing NetBox API connection to: {netbox_url}")
    nb = pynetbox.api(netbox_url, token=netbox_token, threading=True)
    nb.http_session = session  # Attach the custom session
    logger.debug("NetBox API connection established")

    nb_ubiquity = nb.dcim.manufacturers.get(slug='ubiquity')
    try:
        tenant_name = config['NETBOX']['TENANT']
    except (KeyError, TypeError):
        logger.error("NetBox tenant is missing. Set NETBOX_TENANT in .env or NETBOX.TENANT in config.")
        raise SystemExit(1)
    if not tenant_name:
        logger.error("NetBox tenant is empty. Set NETBOX_TENANT in .env.")
        raise SystemExit(1)

    tenant = nb.tenancy.tenants.get(name=tenant_name)

    roles_config = config.get('NETBOX', {}).get('ROLES')
    if not isinstance(roles_config, dict) or not roles_config:
        logger.error(
            "NETBOX.ROLES is missing. Set NETBOX_ROLES JSON in .env "
            "or NETBOX_ROLE_<KEY> variables (e.g. NETBOX_ROLE_WIRELESS=AP)."
        )
        raise SystemExit(1)

    netbox_device_roles.clear()
    for role_key, role_name in roles_config.items():
        if not role_name:
            continue
        normalized_key = str(role_key).upper()
        role_slug = slugify(role_name)
        role_obj = None
        try:
            role_obj = nb.dcim.device_roles.get(slug=role_slug)
        except ValueError:
            # If multiple roles match (unexpected), just pick the first.
            role_obj = next(iter(nb.dcim.device_roles.filter(slug=role_slug)), None)
        if not role_obj:
            try:
                role_obj = nb.dcim.device_roles.get(name=role_name)
            except ValueError:
                role_obj = next(iter(nb.dcim.device_roles.filter(name=role_name)), None)
        if not role_obj:
            try:
                role_obj = nb.dcim.device_roles.create({'name': role_name, 'slug': role_slug})
                if role_obj:
                    logger.info(f"Role {normalized_key} ({role_name}) with ID {role_obj.id} successfully added to NetBox.")
            except pynetbox.core.query.RequestError as e:
                # Another process might have created it, or name/slug might already exist.
                logger.warning(f"Failed to create role {normalized_key} ({role_name}): {e}. Trying to fetch existing role.")
                try:
                    role_obj = nb.dcim.device_roles.get(slug=role_slug) or nb.dcim.device_roles.get(name=role_name)
                except ValueError:
                    role_obj = None
        if role_obj:
            netbox_device_roles[normalized_key] = role_obj

    if not netbox_device_roles:
        logger.error("Could not load or create any roles from NETBOX roles configuration.")
        raise SystemExit(1)

    logger.debug("Fetching all NetBox sites")
    netbox_sites = nb.dcim.sites.all()
    logger.debug(f"Found {len(netbox_sites)} sites in NetBox")

    # Preprocess NetBox sites
    logger.debug("Preparing NetBox sites dictionary")
    netbox_sites_dict = prepare_netbox_sites(netbox_sites)
    logger.debug(f"Prepared {len(netbox_sites_dict)} NetBox sites for mapping")

    if not nb_ubiquity:
        nb_ubiquity = nb.dcim.manufacturers.create({'name': 'Ubiquity Networks', 'slug': 'ubiquity'})
        if nb_ubiquity:
            logger.info(f"Ubiquity manufacturer with ID {nb_ubiquity.id} successfully added to Netbox.")

    # Sync loop — run once or continuously based on SYNC_INTERVAL
    sync_interval = _sync_interval_seconds()
    import time as _time
    run_count = 0
    while True:
        run_count += 1
        # Clear per-run caches on subsequent runs
        if run_count > 1:
            _device_type_specs_done.clear()
            _cleanup_serials_by_site.clear()
            _unifi_dhcp_ranges.clear()
            _unifi_network_info.clear()

        logger.info(f"=== Sync run #{run_count} starting ===")

        # Process all UniFi controllers in parallel
        process_all_controllers(unifi_url_list, unifi_username, unifi_password, unifi_mfa_secret,
                                unifi_api_key, unifi_api_key_header, nb, nb_ubiquity,
                                tenant, netbox_sites_dict, config)

        # Run cleanup after sync
        run_netbox_cleanup(nb, nb_ubiquity, tenant, netbox_sites_dict, _cleanup_serials_by_site)

        logger.info(f"=== Sync run #{run_count} complete ===")

        if sync_interval <= 0:
            break
        logger.info(f"Sleeping {sync_interval} seconds until next sync...")
        _time.sleep(sync_interval)
