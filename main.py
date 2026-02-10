import json
from dotenv import load_dotenv
from slugify import slugify
import os
import re
import sys
import requests
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

# Define threads for each layer
MAX_CONTROLLER_THREADS = 5  # Number of UniFi controllers to process concurrently
MAX_SITE_THREADS = 8  # Number of sites to process concurrently per controller
MAX_DEVICE_THREADS = 8  # Number of devices to process concurrently per site
MAX_THREADS = 8 # Define threads based on available system cores or default

# Populated at runtime from NETBOX roles in env/config
netbox_device_roles = {}
postable_fields_cache = {}
postable_fields_lock = threading.Lock()

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
    response = requests.options(url, headers=headers, verify=False, timeout=15)
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

def _parse_env_bool(raw_value, default=False):
    if raw_value is None:
        return default
    value = str(raw_value).strip().lower()
    if value in {"1", "true", "yes", "on"}:
        return True
    if value in {"0", "false", "no", "off"}:
        return False
    logger.warning(f"Invalid boolean value '{raw_value}'. Using default {default}.")
    return default


def _parse_env_list(var_name):
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


def _parse_env_mapping(var_name):
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

def get_device_name(device):
    return (
        device.get("name")
        or device.get("hostname")
        or device.get("macAddress")
        or device.get("mac")
        or device.get("id")
        or "unknown-device"
    )

def get_device_mac(device):
    return device.get("mac") or device.get("macAddress")

def get_device_ip(device):
    return device.get("ip") or device.get("ipAddress")

def get_device_serial(device):
    # Integration API v1 does not expose serial in list payloads; use stable fallback.
    return device.get("serial") or get_device_mac(device) or device.get("id")

def is_access_point_device(device):
    ap_flag = device.get("is_access_point")
    if isinstance(ap_flag, bool):
        return ap_flag
    features = device.get("features")
    if isinstance(features, list):
        return "accessPoint" in features
    if isinstance(features, dict):
        return "accessPoint" in features
    interfaces = device.get("interfaces")
    if isinstance(interfaces, list):
        return "radios" in interfaces
    if isinstance(interfaces, dict):
        return "radios" in interfaces
    return False

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

def process_device(unifi, nb, site, device, nb_ubiquity, tenant):
    """Process a device and add it to NetBox."""
    try:
        device_name = get_device_name(device)
        device_model = device.get("model") or "Unknown Model"
        device_mac = get_device_mac(device)
        device_ip = get_device_ip(device)
        device_serial = get_device_serial(device)

        logger.info(f"Processing device {device_name} at site {site}...")
        logger.debug(f"Device details: Model={device_model}, MAC={device_mac}, IP={device_ip}, Serial={device_serial}")

        # Determine device role from configured NETBOX.ROLES mapping
        nb_device_role, selected_role_key = select_netbox_role_for_device(device)
        logger.debug(f"Using role '{selected_role_key}' ({nb_device_role.name}) for device {device_name}")

        if not device_serial:
            logger.warning(f"Missing serial/mac/id for device {device_name}. Skipping...")
            return

        # VRF creation
        vrf_name = f"vrf_{site}"
        vrf = None
        logger.debug(f"Checking for existing VRF: {vrf_name}")
        try:
            vrf = nb.ipam.vrfs.get(name=vrf_name)
        except ValueError as e:
            error_message = str(e)
            if "get() returned more than one result." in error_message:
                logger.warning(f"Multiple VRFs with name {vrf_name} found. Using 1st one in the list.")
                vrfs = nb.ipam.vrfs.filter(name=vrf_name)
                for vrf_item in vrfs:
                    vrf = vrf_item
                    break
            else:
                logger.exception(f"Failed to get VRF {vrf_name} for site {site}: {e}. Skipping...")
                return

        if not vrf:
            logger.debug(f"VRF {vrf_name} not found, creating new VRF")
            vrf = nb.ipam.vrfs.create({"name": vrf_name})
            if vrf:
                logger.info(f"VRF {vrf_name} with ID {vrf.id} successfully added to NetBox.")

        # Device Type creation
        logger.debug(f"Checking for existing device type: {device_model} (manufacturer ID: {nb_ubiquity.id})")
        nb_device_type = nb.dcim.device_types.get(model=device_model, manufacturer_id=nb_ubiquity.id)
        if not nb_device_type:
            try:
                nb_device_type = nb.dcim.device_types.create({"manufacturer": nb_ubiquity.id, "model": device_model,
                                                              "slug": slugify(f'{nb_ubiquity.name}-{device_model}')})
                if nb_device_type:
                    logger.info(f"Device type {device_model} with ID {nb_device_type.id} successfully added to NetBox.")
            except pynetbox.core.query.RequestError as e:
                logger.error(f"Failed to create device type for {device_name} at site {site}: {e}")
                return
            if len(device.get("port_table", [])) > 0:
                for port in device["port_table"]:
                    if port["media"] == "GE":
                        port_type = "1000base-t"
                        try:
                            template = nb.dcim.interface_templates.create({
                                "device_type": nb_device_type.id,
                                "name": port["name"],
                                "type": port_type,
                            })
                            if template:
                                logger.info(f"Interface template {port['name']} with ID {template.id} successfully added to NetBox.")
                        except pynetbox.core.query.RequestError as e:
                            logger.exception(f"Failed to create interface template for {device_name} at site {site}: {e}")

        # Check for existing device
        logger.debug(f"Checking if device already exists: {device_name} (serial: {device_serial})")
        if nb.dcim.devices.get(site_id=site.id, serial=device_serial):
            logger.info(f"Device {device_name} with serial {device_serial} already exists. Skipping...")
            return

        # Create NetBox Device
        try:
            device_data = {
                    'name': device_name,
                    'device_type': nb_device_type.id,
                    'tenant': tenant.id,
                    'site': site.id,
                    'serial': device_serial
                }

            logger.debug(f"Getting postable fields for NetBox API")
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
                    # Just update the name in the existing device_data dictionary
                    device_data['name'] = f"{device_name}_{device_serial}"
                    
                    # Add the device to Netbox with updated name
                    nb_device = nb.dcim.devices.create(device_data)
                    if nb_device:
                        logger.info(f"Device {device_name} with ID {nb_device.id} successfully added to NetBox.")
                except pynetbox.core.query.RequestError as e2:
                    logger.exception(f"Failed to create device {device_name} serial {device_serial} at site {site}: {e2}")
                    return
            else:
                logger.exception(f"Failed to create device {device_name} serial {device_serial} at site {site}: {e}")
                return

        # Add primary IP if available
        if not device_ip:
            logger.warning(f"Missing IP for device {device_name}. Skipping IP assignment...")
            return
        try:
            ipaddress.ip_address(device_ip)
        except ValueError:
            logger.warning(f"Invalid IP {device_ip} for device {device_name}. Skipping...")
            return
        # get the prefix that this IP address belongs to
        prefixes = nb.ipam.prefixes.filter(contains=device_ip, vrf_id=vrf.id)
        if not prefixes:
            logger.warning(f"No prefix found for IP {device_ip} for device {device_name}. Skipping...")
            return
        for prefix in prefixes:
            # Extract the prefix length (mask) from the prefix
            subnet_mask = prefix.prefix.split('/')[1]
            ip = f'{device_ip}/{subnet_mask}'
            break
        if nb_device:
            interface = nb.dcim.interfaces.get(device_id=nb_device.id, name="vlan.1")
            if not interface:
                try:
                    interface = nb.dcim.interfaces.create(device=nb_device.id,
                                                          name="vlan.1",
                                                          type="virtual",
                                                          enabled=True,
                                                          vrf_id=vrf.id,)
                    if interface:
                        logger.info(
                            f"Interface vlan.1 for device {device_name} with ID {interface.id} successfully added to NetBox.")
                except pynetbox.core.query.RequestError as e:
                    logger.exception(
                        f"Failed to create interface vlan.1 for device {device_name} at site {site}: {e}")
                    return
            nb_ip = nb.ipam.ip_addresses.get(address=ip, vrf_id=vrf.id, tenant_id=tenant.id)
            if not nb_ip:
                try:
                    nb_ip = nb.ipam.ip_addresses.create({
                        "assigned_object_id": interface.id,
                        "assigned_object_type": 'dcim.interface',
                        "address": ip,
                        "vrf_id": vrf.id,
                        "tenant_id": tenant.id,
                        "status": "active",
                    })
                    if nb_ip:
                        logger.info(f"IP address {ip} with ID {nb_ip.id} successfully added to NetBox.")
                except pynetbox.core.query.RequestError as e:
                    logger.exception(f"Failed to create IP address {ip} for device {device_name} at site {site}: {e}")
                    return
            if nb_ip:
                nb_device.primary_ip4 = nb_ip.id
                nb_device.save()
                logger.info(f"Device {device_name} with IP {ip} added to NetBox.")

    except Exception as e:
        logger.exception(f"Failed to process device {get_device_name(device)} at site {site}: {e}")

def process_site(unifi, nb, site_obj, site_display_name, nb_site, nb_ubiquity, tenant):
    """
    Process devices for a given site and add them to NetBox.
    """
    logger.debug(f"Processing site {site_display_name}...")
    try:
        if site_obj:
            logger.debug(f"Fetching devices for site: {site_display_name}")
            devices = site_obj.device.all()
            logger.debug(f"Found {len(devices)} devices for site {site_display_name}")

            with ThreadPoolExecutor(max_workers=MAX_DEVICE_THREADS) as executor:
                futures = []
                for device in devices:
                    futures.append(executor.submit(process_device, unifi, nb, nb_site, device, nb_ubiquity, tenant))

                for future in as_completed(futures):
                    try:
                        future.result()
                    except Exception as e:
                        logger.error(f"Error processing a device at site {site_display_name}: {e}")
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

def fetch_site_devices(unifi, site_name):
    """Fetch devices for a specific site."""
    logger.info(f"Fetching devices for site {site_name}...")
    try:
        logger.debug(f"Getting site object for: {site_name}")
        site = unifi.site(site_name)
        if site:
            logger.debug(f"Retrieving devices for site: {site_name}")
            devices = site.device.all()
            logger.debug(f"Retrieved {len(devices)} devices for site: {site_name}")
            return devices
        else:
            logger.error(f"Site {site_name} not found")
            return None
    except Exception as e:
        logger.error(f"Failed to fetch devices for site {site_name}: {e}")
        return None

def process_all_sites(unifi, netbox_sites_dict, nb, nb_ubiquity, tenant):
    """Process all sites and their devices concurrently."""
    # Get all sites from the unifi module
    unifi_sites = unifi.sites
    if not unifi_sites:
        logger.error("Failed to fetch sites from UniFi controller.")
        return

    sites = {}
    with ThreadPoolExecutor(max_workers=MAX_THREADS) as executor:
        # Fetch all devices per site concurrently
        future_to_site = {executor.submit(fetch_site_devices, unifi, site_name): site_name for site_name in unifi_sites.keys()}
        for future in as_completed(future_to_site):
            site_name = future_to_site[future]
            try:
                devices = future.result()
                if devices:
                    sites[site_name] = devices
                    logger.info(f"Successfully fetched devices for site {site_name}")
            except Exception as e:
                logger.error(f"Error fetching devices for site {site_name}: {e}")

    logger.info(f"Fetched {len(sites)} sites. Starting device processing...")

    # Process devices in parallel
    with ThreadPoolExecutor(max_workers=MAX_THREADS) as executor:
        future_to_device = {}
        for site_name, devices in sites.items():
            # Use the site mapping to find the corresponding NetBox site
            nb_site = match_sites_to_netbox(site_name, netbox_sites_dict)
            if not nb_site:
                logger.warning(f"No matching NetBox site found for Ubiquity site {site_name}. Add mapping in site_mapping.yaml. Skipping...")
                continue
            for device in devices:
                future = executor.submit(process_device, unifi, nb, nb_site, device, nb_ubiquity, tenant)
                future_to_device[future] = (site_name, device)

        for future in as_completed(future_to_device):
            site_name, device = future_to_device[future]
            try:
                future.result()
                logger.info(f"Successfully processed device {device['name']} at site {site_name}.")
            except Exception as e:
                logger.error(f"Error processing device {device['name']} at site {site_name}: {e}")

def parse_successful_log_entries(log_file):
    """
    Parses a log file to find entries containing 'successfully added to NetBox'
    and builds a dictionary with 'device' and 'ip address' lists of IDs.

    :param log_file: Path to the log file
    :return: Dictionary with lists of IDs for 'device' and 'ip address'
    """
    # Dictionary to store the resulting lists
    result = {
        "device": [],
        "ip address": []
    }

    # Regular expression to extract the ID from the log entry
    id_pattern_device = re.compile(r"^Device .* with ID (\d+) successfully added to NetBox")
    id_pattern_ip = re.compile(r"^IP address .* with ID (\d+) successfully added to NetBox")

    with open(log_file, "r") as file:
        for line in file:
            # Start processing the log entry only after `INFO -`
            if "INFO - " in line:
                log_content = line.split("INFO - ", 1)[1]  # Extract the part after "INFO - "

                # Match and classify the log entry
                if match := id_pattern_device.match(log_content):
                    result["device"].append(int(match.group(1)))  # Extract and add device ID
                elif match := id_pattern_ip.match(log_content):
                    result["ip address"].append(int(match.group(1)))  # Extract and add IP address ID

    return result


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
        logger.exception("UniFi URL list is missing. Set UNIFI_URLS in .env or UNIFI.URLS in config.")
        raise SystemExit(1)
    if not unifi_url_list:
        logger.exception("UniFi URL list is empty. Set UNIFI_URLS in .env (comma-separated or JSON array).")
        raise SystemExit(1)

    unifi_username = os.getenv('UNIFI_USERNAME')
    unifi_password = os.getenv('UNIFI_PASSWORD')
    unifi_mfa_secret = os.getenv('UNIFI_MFA_SECRET')
    unifi_api_key = os.getenv('UNIFI_API_KEY')
    unifi_api_key_header = os.getenv('UNIFI_API_KEY_HEADER')

    if not unifi_api_key and not (unifi_username and unifi_password):
        logger.exception("Missing UniFi credentials. Set UNIFI_API_KEY or UNIFI_USERNAME + UNIFI_PASSWORD.")
        raise SystemExit(1)

    # Connect to Netbox
    try:
        netbox_url = config['NETBOX']['URL']
    except (KeyError, TypeError):
        logger.exception("NetBox URL is missing. Set NETBOX_URL in .env or NETBOX.URL in config.")
        raise SystemExit(1)
    if not netbox_url:
        logger.exception("NetBox URL is empty. Set NETBOX_URL in .env.")
        raise SystemExit(1)
    netbox_token = os.getenv('NETBOX_TOKEN')
    if not netbox_token:
        logger.exception("Netbox token is missing from environment variables.")
        raise SystemExit(1)

    # Create a custom HTTP session as this script will often exceed the default pool size of 10
    session = requests.Session()
    adapter = requests.adapters.HTTPAdapter(pool_connections=50, pool_maxsize=50)

    # Adjust connection pool size
    session.mount("http://", adapter)
    session.mount("https://", adapter)
    session.verify = False

    logger.debug(f"Initializing NetBox API connection to: {netbox_url}")
    nb = pynetbox.api(netbox_url, token=netbox_token, threading=True)
    nb.http_session = session  # Attach the custom session
    logger.debug("NetBox API connection established")

    nb_ubiquity = nb.dcim.manufacturers.get(slug='ubiquity')
    try:
        tenant_name = config['NETBOX']['TENANT']
    except (KeyError, TypeError):
        logger.exception("NetBox tenant is missing. Set NETBOX_TENANT in .env or NETBOX.TENANT in config.")
        raise SystemExit(1)
    if not tenant_name:
        logger.exception("NetBox tenant is empty. Set NETBOX_TENANT in .env.")
        raise SystemExit(1)

    tenant = nb.tenancy.tenants.get(name=tenant_name)

    roles_config = config.get('NETBOX', {}).get('ROLES')
    if not isinstance(roles_config, dict) or not roles_config:
        logger.exception(
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
        role_obj = nb.dcim.device_roles.get(slug=role_slug)
        if not role_obj:
            role_obj = nb.dcim.device_roles.create({'name': role_name, 'slug': role_slug})
            if role_obj:
                logger.info(f"Role {normalized_key} ({role_name}) with ID {role_obj.id} successfully added to NetBox.")
        if role_obj:
            netbox_device_roles[normalized_key] = role_obj

    if not netbox_device_roles:
        logger.exception("Could not load or create any roles from NETBOX.ROLES.")
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

    # Process all UniFi controllers in parallel
    process_all_controllers(unifi_url_list, unifi_username, unifi_password, unifi_mfa_secret, unifi_api_key, unifi_api_key_header, nb, nb_ubiquity,
                            tenant, netbox_sites_dict, config)
