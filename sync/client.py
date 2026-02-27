# filepath: sync/client.py
import os
import logging

# Initialisation du logger comme dans le reste du projet (ex: sites.py)
logger = logging.getLogger(__name__)

# Variables d'environnement pour activer/désactiver les synchronisations
SYNC_VMS = os.getenv("SYNC_VMS", "False").lower() in ("true", "1", "yes")
SYNC_DEVICES = os.getenv("SYNC_DEVICES", "True").lower() in ("true", "1", "yes")

# Liste des constructeurs (OUI) qui identifient les machines virtuelles
VM_MAC_VENDORS = ["vmware", "microsoft corporation", "xen", "qemu", "proxmox", "xensource", "oracle"]

def sync_unifi_clients_to_netbox(netbox_api, unifi_clients, site_id, cluster_id, device_role_id, device_type_id):
    """
    Parcourt les clients UniFi et les dispatche entre Devices (Physique) et VMs (Virtuel) dans NetBox.
    """
    logger.info(f"Configuration : Sync VMs = {SYNC_VMS} | Sync Devices = {SYNC_DEVICES}")
    
    for client in unifi_clients:
        # On utilise les propriétés de l'objet Client tel que défini dans unifi/client.py
        mac_address = client.mac
        hostname = client.hostname
        vendor = client.oui.lower() if client.oui else ""
        ip_address = client.ip
        
        is_vm = any(vm_vendor in vendor for vm_vendor in VM_MAC_VENDORS)

        if is_vm:
            if SYNC_VMS:
                logger.debug(f"[VM détectée] {hostname} ({vendor}) -> Virtual Machines")
                sync_virtual_machine(netbox_api, hostname, mac_address, ip_address, cluster_id)
            else:
                logger.debug(f"[VM ignorée] {hostname} ({vendor}) -> SYNC_VMS est désactivé.")
        else:
            if SYNC_DEVICES:
                logger.debug(f"[Device physique détecté] {hostname} ({vendor}) -> Devices")
                sync_physical_device(netbox_api, hostname, mac_address, ip_address, site_id, device_role_id, device_type_id)
            else:
                logger.debug(f"[Device physique ignoré] {hostname} ({vendor}) -> SYNC_DEVICES est désactivé.")

def sync_physical_device(netbox, name, mac, ip, site_id, role_id, type_id):
    """Crée ou met à jour un équipement physique dans NetBox."""
    existing_device = netbox.dcim.devices.get(name=name)
    
    device_data = {
        "name": name,
        "site": site_id,
        "device_role": role_id,
        "device_type": type_id,
        "status": "active",
    }
    
    if existing_device:
        existing_device.update(device_data)
        device_obj = existing_device
        logger.debug(f"Device mis à jour : {name}")
    else:
        device_obj = netbox.dcim.devices.create(device_data)
        logger.info(f"Device créé : {name}")
        
    sync_interface(netbox, device_obj.id, mac, ip, is_vm=False)

def sync_virtual_machine(netbox, name, mac, ip, cluster_id):
    """Crée ou met à jour une machine virtuelle dans NetBox."""
    existing_vm = netbox.virtualization.virtual_machines.get(name=name)
    
    vm_data = {
        "name": name,
        "cluster": cluster_id,
        "status": "active",
    }
    
    if existing_vm:
        existing_vm.update(vm_data)
        vm_obj = existing_vm
        logger.debug(f"VM mise à jour : {name}")
    else:
        vm_obj = netbox.virtualization.virtual_machines.create(vm_data)
        logger.info(f"VM créée : {name}")
        
    sync_interface(netbox, vm_obj.id, mac, ip, is_vm=True)

def sync_interface(netbox, parent_id, mac, ip, is_vm):
    """Crée l'interface réseau et lui assigne l'adresse IP si disponible."""
    interface_name = "eth0" # Nom générique
    
    # 1. Création / Mise à jour de l'interface
    if is_vm:
        existing_iface = netbox.virtualization.interfaces.get(virtual_machine_id=parent_id, name=interface_name)
        iface_data = {"virtual_machine": parent_id, "name": interface_name, "mac_address": mac}
        if existing_iface:
            existing_iface.update(iface_data)
            interface_obj = existing_iface
        else:
            interface_obj = netbox.virtualization.interfaces.create(iface_data)
    else:
        existing_iface = netbox.dcim.interfaces.get(device_id=parent_id, name=interface_name)
        iface_data = {"device": parent_id, "name": interface_name, "mac_address": mac, "type": "other"}
        if existing_iface:
            existing_iface.update(iface_data)
            interface_obj = existing_iface
        else