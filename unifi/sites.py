import logging
from .portconf import PortConf
from .device import Device
from .radiusprofile import RadiusProfile
from .setting import Setting
from .networkconf import NetworkConf
from .wlanconf import WlanConf
from .usergroup import UserGroup
from .apgroups import ApGroups
logger = logging.getLogger(__name__)

class Sites:

    def __init__(self, unifi, data):
        """
        :param unifi: Unifi instance
        :param data: Dictionary with site data (name, description, etc.)
        """

        self.unifi = unifi
        # Legacy API: name=<site-code>, desc=<display-name>, _id=<object-id>
        # Integration v1: id=<uuid>, internalReference=<site-code>, name=<display-name>
        self._id = data.get("_id") or data.get("id")
        self.internal_reference = data.get("internalReference")
        self.desc = data.get("desc") or data.get("name") or self.internal_reference
        self.name: str = data.get("name") or data.get("desc") or self.internal_reference or str(self._id)
        self.api_id = data.get("id") or data.get("name") or self.internal_reference

        # Initialize resource classes
        self.port_conf = PortConf(self.unifi, self)
        self.device = Device(self.unifi, self)
        self.radius_profile = RadiusProfile(self.unifi, self)
        self.setting = Setting(self.unifi, self)
        self.network_conf = NetworkConf(self.unifi, self)
        self.wlan_conf = WlanConf(self.unifi, self)
        self.user_group = UserGroup(self.unifi, self)
        self.ap_groups = ApGroups(self.unifi, self)

    def __str__(self):
        return f"{self.__class__.__name__}: {self.desc}"

    def __repr__(self):
        return f"<Site(name={self.name}, desc={self.desc})>"

    def __eq__(self, other):
        return self._id == other._id
