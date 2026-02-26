# filepath: unifi/vm.py
from .resources import BaseResource

class VirtualMachine(BaseResource):
    endpoint = "/api/v2.1/vms"  

    def normalize(self, data):
        """Normalize VM data for internal use."""
        return {
            "id": data["id"],
            "name": data["name"],
            "cpu": data["cpu"],
            "memory": data["memory"],
            "status": data["status"],
        }