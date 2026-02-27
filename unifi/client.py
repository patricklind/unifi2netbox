# filepath: unifi/client.py
import logging

# On importe la classe de base que ton projet utilise (probablement BaseResource ou similaire)
# Ajuste cet import selon ce qui est écrit au début de ton fichier unifi/device.py
from .resources import BaseResource 

logger = logging.getLogger(__name__)

class Client(BaseResource):
    """
    Modèle représentant un Client (physique ou VM) connecté au contrôleur UniFi.
    S'inspire de unifi/device.py.
    """
    
    # L'endpoint API d'UniFi pour récupérer les clients actifs/connus
    # Note : Sur les versions très récentes d'UniFi OS, cela peut être '/v2/api/site/{site}/clients/active'
    endpoint = '/api/s/{site}/stat/sta' 

    @property
    def mac(self):
        return self.data.get('mac')

    @property
    def hostname(self):
        # Certains clients n'ont pas de nom défini, on fallback sur le nom ou la MAC
        return self.data.get('hostname') or self.data.get('name') or f"client-{self.mac}"

    @property
    def oui(self):
        # Le constructeur de la carte réseau (ex: "VMware", "Apple", etc.)
        return self.data.get('oui', '')

    @property
    def ip(self):
        return self.data.get('ip')
        
    @property
    def is_guest(self):
        return self.data.get('is_guest', False)

    # Si ton unifi/device.py a une méthode spécifique pour tout lister, tu peux la reproduire ici.
    # Par exemple :
    @classmethod
    def list(cls, unifi_client, site="default"):
        """Récupère la liste des clients depuis l'API UniFi."""
        url = cls.endpoint.format(site=site)
        logger.debug(f"Récupération des clients UniFi via l'endpoint : {url}")
        
        # Adapte la méthode 'get' selon comment ton unifi_client fait ses requêtes
        response = unifi_client.get(url) 
        
        # On retourne une liste d'instances de la classe Client
        return [cls(client_data) for client_data in response.get('data', [])]