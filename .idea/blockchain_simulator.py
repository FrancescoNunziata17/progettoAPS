import json

class BlockchainSimulator:
    """
    Simula un registro blockchain immutabile per la gestione delle revoche.
    """
    def __init__(self, storage_file="revocation_list.json"):
        self.revoked_credentials = set() # Usiamo un set per l'efficienza nel lookup
        self.storage_file = storage_file
        self._load_from_file() # Carica lo stato precedente se esiste

    def _load_from_file(self):
        """Carica gli ID revocati da un file JSON."""
        try:
            with open(self.storage_file, 'r') as f:
                data = json.load(f)
                self.revoked_credentials = set(data.get("revoked_ids", []))
        except FileNotFoundError:
            pass # Il file non esiste ancora, va bene
        except json.JSONDecodeError:
            print(f"Attenzione: Errore di decodifica JSON nel file {self.storage_file}. Inizio con lista vuota.")
            self.revoked_credentials = set()

    def _save_to_file(self):
        """Salva gli ID revocati su un file JSON."""
        with open(self.storage_file, 'w') as f:
            json.dump({"revoked_ids": list(self.revoked_credentials)}, f, indent=2)

    def revoke_credential(self, credential_id: str) -> bool:
        """
        Aggiunge l'ID di una credenziale alla lista delle credenziali revocate.
        In una blockchain reale, questo sarebbe un'operazione irreversibile.
        """
        if credential_id in self.revoked_credentials:
            return False # Già revocata
        self.revoked_credentials.add(credential_id)
        self._save_to_file()
        print(f"Credenziale '{credential_id}' revocata con successo e aggiunta al registro simulato.")
        return True

    def is_revoked(self, credential_id: str) -> bool:
        """
        Verifica se una credenziale è stata revocata.
        """
        return credential_id in self.revoked_credentials

    def get_revoked_list(self) -> list:
        """Restituisce la lista di tutti gli ID revocati."""
        return list(self.revoked_credentials)