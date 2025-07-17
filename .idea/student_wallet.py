import json
from credential import AcademicCredential
from merkle_tree import MerkleTree # Necessario per generare le prove
import os

class StudentWallet:
    """
    Simula il wallet di uno studente per conservare e presentare credenziali.
    """
    def __init__(self, student_id: str, storage_file: str = "FileFolder\\Unisa_credential.json", wallet_file: str = "FileFolder\\student_wallet.json"):
        self.student_id = student_id
        # Potresti voler cifrare queste credenziali in un'applicazione reale
        self.credentials = {} # {'credential_id': AcademicCredential_object}
        self.storage_file = storage_file
        self.wallet_file = wallet_file
        self._load_credentials()
        self._save_credentials()

    def _load_credentials(self):
        """Carica le credenziali dal file di storage."""
        try:
            with open(self.storage_file, 'r') as f:
                data = json.load(f)
                for cred_json in data.get("credentials", []):
                    cred = AcademicCredential.from_json(json.dumps(cred_json))
                    if cred.holder["id"] == self.student_id: # Assicurati che la credenziale sia per questo studente
                        self.credentials[cred.id] = cred
        except FileNotFoundError:
            pass # Il wallet è vuoto inizialmente
        except json.JSONDecodeError:
            print(f"Attenzione: Errore di decodifica JSON nel file del wallet {self.storage_file}.")
            self.credentials = {}

    def _save_credentials(self):
        """Salva le credenziali nel file di storage."""
        with open(self.wallet_file, 'w') as f:
            json.dump({"credentials": [cred.to_dict() for cred in self.credentials.values()]}, f, indent=2)

    def add_credential(self, credential: AcademicCredential):
        """Aggiunge una nuova credenziale al wallet."""
        if credential.holder["id"] != self.student_id:
            raise ValueError("La credenziale non è destinata a questo studente.")
        self.credentials[credential.id] = credential
        self._save_credentials()
        print(f"Credenziale '{credential.id}' aggiunta al wallet di {self.student_id}.")

    def get_credential(self, credential_id: str) -> AcademicCredential:
        """Recupera una credenziale dal wallet."""
        return self.credentials.get(credential_id)

    def print_credentials(self):
        """Visualizza tutte le credenziali presenti nel wallet dello studente."""
        print("\n--- Elenco delle Credenziali nel Wallet ---")
        tutte_le_credenziali = self.credentials  # Recupera tutte le credenziali dal wallet

        if not tutte_le_credenziali:
            print("Il wallet è vuoto. Nessuna credenziale disponibile.")
            return

        for idx, credenziale in enumerate(tutte_le_credenziali, start=1):
            print(f"\nCredenziale #{idx}:")
            print(credenziale)

    def generate_selective_presentation(self, credential_id: str, attributes_to_reveal: list) -> dict:
        """
        Genera una presentazione selettiva per una credenziale specificata,
        rivelando solo gli attributi richiesti.
        """
        cred = self.get_credential(credential_id)
        if not cred:
            raise ValueError(f"Credenziale con ID '{credential_id}' non trovata nel wallet.")
        if not cred.proof or "merkleRootHash" not in cred.proof:
            raise ValueError("La credenziale non ha un Merkle Root Hash valido per la presentazione selettiva.")

        selective_presentation = {
            "id": cred.id,
            "issuer": cred.issuer,
            "holder": cred.holder,
            "issuanceDate": cred.issuanceDate,
            "proof": {
                "type": cred.proof["type"],
                "signature": cred.proof["signature"],
                "merkleRootHash": cred.proof["merkleRootHash"],
                "revocationMechanism": cred.proof["revocationMechanism"]
            },
            "disclosedClaims": {},
            "merkleProofs": {}
        }

        # Per generare le prove, ricreiamo il MerkleTree dal subject completo della credenziale
        full_subject_data_items = cred.get_subject_data_for_merkle_tree()
        merkle_tree_for_proof = MerkleTree(full_subject_data_items)

        for attr in attributes_to_reveal:
            if attr in cred.credentialSubject:
                value = cred.credentialSubject[attr]
                selective_presentation["disclosedClaims"][attr] = value

                # Prepara l'elemento dati esatto come viene usato nel Merkle Tree
                data_item_for_proof = json.dumps(value, sort_keys=True) if isinstance(value, (dict, list)) else str(value)
                full_data_item_string = f"{attr}:{data_item_for_proof}"

                proof = merkle_tree_for_proof.generate_proof(full_data_item_string)
                if proof:
                    selective_presentation["merkleProofs"][attr] = proof
                else:
                    print(f"Attenzione: Impossibile generare prova per '{attr}'. Controlla la logica del Merkle Tree.")
            else:
                print(f"Attenzione: L'attributo '{attr}' non trovato nel credentialSubject.")

        return selective_presentation