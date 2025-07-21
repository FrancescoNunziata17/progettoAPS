import json
import os
import base64
from cryptography.fernet import Fernet
from cryptography.hazmat.primitives.asymmetric import padding
from cryptography.hazmat.primitives import hashes
from datetime import datetime

# Assicurati che queste funzioni siano correttamente accessibili
from credential import load_private_key, load_public_key

class StudentWallet:
    def __init__(self, student_matricola):
        self.student_matricola = student_matricola
        self.personal_data = {} # Dati personali decifrati
        self.credentials = []   # Credenziali decifrate
        self.wallet_file_path = "" # Verrà impostato in load_student_data_and_credentials

    def _get_wallet_path(self, student_email):
        # Usiamo una cartella 'wallets' per i file dei wallet degli studenti
        # per distinguerli dai file delle credenziali emesse dall'università in 'FileFolder'.
        os.makedirs("wallets", exist_ok=True)
        return os.path.join("wallets", f"{student_email}_wallet.json")

    def load_student_data_and_credentials(self, student_email, password):
        """
        Carica i dati personali e le credenziali dello studente.
        Se il wallet non esiste o è corrotto, li decifra da users.json e li salva nel wallet.
        """
        self.wallet_file_path = self._get_wallet_path(student_email)

        # 1. Tenta di caricare dal wallet file esistente
        if os.path.exists(self.wallet_file_path):
            try:
                with open(self.wallet_file_path, 'r') as f:
                    wallet_data = json.load(f)
                    self.personal_data = wallet_data.get('personal_data', {})
                    self.credentials = wallet_data.get('credentials', [])
                    # Se la matricola nel wallet caricato è diversa da quella inizializzata, aggiorna
                    if self.student_matricola == "" and self.personal_data.get('matricola'):
                        self.student_matricola = self.personal_data.get('matricola')

                    print(f"DEBUG (StudentWallet): Dati caricati dal wallet esistente: {self.wallet_file_path}")
                    return True
            except json.JSONDecodeError as e:
                print(f"ERRORE (StudentWallet): File wallet {self.wallet_file_path} corrotto o malformato: {e}. Tentativo di rigenerare da users.json.")
                # Continua per tentare di rigenerare dal users.json
            except Exception as e:
                print(f"ERRORE (StudentWallet): Errore durante il caricamento del wallet {self.wallet_file_path}: {e}. Tentativo di rigenerare da users.json.")
                # Continua per tentare di rigenerare dal users.json

        print(f"DEBUG (StudentWallet): Wallet {self.wallet_file_path} non trovato o corrotto. Tentativo di decifrare da users.json.")

        # 2. Se il wallet non esiste o è corrotto, decifra da users.json
        user_data_from_json = None
        try:
            with open("users.json", "r") as f:
                for line in f:
                    user = json.loads(line)
                    if user.get("email") == student_email and user.get("role") == "s":
                        user_data_from_json = user
                        break
        except FileNotFoundError:
            print("ERRORE (StudentWallet): File users.json non trovato.")
            return False
        except json.JSONDecodeError as e:
            print(f"ERRORE (StudentWallet): File users.json malformato: {e}")
            return False

        if not user_data_from_json:
            print(f"ERRORE (StudentWallet): Dati studente {student_email} non trovati in users.json.")
            return False

        try:
            private_key = load_private_key(student_email, password)
            if private_key is None:
                raise ValueError(f"Impossibile caricare la chiave privata per {student_email}.")

            # Decifra la chiave Fernet usando la chiave privata RSA dello studente
            encrypted_fernet_key_hex = user_data_from_json["personal_data_encrypted"]["encrypted_fernet_key"]
            encrypted_fernet_key_bytes = bytes.fromhex(encrypted_fernet_key_hex)

            personal_data_fernet_key = private_key.decrypt(
                encrypted_fernet_key_bytes,
                padding.OAEP(
                    mgf=padding.MGF1(hashes.SHA256()),
                    algorithm=hashes.SHA256(),
                    label=None
                )
            )
            fernet_personal_data = Fernet(personal_data_fernet_key)
            print("DEBUG (StudentWallet): Chiave Fernet per dati personali decifrata con successo.")

            # Decifra i dati personali usando la chiave Fernet
            self.personal_data = {
                "email": student_email, # Aggiungiamo l'email qui per coerenza
                "matricola": fernet_personal_data.decrypt(base64.urlsafe_b64decode(user_data_from_json["personal_data_encrypted"]["matricola"])).decode('utf-8'),
                "nome": fernet_personal_data.decrypt(base64.urlsafe_b64decode(user_data_from_json["personal_data_encrypted"]["nome"])).decode('utf-8'),
                "cognome": fernet_personal_data.decrypt(base64.urlsafe_b64decode(user_data_from_json["personal_data_encrypted"]["cognome"])).decode('utf-8'),
                "data_nascita": fernet_personal_data.decrypt(base64.urlsafe_b64decode(user_data_from_json["personal_data_encrypted"]["data_nascita"])).decode('utf-8'),
                "corso_di_laurea": fernet_personal_data.decrypt(base64.urlsafe_b64decode(user_data_from_json["personal_data_encrypted"]["corso_di_laurea"])).decode('utf-8')
            }
            # Aggiorna la matricola interna del wallet
            self.student_matricola = self.personal_data["matricola"]
            print(f"DEBUG (StudentWallet): Dati personali decifrati e caricati per {student_email}.")

            # 3. Salva i dati decifrati nel file wallet
            self.save_wallet_to_file()
            return True

        except Exception as e:
            print(f"ERRORE (StudentWallet): Errore durante la decifratura o il salvataggio del wallet per {student_email}: {e}")
            return False

    def save_wallet_to_file(self):
        """Salva i dati correnti del wallet nel file."""
        try:
            with open(self.wallet_file_path, 'w') as f:
                json.dump({
                    'personal_data': self.personal_data,
                    'credentials': self.credentials
                }, f, indent=2)
            print(f"DEBUG (StudentWallet): Wallet salvato in: {self.wallet_file_path}")
        except Exception as e:
            print(f"ERRORE (StudentWallet): Impossibile salvare il wallet in {self.wallet_file_path}: {e}")

    def display_personal_data(self):
        """Visualizza i dati personali dello studente."""
        print("\n--- Dati Personali ---")
        if self.personal_data:
            for key, value in self.personal_data.items():
                print(f"{key.replace('_', ' ').capitalize()}: {value}")
        else:
            print("Nessun dato personale disponibile. Assicurati di aver effettuato l'accesso.")

    def display_credentials(self):
        """Visualizza le credenziali dello studente."""
        print("\n--- Credenziali ---")
        if self.credentials:
            for cred in self.credentials:
                print(f"ID Credenziale: {cred.get('id', 'N/A')}")
                print(f"  Emittente: {cred.get('issuer_id', 'N/A')}")
                print(f"  Titolare (Matricola): {cred.get('holder', {}).get('id', 'N/A')}")

                # Il credential_subject dovrebbe essere già decifrato da retrieve_and_add_credentials_to_wallet
                subject = cred.get('credential_subject', {})
                if isinstance(subject, dict):
                    print(f"  Soggetto:")
                    for sub_key, sub_value in subject.items():
                        print(f"    {sub_key}: {sub_value}")
                else:
                    print(f"  Soggetto: {subject}") # Nel caso fosse una stringa o altro
                print(f"  Data Emissione: {cred.get('issuance_date', 'N/A')}")
                print("-" * 20)
        else:
            print("Nessuna credenziale disponibile.")

    def add_credential(self, credential_dict):
        """Aggiunge una nuova credenziale al wallet."""
        # Aggiungo un controllo per evitare duplicati basato sull'ID della credenziale
        if not any(c.get('id') == credential_dict.get('id') for c in self.credentials):
            self.credentials.append(credential_dict)
            print(f"DEBUG (StudentWallet): Credenziale {credential_dict.get('id')} aggiunta al wallet.")
        else:
            print(f"DEBUG (StudentWallet): Credenziale {credential_dict.get('id')} già presente. Non aggiunta.")
        # Il salvataggio deve avvenire esplicitamente dopo l'aggiunta (gestito nel main)

    def generate_selective_presentation(self, credential_id, attributes_to_reveal):
        """
        Genera una presentazione selettiva di una credenziale.
        Gli attributi sono già decifrati nel wallet.
        """
        target_credential = None
        for cred in self.credentials:
            if cred.get('id') == credential_id:
                target_credential = cred
                break

        if not target_credential:
            raise ValueError(f"Credenziale con ID '{credential_id}' non trovata nel wallet.")

        original_subject = target_credential.get('credentialSubject', {})
        print(f"DEBUG (StudentWallet): Soggetto della credenziale {credential_id}: {original_subject}")
        if not isinstance(original_subject, dict):
            raise ValueError("Il soggetto della credenziale non è un dizionario valido.")

        revealed_attributes = {}
        for attr in attributes_to_reveal:
            if attr in original_subject:
                revealed_attributes[attr] = original_subject[attr]
            else:
                print(f"AVVISO: Attributo '{attr}' non trovato nel soggetto della credenziale {credential_id}.")

        # Crea una nuova credenziale parziale per la presentazione
        selective_presentation = {
            "id": f"presentation:{credential_id}",
            "type": ["VerifiablePresentation", "SelectiveDisclosure"],
            "issuer": target_credential.get("issuer"),
            "issuance_date": datetime.now().isoformat(),
            "expirationDate" : target_credential.get("expirationDate"),
            "holder": target_credential.get("holder"),
            "credentialSubject": {
                "encrypted_data" : revealed_attributes,
                "encrypted_fernet_key" : None,
            },
            "original_credential_id": credential_id,
            "proof": target_credential.get("proof"),
        }

        print(f"DEBUG (StudentWallet): Presentazione selettiva generata per {credential_id}.")
        return selective_presentation