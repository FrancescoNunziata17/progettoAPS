import json
from credential import AcademicCredential
from merkle_tree import MerkleTree # Necessario per generare le prove
import os
from cryptography.fernet import Fernet

class StudentWallet:
    def __init__(self, student_id):
        self.student_id = student_id
        self.credentials = {}  # ID -> Credenziale
        self.personal_data = None  # Per i dati personali decifrati
        self.client = None  # Client per KDC, inizializzato durante il recupero dati

    def initialize_kdc_client(self, email, password_hash):
        """Inizializza il client KDC con le credenziali dell'utente"""
        try:
            self.client = Client(email)
            # Carica la chiave privata del client
            with open(f"keys/{email}_private.pem", "rb") as f:
                private_key_data = f.read()
                self.client.private_key = serialization.load_pem_private_key(
                    private_key_data,
                    password=password_hash.encode()  # Usa l'hash della password
                )
            self.client.public_key = self.client.private_key.public_key()
            return True
        except Exception as e:
            print(f"Errore nell'inizializzazione del client KDC: {str(e)}")
            return False

    def fetch_encrypted_data(self, email, password_hash):
        """Recupera e decifra i dati personali e le credenziali usando KDC"""
        if not self.initialize_kdc_client(email, password_hash):
            return False

        try:
            # Ottieni istanza KDC
            kdc = KDC()

            # Registra il client
            kdc.register_user(email, self.client.public_key)

            # Richiedi una sessione
            server_id = "data_retrieval_server"
            session_key, ticket = self.client.request_service(kdc, server_id)

            # Verifica il ticket con un server
            data_server = Server(server_id)
            success, server_session_key = data_server.handle_client_request(
                kdc,
                ticket['data'],
                ticket['signature']
            )

            if not success:
                raise ValueError("Errore nella verifica del ticket")

            # Usa Fernet per decifrare i dati
            f = Fernet(session_key)

            # Recupera i dati cifrati e le credenziali
            with open("Uni_credential.json", "r") as file:
                for line in file:
                    credential = json.loads(line)
                    if credential["holder"]["id"] == email:
                        # Decifra i dati personali
                        self.personal_data = {
                            "nome": f.decrypt(base64.b64decode(user["nome"]["encrypted_data"])).decode(),
                            "cognome": f.decrypt(base64.b64decode(user["cognome"]["encrypted_data"])).decode(),
                            "data_nascita": f.decrypt(base64.b64decode(user["data_nascita"]["encrypted_data"])).decode(),
                            "matricola": f.decrypt(base64.b64decode(user["student_id"]["encrypted_data"])).decode()
                        }

                        # Recupera e decifra le credenziali accademiche
                        if "academic_credentials" in user:
                            for encrypted_cred in user["academic_credentials"]:
                                decrypted_cred_data = f.decrypt(base64.b64decode(encrypted_cred["encrypted_data"])).decode()
                                cred_data = json.loads(decrypted_cred_data)

                                # Crea l'oggetto AcademicCredential
                                credential = AcademicCredential(
                                    id=cred_data["id"],
                                    issuer_id=cred_data["issuer_id"],
                                    holder_id=self.student_id,
                                    credential_subject={
                                        "studentId": cred_data["studentId"],
                                        "firstName": cred_data["firstName"],
                                        "lastName": cred_data["lastName"],
                                        "dateOfBirth": cred_data["dateOfBirth"],
                                        "courseName": cred_data["courseName"],
                                        "grade": cred_data["grade"],
                                        "ectsCredits": cred_data["ectsCredits"],
                                        "issueSemester": cred_data["issueSemester"],
                                        "courseCompleted": cred_data["courseCompleted"],
                                        "courseDescription": cred_data["courseDescription"]
                                    },
                                    issuance_date=cred_data["issuance_date"]
                                )

                                # Aggiungi la credenziale al wallet
                                self.credentials[credential.id] = credential

                                # Salva le credenziali nel file del wallet
                                self._save_credentials()

                        return True

            return False

        except Exception as e:
            print(f"Errore nel recupero dei dati: {str(e)}")
            return False

    def add_credential(self, credential):
        """Aggiunge una credenziale al wallet"""
        self.credentials[credential.id] = credential

    def print_credentials(self):
        """Mostra tutte le credenziali nel wallet"""
        if self.personal_data:
            print("\nDati Personali:")
            print(f"Nome: {self.personal_data['nome']}")
            print(f"Cognome: {self.personal_data['cognome']}")
            print(f"Data di Nascita: {self.personal_data['data_nascita']}")
            print(f"Matricola: {self.personal_data['matricola']}")

        print("\nCredenziali Accademiche:")
        if not self.credentials:
            print("Nessuna credenziale presente nel wallet.")
            return

        for cred_id, credential in self.credentials.items():
            print(f"\nID Credenziale: {cred_id}")
            print(json.dumps(credential.credential_subject, indent=2))

    def generate_selective_presentation(self, credential_id, attributes_to_reveal):
        """Genera una presentazione selettiva di una credenziale"""
        if credential_id not in self.credentials:
            raise ValueError(f"Credenziale {credential_id} non trovata nel wallet")

        return self.credentials[credential_id].generate_presentation(attributes_to_reveal)