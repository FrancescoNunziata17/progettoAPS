from cryptography.hazmat.primitives.asymmetric import rsa, padding
from cryptography.hazmat.primitives import serialization, hashes
from cryptography.fernet import Fernet
import base64
import time
import json

class KDC:
    def __init__(self):
        # Chiave privata del KDC per firmare i ticket
        self.private_key = rsa.generate_private_key(
            public_exponent=65537,
            key_size=2048
        )
        self.public_key = self.private_key.public_key()

        # Dizionario per memorizzare le chiavi pubbliche degli utenti
        self.user_public_keys = {}

        # Dizionario per le chiavi di sessione
        self.session_keys = {}

    def register_user(self, user_id, user_public_key):
        """Registra la chiave pubblica di un utente"""
        self.user_public_keys[user_id] = user_public_key

    def request_session(self, client_id, server_id, client_nonce):
        """
        Step 1: Il client richiede un ticket per comunicare con il server
        Restituisce: (session_key, ticket_per_server)
        """
        if client_id not in self.user_public_keys:
            raise ValueError("Client non registrato")

        # Genera chiave di sessione
        session_key = Fernet.generate_key()

        # Crea il ticket per il server
        ticket = {
            'client_id': client_id,
            'server_id': server_id,
            'session_key': session_key.decode(),
            'timestamp': int(time.time()),
            'lifetime': 3600  # validità 1 ora
        }

        # Firma il ticket con la chiave privata del KDC
        ticket_signature = self.private_key.sign(
            json.dumps(ticket).encode(),
            padding.PSS(
                mgf=padding.MGF1(hashes.SHA256()),
                salt_length=padding.PSS.MAX_LENGTH
            ),
            hashes.SHA256()
        )

        # Cifra la chiave di sessione con la chiave pubblica del client
        client_public_key = self.user_public_keys[client_id]
        encrypted_session_key = client_public_key.encrypt(
            session_key,
            padding.OAEP(
                mgf=padding.MGF1(algorithm=hashes.SHA256()),
                algorithm=hashes.SHA256(),
                label=None
            )
        )

        return {
            'encrypted_session_key': base64.b64encode(encrypted_session_key).decode(),
            'ticket': {
                'data': ticket,
                'signature': base64.b64encode(ticket_signature).decode()
            }
        }

    def verify_ticket(self, ticket_data, ticket_signature):
        """Verifica la validità di un ticket"""
        try:
            # Decodifica la firma
            signature = base64.b64decode(ticket_signature)

            # Verifica la firma
            self.public_key.verify(
                signature,
                json.dumps(ticket_data).encode(),
                padding.PSS(
                    mgf=padding.MGF1(hashes.SHA256()),
                    salt_length=padding.PSS.MAX_LENGTH
                ),
                hashes.SHA256()
            )

            # Verifica la validità temporale
            current_time = int(time.time())
            if current_time > ticket_data['timestamp'] + ticket_data['lifetime']:
                raise ValueError("Ticket scaduto")

            return True

        except Exception as e:
            print(f"Errore nella verifica del ticket: {e}")
            return False

class Client:
    def __init__(self, client_id):
        self.client_id = client_id
        self.private_key = rsa.generate_private_key(
            public_exponent=65537,
            key_size=2048
        )
        self.public_key = self.private_key.public_key()

    def request_service(self, kdc, server_id):
        """Richiede un servizio attraverso il KDC"""
        # Genera un nonce
        nonce = os.urandom(16)

        # Richiede un ticket al KDC
        response = kdc.request_session(self.client_id, server_id, nonce)

        # Decifra la chiave di sessione
        encrypted_session_key = base64.b64decode(response['encrypted_session_key'])
        session_key = self.private_key.decrypt(
            encrypted_session_key,
            padding.OAEP(
                mgf=padding.MGF1(algorithm=hashes.SHA256()),
                algorithm=hashes.SHA256(),
                label=None
            )
        )

        return session_key, response['ticket']

class Server:
    def __init__(self, server_id):
        self.server_id = server_id

    def handle_client_request(self, kdc, ticket_data, ticket_signature):
        """Gestisce una richiesta del client verificando il ticket"""
        if kdc.verify_ticket(ticket_data, ticket_signature):
            # Estrae la chiave di sessione dal ticket
            session_key = ticket_data['session_key']
            return True, session_key
        return False, None
