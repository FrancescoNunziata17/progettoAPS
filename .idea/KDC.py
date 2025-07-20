from cryptography.hazmat.primitives.asymmetric import rsa, padding
from cryptography.hazmat.primitives import serialization, hashes
from cryptography.fernet import Fernet
import base64
import time
import json
import os
from cryptography.hazmat.primitives.kdf.hkdf import HKDF
from cryptography.hazmat.backends import default_backend

class KDC:
    _instance = None
    _initialized_kdc_secrets = False # Renamed for clarity on what this flag controls

    def __new__(cls):
        if cls._instance is None:
            cls._instance = super(KDC, cls).__new__(cls)
        return cls._instance

    def __init__(self):
        # Always initialize user_public_keys for the current instance
        # This needs to be available even if secrets are loaded/already initialized
        self.user_public_keys = {}

        if not KDC._initialized_kdc_secrets:
            # Load or generate KDC's private key
            try:
                with open('kdc_private.pem', 'rb') as f:
                    private_key_data = f.read()
                    self.private_key = serialization.load_pem_private_key(
                        private_key_data,
                        password=None
                    )
            except FileNotFoundError:
                self.private_key = rsa.generate_private_key(
                    public_exponent=65537,
                    key_size=2048,
                    backend=default_backend()
                )
                with open('kdc_private.pem', 'wb') as f:
                    f.write(self.private_key.private_bytes(
                        encoding=serialization.Encoding.PEM,
                        format=serialization.PrivateFormat.PKCS8,
                        encryption_algorithm=serialization.NoEncryption()
                    ))
            self.public_key = self.private_key.public_key()

            # Load or generate KDC's master secret
            try:
                with open('kdc_master_secret.key', 'rb') as f:
                    self.master_secret = f.read()
                print("DEBUG (KDC): Master secret caricato da kdc_master_secret.key")
            except FileNotFoundError:
                self.master_secret = os.urandom(32)
                with open('kdc_master_secret.key', 'wb') as f:
                    f.write(self.master_secret)
                print("DEBUG (KDC): Nuovo master secret generato e salvato in kdc_master_secret.key")

            KDC._initialized_kdc_secrets = True
            print("DEBUG (KDC): KDC secrets initialized.")

        # If the KDC is re-instantiated (e.g., in a new run),
        # but the secrets are already loaded, we still want to indicate init.
        # This ensures private_key and public_key are set on the instance even if the _initialized_kdc_secrets was already True
        if KDC._initialized_kdc_secrets and not hasattr(self, 'private_key'):
            try:
                with open('kdc_private.pem', 'rb') as f:
                    private_key_data = f.read()
                    self.private_key = serialization.load_pem_private_key(
                        private_key_data,
                        password=None
                    )
                self.public_key = self.private_key.public_key()
            except FileNotFoundError:
                # Should not happen if _initialized_kdc_secrets is True and private.pem was created
                pass

        print("DEBUG (KDC): KDC object fully initialized for this instance.")


    def _derive_session_key_bytes(self, client_id, server_id):
        info = f"{client_id}-{server_id}".encode('utf-8')

        hkdf = HKDF(
            algorithm=hashes.SHA256(),
            length=32,
            salt=None,
            info=info,
            backend=default_backend()
        )
        derived_key_bytes = hkdf.derive(self.master_secret)
        return derived_key_bytes

    def register_user(self, user_id, user_public_key):
        self.user_public_keys[user_id] = user_public_key

    def request_session(self, client_id, server_id, client_nonce):
        if client_id not in self.user_public_keys:
            raise ValueError("Client non registrato")

        session_key_raw_bytes = self._derive_session_key_bytes(client_id, server_id)

        ticket = {
            'client_id': client_id,
            'server_id': server_id,
            'timestamp': int(time.time()),
            'lifetime': 3600
        }

        ticket_signature = self.private_key.sign(
            json.dumps(ticket).encode(),
            padding.PSS(
                mgf=padding.MGF1(hashes.SHA256()),
                salt_length=padding.PSS.MAX_LENGTH
            ),
            hashes.SHA256()
        )

        client_public_key = self.user_public_keys[client_id]

        encrypted_session_key_for_client = client_public_key.encrypt(
            session_key_raw_bytes,
            padding.OAEP(
                mgf=padding.MGF1(algorithm=hashes.SHA256()),
                algorithm=hashes.SHA256(),
                label=None
            )
        )

        return {
            'encrypted_session_key': base64.b64encode(encrypted_session_key_for_client).decode('ascii'),
            'ticket': {
                'data': ticket,
                'signature': base64.b64encode(ticket_signature).decode('ascii')
            }
        }

    def verify_ticket(self, ticket_data, ticket_signature):
        try:
            signature = base64.b64decode(ticket_signature)

            self.public_key.verify(
                signature,
                json.dumps(ticket_data).encode(),
                padding.PSS(
                    mgf=padding.MGF1(hashes.SHA256()),
                    salt_length=padding.PSS.MAX_LENGTH
                ),
                hashes.SHA256()
            )

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
        self.private_key = None
        self.public_key = None

    def request_service(self, kdc, server_id):
        if self.private_key is None or self.public_key is None:
            raise ValueError("Chiavi del client non inizializzate. Caricare o generare prima.")

        nonce = os.urandom(16)

        response = kdc.request_session(self.client_id, server_id, nonce)

        encrypted_session_key_from_kdc = base64.b64decode(response['encrypted_session_key'])

        session_key_decrypted_bytes = self.private_key.decrypt(
            encrypted_session_key_from_kdc,
            padding.OAEP(
                mgf=padding.MGF1(algorithm=hashes.SHA256()),
                algorithm=hashes.SHA256(),
                label=None
            )
        )
        fernet_obj = Fernet(base64.urlsafe_b64encode(session_key_decrypted_bytes))

        return fernet_obj, response['ticket']

class Server:
    def __init__(self, server_id):
        self.server_id = server_id

    def handle_client_request(self, kdc, ticket_data, ticket_signature):
        if kdc.verify_ticket(ticket_data, ticket_signature):
            derived_key_raw_bytes = kdc._derive_session_key_bytes(ticket_data['client_id'], ticket_data['server_id'])
            fernet_session_key_obj = Fernet(base64.urlsafe_b64encode(derived_key_raw_bytes))
            return True, fernet_session_key_obj
        return False, None