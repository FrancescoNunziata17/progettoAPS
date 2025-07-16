import json
import hashlib
from datetime import datetime, timezone

from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.primitives.asymmetric import rsa, padding
from cryptography.hazmat.primitives import serialization
from cryptography.exceptions import InvalidSignature

# Importa la classe MerkleTree dal file merkle_tree.py (che definiremo dopo)
# Assicurati che merkle_tree.py sia nella stessa directory o nel PYTHONPATH
from merkle_tree import MerkleTree

class AcademicCredential:
    """
    Rappresenta una credenziale accademica digitale secondo la struttura definita in WP1.
    Gestisce la creazione, la firma digitale e la verifica della credenziale.
    """
    def __init__(self, id: str, issuer_id: str, holder_id: str, credential_subject: dict, issuance_date: str = None, expiration_date: str = None):
        self.id = id
        self.type = ["VerifiableCredential", "AcademicCredential"]
        self.issuer = {"id": issuer_id}
        self.holder = {"id": holder_id}
        self.credentialSubject = credential_subject

        # Se le date non sono fornite, usa la data e ora UTC correnti
        self.issuanceDate = issuance_date if issuance_date else datetime.now(timezone.utc).isoformat()
        self.expirationDate = expiration_date

        # Il campo proof verrà riempito dopo la firma e la costruzione del Merkle Tree
        self.proof = {}

    def get_subject_data_for_merkle_tree(self) -> list:
        """
        Prepara i dati del credentialSubject per la costruzione del Merkle Tree.
        Ogni attributo del subject (e il suo valore) diventa un'istanza di dato.
        Es: ['nome:Mario', 'cognome:Rossi', 'corso:Ingegneria']
        """
        data = []
        for key, value in self.credentialSubject.items():
            # Converti anche valori complessi in stringhe JSON per coerenza
            if isinstance(value, (dict, list)):
                data.append(f"{key}:{json.dumps(value, sort_keys=True)}")
            else:
                data.append(f"{key}:{value}")
        # Ordina per garantire una costruzione Merkle Tree deterministica
        return sorted(data)

    def generate_merkle_root(self):
        """
        Genera il Merkle Root Hash dal credentialSubject.
        """
        subject_data = self.get_subject_data_for_merkle_tree()
        merkle_tree = MerkleTree(subject_data)
        return merkle_tree.get_root()

    def get_credential_hash_for_signing(self, merkle_root_hash: str, revocation_reference: str) -> bytes:
        """
        Prepara l'hash dei dati essenziali della credenziale per la firma.
        Secondo WP1, la firma si applica all'hash della radice Merkle e ad altri campi.
        """
        # Utilizziamo un dizionario ordinato per garantire un hash deterministico
        data_to_hash = {
            "id": self.id,
            "issuer_id": self.issuer["id"],
            "holder_id": self.holder["id"],
            "issuanceDate": self.issuanceDate,
            "merkleRootHash": merkle_root_hash,
            "revocationReference": revocation_reference
        }
        # Converti in stringa JSON ordinata per garantire un hash consistente
        json_string = json.dumps(data_to_hash, sort_keys=True).encode('utf-8')
        return hashlib.sha256(json_string).digest()

    def sign(self, private_key: rsa.RSAPrivateKey, revocation_reference: str):
        """
        Firma digitalmente la credenziale.
        Il `revocation_reference` è il riferimento al meccanismo di revoca (es. un ID o hash).
        """
        merkle_root_hash = self.generate_merkle_root()
        data_to_sign_hash = self.get_credential_hash_for_signing(merkle_root_hash, revocation_reference)

        signature = private_key.sign(
            data_to_sign_hash,
            padding.PSS(
                mgf=padding.MGF1(hashes.SHA256()),
                salt_length=padding.PSS.MAX_LENGTH
            ),
            hashes.SHA256()
        )

        self.proof = {
            "type": "DataIntegrityProof",
            "signature": signature.hex(), # Archivia la firma come stringa esadecimale
            "merkleRootHash": merkle_root_hash,
            "revocationMechanism": {
                "type": "BlockchainRevocationList", # O un altro tipo di meccanismo
                "reference": revocation_reference
            }
        }

    def verify_signature(self, public_key: rsa.RSAPublicKey) -> bool:
        """
        Verifica la firma digitale della credenziale.
        """
        if not self.proof or "signature" not in self.proof or "merkleRootHash" not in self.proof:
            return False

        try:
            signature = bytes.fromhex(self.proof["signature"])
            merkle_root_hash = self.proof["merkleRootHash"]
            revocation_reference = self.proof["revocationMechanism"]["reference"]

            data_to_verify_hash = self.get_credential_hash_for_signing(merkle_root_hash, revocation_reference)

            public_key.verify(
                signature,
                data_to_verify_hash,
                padding.PSS(
                    mgf=padding.MGF1(hashes.SHA256()),
                    salt_length=padding.PSS.MAX_LENGTH
                ),
                hashes.SHA256()
            )
            return True
        except InvalidSignature:
            return False
        except Exception as e:
            print(f"Errore durante la verifica della firma: {e}")
            return False

    def to_dict(self) -> dict:
        """Converte l'oggetto credenziale in un dizionario Python."""
        return {
            "@context": ["https://www.w3.org/2018/credentials/v1", "https://example.org/credentials/v2"], # Esempio di contesto
            "id": self.id,
            "type": self.type,
            "issuer": self.issuer,
            "issuanceDate": self.issuanceDate,
            "expirationDate": self.expirationDate,
            "holder": self.holder,
            "credentialSubject": self.credentialSubject,
            "proof": self.proof
        }

    def to_json(self) -> str:
        """Converte l'oggetto credenziale in una stringa JSON."""
        return json.dumps(self.to_dict(), indent=2, sort_keys=False) # sort_keys=False per non modificare l'ordine dei campi rispetto alla loro definizione.

    @classmethod
    def from_json(cls, json_string: str):
        """Crea un'istanza di AcademicCredential da una stringa JSON."""
        data = json.loads(json_string)
        # Ricostruisci l'oggetto, assicurandoti di passare solo i parametri del costruttore
        credential = cls(
            id=data["id"],
            issuer_id=data["issuer"]["id"],
            holder_id=data["holder"]["id"],
            credential_subject=data["credentialSubject"],
            issuance_date=data.get("issuanceDate"),
            expiration_date=data.get("expirationDate")
        )
        # Reimposta il campo proof che non viene passato al costruttore
        credential.proof = data.get("proof", {})
        return credential

# Funzioni per la gestione delle chiavi (per l'università emittente)
def generate_key_pair():
    """Genera una nuova coppia di chiavi RSA."""
    private_key = rsa.generate_private_key(
        public_exponent=65537,
        key_size=2048
    )
    public_key = private_key.public_key()
    return private_key, public_key

def save_private_key(private_key: rsa.RSAPrivateKey, filename: str, password: str = None):
    """Salva la chiave privata su file (cifrata opzionalmente con password)."""
    encryption_algorithm = serialization.BestAvailableEncryption(password.encode()) if password else serialization.NoEncryption()
    with open(filename, "wb") as f:
        f.write(private_key.private_bytes(
            encoding=serialization.Encoding.PEM,
            format=serialization.PrivateFormat.PKCS8,
            encryption_algorithm=encryption_algorithm
        ))

def load_private_key(filename: str, password: str = None) -> rsa.RSAPrivateKey:
    """Carica una chiave privata da file."""
    with open(filename, "rb") as f:
        private_key = serialization.load_pem_private_key(
            f.read(),
            password=password.encode() if password else None
        )
    return private_key

def save_public_key(public_key: rsa.RSAPublicKey, filename: str):
    """Salva la chiave pubblica su file."""
    with open(filename, "wb") as f:
        f.write(public_key.public_bytes(
            encoding=serialization.Encoding.PEM,
            format=serialization.PublicFormat.SubjectPublicKeyInfo
        ))

def load_public_key(filename: str) -> rsa.RSAPublicKey:
    """Carica una chiave pubblica da file."""
    with open(filename, "rb") as f:
        public_key = serialization.load_pem_public_key(f.read())
    return public_key