import json
import time
from datetime import datetime, timezone
import hashlib
from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.primitives.asymmetric import rsa, padding
from cryptography.hazmat.primitives import serialization
from cryptography.exceptions import InvalidSignature

# Importa i tuoi moduli
from credential import AcademicCredential, generate_key_pair, save_private_key, load_private_key, save_public_key, load_public_key
from merkle_tree import MerkleTree
from blockchain_simulator import BlockchainSimulator
from student_wallet import StudentWallet
from cryptography.exceptions import InvalidSignature

# --- Configurazione e Inizializzazione ---
print("--- Inizializzazione Sistema ---")

# Inizializza il simulatore di blockchain
blockchain_register = BlockchainSimulator()

# Generazione/Caricamento Chiavi dell'Università Emittente
issuer_private_key_file = "issuer_private_key.pem"
issuer_public_key_file = "issuer_public_key.pem"
issuer_password = "my_strong_password" # Usa una password più robusta in un caso reale

try:
    issuer_private_key = load_private_key(issuer_private_key_file, password=issuer_password)
    issuer_public_key = load_public_key(issuer_public_key_file)
    print("Chiavi dell'emittente caricate.")
except FileNotFoundError:
    print("Chiavi dell'emittente non trovate, generazione di nuove chiavi...")
    issuer_private_key, issuer_public_key = generate_key_pair()
    save_private_key(issuer_private_key, issuer_private_key_file, password=issuer_password)
    save_public_key(issuer_public_key, issuer_public_key_file)
    print("Nuove chiavi dell'emittente generate e salvate.")

# Inizializza il wallet dello studente
student_id = "did:example:studentS12345"
student_wallet = StudentWallet(student_id)
print(f"Wallet dello studente '{student_id}' inizializzato.")

# --- Esempio di Flusso Operativo ---

# 1. Fase: Emissione Credenziale (Università di Rennes)
print("\n--- Fase 1: Emissione Credenziale (Università di Rennes) ---")
credential_id = "urn:vc:example:cred001"
revocation_reference = credential_id # Usiamo l'ID della credenziale come riferimento per la revoca

credential_subject_data = {
    "studentId": "S12345",
    "firstName": "Mario",
    "lastName": "Rossi",
    "dateOfBirth": "2000-01-15",
    "courseName": "Algoritmi e Protocolli per la Sicurezza",
    "grade": "30 cum laude",
    "ectsCredits": 6,
    "issueSemester": "2024-2025/1",
    "courseCompleted": True,
    "courseDescription": "Corso avanzato di sicurezza informatica."
}

start_time = time.perf_counter()
issued_credential = AcademicCredential(
    id=credential_id,
    issuer_id="did:example:universityofrennes",
    holder_id=student_id,
    credential_subject=credential_subject_data,
    issuance_date=datetime.now().isoformat()
)
issued_credential.sign(issuer_private_key, revocation_reference)
end_time = time.perf_counter()
issuance_time = (end_time - start_time) * 1000 # in ms
print(f"Credenziale emessa in {issuance_time:.2f} ms.")

# Aggiungi la credenziale al wallet dello studente
student_wallet.add_credential(issued_credential)

# Simula la "pubblicazione" del riferimento di revoca sulla blockchain
# (Questo significa che la credenziale è ora "registrata" e potenzialmente revocabile, non che sia già revocata)
if not blockchain_register.is_revoked(revocation_reference): # Assicurati di non aggiungerla come revocata se non lo è
    # La logica di blockchain_simulator.py.revoke_credential() stampa "revocata"
    # ma qui la usiamo per "registrare" la possibilità di revoca, non per revocare subito.
    # In un caso reale, ci sarebbe un'operazione di "registrazione" separata dalla "revoca".
    # Per questo simulatore, aggiungiamo semplicemente l'ID al set.
    blockchain_register.revoked_credentials.add(revocation_reference)
    blockchain_register._save_to_file()
    print(f"Riferimento di revoca '{revocation_reference}' registrato nel simulatore blockchain (non ancora revocato).")

# 2. Fase: Presentazione Credenziale (Studente Erasmus)
print("\n--- Fase 2: Presentazione Credenziale (Studente Erasmus) ---")
attributes_to_reveal = ["firstName", "lastName", "courseName", "grade"]

start_time = time.perf_counter()
selective_presentation = student_wallet.generate_selective_presentation(credential_id, attributes_to_reveal)
end_time = time.perf_counter()
presentation_time = (end_time - start_time) * 1000 # in ms
print(f"Presentazione selettiva generata in {presentation_time:.2f} ms.")

print("Presentazione selettiva JSON:")
print(json.dumps(selective_presentation, indent=2))

# 3. Fase: Verifica Credenziale (Università di Salerno)
print("\n--- Fase 3: Verifica Credenziale (Università di Salerno) ---")
# L'università ricevente usa la chiave pubblica dell'emittente per la verifica

def verify_full_presentation(presentation: dict, public_key_issuer, blockchain_reg) -> bool:
    """Funzione modificata per verificare una presentazione selettiva."""
    print("  - Verificando firma digitale...")

    # Verifica della firma digitale utilizzando i dati nella proof
    try:
        signature = bytes.fromhex(presentation["proof"]["signature"])
        merkle_root_hash = presentation["proof"]["merkleRootHash"]
        revocation_reference = presentation["proof"]["revocationMechanism"]["reference"]

        # Prepara l'hash da verificare, utilizzando i dati della presentazione
        data_to_verify = {
            "id": presentation["id"],
            "issuer_id": presentation["issuer"]["id"],
            "holder_id": presentation["holder"]["id"],
            "issuanceDate": presentation["issuanceDate"],
            "merkleRootHash": merkle_root_hash,
            "revocationReference": revocation_reference,
        }
        json_data_to_verify = json.dumps(data_to_verify, sort_keys=True).encode('utf-8')
        hash_to_verify = hashlib.sha256(json_data_to_verify).digest()

        # Verifica la firma utilizzando la chiave pubblica dell'emittente
        public_key_issuer.verify(
            signature,
            hash_to_verify,
            padding.PSS(
                mgf=padding.MGF1(hashes.SHA256()),
                salt_length=padding.PSS.MAX_LENGTH,
            ),
            hashes.SHA256(),
        )
        print("  Firma digitale: Valida")
        is_signature_valid = True
    except InvalidSignature:
        print("  Firma digitale: NON VALIDA")
        is_signature_valid = False
    except Exception as e:
        print(f"Errore durante la verifica della firma: {e}")
        is_signature_valid = False

    # Verifica delle prove Merkle
    print("  - Verificando prove Merkle...")
    all_merkle_proofs_valid = True
    for attr, value in presentation["disclosedClaims"].items():
        proof = presentation["merkleProofs"].get(attr)
        if not proof:
            print(f"    Manca prova Merkle per '{attr}'.")
            all_merkle_proofs_valid = False
            continue

        # Prepara il dato esatto per la verifica (coerente con la costruzione Merkle Tree)
        data_item_for_verification = json.dumps(value, sort_keys=True) if isinstance(value, (dict, list)) else str(value)
        full_data_item_string_for_verification = f"{attr}:{data_item_for_verification}"

        is_proof_valid = MerkleTree.verify_proof(full_data_item_string_for_verification, proof, merkle_root_hash)
        print(f"    Prova Merkle per '{attr}': {'Valida' if is_proof_valid else 'NON VALIDA'}")
        if not is_proof_valid:
            all_merkle_proofs_valid = False

    print(f"  Tutte le prove Merkle: {'Valide' if all_merkle_proofs_valid else 'NON VALIDE'}")

    # Verifica dello stato di revoca
    print("  - Controllando stato di revoca...")
    cred_reference_for_revocation = presentation["proof"]["revocationMechanism"]["reference"]
    is_cred_revoked = blockchain_reg.is_revoked(cred_reference_for_revocation)
    print(f"  Stato di revoca: {'Revocata' if is_cred_revoked else 'Non Revocata'}")

    # Restituisce il risultato complessivo
    return is_signature_valid and all_merkle_proofs_valid and not is_cred_revoked

start_time = time.perf_counter()
verification_result = verify_full_presentation(selective_presentation, issuer_public_key, blockchain_register)
end_time = time.perf_counter()
verification_time = (end_time - start_time) * 1000 # in ms
print(f"Tempo di verifica: {verification_time:.2f} ms.")
print(f"\nRisultato verifica credenziale: {'SUCCESSO' if verification_result else 'FALLIMENTO'}")

# 4. Fase: Revoca Credenziale (Università di Rennes)
print("\n--- Fase 4: Revoca Credenziale (Università di Rennes) ---")
# L'emittente decide di revocare la credenziale
blockchain_register.revoke_credential(revocation_reference)

print(f"Credenziale con riferimento '{revocation_reference}' ora revocata nel registro.")

# 5. Fase: Ri-Verifica dopo la Revoca (Università di Salerno)
print("\n--- Fase 5: Ri-Verifica dopo Revoca (Università di Salerno) ---")
start_time = time.perf_counter()
re_verification_result = verify_full_presentation(selective_presentation, issuer_public_key, blockchain_register)
end_time = time.perf_counter()
re_verification_time = (end_time - start_time) * 1000 # in ms
print(f"Tempo di ri-verifica: {re_verification_time:.2f} ms.")
print(f"\nRisultato ri-verifica credenziale: {'SUCCESSO' if re_verification_result else 'FALLIMENTO'} (atteso: FALLIMENTO)")

# --- Misurazione delle Dimensioni ---
print("\n--- Misurazione delle Dimensioni ---")
full_credential_json_size = len(issued_credential.to_json().encode('utf-8')) # Dimensione in byte
print(f"Dimensione credenziale completa (JSON): {full_credential_json_size} bytes")

selective_presentation_json_size = len(json.dumps(selective_presentation).encode('utf-8'))
print(f"Dimensione presentazione selettiva (JSON): {selective_presentation_json_size} bytes")