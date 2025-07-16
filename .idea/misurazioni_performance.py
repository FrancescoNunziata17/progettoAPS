import json
import time
from datetime import datetime
import csv # Per salvare i risultati delle performance

# Importa i tuoi moduli
from credential import AcademicCredential, generate_key_pair, save_private_key, load_private_key, save_public_key, load_public_key
from merkle_tree import MerkleTree
from blockchain_simulator import BlockchainSimulator
from student_wallet import StudentWallet

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

# --- Funzione per la verifica completa della presentazione ---
def verify_full_presentation(presentation: dict, public_key_issuer, blockchain_reg) -> bool:
    """Funzione ausiliaria per la verifica completa della presentazione."""
    # print("  - Verificando firma digitale...") # Rimosso per non intasare l'output durante i test di performance
    temp_cred = AcademicCredential.from_json(json.dumps(presentation))
    is_signature_valid = temp_cred.verify_signature(public_key_issuer)
    # print(f"  Firma digitale: {'Valida' if is_signature_valid else 'NON VALIDA'}")

    # print("  - Verificando prove Merkle...")
    all_merkle_proofs_valid = True
    merkle_root_hash_from_proof = presentation["proof"]["merkleRootHash"]

    for attr, value in presentation["disclosedClaims"].items():
        proof = presentation["merkleProofs"].get(attr)
        if not proof:
            # print(f"    Manca prova Merkle per '{attr}'.")
            all_merkle_proofs_valid = False
            continue

        data_item_for_verification = json.dumps(value, sort_keys=True) if isinstance(value, (dict, list)) else str(value)
        full_data_item_string_for_verification = f"{attr}:{data_item_for_verification}"

        is_proof_valid = MerkleTree.verify_proof(full_data_item_string_for_verification, proof, merkle_root_hash_from_proof)
        # print(f"    Prova Merkle per '{attr}': {'Valida' if is_proof_valid else 'NON VALIDA'}")
        if not is_proof_valid:
            all_merkle_proofs_valid = False
    # print(f"  Tutte le prove Merkle: {'Valide' if all_merkle_proofs_valid else 'NON VALIDE'}")

    # print("  - Controllando stato di revoca...")
    cred_reference_for_revocation = presentation["proof"]["revocationMechanism"]["reference"]
    is_cred_revoked = blockchain_reg.is_revoked(cred_reference_for_revocation)
    # print(f"  Stato di revoca: {'Revocata' if is_cred_revoked else 'Non Revocata'}")

    return is_signature_valid and all_merkle_proofs_valid and not is_cred_revoked

# --- Esempio di Flusso Operativo Singolo (come prima, per dimostrazione) ---
print("\n--- Esempio di Flusso Operativo Singolo ---")

# 1. Emissione
credential_id_single = "urn:vc:example:cred_single_001"
revocation_reference_single = credential_id_single

credential_subject_data_single = {
    "studentId": "S12345",
    "firstName": "Mario",
    "lastName": "Rossi",
    "dateOfBirth": "2000-01-15",
    "courseName": "Algoritmi e Protocolli per la Sicurezza",
    "grade": "30 cum laude",
    "ectsCredits": 6,
} # Soggetto semplificato per brevità

start_time = time.perf_counter()
issued_credential_single = AcademicCredential(
    id=credential_id_single,
    issuer_id="did:example:universityofrennes",
    holder_id=student_id,
    credential_subject=credential_subject_data_single,
    issuance_date=datetime.now().isoformat()
)
issued_credential_single.sign(issuer_private_key, revocation_reference_single)
end_time = time.perf_counter()
issuance_time_single = (end_time - start_time) * 1000 # in ms
print(f"Credenziale singola emessa in {issuance_time_single:.2f} ms.")
student_wallet.add_credential(issued_credential_single)
# Registra il riferimento nel simulatore, non lo revoca ancora
if not blockchain_register.is_revoked(revocation_reference_single):
    blockchain_register.revoked_credentials.add(revocation_reference_single)
    blockchain_register._save_to_file()

# 2. Presentazione
attributes_to_reveal_single = ["firstName", "lastName", "grade"]
start_time = time.perf_counter()
selective_presentation_single = student_wallet.generate_selective_presentation(credential_id_single, attributes_to_reveal_single)
end_time = time.perf_counter()
presentation_time_single = (end_time - start_time) * 1000 # in ms
print(f"Presentazione singola generata in {presentation_time_single:.2f} ms.")

# 3. Verifica
start_time = time.perf_counter()
verification_result_single = verify_full_presentation(selective_presentation_single, issuer_public_key, blockchain_register)
end_time = time.perf_counter()
verification_time_single = (end_time - start_time) * 1000 # in ms
print(f"Verifica singola: {'SUCCESSO' if verification_result_single else 'FALLIMENTO'} in {verification_time_single:.2f} ms.")

# 4. Revoca
print(f"\nTentativo di revoca di '{revocation_reference_single}'...")
blockchain_register.revoke_credential(revocation_reference_single)

# 5. Ri-verifica dopo revoca
print("Ri-verifica credenziale singola dopo revoca...")
start_time = time.perf_counter()
re_verification_result_single = verify_full_presentation(selective_presentation_single, issuer_public_key, blockchain_register)
end_time = time.perf_counter()
re_verification_time_single = (end_time - start_time) * 1000 # in ms
print(f"Ri-verifica singola: {'SUCCESSO' if re_verification_result_single else 'FALLIMENTO'} (atteso: FALLIMENTO) in {re_verification_time_single:.2f} ms.")

# --- Implementazione Dettagliata delle Misurazioni delle Prestazioni ---
print("\n--- Misurazione delle Prestazioni Approfondita ---")

num_iterations = 100 # Numero di volte per ripetere ogni test
performance_results = []

# Attributi base del soggetto per le credenziali di test
base_subject_data = {
    "studentId": "S{num}",
    "firstName": "Test",
    "lastName": "User",
    "dateOfBirth": "2000-01-01",
    "courseName": "Advanced Cryptography",
    "grade": "A",
    "ectsCredits": 6,
    "issueSemester": "2024-2025/1",
    "university": "Example University"
}

# Test con numero variabile di attributi
attribute_counts = [5, 10, 20] # Test con 5, 10, 20 attributi nel subject
print(f"\nEsecuzione di {num_iterations} iterazioni per diversi conteggi di attributi...")

for num_attrs in attribute_counts:
    print(f"\nTesting con {num_attrs} attributi...")

    current_subject_data = dict(list(base_subject_data.items())[:num_attrs])
    if num_attrs > len(base_subject_data): # Aggiungi attributi generici se richiesto un numero maggiore del base
        for i in range(len(base_subject_data), num_attrs):
            current_subject_data[f"customAttr{i}"] = f"Value{i}"

    issuance_times = []
    presentation_times = []
    verification_times = []

    credential_size = 0
    presentation_size = 0

    for i in range(num_iterations):
        cred_id = f"urn:vc:example:perf_cred_{num_attrs}_{i}"
        rev_ref = cred_id

        # Emissione
        start_t = time.perf_counter()
        cred = AcademicCredential(id=cred_id, issuer_id="did:example:perf_issuer", holder_id=student_id, credential_subject=current_subject_data)
        cred.sign(issuer_private_key, rev_ref)
        end_t = time.perf_counter()
        issuance_times.append((end_t - start_t) * 1000)

        # Simula registrazione revoca
        if not blockchain_register.is_revoked(rev_ref):
            blockchain_register.revoked_credentials.add(rev_ref)
            blockchain_register._save_to_file()

        # Presentazione (rivelando tutti gli attributi per semplicità nel test di base)
        attrs_to_reveal = list(current_subject_data.keys())
        start_t = time.perf_counter()
        pres = student_wallet.generate_selective_presentation(cred.id, attrs_to_reveal) # Usiamo l'oggetto cred appena creato per la presentazione
        end_t = time.perf_counter()
        presentation_times.append((end_t - start_t) * 1000)

        # Verifica
        start_t = time.perf_counter()
        verify_full_presentation(pres, issuer_public_key, blockchain_register)
        end_t = time.perf_counter()
        verification_times.append((end_t - start_t) * 1000)

        # Misura dimensioni (solo alla prima iterazione o occasionalmente per rappresentatività)
        if i == 0:
            credential_size = len(cred.to_json().encode('utf-8'))
            presentation_size = len(json.dumps(pres).encode('utf-8'))

    avg_issuance_time = sum(issuance_times) / num_iterations
    avg_presentation_time = sum(presentation_times) / num_iterations
    avg_verification_time = sum(verification_times) / num_iterations

    print(f"  Media Emissione ({num_attrs} attr): {avg_issuance_time:.2f} ms")
    print(f"  Media Presentazione ({num_attrs} attr): {avg_presentation_time:.2f} ms")
    print(f"  Media Verifica ({num_attrs} attr): {avg_verification_time:.2f} ms")
    print(f"  Dimensione Credenziale ({num_attrs} attr): {credential_size} bytes")
    print(f"  Dimensione Presentazione ({num_attrs} attr): {presentation_size} bytes")

    performance_results.append({
        "num_attributes": num_attrs,
        "avg_issuance_time_ms": avg_issuance_time,
        "avg_presentation_time_ms": avg_presentation_time,
        "avg_verification_time_ms": avg_verification_time,
        "credential_size_bytes": credential_size,
        "presentation_size_bytes": presentation_size
    })

# Test con numero variabile di attributi rivelati (fissando il totale degli attributi)
print(f"\nEsecuzione di {num_iterations} iterazioni per diversi attributi rivelati (su 10 totali)...")

fixed_total_attrs = 10
fixed_subject_data = dict(list(base_subject_data.items())[:fixed_total_attrs])
if fixed_total_attrs > len(base_subject_data):
    for i in range(len(base_subject_data), fixed_total_attrs):
        fixed_subject_data[f"customAttr{i}"] = f"Value{i}"

num_revealed_attrs_list = [2, 5, 8, fixed_total_attrs]

for num_revealed in num_revealed_attrs_list:
    print(f"\nTesting con {num_revealed} attributi rivelati (su {fixed_total_attrs} totali)...")

    current_revealed_attrs = list(fixed_subject_data.keys())[:num_revealed]

    presentation_times = []
    verification_times = []
    presentation_size = 0 # Media

    for i in range(num_iterations):
        cred_id = f"urn:vc:example:perf_cred_revealed_{fixed_total_attrs}_{num_revealed}_{i}"
        rev_ref = cred_id

        # Creare e firmare una nuova credenziale per ogni iterazione per isolare le performance
        cred = AcademicCredential(id=cred_id, issuer_id="did:example:perf_issuer", holder_id=student_id, credential_subject=fixed_subject_data)
        cred.sign(issuer_private_key, rev_ref)
        student_wallet.add_credential(cred) # Aggiungi al wallet per la presentazione

        # Simula registrazione revoca
        if not blockchain_register.is_revoked(rev_ref):
            blockchain_register.revoked_credentials.add(rev_ref)
            blockchain_register._save_to_file()

        # Presentazione
        start_t = time.perf_counter()
        pres = student_wallet.generate_selective_presentation(cred.id, current_revealed_attrs)
        end_t = time.perf_counter()
        presentation_times.append((end_t - start_t) * 1000)

        # Verifica
        start_t = time.perf_counter()
        verify_full_presentation(pres, issuer_public_key, blockchain_register)
        end_t = time.perf_counter()
        verification_times.append((end_t - start_t) * 1000)

        if i == 0:
            presentation_size = len(json.dumps(pres).encode('utf-8'))

    avg_presentation_time = sum(presentation_times) / num_iterations
    avg_verification_time = sum(verification_times) / num_iterations

    print(f"  Media Presentazione ({num_revealed} rivelati): {avg_presentation_time:.2f} ms")
    print(f"  Media Verifica ({num_revealed} rivelati): {avg_verification_time:.2f} ms")
    print(f"  Dimensione Presentazione ({num_revealed} rivelati): {presentation_size} bytes")

    performance_results.append({
        "num_total_attributes": fixed_total_attrs,
        "num_revealed_attributes": num_revealed,
        "avg_presentation_time_ms": avg_presentation_time,
        "avg_verification_time_ms": avg_verification_time,
        "presentation_size_bytes": presentation_size
    })

# Salva i risultati delle performance su un file CSV
output_csv_file = "performance_results.csv"
if performance_results:
    keys = performance_results[0].keys()
    with open(output_csv_file, 'w', newline='') as output_file:
        dict_writer = csv.DictWriter(output_file, fieldnames=keys)
        dict_writer.writeheader()
        dict_writer.writerows(performance_results)
    print(f"\nRisultati delle performance salvati in '{output_csv_file}'")
else:
    print("\nNessun risultato di performance da salvare.")

print("\n--- Esecuzione completata ---")