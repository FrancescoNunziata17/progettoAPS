import json
import time
from datetime import datetime
import hashlib
from cryptography.hazmat.primitives.asymmetric import rsa, padding
from cryptography.hazmat.primitives import serialization, hashes
from credential import AcademicCredential, generate_key_pair, save_private_key, load_private_key, save_public_key, load_public_key
from merkle_tree import MerkleTree
from blockchain_simulator import BlockchainSimulator
from student_wallet import StudentWallet
from cryptography.exceptions import InvalidSignature

import base64
import os
from cryptography.fernet import Fernet
from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.primitives.kdf.pbkdf2 import PBKDF2HMAC

from login_register import verify_password, hash_password
current_email = "";
current_id = ""
current_role = "s";

# Funzioni di supporto per autenticazione
def registra_utente():
    email = input("Inserisci la tua email per registrarti: ")
    hashed_password, salt_ex = hash_password(input("Crea una password sicura: "))
    student_id = input("Inserisci la tua matricola studente: ")
    role = "s"
    
    with open("users.json", "a") as file:
        user = {"email": email, "password": hashed_password, "student_id": student_id, "salt_ex": salt_ex, "role": role}
        file.write(json.dumps(user) + "\n")

    global current_email
    global current_role
    global current_id
    current_email = email;
    current_role = role;
    current_id = student_id;
    print("Registrazione completata! Ora sei connesso come:", email)

def accedi_utente():
    while True:
        email = input("Email: ")
        password = input("Password: ")
        with open("users.json", "r") as file:
            utenti = [json.loads(line) for line in file]
            for utente in utenti:
                if utente["email"] == email:
                    if not verify_password(password, utente["password"], utente["salt_ex"]):
                        print("Credenziali non valide. Riprova.")
                    else:
                        global current_email
                        global current_role
                        global current_id
                        current_email = email;
                        current_role = utente["role"];
                        current_id = utente["student_id"];
                        print(f"Accesso effettuato con successo! Benvenuto/a {email} - Ruolo: {'Studente' if utente['role'] == 's' else 'Università'}.")
                        return

# --- Main del Programma ---
print("--- Benvenuto nel Sistema ---")
scelta = input("Vuoi registrarti o accedere? (r/a): ").lower()
if scelta == "r":
    registra_utente()
    print(f"Benvenuto {current_email}")
elif scelta == "a":
    accedi_utente()
    print(f"Benvenuto {current_email}")
else:
    print("Scelta non valida. Terminando il programma.")
    exit()

# Inizializza il simulatore di blockchain
blockchain_register = BlockchainSimulator()

# Generazione/Caricamento Chiavi dell'Università Emittente
issuer_private_key_file = "issuer_private_key.pem"
issuer_public_key_file = "issuer_public_key.pem"
issuer_password = "my_strong_password"  # Usa una password più robusta in un caso reale

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

# Inizializza il wallet dello studente (solo per studenti)
if current_role == "s":
    student_id = ""
    student_wallet = StudentWallet(current_id)
    print(f"Wallet dello studente {current_email} inizializzato.")

# Menu con opzioni specifiche per ruolo
while True:
    print("\n--- Menu ---")
    print(f"Utente corrente: {current_email} - Ruolo: {'Studente' if current_role == 's' else 'Università'}")
    
    if current_role == "s":
        # Menu per studenti
        print("1. Visualizza tutte le tue credenziali")
        print("2. Presenta credenziale selettiva")
    elif current_role == "u":
        # Menu per università
        print("1. Emetti credenziale")
        print("2. Revoca credenziale")
    print("5. Esci")

    scelta = input("Scegli un'opzione: ")

    if current_role == "s" and scelta == "1":
        print("\n--- Presentazione delle credenziali del wallet ---")
        student_wallet.print_credentials()

    elif current_role == "s" and scelta == "2":
        print("\n--- Presentazione Credenziale Selettiva ---")
        credential_id = input("Inserisci l'ID della credenziale da presentare: ")
        attributes_to_reveal = input("Specifica gli attributi da rivelare (separati da virgola): ").split(",")
        selective_presentation = student_wallet.generate_selective_presentation(credential_id, attributes_to_reveal)
        print("Presentazione selettiva generata:")
        print(json.dumps(selective_presentation, indent=2))

    elif current_role == "u" and scelta == "1":
        print("\n--- Emissione Credenziale ---")
        credential_id = "urn:vc:example:cred001"
        revocation_reference = credential_id
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

        issued_credential = AcademicCredential(
            id=credential_id,
            issuer_id="did:example:universityofrennes",
            holder_id=student_id,
            credential_subject=credential_subject_data,
            issuance_date=datetime.now().isoformat()
        )
        issued_credential.sign(issuer_private_key, revocation_reference)
        student_wallet.add_credential(issued_credential)
        if not blockchain_register.is_revoked(revocation_reference):
            blockchain_register.revoked_credentials.add(revocation_reference)
            blockchain_register._save_to_file()
        print("Credenziale emessa con successo e registrata sulla blockchain.")

    elif current_role == "u" and scelta == "2":
        print("\n--- Revoca Credenziale ---")
        revocation_reference = input("Inserisci il riferimento della credenziale da revocare: ")
        blockchain_register.revoke_credential(revocation_reference)
        print(f"Credenziale con riferimento '{revocation_reference}' revocata con successo.")

    elif scelta == "4":
        print("Uscendo dal sistema. Arrivederci!")
        break

    else:
        print("Opzione non valida. Riprova.")