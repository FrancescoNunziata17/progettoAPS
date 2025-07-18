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

import re
from KDC import KDC, Client, Server

from login_register import verify_password, hash_password
current_email = "";
current_id = ""
current_role = "u";

def registra_università():
    kdc = KDC()  # Ottiene l'istanza unica del KDC

    # [Tutto il codice di validazione rimane invariato]
    # Validazione nome università
    while True:
        nome = input("Inserisci il nome dell'università: ")
        if len(nome) < 2 or not nome.replace(" ", "").isalpha():
            print("Il nome deve contenere almeno 2 caratteri e solo lettere.")
            continue
        break

    # Validazione ID
    while True:
        university_id = input("Inserisci l'ID dell'università: ")
        if len(university_id) < 2:
            print("L'ID deve contenere almeno 2 caratteri.")
            continue
        break

    # Dopo le validazioni, creiamo un nuovo Client per l'utente
    while True:
        email = input("Inserisci la tua email per registrarti: ")
        pattern_email = r'^[a-zA-Z0-9_.+-]+@[a-zA-Z0-9-]+\.[a-zA-Z0-9-.]+$'
        if not re.match(pattern_email, email):
            print("Formato email non valido. Riprova.")
            continue
        break

    while True:
        password = input("Crea una password sicura: ")
        if len(password) < 8:
            print("La password deve essere lunga almeno 8 caratteri.")
            continue
        if not re.search(r'[A-Z]', password):
            print("La password deve contenere almeno una lettera maiuscola.")
            continue
        if not re.search(r'\d', password):
            print("La password deve contenere almeno un numero.")
            continue
        if not re.search(r'[!@#$%^&*(),.?":{}|<>]', password):
            print("La password deve contenere almeno un carattere speciale.")
            continue
        break
    hashed_password, salt_ex = hash_password(password)

    # Salvataggio nel file users.json
    with open("users.json", "a") as file:
        user = {
            "nome": nome,
            "email": email,  # email è l'identificativo pubblico
            "password": hashed_password,  # password rimane hashata
            "university_id": university_id,
            "salt_ex": salt_ex,
            "role": "u",
        }
        file.write(json.dumps(user) + "\n")

# Funzioni di supporto per autenticazione
def registra_utente():
    kdc = KDC()  # Ottiene l'istanza unica del KDC

    # [Tutto il codice di validazione rimane invariato]
    # Validazione nome
    while True:
        nome = input("Inserisci il tuo nome: ")
        if len(nome) < 2 or not nome.replace(" ", "").isalpha():
            print("Il nome deve contenere almeno 2 caratteri e solo lettere.")
            continue
        break

    # Validazione cognome
    while True:
        cognome = input("Inserisci il tuo cognome: ")
        if len(cognome) < 2 or not cognome.replace(" ", "").isalpha():
            print("Il cognome deve contenere almeno 2 caratteri e solo lettere.")
            continue
        break

    # Validazione data di nascita
    while True:
        data_nascita = input("Inserisci la tua data di nascita (formato: YYYY-MM-DD): ")
        try:
            datetime.strptime(data_nascita, '%Y-%m-%d')
            break
        except ValueError:
            print("Formato data non valido. Usa il formato YYYY-MM-DD.")
            continue


    # Dopo le validazioni, creiamo un nuovo Client per l'utente
    while True:
        email = input("Inserisci la tua email per registrarti: ")
        pattern_email = r'^[a-zA-Z0-9_.+-]+@[a-zA-Z0-9-]+\.[a-zA-Z0-9-.]+$'
        if not re.match(pattern_email, email):
            print("Formato email non valido. Riprova.")
            continue
        break
    client = Client(email)  # email come client_id

    # Registriamo la chiave pubblica del client nel KDC
    kdc.register_user(email, client.public_key)

    # Validazione matricola
    while True:
        student_id = input("Inserisci la tua matricola studente: ")
        if not student_id.isdigit():
            print("La matricola deve contenere solo numeri.")
            continue
        if len(student_id) < 3:
            print("La matricola deve contenere almeno 3 caratteri.")
            continue
        break
    # Hash della password
    while True:
        password = input("Crea una password sicura: ")
        if len(password) < 8:
            print("La password deve essere lunga almeno 8 caratteri.")
            continue
        if not re.search(r'[A-Z]', password):
            print("La password deve contenere almeno una lettera maiuscola.")
            continue
        if not re.search(r'\d', password):
            print("La password deve contenere almeno un numero.")
            continue
        if not re.search(r'[!@#$%^&*(),.?":{}|<>]', password):
            print("La password deve contenere almeno un carattere speciale.")
            continue
        break
    hashed_password, salt_ex = hash_password(password)

    # Richiediamo un ticket al KDC per cifrare i dati
    server_id = "registration_server"
    session_key, ticket = client.request_service(kdc, server_id)

    # Creiamo un oggetto Fernet con la chiave di sessione per cifrare i dati
    f = Fernet(session_key)

    # Cifriamo i dati sensibili con la chiave di sessione
    encrypted_nome = f.encrypt(nome.encode())
    encrypted_cognome = f.encrypt(cognome.encode())
    encrypted_data_nascita = f.encrypt(data_nascita.encode())
    encrypted_matricola = f.encrypt(student_id.encode())

    # Salvataggio nel file users.json
    with open("users.json", "a") as file:
        user = {
            "email": email,  # email è l'identificativo pubblico
            "password": hashed_password,  # password rimane hashata
            "student_id": {
                "encrypted_data": encrypted_matricola.decode(),
                "ticket": ticket  # includiamo il ticket per verifica
            },
            "nome": {
                "encrypted_data": encrypted_nome.decode(),
                "ticket": ticket
            },
            "cognome": {
                "encrypted_data": encrypted_cognome.decode(),
                "ticket": ticket
            },
            "data_nascita": {
                "encrypted_data": encrypted_data_nascita.decode(),
                "ticket": ticket
            },
            "salt_ex": salt_ex,
            "role": "s",
            "public_key": client.public_key.public_bytes(
                encoding=serialization.Encoding.PEM,
                format=serialization.PublicFormat.SubjectPublicKeyInfo
            ).decode()
        }
        file.write(json.dumps(user) + "\n")

    # Salviamo la chiave privata del client
    os.makedirs('keys', exist_ok=True)
    with open(f"keys/{email}_private.pem", "wb") as f:
        f.write(client.private_key.private_bytes(
            encoding=serialization.Encoding.PEM,
            format=serialization.PrivateFormat.PKCS8,
            encryption_algorithm=serialization.BestAvailableEncryption(password.encode())
        ))

    # Server verifica il ticket
    registration_server = Server(server_id)
    success, _ = registration_server.handle_client_request(
        kdc,
        ticket['data'],
        ticket['signature']
    )

    if not success:
        raise ValueError("Errore nella verifica del ticket")

    global current_email, current_role, current_id
    current_email = email
    current_role = "s"
    current_id = student_id
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
                        current_id = utente["student_id"] if current_role == "s" else utente["university_id"];
                        print(f"Accesso effettuato con successo! Benvenuto/a {email} - Ruolo: {'Studente' if utente['role'] == 's' else 'Università'}.")
                        return

def get_student_info(matricola):
    try:
        with open("users.json", "r") as file:
            for line in file:
                user = json.loads(line)
                # Confronta l'hash della matricola fornita con quello memorizzato
                if "student_id" in user:
                #if user["student_id"] == hashlib.sha256(matricola.encode()).hexdigest() and user["role"] == "s":
                    return {
                        "firstName": user["nome"],
                        "lastName": user["cognome"],
                        "dateOfBirth": user["data_nascita"]
                    }
    except FileNotFoundError:
        print("File users.json non trovato")
        return None
    return None



# --- Main del Programma ---
print("--- Benvenuto nel Sistema ---")
scelta = input("Vuoi registrarti o accedere? (r/a): ").lower()
if scelta == "r":
    if current_role == "s":
        registra_utente()
    elif current_role == "u":
        registra_università()
    else:
        print("Errore")
        exit()
    print(f"Benvenuto {current_email}")
elif scelta == "a":
    accedi_utente()
    print(f"Benvenuto {current_email}")
else:
    print("Scelta non valida. Terminando il programma.")
    exit()

# Inizializza il simulatore di blockchain
blockchain_register = BlockchainSimulator()

# Inizializza il wallet dello studente (solo per studenti)
if current_role == "s":
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

        # Richiedi la matricola dello studente
        matricola_studente = input("Inserisci la matricola dello studente: ")

        # Recupera i dati dello studente
        student_info = get_student_info(matricola_studente)
        if not student_info:
            print("Studente non trovato nel sistema.")
            continue

        # Genera un ID univoco per la credenziale
        credential_id = f"urn:vc:example:{int(time.time())}"
        revocation_reference = credential_id

        # Richiedi i dati del corso
        print("\nInserisci i dati del corso:")
        course_name = input("Nome del corso: ")
        grade = input("Voto: ")
        ects = int(input("Crediti ECTS: "))
        semester = input("Semestre (es. 2024-2025/1): ")
        completed = input("Corso completato? (s/n): ").lower() == 's'
        description = input("Descrizione del corso: ")

        # Prepara i dati della credenziale
        credential_subject_data = {
            "studentId": matricola_studente,
            "firstName": student_info["firstName"],
            "lastName": student_info["lastName"],
            "dateOfBirth": student_info["dateOfBirth"],
            "courseName": course_name,
            "grade": grade,
            "ectsCredits": ects,
            "issueSemester": semester,
            "courseCompleted": completed,
            "courseDescription": description
        }

        # Ottieni istanza KDC e crea una sessione per cifrare i dati
        kdc = KDC()
        client = Client(current_email)
        # Registriamo la chiave pubblica del client nel KDC
        kdc.register_user(current_email, client.public_key)
        server_id = "credential_server"
        session_key, ticket = client.request_service(kdc, server_id)
        f = Fernet(session_key)

        # Cifra i dati della credenziale
        encrypted_credential = f.encrypt(json.dumps(credential_subject_data).encode())

        # Aggiorna il file users.json con la nuova credenziale cifrata
        with open("users.json", "r+") as file:
            users = [json.loads(line) for line in file]
            for user in users:
                if "student_id" in user:
                    if user["student_id"]["encrypted_data"] == student_info:  # Trova lo studente corretto
                        if "academic_credentials" not in user:
                            user["academic_credentials"] = []
                        user["academic_credentials"].append({
                            "encrypted_data": base64.b64encode(encrypted_credential).decode(),
                            "ticket": ticket
                        })
                        break
            
            # Riscrivi il file con i dati aggiornati
            file.seek(0)
            for user in users:
                file.write(json.dumps(user) + "\n")
            file.truncate()

        # Crea e firma la credenziale
        issued_credential = AcademicCredential(
            id=credential_id,
            issuer_id=current_id,
            holder_id=matricola_studente,
            credential_subject=credential_subject_data,
            issuance_date=datetime.now().isoformat()
        )

        issued_credential.sign(client.private_key, revocation_reference)
        
        # Registra nella blockchain
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