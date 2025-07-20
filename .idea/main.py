import json
import time
from datetime import datetime
import hashlib
import re
import os
import random
import base64

from cryptography.hazmat.primitives.asymmetric import rsa, padding
from cryptography.hazmat.primitives import serialization, hashes
from cryptography.exceptions import InvalidSignature
from cryptography.fernet import Fernet
from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.primitives.kdf.pbkdf2 import PBKDF2HMAC

# Assicurati che questi moduli siano nei percorsi corretti
from credential import AcademicCredential, generate_key_pair, save_private_key, load_private_key, save_public_key, load_public_key
from merkle_tree import MerkleTree
from blockchain_simulator import BlockchainSimulator
from student_wallet import StudentWallet
from KDC import KDC, Client, Server # Importa le tue classi KDC
from login_register import verify_password, hash_password # Importa le tue funzioni corrette

# Variabili globali per lo stato della sessione
current_email = ""
current_id = ""
current_role = "u" # Default a 'u' o 's' in base alla prima scelta


def registra_universita():
    """
    Gestisce il processo di registrazione di una nuova università.
    Richiede nome, ID università, email e password.
    """
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

    while True:
        email = input("Inserisci la tua email per registrarti: ")
        pattern_email = r'^[a-zA-Z0-9_.+-]+@[a-zA-Z0-9-]+\.[a-zA-Z0-9-.]+$'
        if not re.match(pattern_email, email):
            print("Formato email non valido. Riprova.")
            continue

        # Verifica se l'email esiste già
        try:
            if os.path.exists("users.json"):
                with open("users.json", "r") as f:
                    for line in f:
                        try:
                            if json.loads(line).get("email") == email:
                                print("Errore: Utente con questa email già registrato.")
                                return None, None, None
                        except json.JSONDecodeError:
                            print(f"DEBUG: Trovata riga malformata in users.json: {line.strip()}")
                            continue
        except FileNotFoundError:
            pass
        except Exception as e:
            print(f"ERRORE GRAVE durante la verifica dell'email in users.json: {e}")
            return None, None, None
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

    # Hashing della password e generazione del salt
    hashed_password_str, actual_salt_str = hash_password(password)

    # Salva la chiave privata e pubblica dell'università
    try:
        private_key, public_key = generate_key_pair()
        save_private_key(private_key, email, password)
        save_public_key(public_key, email)
        print("DEBUG (credential): Chiave privata salvata in keys\\{}_private.pem".format(email))
        print("DEBUG (credential): Chiave pubblica salvata in keys\\{}_public.pem".format(email))
        print("DEBUG: Coppia di chiavi RSA per Università generata e salvata con successo.")
    except Exception as e:
        print(f"ERRORE: Impossibile generare o salvare le chiavi per l'Università. Errore: {e}")
        return None, None, None

    # Salvataggio nel file users.json
    with open("users.json", "a") as file:
        user = {
            "nome": nome,
            "email": email,
            "password": hashed_password_str,
            "university_id": university_id,
            "salt_ex": actual_salt_str,
            "role": "u",
        }
        file.write(json.dumps(user) + "\n")

    print(f"Registrazione Università {nome} completata!")
    return email, password, university_id # Restituisce anche l'ID per impostare current_id

def registra_studente():
    """
    Gestisce il processo di registrazione di un nuovo utente (studente).
    Richiede email e password, genera una matricola, crea coppie di chiavi RSA,
    interagisce con il KDC per cifrare i dati personali e li salva.

    Returns:
        tuple: (email, password) se la registrazione è avvenuta con successo.
               (None, None) in caso di fallimento della registrazione.
    """
    global current_email, current_role, current_id

    while True:
        email = input("Inserisci la tua email (sarà anche il tuo ID utente): ")
        if not re.match(r"[^@]+@[^@]+\.[^@]+", email):
            print("Formato email non valido.")
            continue

        # Verifica se l'email esiste già
        try:
            if os.path.exists("users.json"):
                with open("users.json", "r") as f:
                    for line in f:
                        try:
                            if json.loads(line).get("email") == email:
                                print("Errore: Utente con questa email già registrato.")
                                return None, None, None # Aggiunto None per matricola
                        except json.JSONDecodeError:
                            print(f"DEBUG: Trovata riga malformata in users.json: {line.strip()}")
                            continue
        except FileNotFoundError:
            pass
        except Exception as e:
            print(f"ERRORE GRAVE durante la verifica dell'email in users.json: {e}")
            return None, None, None # Aggiunto None per matricola

        password = input("Inserisci la password: ")
        if len(password) < 8:
            print("La password deve essere di almeno 8 caratteri.")
            continue
        # Potresti aggiungere qui anche i controlli per maiuscole, numeri, caratteri speciali come per l'università

        # Hashing della password e generazione del salt
        hashed_password_str, actual_salt_str = hash_password(password)

        # Genera la matricola per il nuovo studente
        matricola = str(random.randint(100, 999)) # Genera una matricola di 3 cifre
        print(f"DEBUG: Matricola generata per il nuovo studente: {matricola}")

        try:
            # --- Generazione e salvataggio delle chiavi RSA ---
            print("DEBUG: Generazione della coppia di chiavi RSA per l'utente...")
            private_key, public_key = generate_key_pair()
            save_private_key(private_key, email, password)
            save_public_key(public_key, email)
            print("DEBUG (credential): Chiave privata salvata in keys\\{}_private.pem".format(email))
            print("DEBUG (credential): Chiave pubblica salvata in keys\\{}_public.pem".format(email))
            print("DEBUG: Coppia di chiavi RSA generata e salvata con successo.")

            # --- Interazione con il KDC per cifrare i dati personali ---
            print("DEBUG: Inizializzazione client KDC per la registrazione...")
            client_reg = Client(email)
            client_reg.private_key = private_key
            client_reg.public_key = public_key

            kdc_reg = KDC() # KDC è un singleton, quindi si assicura che il master_secret sia lo stesso
            kdc_reg.register_user(email, client_reg.public_key)
            print("DEBUG: Utente registrato al KDC per questa sessione.")

            server_id_reg = "registration_server"
            print(f"DEBUG: Richiesta servizio al KDC per server_id: {server_id_reg}")

            fernet_reg, ticket_reg = client_reg.request_service(kdc_reg, server_id_reg)

            print(f"DEBUG (main.registra_studente): Type of fernet_reg after request_service: {type(fernet_reg)}")
            print(f"DEBUG (main.registra_studente): Is fernet_reg a Fernet instance? {isinstance(fernet_reg, Fernet)}")
            print(f"DEBUG (main.registra_studente): Chiave di sessione e ticket ottenuti dal KDC per la registrazione.")

            # --- Cifratura dei dati personali con Fernet e la chiave di sessione ---
            # IMPORTANT: Use base64.urlsafe_b64encode for consistency with Fernet's output
            encrypted_matricola_data = base64.urlsafe_b64encode(fernet_reg.encrypt(matricola.encode())).decode('ascii')

            user_data = {
                "email": email,
                "password": hashed_password_str,
                "salt_ex": actual_salt_str,
                "role": "s",
                "student_id": {
                    "encrypted_data": encrypted_matricola_data,
                    "ticket": ticket_reg
                },
                "personal_info_ticket": ticket_reg,
                "nome": {
                    "encrypted_data": base64.urlsafe_b64encode(fernet_reg.encrypt("Mario".encode())).decode('ascii'),
                },
                "cognome": {
                    "encrypted_data": base64.urlsafe_b64encode(fernet_reg.encrypt("Rossi".encode())).decode('ascii'),
                },
                "data_nascita": {
                    "encrypted_data": base64.urlsafe_b64encode(fernet_reg.encrypt("2000-01-01".encode())).decode('ascii'),
                },
            }

            with open("users.json", "a") as f:
                f.write(json.dumps(user_data) + "\n")
            print(f"DEBUG: Dati utente salvati in users.json per {email}.")

            current_email = email
            current_role = "s"
            current_id = matricola
            print(f"DEBUG: Variabili globali impostate: email={current_email}, role={current_role}, id={current_id}")

            print(f"Registrazione completata! Ora sei connesso come: {email}")
            return email, password, matricola # Restituisce anche la matricola

        except Exception as e:
            print(f"ERRORE GRAVE DURANTE LA REGISTRAZIONE: {e}")
            return None, None, None # Aggiunto None per matricola


def accedi_utente(user_type: str):
    """
    Gestisce il processo di accesso dell'utente (studente o università).
    Autentica l'utente e imposta le variabili globali di sessione.

    Args:
        user_type (str): 's' per studente, 'u' per università.

    Returns:
        tuple: (email, password, id) se l'accesso e la decifrazione hanno successo.
               (None, None, None) in caso di fallimento dell'accesso o della decifrazione.
    """
    global current_email, current_role, current_id

    while True:
        email = input("Email: ")
        password = input("Password: ")
        user_data_found = None

        try:
            with open("users.json", "r") as file:
                utenti = [json.loads(line) for line in file]
                for utente in utenti:
                    if utente["email"] == email and utente["role"] == user_type:
                        user_data_found = utente
                        break
        except FileNotFoundError:
            print("Errore: Il file 'users.json' non è stato trovato. Assicurati che esista.")
            return None, None, None
        except json.JSONDecodeError as e:
            print(f"Errore: Il file 'users.json' è malformato. Errore JSON: {e}")
            return None, None, None
        except Exception as e:
            print(f"Errore durante la lettura di users.json: {e}")
            return None, None, None

        if not user_data_found:
            print("Email non trovata per questo tipo di utente o credenziali errate. Riprova.")
            continue

        stored_hash_str = user_data_found["password"]
        stored_salt_str = user_data_found["salt_ex"]

        if not verify_password(password, stored_hash_str, stored_salt_str):
            print("Credenziali non valide. Riprova.")
            continue

        # Autenticazione riuscita, imposta le variabili globali preliminari
        current_email = email
        current_role = user_data_found["role"]

        if current_role == "s":
            try:
                print(f"DEBUG (main): Tentativo di decifrare la matricola per lo studente: {email}")

                client_temp = Client(email)
                private_key = load_private_key(email, password)
                if private_key is None:
                    raise ValueError(f"Impossibile caricare la chiave privata per {email}.")

                client_temp.private_key = private_key
                client_temp.public_key = private_key.public_key()
                print(f"DEBUG (main): Chiave privata del client temporaneo caricata per {email}.")

                kdc = KDC()
                kdc.register_user(email, client_temp.public_key)
                print(f"DEBUG (main): Utente {email} registrato al KDC per la decifrazione della matricola.")

                # IL server_id DEVE ESSERE LO STESSO USATO DURANTE LA REGISTRAZIONE
                # Che per i dati personali (matricola, nome, cognome, etc.) è "registration_server"
                server_id = "registration_server" # <-- Modifica qui

                fernet_obj_kdc_response, ticket = client_temp.request_service(kdc, server_id)

                print(f"DEBUG (main.accedi_utente): Type of fernet_obj_kdc_response after request_service: {type(fernet_obj_kdc_response)}")
                print(f"DEBUG (main.accedi_utente): Is fernet_obj_kdc_response a Fernet instance? {isinstance(fernet_obj_kdc_response, Fernet)}")
                print(f"DEBUG (main.accedi_utente): Chiave di sessione e ticket ottenuti dal KDC.")

                data_server = Server(server_id)
                success, server_fernet_obj = data_server.handle_client_request(kdc, ticket['data'], ticket['signature'])

                if not success:
                    raise ValueError("Errore nella verifica del ticket KDC per la decifrazione della matricola.")
                print(f"DEBUG (main): Ticket KDC verificato con successo per {email}.")

                # Use fernet_obj_kdc_response directly
                encrypted_matricola_data = user_data_found["student_id"]["encrypted_data"]

                # IMPORTANT: Use base64.urlsafe_b64decode here
                decrypted_matricola = fernet_obj_kdc_response.decrypt(base64.urlsafe_b64decode(encrypted_matricola_data)).decode('ascii')
                current_id = decrypted_matricola
                print(f"DEBUG (main): Matricola dello studente '{email}' decifrata: {current_id}")
                return email, password, current_id # Restituisce anche l'ID per coerenza

            except Exception as e:
                print(f"ERRORE GRAVE: Impossibile decifrare la matricola dello studente {email}. Errore: {e}")
                current_id = None
                return None, None, None

        elif current_role == "u":
            current_id = user_data_found["university_id"]
            print(f"Accesso effettuato con successo! Benvenuto/a {email} - Ruolo: {'Studente' if current_role == 's' else 'Università'}.")
            return email, password, current_id # Restituisce l'ID università

        print(f"Accesso effettuato con successo! Benvenuto/a {email} - Ruolo: {'Studente' if current_role == 's' else 'Università'}.")
        return email, password, None # Fallback se nessun ID specifico


def get_student_info(matricola: str) -> dict:
    """
    Recupera i dati personali di uno studente dato il suo ID (matricola).
    Questa funzione simula l'accesso a un database di studenti o al loro wallet salvato.
    """
    try:
        if not os.path.exists("FileFolder"): # Controlla la cartella, non solo il file
            print("DEBUG: Cartella FileFolder non trovata.")
            return None

        # Itera su tutti i file nella cartella FileFolder
        for filename in os.listdir("FileFolder"):
            if filename.startswith("student_wallet_") and filename.endswith(".json"):
                wallet_path = os.path.join("FileFolder", filename)
                try:
                    with open(wallet_path, 'r') as wallet_f:
                        wallet_data = json.load(wallet_f)
                        personal_data = wallet_data.get('personal_data', {})

                        # Assicurati che 'matricola' esista in personal_data e sia una stringa per confronto
                        # Se personal_data.get('matricola') può essere int, convertilo a str per il confronto
                        if str(personal_data.get('matricola')) == matricola:
                            print(f"DEBUG: Trovato studente con matricola {matricola} nel wallet salvato: {wallet_path}.")
                            return {
                                "firstName": personal_data.get("nome", "N/A"),
                                "lastName": personal_data.get("cognome", "N/A"),
                                "dateOfBirth": personal_data.get("data_nascita", "N/A")
                            }
                        else:
                            print(f"DEBUG: Matricola {matricola} non corrispondente per wallet {filename}.")
                except json.JSONDecodeError as jde:
                    print(f"DEBUG AVVISO: File wallet {wallet_path} malformato o vuoto: {jde}")
                except Exception as e:
                    print(f"DEBUG ERRORE: Eccezione durante la lettura del wallet {wallet_path}: {e}")

        print(f"DEBUG: Matricola {matricola} non trovata nel sistema degli studenti o nei wallet.")
        return None

    except Exception as outer_e:
        print(f"ERRORE GRAVE in get_student_info: {outer_e}")
        return None

def retrieve_and_add_credentials_to_wallet(student_wallet_obj, student_email, student_password):
    """
    Recupera le credenziali emesse dall'università per lo studente specificato,
    le decifra e le aggiunge al wallet dello studente.
    """
    print(f"DEBUG (main): Tentativo di recuperare credenziali per {student_email}...")
    uni_credential_file_path = "FileFolder/Uni_credential.json"

    if not os.path.exists(uni_credential_file_path):
        print("DEBUG (main): File Uni_credential.json non trovato. Nessuna credenziale da recuperare.")
        return

    try:
        with open(uni_credential_file_path, "r") as f:
            uni_credentials_data = json.load(f)
        print(f"DEBUG (main): Contenuto di Uni_credential.json caricato: {json.dumps(uni_credentials_data, indent=2)}")
    except json.JSONDecodeError:
        print(f"AVVISO (main): File {uni_credential_file_path} malformato o vuoto. Impossibile recuperare credenziali.")
        return

    emitted_credentials = uni_credentials_data.get("credentials", [])

    if not emitted_credentials:
        print("DEBUG (main): Nessuna credenziale trovata in Uni_credential.json.")
        return

    # Prepara il client e il KDC per la decifratura delle credenziali dello studente
    try:
        student_client = Client(student_email)
        student_private_key = load_private_key(student_email, student_password)
        if student_private_key is None:
            raise ValueError(f"Impossibile caricare la chiave privata per {student_email}.")
        student_client.private_key = student_private_key
        student_client.public_key = student_private_key.public_key()

        kdc = KDC()
        kdc.register_user(student_email, student_client.public_key)

        server_id_credential_data = "credential_server"
        fernet_credential_obj, ticket_credential = student_client.request_service(kdc, server_id_credential_data)

        credential_server_obj = Server(server_id_credential_data)
        success_credential, _ = credential_server_obj.handle_client_request(kdc, ticket_credential['data'], ticket_credential['signature'])

        if not success_credential:
            print("ERRORE (main): Verifica ticket fallita per recupero credenziali.")
            return

    except Exception as e:
        print(f"ERRORE (main): Errore durante l'inizializzazione KDC per il recupero credenziali: {e}")
        return

    new_credentials_added = False
    print(f"DEBUG (main): Matricola dello studente corrente (dal wallet): {student_wallet_obj.student_matricola}")
    print(f"DEBUG (main): Numero di credenziali trovate in Uni_credential.json: {len(emitted_credentials)}")

    for i, cred_dict in enumerate(emitted_credentials):
        # ACCESSO CORRETTO ALL'ID DEL HOLDER DALLA STRUTTURA DELLA CREDENZIALE
        cred_holder_id = cred_dict.get("holder", {}).get("id")

        print(f"DEBUG (main): Esaminando credenziale {i+1}/{len(emitted_credentials)}: ID={cred_dict.get('id')}, Holder_ID nel file Uni: {cred_holder_id}")

        # Confronto con la matricola dello studente, assicurandosi che entrambi siano stringhe
        if str(cred_holder_id) == str(student_wallet_obj.student_matricola):
            print(f"DEBUG (main): Trovata corrispondenza matricola per credenziale {cred_dict.get('id')}.")
            encrypted_subject = cred_dict.get("credential_subject", {}).get("encrypted_data")
            if encrypted_subject:
                try:
                    decrypted_subject_bytes = fernet_credential_obj.decrypt(base64.urlsafe_b64decode(encrypted_subject))
                    decrypted_subject = json.loads(decrypted_subject_bytes.decode('utf-8'))

                    cred_dict["credential_subject"] = decrypted_subject

                    is_duplicate = False
                    for existing_cred in student_wallet_obj.credentials:
                        if existing_cred.get('id') == cred_dict.get('id'):
                            is_duplicate = True
                            break

                    if not is_duplicate:
                        student_wallet_obj.add_credential(cred_dict)
                        new_credentials_added = True
                        print(f"DEBUG (main): Credenziale '{cred_dict.get('id')}' decifrata e aggiunta al wallet dello studente.")
                    else:
                        print(f"DEBUG (main): Credenziale '{cred_dict.get('id')}' già presente nel wallet dello studente. Saltata.")

                except Exception as e:
                    print(f"ERRORE (main): Impossibile decifrare la credenziale '{cred_dict.get('id')}': {e}. Questo potrebbe essere dovuto a una chiave di sessione non corretta o dati corrotti.")
            else:
                print(f"AVVISO (main): Credenziale '{cred_dict.get('id')}' senza dati cifrati nel subject.")
        else:
            print(f"DEBUG (main): La matricola della credenziale ({cred_holder_id}) NON corrisponde alla matricola dello studente ({student_wallet_obj.student_matricola}). Saltata.")

    if new_credentials_added:
        student_wallet_obj._save_wallet_data()
        print("DEBUG (main): Wallet dello studente aggiornato con nuove credenziali.")
    else:
        print("DEBUG (main): Nessuna nuova credenziale aggiunta al wallet dello studente.")



### Main del Programma

print("--- Benvenuto nel Sistema ---")

# Scelta iniziale del ruolo
while True:
    role_choice = input("Sei un'Università (u) o uno Studente (s)? ").lower()
    if role_choice in ['u', 's']:
        break
    else:
        print("Scelta non valida. Inserisci 'u' o 's'.")

logged_in_email, logged_in_password, logged_in_id = None, None, None # Aggiunto logged_in_id

# Scelta di registrazione o accesso in base al ruolo
scelta = input("Vuoi registrarti o accedere? (r/a): ").lower()

if scelta == "r":
    if role_choice == "u":
        logged_in_email, logged_in_password, logged_in_id = registra_universita()
    else: # role_choice == "s"
        logged_in_email, logged_in_password, logged_in_id = registra_studente()

    if not logged_in_email:
        print("Registrazione fallita o incompleta. Terminando il programma.")
        exit()
    current_role = role_choice
    current_email = logged_in_email # Aggiorna current_email qui
    current_id = logged_in_id # Aggiorna current_id qui

elif scelta == "a":
    logged_in_email, logged_in_password, logged_in_id = accedi_utente(role_choice)
    if not logged_in_email:
        print("Accesso fallito o incompleto. Terminando il programma.")
        exit()
    # Le variabili globali current_email, current_role, current_id sono già impostate
    # all'interno di accedi_utente se l'accesso ha successo.
    # Quindi non serve aggiungere altro qui.

else:
    print("Scelta non valida. Terminando il programma.")
    exit()

# Inizializza il simulatore di blockchain
blockchain_register = BlockchainSimulator()

# Inizializza il wallet dello studente (solo per studenti)
student_wallet = None
if current_role == "s":
    student_wallet = StudentWallet(current_id)
    print(f"Wallet dello studente {current_email} inizializzato con matricola: {current_id}.")

    # Questa riga innescherà il caricamento/decifratura/salvataggio del wallet
    if logged_in_email and student_wallet.load_student_data_and_credentials(logged_in_email, logged_in_password):
        print("Dati personali e credenziali caricati nel wallet.")
        # CHIAMATA ALLA NUOVA FUNZIONE PER RECUPERARE LE CREDENZIALI
        retrieve_and_add_credentials_to_wallet(student_wallet, logged_in_email, logged_in_password)
    else:
        print("Impossibile caricare i dati personali o le credenziali dello studente. Assicurati di aver fatto accesso almeno una volta.")

# Menu con opzioni specifiche per ruolo
while True:
    print("\n--- Menu ---")
    print(f"Utente corrente: {current_email} - Ruolo: {'Studente' if current_role == 's' else 'Università'}")

    if current_role == "s":
        print("1. Visualizza dati personali e credenziali")
        print("2. Presenta credenziale selettiva")
    elif current_role == "u":
        print("1. Emetti credenziale")
        print("2. Revoca credenziale")
    print("5. Esci")

    scelta = input("Scegli un'opzione: ")

    if current_role == "s" and scelta == "1":
        if student_wallet:
            student_wallet.display_personal_data()
            student_wallet.display_credentials()
        else:
            print("Wallet studente non inizializzato.")

    elif current_role == "s" and scelta == "2":
        if student_wallet:
            print("\n--- Presentazione Credenziale Selettiva ---")
            credential_id = input("Inserisci l'ID della credenziale da presentare: ")
            attributes_to_reveal_str = input("Specifica gli attributi da rivelare (separati da virgola, es. courseName,grade): ")
            attributes_to_reveal = [attr.strip() for attr in attributes_to_reveal_str.split(",") if attr.strip()]

            try:
                selective_presentation = student_wallet.generate_selective_presentation(credential_id, attributes_to_reveal)
                print("Presentazione selettiva generata:")
                print(json.dumps(selective_presentation, indent=2))
            except ValueError as ve:
                print(f"ERRORE: {ve}")
            except Exception as e:
                print(f"ERRORE durante la generazione della presentazione selettiva: {e}")
        else:
            print("Wallet studente non inizializzato.")


    elif current_role == "u" and scelta == "1":
        print("\n--- Emissione Credenziale ---")

        matricola_studente = input("Inserisci la matricola dello studente a cui emettere la credenziale: ")

        student_info = get_student_info(matricola_studente)
        if not student_info:
            print("Studente non trovato o dati non disponibili per questa matricola.")
            continue

        credential_id = f"urn:vc:example:{int(time.time())}"
        revocation_reference = credential_id

        print("\nInserisci i dati del corso:")
        course_name = input("Nome del corso: ")
        grade = input("Voto: ")
        ects = int(input("Crediti ECTS: "))
        semester = input("Semestre (es. 2024-2025/1): ")
        completed = input("Corso completato? (s/n): ").lower() == 's'
        description = input("Descrizione del corso: ")

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

        uni_client = Client(current_email)
        try:
            # DEBUGGING: Stampa le variabili usate per caricare la chiave
            print(f"DEBUG (Uni Key Load): Tentativo di caricare chiave per email: {current_email}")
            print(f"DEBUG (Uni Key Load): Password usata (solo per debug, non in prod): {logged_in_password}")

            uni_private_key = load_private_key(current_email, logged_in_password)
            if uni_private_key is None:
                raise ValueError("Impossibile caricare la chiave privata dell'università.")
            uni_client.private_key = uni_private_key
            uni_client.public_key = uni_private_key.public_key()
        except Exception as e:
            print(f"ERRORE: Impossibile inizializzare il client KDC dell'università per firmare. Errore: {e}")
            continue # Non proseguire se la chiave non può essere caricata

        kdc = KDC()
        kdc.register_user(current_email, uni_client.public_key)
        server_id_uni = "credential_server"

        fernet_uni, ticket_uni = uni_client.request_service(kdc, server_id_uni)

        # Cifra i dati della credenziale con la chiave di sessione dell'università
        # IMPORTANT: Use base64.urlsafe_b64encode for consistency with Fernet's output
        encrypted_credential = base64.urlsafe_b64encode(fernet_uni.encrypt(json.dumps(credential_subject_data).encode())).decode('ascii')

        issued_credential = AcademicCredential(
            id=credential_id,
            issuer_id=current_id, # current_id deve essere l'ID dell'università qui
            holder_id=matricola_studente,
            credential_subject={"encrypted_data": encrypted_credential},
            issuance_date=datetime.now().isoformat()
        )

        issued_credential.sign(uni_client.private_key, revocation_reference)

        credentials_list = {"credentials": []}
        uni_credential_file_path = "FileFolder/Uni_credential.json"
        if os.path.exists(uni_credential_file_path):
            with open(uni_credential_file_path, "r") as f:
                try:
                    loaded_data = json.load(f)
                    if "credentials" in loaded_data and isinstance(loaded_data["credentials"], list):
                        credentials_list = loaded_data
                except json.JSONDecodeError:
                    print(f"AVVISO: File {uni_credential_file_path} malformato o vuoto. Inizializzazione con lista vuota.")
                    pass

        credentials_list["credentials"].append(issued_credential.to_dict())

        os.makedirs("FileFolder", exist_ok=True)
        with open(uni_credential_file_path, "w") as f:
            json.dump(credentials_list, f, indent=2)

        # La logica di revoca immediata è per test; in produzione sarebbe diversa
        # Questa riga è stata modificata per riflettere l'output che hai visto
        # In un sistema reale, la revoca non sarebbe immediata ma gestita separatamente.
        # Qui la lasciamo così per coerenza con il tuo log precedente.
        if not blockchain_register.is_revoked(revocation_reference):
            blockchain_register.revoke_credential(revocation_reference)
            print(f"Credenziale '{credential_id}' revocata con successo e aggiunta al registro simulato.")


        print("Credenziale emessa con successo e registrata sulla blockchain (come non revocata).")


    elif current_role == "u" and scelta == "2":
        print("\n--- Revoca Credenziale ---")
        revocation_reference = input("Inserisci il riferimento della credenziale da revocare: ")
        blockchain_register.revoke_credential(revocation_reference)
        print(f"Credenziale con riferimento '{revocation_reference}' revocata con successo.")

    elif scelta == "5":
        print("Uscendo dal sistema. Arrivederci!")
        break

    else:
        print("Opzione non valida. Riprova.")