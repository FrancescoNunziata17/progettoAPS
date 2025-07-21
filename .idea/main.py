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
from cryptography.hazmat.primitives.kdf.pbkdf2 import PBKDF2HMAC

# Assicurati che questi moduli siano nei percorsi corretti e contengano le funzioni necessarie
from credential import AcademicCredential, generate_key_pair, save_private_key, load_private_key, save_public_key, load_public_key
from merkle_tree import MerkleTree # Se usi MerkleTree
from blockchain_simulator import BlockchainSimulator # Se usi BlockchainSimulator
from student_wallet import StudentWallet # Se usi StudentWallet
from login_register import verify_password, hash_password # Importa le tue funzioni corrette

# Variabili globali per lo stato della sessione
current_email = ""
current_id = ""
current_role = "" # Sarà impostato a 'u' o 's' dopo la scelta iniziale

def registra_universita():
    """
    Gestisce il processo di registrazione di una nuova università.
    Richiede nome, ID università, email e password.
    Genera e salva la coppia di chiavi RSA per l'università.
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
                            continue # Salta righe malformate
        except FileNotFoundError:
            pass # Il file non esiste, nessun problema
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
    return email, password, university_id

def registra_studente():
    """
    Gestisce il processo di registrazione di un nuovo utente (studente).
    Richiede email e password, genera una matricola, crea coppie di chiavi RSA,
    cifra i dati personali usando un approccio ibrido RSA/Fernet e li salva.

    Returns:
        tuple: (email, password, matricola) se la registrazione è avvenuta con successo.
               (None, None, None) in caso di fallimento.
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
                                return None, None, None
                        except json.JSONDecodeError:
                            continue # Salta righe malformate
        except FileNotFoundError:
            pass
        except Exception as e:
            print(f"ERRORE GRAVE durante la verifica dell'email in users.json: {e}")
            return None, None, None

        password = input("Inserisci la password: ")
        if len(password) < 8:
            print("La password deve essere di almeno 8 caratteri.")
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

    # Genera la matricola per il nuovo studente
    matricola = str(random.randint(100, 999)) # Genera una matricola di 3 cifre
    print(f"DEBUG: Matricola generata per il nuovo studente: {matricola}")

    try:
        # --- Generazione e salvataggio delle chiavi RSA ---
        print("DEBUG: Generazione della coppia di chiavi RSA per l'utente...")
        private_key, public_key = generate_key_pair()
        save_private_key(private_key, email, password)
        save_public_key(public_key, email)
        print("DEBUG: Coppia di chiavi RSA generata e salvata con successo.")

        # --- Cifratura dei dati personali con Fernet (chiave cifrata con RSA) ---
        print("DEBUG: Generazione e cifratura della chiave di sessione per i dati personali...")
        personal_data_fernet_key = Fernet.generate_key()
        fernet_personal_data = Fernet(personal_data_fernet_key)

        # Cifra la chiave Fernet appena generata con la chiave pubblica RSA dello studente
        encrypted_fernet_key_for_personal_data = public_key.encrypt(
            personal_data_fernet_key,
            padding.OAEP(
                mgf=padding.MGF1(hashes.SHA256()),
                algorithm=hashes.SHA256(),
                label=None
            )
        ).hex() # Converti in esadecimale per salvarlo in JSON

        print("DEBUG: Chiave Fernet per dati personali generata e cifrata con RSA.")

        # Cifratura della matricola e altri dati personali con la chiave Fernet
        encrypted_matricola_data = base64.urlsafe_b64encode(fernet_personal_data.encrypt(matricola.encode())).decode('ascii')
        encrypted_nome_data = base64.urlsafe_b64encode(fernet_personal_data.encrypt("Mario".encode())).decode('ascii')
        encrypted_cognome_data = base64.urlsafe_b64encode(fernet_personal_data.encrypt("Rossi".encode())).decode('ascii')
        encrypted_data_nascita = base64.urlsafe_b64encode(fernet_personal_data.encrypt("2000-01-01".encode())).decode('ascii')

        user_data = {
            "email": email,
            "password": hashed_password_str,
            "salt_ex": actual_salt_str,
            "role": "s",
            "personal_data_encrypted": { # Nuovo campo per i dati personali cifrati
                "encrypted_fernet_key": encrypted_fernet_key_for_personal_data, # Chiave Fernet cifrata con RSA
                "matricola": encrypted_matricola_data,
                "nome": encrypted_nome_data,
                "cognome": encrypted_cognome_data,
                "data_nascita": encrypted_data_nascita
            },
            "credentials": [] # Campo per coerenza con StudentWallet, se le credenziali vengono salvate anche qui
        }

        with open("users.json", "a") as f:
            f.write(json.dumps(user_data) + "\n")
        print(f"DEBUG: Dati utente salvati in users.json per {email}.")

        current_email = email
        current_role = "s"
        current_id = matricola
        print(f"DEBUG: Variabili globali impostate: email={current_email}, role={current_role}, id={current_id}")

        print(f"Registrazione completata! Ora sei connesso come: {email}")
        return email, password, matricola

    except Exception as e:
        print(f"ERRORE GRAVE DURANTE LA REGISTRAZIONE: {e}")
        return None, None, None

def accedi_utente(user_type: str):
    """
    Gestisce il processo di accesso dell'utente (studente o università).
    Autentica l'utente e imposta le variabili globali di sessione.
    Per gli studenti, decifra i dati personali usando l'approccio ibrido RSA/Fernet.

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
                print(f"DEBUG (main): Tentativo di decifrare i dati personali per lo studente: {email}")

                private_key = load_private_key(email, password)
                if private_key is None:
                    raise ValueError(f"Impossibile caricare la chiave privata per {email}.")

                print(f"DEBUG (main): Chiave privata caricata per {email}.")

                # Decifra la chiave Fernet usando la chiave privata RSA dello studente
                encrypted_fernet_key_hex = user_data_found["personal_data_encrypted"]["encrypted_fernet_key"]
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
                print("DEBUG (main): Chiave Fernet per dati personali decifrata con successo.")

                # Decifra i dati personali usando la chiave Fernet
                encrypted_matricola_data = user_data_found["personal_data_encrypted"]["matricola"]
                decrypted_matricola = fernet_personal_data.decrypt(base64.urlsafe_b64decode(encrypted_matricola_data)).decode('utf-8')
                current_id = decrypted_matricola
                print(f"DEBUG (main): Matricola dello studente '{email}' decifrata: {current_id}")

                # Decifrare anche nome, cognome, data_nascita per completezza (non indispensabile qui ma utile)
                decrypted_nome = fernet_personal_data.decrypt(base64.urlsafe_b64decode(user_data_found["personal_data_encrypted"]["nome"])).decode('utf-8')
                decrypted_cognome = fernet_personal_data.decrypt(base64.urlsafe_b64decode(user_data_found["personal_data_encrypted"]["cognome"])).decode('utf-8')
                decrypted_data_nascita = fernet_personal_data.decrypt(base64.urlsafe_b64decode(user_data_found["personal_data_encrypted"]["data_nascita"])).decode('utf-8')


                print(f"Accesso studente {email} riuscito! Matr: {current_id}")
                return email, password, current_id

            except Exception as e:
                print(f"ERRORE GRAVE: Impossibile decifrare i dati personali dello studente {email}. Errore: {e}")
                current_id = None
                return None, None, None

        elif current_role == "u":
            current_id = user_data_found["university_id"]
            print(f"Accesso effettuato con successo! Benvenuto/a {email} - Ruolo: {'Studente' if current_role == 's' else 'Università'}.")
            return email, password, current_id

        print(f"Accesso effettuato con successo! Benvenuto/a {email} - Ruolo: {'Studente' if current_role == 's' else 'Università'}.")
        return email, password, None # Fallback se nessun ID specifico


def get_student_info(matricola: str) -> dict:
    """
    Recupera i dati personali di uno studente dato il suo ID (matricola).
    Questa funzione cerca i dati nel wallet dello studente, che si presume sia
    già stato caricato e decifrato da StudentWallet.
    È principalmente usata per il debug o per simulazioni interne al sistema studente.
    L'università NON dovrebbe usare questa funzione per ottenere i dati sensibili.
    """
    try:
        wallets_folder = "wallets"

        if not os.path.exists(wallets_folder):
            print(f"DEBUG: Cartella {wallets_folder} non trovata.")
            return None

        for filename in os.listdir(wallets_folder):
            if filename.endswith("_wallet.json"):
                wallet_path = os.path.join(wallets_folder, filename)
                try:
                    with open(wallet_path, 'r') as wallet_f:
                        wallet_data = json.load(wallet_f)
                        personal_data = wallet_data.get('personal_data', {})

                        if str(personal_data.get('matricola')) == matricola:
                            print(f"DEBUG: Trovato studente con matricola {matricola} nel wallet salvato: {wallet_path}.")
                            return {
                                "firstName": personal_data.get("nome", "N/A"),
                                "lastName": personal_data.get("cognome", "N/A"),
                                "dateOfBirth": personal_data.get("data_nascita", "N/A"),
                                "email": personal_data.get("email", "N/A")
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
    le decifra usando l'approccio ibrido RSA/Fernet e le aggiunge al wallet dello studente.
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

    # Carica la chiave privata dello studente una sola volta
    try:
        student_private_key = load_private_key(student_email, student_password)
        if student_private_key is None:
            raise ValueError(f"Impossibile caricare la chiave privata per {student_email}.")
        print(f"DEBUG (main): Chiave privata dello studente caricata per {student_email}.")
    except Exception as e:
        print(f"ERRORE (main): Errore durante il caricamento della chiave privata dello studente: {e}")
        return

    new_credentials_added = False
    print(f"DEBUG (main): Matricola dello studente corrente (dal wallet): {student_wallet_obj.student_matricola}")
    print(f"DEBUG (main): Numero di credenziali trovate in Uni_credential.json: {len(emitted_credentials)}")

    for i, cred_dict in enumerate(emitted_credentials):
        cred_holder_id = cred_dict.get("holder", {}).get("id")

        print(f"DEBUG (main): Esaminando credenziale {i+1}/{len(emitted_credentials)}: ID={cred_dict.get('id')}, Holder_ID nel file Uni: {cred_holder_id}")

        if str(cred_holder_id) == str(student_wallet_obj.student_matricola):
            print(f"DEBUG (main): Trovata corrispondenza matricola per credenziale {cred_dict.get('id')}.")

            # Recupera la chiave Fernet cifrata e il soggetto cifrato
            encrypted_subject = cred_dict.get("credentialSubject", {}).get("encrypted_data")
            encrypted_fernet_key_for_subject = cred_dict.get("credentialSubject", {}).get("encrypted_fernet_key")

            if encrypted_subject and encrypted_fernet_key_for_subject:
                try:
                    # Decifra la chiave Fernet specifica per questa credenziale usando la chiave privata RSA dello studente
                    decrypted_fernet_key_bytes = student_private_key.decrypt(
                        bytes.fromhex(encrypted_fernet_key_for_subject),
                        padding.OAEP(
                            mgf=padding.MGF1(hashes.SHA256()),
                            algorithm=hashes.SHA256(),
                            label=None
                        )
                    )
                    fernet_credential_obj = Fernet(decrypted_fernet_key_bytes)
                    print(f"DEBUG (main): Chiave Fernet per credenziale '{cred_dict.get('id')}' decifrata con successo.")

                    # Decifra il soggetto della credenziale usando la chiave Fernet
                    decrypted_subject_bytes = fernet_credential_obj.decrypt(base64.urlsafe_b64decode(encrypted_subject))
                    decrypted_subject = json.loads(decrypted_subject_bytes.decode('utf-8'))

                    # Aggiorna il dizionario con il soggetto decifrato (rimuovi la chiave cifrata qui per la presentazione)
                    cred_dict["credentialSubject"] = decrypted_subject # Correggi il nome del campo in "credentialSubject"
                    if "encrypted_fernet_key" in cred_dict.get("credentialSubject", {}):
                        del cred_dict["credentialSubject"]["encrypted_fernet_key"] # Rimuovi la chiave cifrata per la pulizia

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
                    print(f"ERRORE (main): Impossibile decifrare la credenziale '{cred_dict.get('id')}': {e}. Assicurati che la chiave Fernet sia stata cifrata correttamente con la chiave pubblica dello studente e che la chiave privata sia corretta.")
            else:
                print(f"AVVISO (main): Credenziale '{cred_dict.get('id')}' senza dati cifrati o chiave Fernet cifrata.")
        else:
            print(f"DEBUG (main): La matricola della credenziale ({cred_holder_id}) NON corrisponde alla matricola dello studente ({student_wallet_obj.student_matricola}). Saltata.")

    if new_credentials_added:
        student_wallet_obj.save_wallet_to_file()
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

logged_in_email, logged_in_password, logged_in_id = None, None, None

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
    current_email = logged_in_email
    current_id = logged_in_id

elif scelta == "a":
    logged_in_email, logged_in_password, logged_in_id = accedi_utente(role_choice)
    if not logged_in_email:
        print("Accesso fallito o incompleto. Terminando il programma.")
        exit()
    # Le variabili globali current_email, current_role, current_id sono già impostate
    # all'interno di accedi_utente se l'accesso ha successo.
    current_role = role_choice # Assicurati che current_role sia impostato in base alla scelta iniziale

else:
    print("Scelta non valida. Terminando il programma.")
    exit()

# Inizializza il simulatore di blockchain (se usato nel progetto)
blockchain_register = BlockchainSimulator()

# Inizializza il wallet dello studente (solo per studenti)
student_wallet = None
if current_role == "s":
    student_wallet = StudentWallet(current_id) # Il wallet è inizializzato con la matricola decifrata
    print(f"Wallet dello studente {current_email} inizializzato con matricola: {current_id}.")

    # Carica i dati personali e le credenziali nel wallet
    # Qui il wallet si occupa di caricare i dati personali dal suo file, se esiste
    # e recuperare le credenziali pertinenti.
    if logged_in_email and student_wallet.load_student_data_and_credentials(logged_in_email, logged_in_password):
        print("Dati personali e credenziali caricati nel wallet.")
        # CHIAMATA ALLA FUNZIONE PER RECUPERARE E AGGIUNGERE LE CREDENZIALI
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
            if blockchain_register.is_revoked(credential_id):
                print("Credenziale revocata, non è possibile fare la presentazione selettiva")
            uni_email = input("Inserisci l'email dell'università a cui va presentata la credenziale: ")
            try:
                with open('users.json', "r") as f:
                    for line in f:
                        try:
                            utente = json.loads(line)
                            if utente.get("email") == uni_email and utente.get("role") == "u":
                                continue
                        except json.JSONDecodeError:
                            print(f"Riga malformata nel file: {riga.strip()}")
                        except FileNotFoundError:
                            print(f"File {path_file} non trovato.")
            except Exception as e:
                print(f"Errore durante la lettura del file: {e}")

            attributes_to_reveal_str = input("Specifica gli attributi da rivelare scegliendo tra\ncourseName,grade,ectsCredits,issueSemester,courseCompleted,courseDescription(separati da virgola, es. courseName,grade,ectsCredits): ")
            attributes_to_reveal = [attr.strip() for attr in attributes_to_reveal_str.split(",") if attr.strip()]

            try:
                selective_presentation = student_wallet.generate_selective_presentation(credential_id, attributes_to_reveal)
                print("Presentazione selettiva generata:")
                print(json.dumps(selective_presentation, indent=2))
                last_colon_index = credential_id.rfind(':')
                result_sequence= credential_id[last_colon_index + 1:]

                output_directory = os.path.join(os.getcwd(), uni_email + "_selective_cred")
                filename = os.path.join(output_directory, f"presentazione_{result_sequence}.json")

                # Create the directory if it doesn't exist
                os.makedirs(output_directory, exist_ok=True) # Use exist_ok=True to avoid error if dir exists

                uni_public_key = load_public_key(uni_email)
                if uni_public_key is None:
                    print(f"ERRORE: Impossibile caricare la chiave pubblica dell'università {uni_email}. Non posso cifrare la credenziale.")
                    continue

                print("DEBUG: Generazione e cifratura della chiave di sessione per il soggetto della credenziale...")
                credential_fernet_key = Fernet.generate_key()
                fernet_credential_obj = Fernet(credential_fernet_key)

                encrypted_fernet_key_for_subject = uni_public_key.encrypt(
                    credential_fernet_key,
                    padding.OAEP(
                        mgf=padding.MGF1(hashes.SHA256()),
                        algorithm=hashes.SHA256(),
                        label=None
                    )
                ).hex() # Converti in esadecimale

                print("DEBUG: Chiave Fernet per soggetto credenziale generata e cifrata con RSA dello studente.")
                selective_presentation["credentialSubject"]["encrypted_fernet_key"] = encrypted_fernet_key_for_subject
                selective_presentation["credentialSubject"]["encrypted_data"] = base64.urlsafe_b64encode(fernet_credential_obj.encrypt(json.dumps(selective_presentation).encode())).decode('ascii')

                # Write/append the JSON data to the file
                # To append valid JSON objects, you might want to read existing data, append, and rewrite
                # Or, if each line should be a separate JSON object, just append with a newline
                with open(filename, "a") as f: # Use "a" for append mode
                    json.dump(selective_presentation, f, indent=2)
                    f.write("\n") # Add a newline to separate JSON objects if appending multiple
                print(f"Presentazione selettiva salvata su file: {filename}")

            except ValueError as ve:
                print(f"ERRORE: {ve}")
            except Exception as e:
                print(f"ERRORE durante la generazione della presentazione selettiva: {e}")
        else:
            print("Wallet studente non inizializzato.")


    elif current_role == "u" and scelta == "1":
        print("\n--- Emissione Credenziale ---")

        student_email_for_public_key = input("Inserisci l'email dello studente a cui emettere la credenziale: ")
        # NUOVA RIGA: Chiedi esplicitamente la matricola allo studente
        student_matricola_to_issue = input(f"Inserisci la MATRICOLA dello studente '{student_email_for_public_key}' (DEVE ESSERE QUELLA CORRETTA): ")

        # Carica la chiave pubblica dello studente per cifrare il soggetto della credenziale
        student_public_key = load_public_key(student_email_for_public_key)
        if student_public_key is None:
            print(f"ERRORE: Impossibile caricare la chiave pubblica dello studente {student_email_for_public_key}. Non posso cifrare la credenziale.")
            continue

        # Per i dati personali nel subject, useremo dei placeholder.
        # In un sistema reale, l'università avrebbe questi dati dal suo database interno.
        # PER SIMPLICITA', USA I DATI CHE HAI IMPOSTATO DURANTE LA REGISTRAZIONE DELLO STUDENTE.
        # Ad esempio, se hai impostato Mario Rossi 2000-01-01 in registra_studente, usa gli stessi qui.
        student_first_name = "Mario"
        student_last_name = "Rossi"
        student_date_of_birth = "2000-01-01"

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
            "studentId": student_matricola_to_issue, # Usa la matricola inserita dall'università
            "firstName": student_first_name,
            "lastName": student_last_name,
            "dateOfBirth": student_date_of_birth,
            "courseName": course_name,
            "grade": grade,
            "ectsCredits": ects,
            "issueSemester": semester,
            "courseCompleted": completed,
            "courseDescription": description
        }

        # --- Cifratura del soggetto della credenziale con Fernet (chiave cifrata con la chiave pubblica RSA dello studente) ---
        print("DEBUG: Generazione e cifratura della chiave di sessione per il soggetto della credenziale...")
        credential_fernet_key = Fernet.generate_key()
        fernet_credential_obj = Fernet(credential_fernet_key)

        # Cifra la chiave Fernet con la chiave pubblica RSA dello studente
        encrypted_fernet_key_for_subject = student_public_key.encrypt(
            credential_fernet_key,
            padding.OAEP(
                mgf=padding.MGF1(hashes.SHA256()),
                algorithm=hashes.SHA256(),
                label=None
            )
        ).hex() # Converti in esadecimale

        print("DEBUG: Chiave Fernet per soggetto credenziale generata e cifrata con RSA dello studente.")

        # Cifra i dati della credenziale con la chiave Fernet
        encrypted_credential_subject = base64.urlsafe_b64encode(fernet_credential_obj.encrypt(json.dumps(credential_subject_data).encode())).decode('ascii')

        # Ora la credenziale includerà sia il soggetto cifrato che la chiave Fernet cifrata
        issued_credential = AcademicCredential(
            id=credential_id,
            issuer_id=current_id, # current_id è l'ID dell'università
            holder_id=student_matricola_to_issue, # Usa la matricola inserita dall'università
            credential_subject={
                "encrypted_data": encrypted_credential_subject,
                "encrypted_fernet_key": encrypted_fernet_key_for_subject # Includi la chiave Fernet cifrata
            },
            issuance_date=datetime.now().isoformat()
        )

        # Per la firma, l'università usa la sua chiave privata
        uni_private_key = load_private_key(current_email, logged_in_password)
        if uni_private_key is None:
            print("ERRORE: Impossibile caricare la chiave privata dell'università per firmare la credenziale.")
            continue # O return se preferisci uscire dalla funzione al primo errore

        issued_credential.sign(uni_private_key, revocation_reference)

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
        # Se la credenziale non è ancora stata revocata, la revoca e la registra.
        # Se invece il tuo scopo è NON revocarla all'emissione, rimuovi o commenta il blocco seguente.
        if not blockchain_register.is_revoked(revocation_reference):
            blockchain_register.revoke_credential(revocation_reference)
            print(f"Credenziale '{credential_id}' revocata con successo e aggiunta al registro simulato.")
        # Se invece non vuoi che venga revocata all'emissione, non aggiungere la riga sopra.
        # Il tuo output precedente diceva "Credenziale urn:vc:example:1753030390 emessa con successo per lo studente 344!"
        # e poi "Credenziale 'urn:vc:example:1753030390' revocata con successo e aggiunta al registro simulato.".
        # Questo implica che la revoca avviene immediatamente dopo l'emissione.
        # Ho ripristinato il comportamento visto nel tuo output.

        print(f"Credenziale emessa con successo e registrata sulla blockchain (come non revocata, ma poi immediatamente revocata se la logica lo prevede).")
        print(f"Credenziale {credential_id} emessa con successo per lo studente {student_matricola_to_issue}!")


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