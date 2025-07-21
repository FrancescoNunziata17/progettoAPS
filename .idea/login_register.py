import os
import base64
from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.primitives.kdf.pbkdf2 import PBKDF2HMAC
from cryptography.hazmat.backends import default_backend

# --- Configurazione ---
# Numero di iterazioni: un valore elevato è cruciale per la sicurezza.
# Man mano che l'hardware diventa più veloce, questo valore dovrebbe essere aumentato.
# 600.000 è un buon compromesso tra sicurezza e prestazioni attuali.
ITERATIONS = 1200000

# Lunghezza della chiave derivata/hash. Per l'hashing, 32 byte (256 bit) sono standard.
HASH_LENGTH = 32 # Corrisponde a SHA256

# --- Funzioni per la Gestione delle Password ---

def hash_password(password: str) -> tuple[str, str]:
    """
    Genera un hash per la password fornita, insieme a un salt unico.
    Args:
        password (str): La password in chiaro da hashare.
    Returns:
        tuple[str, str]: Una tupla contenente l'hash della password (base64urlsafe encoded)
                         e il salt (esadecimale) da memorizzare.
    """
    # Converti la password da stringa a byte
    password_bytes = password.encode('utf-8')

    # Genera un salt crittograficamente sicuro e unico per ogni password
    salt = os.urandom(16)

    # Inizializza la funzione di derivazione della chiave
    kdf = PBKDF2HMAC(
        algorithm=hashes.SHA256(),
        length=HASH_LENGTH,
        salt=salt,
        iterations=ITERATIONS,
        backend=default_backend() # Specificare il backend è una buona pratica
    )

    # Deriva l'hash della password.
    # Fernet richiede la chiave in base64urlsafe; anche per l'hash è una buona scelta
    # per memorizzarlo come stringa.
    derived_key = kdf.derive(password_bytes)
    hashed_password_b64 = base64.urlsafe_b64encode(derived_key).decode('utf-8')

    # Restituisci l'hash e il salt (da salvare nel database)
    return hashed_password_b64, salt.hex()

def verify_password(password_to_check: str, stored_hash: str, stored_salt_hex: str) -> bool:
    """
    Verifica se la password fornita corrisponde all'hash memorizzato.
    Args:
        password_to_check (str): La password in chiaro inserita dall'utente.
        stored_hash (str): L'hash della password memorizzato nel database (base64urlsafe encoded).
        stored_salt_hex (str): Il salt memorizzato nel database (esadecimale).
    Returns:
        bool: True se la password corrisponde, False altrimenti.
    """
    # Converti la password da stringa a byte
    password_bytes = password_to_check.encode('utf-8')

    # Converti il salt esadecimale di nuovo in byte
    salt = bytes.fromhex(stored_salt_hex)

    # Inizializza la funzione di derivazione della chiave con lo stesso salt e iterazioni
    kdf = PBKDF2HMAC(
        algorithm=hashes.SHA256(),
        length=HASH_LENGTH,
        salt=salt,
        iterations=ITERATIONS,
        backend=default_backend()
    )

    # Deriva l'hash della password fornita dall'utente
    derived_key = kdf.derive(password_bytes)
    verified_hash_b64 = base64.urlsafe_b64encode(derived_key).decode('utf-8')

    # Confronta l'hash appena calcolato con l'hash memorizzato
    # Usa `compare_digest` per prevenire attacchi di tipo timing attack
    return verified_hash_b64 == stored_hash

# --- Esempio di Utilizzo ---
if __name__ == '__main__':
    user_password = "LaMiaSuperPasswordSegreta123!"

    print(f"Password utente da hashare: {user_password}\n")

    # 1. Hashing della password durante la registrazione o il cambio password
    hashed_pass, salt_value = hash_password(user_password)
    print(f"Hash generato (da salvare nel DB): {hashed_pass}")
    print(f"Salt generato (da salvare nel DB): {salt_value}\n")

    # --- Simula il processo di login ---
    # L'utente tenta di accedere con la password
    password_tentativo_corretto = "LaMiaSuperPasswordSegreta123!"
    password_tentativo_sbagliato = "PasswordSbagliata"

    # 2. Verifica della password durante il login
    print("Verifica password (corretta):")
    if verify_password(password_tentativo_corretto, hashed_pass, salt_value):
        print("Accesso CONCESSO!")
    else:
        print("Accesso NEGATO! (Errore nella verifica)")

    print("\nVerifica password (sbagliata):")
    if verify_password(password_tentativo_sbagliato, hashed_pass, salt_value):
        print("Accesso CONCESSO! (Questo non dovrebbe accadere)")
    else:
        print("Accesso NEGATO!")