import hashlib
import json

class MerkleTree:
    """
    Implementa un Merkle Tree per la verifica dell'integrità dei dati e la generazione di prove di inclusione.
    """
    def __init__(self, data_list: list):
        """
        Inizializza il Merkle Tree con una lista di dati.
        Ogni elemento della lista viene prima convertito in una stringa JSON (per dati complessi)
        e poi hashato per formare una foglia.
        """
        # Assicurati che i dati siano ordinati e convertiti in stringhe per hashing consistente
        self.data_list = sorted([json.dumps(item, sort_keys=True) if isinstance(item, (dict, list)) else str(item) for item in data_list])

        # Le foglie sono gli hash dei dati originali
        self.leaves = [hashlib.sha256(item.encode('utf-8')).hexdigest() for item in self.data_list]

        # La struttura dell'albero (lista di livelli)
        if not self.leaves:
            self.tree = []
            self.root = None
        else:
            self.tree = [self.leaves] # Il primo livello sono le foglie
            self._build_tree()
            self.root = self.tree[-1][0] # La radice è l'unico nodo dell'ultimo livello

    def _build_tree(self):
        """Costruisce l'albero di hash livello per livello."""
        current_level = self.leaves
        while len(current_level) > 1:
            next_level = []
            for i in range(0, len(current_level), 2):
                left_child = current_level[i]
                right_child = current_level[i + 1] if i + 1 < len(current_level) else left_child # Gestisce un numero dispari di nodi duplicando l'ultimo

                # Concatena gli hash e calcola l'hash del genitore
                combined_hash = hashlib.sha256((left_child + right_child).encode('utf-8')).hexdigest()
                next_level.append(combined_hash)
            self.tree.append(next_level)
            current_level = next_level

    def get_root(self) -> str:
        """Restituisce l'hash della radice Merkle."""
        return self.root

    def generate_proof(self, data_item) -> list:
        """
        Genera una prova di inclusione (Merkle Proof) per un dato specifico.
        La prova è una lista di hash dei nodi "fratelli" lungo il percorso dalla foglia alla radice.
        """
        # Normalizza e calcola l'hash dell'elemento da verificare
        normalized_data_item = json.dumps(data_item, sort_keys=True) if isinstance(data_item, (dict, list)) else str(data_item)
        item_hash = hashlib.sha256(normalized_data_item.encode('utf-8')).hexdigest()

        try:
            leaf_index = self.leaves.index(item_hash)
        except ValueError:
            # L'elemento non è contenuto nelle foglie
            return []

        proof = []
        current_index = leaf_index

        # Salta la radice (ultimo livello) perché non fa parte della prova
        for level in self.tree[:-1]:
            is_right_child = (current_index % 2 != 0)  # Nodo destro se indice è dispari
            sibling_index = current_index - 1 if is_right_child else current_index + 1

            # Aggiungi il nodo fratello alla lista delle prove se esiste
            if sibling_index < len(level):  # Verifica che `sibling_index` esista
                proof.append({
                    "hash": level[sibling_index],
                    "position": "left" if is_right_child else "right"
                })

            # Calcola l'indice del genitore per il livello successivo
            current_index //= 2

        return proof

    @staticmethod
    def verify_proof(data_item, proof: list, expected_merkle_root: str) -> bool:
        """
        Verifica una prova di inclusione (Merkle Proof) per un dato.
        """
        if not proof and expected_merkle_root is not None:
            # Se non ci sono foglie e la radice è None, e la prova è vuota, è un caso valido per un albero vuoto
            if expected_merkle_root is None:
                return True
            return False # Se la prova è vuota ma la radice attesa non è None, c'è un problema

        # Normalizza e hasha l'elemento dati per ottenere la foglia iniziale
        normalized_data_item = json.dumps(data_item, sort_keys=True) if isinstance(data_item, (dict, list)) else str(data_item)
        current_hash = hashlib.sha256(normalized_data_item.encode('utf-8')).hexdigest()

        for step in proof:
            sibling_hash = step["hash"]
            position = step["position"]

            if position == "left":
                current_hash = hashlib.sha256((sibling_hash + current_hash).encode('utf-8')).hexdigest()
            elif position == "right":
                current_hash = hashlib.sha256((current_hash + sibling_hash).encode('utf-8')).hexdigest()
            else:
                return False # Posizione non valida nella prova

        return current_hash == expected_merkle_root