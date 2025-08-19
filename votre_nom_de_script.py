import csv
from collections import Counter
from pymongo import MongoClient

# --- Configuration des fichiers et de la base de données ---
CSV_FILE_PATH = "healthcare_dataset.csv"
MONGO_HOST = "localhost"
MONGO_PORT = 27017
MONGO_DB_NAME = "healthcare_db"
MONGO_COLLECTION_NAME = "patients"

def check_pre_migration_integrity(file_path):
    """
    Vérifie l'intégrité des données dans le fichier CSV avant la migration.
    """
    print("--- Vérification de l'intégrité du fichier CSV (Avant la migration) ---")
    data = []
    with open(file_path, 'r', encoding='utf-8') as file:
        reader = csv.DictReader(file)
        headers = reader.fieldnames
        for row in reader:
            data.append(row)
            
    print(f"Nombre total de lignes (documents) : {len(data)}")
    
    # 1. Vérification des colonnes
    expected_headers = ['Name', 'Age', 'Gender', 'Blood Type', 'Medical Condition', 'Date of Admission', 'Doctor', 'Hospital', 'Insurance Provider', 'Billing Amount', 'Room Number', 'Admission Type', 'Discharge Date', 'Medication', 'Test Results']
    if set(headers) == set(expected_headers):
        print("✓ Toutes les colonnes attendues sont présentes.")
    else:
        print("✗ Les en-têtes de colonnes ne correspondent pas.")
        print(f"Attendus : {expected_headers}")
        print(f"Trouvés : {headers}")
        
    # 2. Vérification des valeurs manquantes et des doublons
    missing_values = {header: 0 for header in expected_headers}
    duplicate_rows = 0
    
    # Utilisation d'une collection pour détecter les doublons
    data_tuples = [tuple(row.values()) for row in data]
    row_counts = Counter(data_tuples)
    
    for row_tuple, count in row_counts.items():
        if count > 1:
            duplicate_rows += 1
            
    if duplicate_rows == 0:
        print("✓ Aucune ligne en double détectée.")
    else:
        print(f"✗ {duplicate_rows} ligne(s) en double détectée(s).")

    # Vérification des valeurs manquantes dans les colonnes clés
    for row in data:
        for header in ['Age', 'Billing Amount', 'Room Number']:
            if not row.get(header) or row[header].strip() == '':
                missing_values[header] += 1
    
    print("\nAnalyse des valeurs manquantes dans les colonnes clés :")
    for header, count in missing_values.items():
        if count == 0:
            print(f"✓ La colonne '{header}' ne contient aucune valeur manquante.")
        else:
            print(f"✗ La colonne '{header}' contient {count} valeur(s) manquante(s).")
            
    return data

def check_post_migration_integrity(client):
    """
    Vérifie l'intégrité des données dans la base de données MongoDB après la migration.
    """
    print("\n--- Vérification de l'intégrité de la base de données MongoDB (Après la migration) ---")
    db = client[MONGO_DB_NAME]
    collection = db[MONGO_COLLECTION_NAME]
    
    # 1. Vérification du nombre de documents
    count_after_migration = collection.count_documents({})
    if count_after_migration == 55500:
        print("✓ Le nombre total de documents correspond (55500).")
    else:
        print(f"✗ Le nombre de documents est incorrect. Trouvé : {count_after_migration}")
    
    # 2. Vérification des types de données
    print("\nVérification des types de données dans les documents :")
    sample_doc = collection.find_one()
    
    # Récupérer un document pour vérifier les types
    if sample_doc:
        # Vérifier si les champs clés sont des nombres
        if isinstance(sample_doc.get('Age'), int):
            print("✓ Le champ 'Age' est de type entier (int).")
        else:
            print("✗ Le champ 'Age' n'est pas de type entier.")
            
        if isinstance(sample_doc.get('Billing Amount'), (int, float)):
            print("✓ Le champ 'Billing Amount' est de type float.")
        else:
            print("✗ Le champ 'Billing Amount' n'est pas de type float.")

        if isinstance(sample_doc.get('Room Number'), int):
            print("✓ Le champ 'Room Number' est de type entier (int).")
        else:
            print("✗ Le champ 'Room Number' n'est pas de type entier.")
    else:
        print("✗ Impossible de trouver un document échantillon pour la vérification des types.")

    # 3. Recherche de valeurs manquantes (null)
    print("\nRecherche de valeurs manquantes (null) dans la base de données :")
    missing_age = collection.count_documents({"Age": None})
    missing_billing = collection.count_documents({"Billing Amount": None})
    missing_room = collection.count_documents({"Room Number": None})
    
    if missing_age == 0:
        print("✓ Aucune valeur 'null' n'a été trouvée pour la colonne 'Age'.")
    else:
        print(f"✗ {missing_age} valeur(s) 'null' trouvée(s) pour la colonne 'Age'.")

    if missing_billing == 0:
        print("✓ Aucune valeur 'null' n'a été trouvée pour la colonne 'Billing Amount'.")
    else:
        print(f"✗ {missing_billing} valeur(s) 'null' trouvée(s) pour la colonne 'Billing Amount'.")
        
    if missing_room == 0:
        print("✓ Aucune valeur 'null' n'a été trouvée pour la colonne 'Room Number'.")
    else:
        print(f"✗ {missing_room} valeur(s) 'null' trouvée(s) pour la colonne 'Room Number'.")

def run_integrity_checks():
    """
    Fonction principale qui orchestre les vérifications.
    """
    try:
        # Étape 1 : Vérification avant la migration (sur le fichier CSV)
        check_pre_migration_integrity(CSV_FILE_PATH)
        
        # Étape 2 : Vérification après la migration (sur la base de données)
        client = MongoClient(MONGO_HOST, MONGO_PORT)
        check_post_migration_integrity(client)
        client.close()
        
    except Exception as e:
        print(f"Une erreur s'est produite lors de la vérification : {e}")

if __name__ == "__main__":
    run_integrity_checks()
