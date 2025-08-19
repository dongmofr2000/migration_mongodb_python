import csv
from pymongo import MongoClient

# --- Configuration de la base de données MongoDB ---
MONGO_HOST = "localhost"
MONGO_PORT = 27017
MONGO_DB_NAME = "healthcare_db"
MONGO_COLLECTION_NAME = "patients"

# --- Configuration du fichier CSV ---
CSV_FILE_PATH = "healthcare_dataset.csv"

def run_migration():
    """
    Lit le fichier CSV et migre les données vers MongoDB.
    """
    try:
        # Connexion à MongoDB
        client = MongoClient(MONGO_HOST, MONGO_PORT)
        db = client[MONGO_DB_NAME]
        collection = db[MONGO_COLLECTION_NAME]

        print(f"Connexion établie à la base de données '{MONGO_DB_NAME}'...")
        
        # Supprime les données précédentes pour éviter les doublons
        collection.delete_many({})
        print("Collection 'patients' vidée pour la nouvelle migration.")

        data_to_insert = []
        with open(CSV_FILE_PATH, 'r', encoding='utf-8') as file:
            reader = csv.DictReader(file)
            
            # Boucle sur chaque ligne du fichier CSV
            for row in reader:
                # Ajout de vérifications pour gérer les valeurs manquantes ou vides
                try:
                    # Conversion de Age
                    if row.get('Age'):
                        row['Age'] = int(row['Age'])
                    else:
                        row['Age'] = None # Ou 0, ou un autre valeur par défaut

                    # Conversion de Billing Amount
                    if row.get('Billing Amount'):
                        # Utilise replace(',', '.') pour gérer les virgules dans les nombres décimaux
                        row['Billing Amount'] = float(row['Billing Amount'].replace(',', '.'))
                    else:
                        row['Billing Amount'] = None
                        
                    # Conversion de Room Number
                    if row.get('Room Number'):
                        row['Room Number'] = int(row['Room Number'])
                    else:
                        row['Room Number'] = None
                        
                except (ValueError, TypeError) as e:
                    print(f"Erreur de conversion de type pour la ligne : {row}. Ignorée. Erreur: {e}")
                    continue

                data_to_insert.append(row)
        
        if data_to_insert:
            # Insère toutes les données en une seule fois pour plus d'efficacité
            collection.insert_many(data_to_insert)
            print(f"Migration terminée ! {len(data_to_insert)} documents insérés dans la collection 'patients'.")
        else:
            print("Aucune donnée trouvée dans le fichier CSV.")

    except Exception as e:
        print(f"Une erreur s'est produite lors de la migration : {e}")
    finally:
        client.close()
        print("Connexion à MongoDB fermée.")

if __name__ == "__main__":
    run_migration()