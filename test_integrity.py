import csv
from pymongo import MongoClient
import pytest

# Configuration des fichiers et de la base de données
CSV_FILE_PATH = "healthcare_dataset.csv"
MONGO_HOST = "localhost"
MONGO_PORT = 27017
MONGO_DB_NAME = "healthcare_db"
MONGO_COLLECTION_NAME = "patients"

def get_csv_data():
    """
    Fonction utilitaire pour lire les données du fichier CSV.
    """
    data = []
    with open(CSV_FILE_PATH, 'r', encoding='utf-8') as file:
        reader = csv.DictReader(file)
        for row in reader:
            data.append(row)
    return data

@pytest.fixture(scope="session")
def mongo_client():
    """
    Fixture Pytest pour se connecter à la base de données.
    La connexion est partagée entre les tests pour plus d'efficacité.
    """
    try:
        client = MongoClient(MONGO_HOST, MONGO_PORT, serverSelectionTimeoutMS=5000)
        # La ligne suivante déclenche une exception si le serveur n'est pas accessible
        client.admin.command('ping')
        return client
    except Exception as e:
        pytest.fail(f"Impossible de se connecter à MongoDB. Assurez-vous que le serveur est démarré. Erreur: {e}")

# --- Tests d'intégrité avant la migration (sur le fichier CSV) ---

def test_csv_row_count():
    """
    Vérifie que le nombre de lignes dans le CSV est correct.
    """
    data = get_csv_data()
    # Le fichier contient 55500 lignes de données plus 1 ligne d'en-tête
    assert len(data) == 55500

def test_csv_columns():
    """
    Vérifie que les colonnes du CSV correspondent aux attentes.
    """
    data = get_csv_data()
    if not data:
        pytest.fail("Le fichier CSV est vide.")
    
    headers = list(data[0].keys())
    expected_headers = ['Name', 'Age', 'Gender', 'Blood Type', 'Medical Condition', 'Date of Admission', 'Doctor', 'Hospital', 'Insurance Provider', 'Billing Amount', 'Room Number', 'Admission Type', 'Discharge Date', 'Medication', 'Test Results']
    
    assert set(headers) == set(expected_headers)

# --- Tests d'intégrité après la migration (sur la base de données MongoDB) ---

def test_mongodb_document_count(mongo_client):
    """
    Vérifie que le nombre de documents dans la base de données est correct.
    """
    db = mongo_client[MONGO_DB_NAME]
    collection = db[MONGO_COLLECTION_NAME]
    
    count = collection.count_documents({})
    assert count == 55500

def test_mongodb_data_types(mongo_client):
    """
    Vérifie que les types de données ont été correctement convertis.
    """
    db = mongo_client[MONGO_DB_NAME]
    collection = db[MONGO_COLLECTION_NAME]
    
    # Récupérer un document échantillon
    sample_doc = collection.find_one()
    
    # Utilisation d'assertions pour vérifier les types
    assert isinstance(sample_doc.get('Age'), int)
    assert isinstance(sample_doc.get('Billing Amount'), float)
    assert isinstance(sample_doc.get('Room Number'), int)

def test_mongodb_no_missing_values(mongo_client):
    """
    Vérifie qu'il n'y a pas de valeurs nulles (valeurs manquantes) après la migration.
    """
    db = mongo_client[MONGO_DB_NAME]
    collection = db[MONGO_COLLECTION_NAME]
    
    # Compte le nombre de documents avec des valeurs nulles
    missing_age = collection.count_documents({"Age": None})
    missing_billing = collection.count_documents({"Billing Amount": None})
    missing_room = collection.count_documents({"Room Number": None})
    
    # Les assertions vérifient que le compte est bien zéro
    assert missing_age == 0
    assert missing_billing == 0
    assert missing_room == 0
