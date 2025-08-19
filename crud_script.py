import csv
from pymongo import MongoClient

# Configuration de la base de données MongoDB
MONGO_HOST = "localhost"
MONGO_PORT = 27017
MONGO_DB_NAME = "healthcare_db"
MONGO_COLLECTION_NAME = "patients"

def create_document(collection):
    """
    Opération CREATE : Insère un nouveau document.
    """
    print("\n--- Opération CREATE (Insertion d'un nouveau document) ---")
    new_patient = {
      "Name": "Clara Dubois",
      "Age": 35,
      "Gender": "Female",
      "Medical Condition": "Diabetes",
      "Billing Amount": 14500.00,
      "Room Number": 305,
      "Admission Type": "Elective"
    }
    try:
        result = collection.insert_one(new_patient)
        print(f"Document inséré avec succès. ID : {result.inserted_id}")
    except Exception as e:
        print(f"Erreur lors de l'insertion du document : {e}")

def read_documents(collection):
    """
    Opération READ : Lit des documents de la collection.
    """
    print("\n--- Opération READ (Lecture des documents) ---")
    
    # Trouver un document par son nom
    print("\n- Recherche d'un document par son nom (Bobby JacksOn) :")
    patient = collection.find_one({"Name": "Bobby JacksOn"})
    if patient:
        print(f"Document trouvé : {patient}")
    else:
        print("Document non trouvé.")
        
    # Trouver tous les documents avec une condition médicale spécifique
    print("\n- Recherche de tous les patients atteints de 'Cancer' :")
    cancer_patients = collection.find({"Medical Condition": "Cancer"})
    count = 0
    for doc in cancer_patients:
        print(doc)
        count += 1
    print(f"{count} documents trouvés.")

def update_document(collection):
    """
    Opération UPDATE : Met à jour un document existant.
    """
    print("\n--- Opération UPDATE (Mise à jour d'un document) ---")
    try:
        # Critère de recherche du document à mettre à jour
        query = {"Name": "Clara Dubois"}
        # Les mises à jour à effectuer
        new_values = {"$set": {"Billing Amount": 16000.00}}
        result = collection.update_one(query, new_values)
        
        print(f"{result.matched_count} document(s) correspondants trouvés.")
        print(f"{result.modified_count} document(s) mis à jour.")
    except Exception as e:
        print(f"Erreur lors de la mise à jour du document : {e}")

def delete_document(collection):
    """
    Opération DELETE : Supprime un document.
    """
    print("\n--- Opération DELETE (Suppression d'un document) ---")
    try:
        # Critère de suppression
        query = {"Name": "Clara Dubois"}
        result = collection.delete_one(query)
        
        print(f"{result.deleted_count} document(s) supprimé(s).")
    except Exception as e:
        print(f"Erreur lors de la suppression du document : {e}")

def run_crud_operations():
    """
    Fonction principale pour exécuter toutes les opérations CRUD.
    """
    try:
        # Connexion à MongoDB
        client = MongoClient(MONGO_HOST, MONGO_PORT)
        db = client[MONGO_DB_NAME]
        collection = db[MONGO_COLLECTION_NAME]
        
        print("Connexion établie. Lancement des opérations CRUD...")
        
        # Lancement des opérations
        create_document(collection)
        read_documents(collection)
        update_document(collection)
        read_documents(collection) # Relit pour voir la mise à jour
        delete_document(collection)
        read_documents(collection) # Relit pour voir la suppression
        
    except Exception as e:
        print(f"Une erreur s'est produite lors de l'exécution : {e}")
    finally:
        client.close()
        print("\nConnexion à MongoDB fermée.")

if __name__ == "__main__":
    run_crud_operations()
