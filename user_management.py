import bcrypt
import os
from pymongo import MongoClient
from pymongo.errors import ConnectionFailure

# Configuration de la connexion MongoDB
MONGO_URI = "mongodb://localhost:27017/"
DATABASE_NAME = "user_db"
COLLECTION_NAME = "users"

def get_mongo_client():
    """Tente d'établir une connexion au client MongoDB."""
    try:
        client = MongoClient(MONGO_URI)
        # La ligne suivante lancera une exception si la connexion échoue
        client.admin.command('ping')
        print("Connexion à MongoDB réussie.")
        return client
    except ConnectionFailure as e:
        print(f"Erreur de connexion à MongoDB : {e}")
        return None

def hash_password(password):
    """
    Hache un mot de passe en utilisant un sel généré de manière aléatoire.
    Le sel est intégré au hachage pour assurer un hachage unique pour chaque mot de passe.
    """
    # Le mot de passe doit être encodé en octets
    password_bytes = password.encode('utf-8')
    # Un sel est généré, qui sera intégré au hachage
    salt = bcrypt.gensalt()
    # Le mot de passe est haché avec le sel
    hashed_password = bcrypt.hashpw(password_bytes, salt)
    return hashed_password

def register_user(client, username, password):
    """
    Enregistre un nouvel utilisateur en hachant son mot de passe avant de le sauvegarder.
    """
    db = client[DATABASE_NAME]
    users_collection = db[COLLECTION_NAME]

    # Vérifier si l'utilisateur existe déjà
    if users_collection.find_one({"username": username}):
        print(f"Échec de l'enregistrement : L'utilisateur '{username}' existe déjà.")
        return False

    # Hacher le mot de passe avant de le stocker
    hashed_password = hash_password(password)

    # Créer un document utilisateur
    user_document = {
        "username": username,
        "password_hash": hashed_password
    }

    # Insérer le document dans la base de données
    try:
        users_collection.insert_one(user_document)
        print(f"Succès de l'enregistrement : L'utilisateur '{username}' a été créé.")
        return True
    except Exception as e:
        print(f"Erreur lors de l'insertion de l'utilisateur : {e}")
        return False

def login_user(client, username, password):
    """
    Vérifie les informations de connexion d'un utilisateur en comparant
    le mot de passe saisi avec le hachage stocké.
    """
    db = client[DATABASE_NAME]
    users_collection = db[COLLECTION_NAME]

    # Trouver l'utilisateur par nom d'utilisateur
    user_document = users_collection.find_one({"username": username})

    if user_document:
        # Extraire le hachage stocké
        stored_hash = user_document.get("password_hash")
        # Vérifier si le mot de passe saisi correspond au hachage
        if bcrypt.checkpw(password.encode('utf-8'), stored_hash):
            print(f"Connexion réussie : Bienvenue, {username} !")
            return True
        else:
            print("Échec de la connexion : Mot de passe incorrect.")
            return False
    else:
        print("Échec de la connexion : Nom d'utilisateur non trouvé.")
        return False

if __name__ == "__main__":
    # Connexion à MongoDB
    mongo_client = get_mongo_client()
    if not mongo_client:
        exit()

    # Exemple d'utilisation
    print("\n--- Test 1 : Enregistrement d'un nouvel utilisateur ---")
    register_user(mongo_client, "utilisateur_test", "motdepasse123")

    print("\n--- Test 2 : Tentative de connexion avec le bon mot de passe ---")
    login_user(mongo_client, "utilisateur_test", "motdepasse123")

    print("\n--- Test 3 : Tentative de connexion avec un mot de passe incorrect ---")
    login_user(mongo_client, "utilisateur_test", "mauvaismotdepasse")

    print("\n--- Test 4 : Tentative de connexion avec un nom d'utilisateur inexistant ---")
    login_user(mongo_client, "utilisateur_inconnu", "unmotdepassequelconque")

    # Fermer la connexion
    mongo_client.close()
    print("\nConnexion à MongoDB fermée.")
