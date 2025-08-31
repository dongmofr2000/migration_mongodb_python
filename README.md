Projet de Migration de Données : CSV vers MongoDB
Vue d'ensemble

Ce projet a pour but d'automatiser et de sécuriser la migration d'un grand jeu de données (healthcare_dataset.csv) vers une base de données MongoDB. Il est composé de deux scripts Python distincts mais complémentaires :

    migration.py : Le cœur du processus. Il lit, transforme et charge les données.
    test_integrity.py : Un script de test qui utilise le framework pytest pour vérifier l'intégrité des données avant et après la migration.

Composants du projet
1. Script de Migration (migration.py)

Ce script suit le processus ETL (Extract, Transform, Load) pour une migration fiable :

    Extraction : Il lit le fichier healthcare_dataset.csv en utilisant la bibliothèque csv.
    Transformation : Il convertit les types de données pour qu'ils soient corrects dans MongoDB. Les chaînes de caractères pour 'Age', 'Billing Amount' et 'Room Number' sont converties en types numériques (int et float). Les dates sont converties en objets datetime.
    Chargement : Il se connecte à votre base de données MongoDB et insère les documents. La collection cible est vidée avant l'insertion pour garantir que la migration se fait sur une base propre.

2. Script de Tests d'Intégrité (test_integrity.py)

L'objectif de ce script est de vous assurer que la migration a été effectuée correctement, sans perte ni corruption de données. Il contient plusieurs tests automatisés :

    Tests pré-migration : Ils vérifient le fichier CSV source pour s'assurer que le nombre de lignes et les en-têtes de colonnes sont corrects.
    Tests post-migration : Ils se connectent à la base de données MongoDB pour vérifier que :
        Le nombre de documents importés est le bon.
        Les types de données des champs clés (Age, Billing Amount, Room Number) sont corrects.
        Aucune valeur null n'a été introduite pour ces champs après la migration.

Prérequis

Avant de lancer les scripts, assurez-vous d'avoir installé les logiciels suivants sur votre machine :

    Python 3.x
    MongoDB (serveur)

Vous devez également installer les bibliothèques Python nécessaires via pip :
pip install pymongo pandas pytest
Installation et utilisation

    Clonez ce dépôt sur votre machine locale :
    git clone https://github.com/dongmofr2000/migration\_mongodb\_python.git

    Naviguez vers le dossier du projet :
    cd migration_mongodb_python

    Placez votre fichier CSV (healthcare_dataset.csv) à la racine de ce dossier.

    Assurez-vous que votre serveur MongoDB est en cours d'exécution sur localhost:27017.

    Exécutez la migration depuis votre terminal :
    python migration.py

    Ce script affichera la progression et le résultat de l'importation.

Lancement des tests
Pour vérifier que la migration s'est bien déroulée, exécutez le script de tests avec la commande pytest :
pytest test_integrity.py
```pytest` exécutera automatiquement tous les tests définis dans le fichier `test_integrity.py` et affichera un rapport détaillé des résultats, en indiquant quels tests ont réussi ou échoué.


un schéma NoSQL pertinent
{
  "_id": "<ObjectId>",
  "user_id": "<string>",
  "username": "<string>",
  "email": "<string>",
  "roles": [
    {
      "role_id": "<string>",
      "name": "<string>"
    }
  ],
  "password_hash": "<string>",
  "is_active": "<boolean>",
  "last_login": "<ISODate>",
  "created_at": "<ISODate>"
  un système d'authentification conforme aux régulations en vigueur

# -*- coding: utf-8 -*-

import os
import secrets
from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.primitives.kdf.scrypt import Scrypt
from cryptography.hazmat.backends import default_backend
import jwt
import time
from datetime import datetime, timedelta

# In-memory "database" to store user information for this example
# In a real application, you would use a database like MongoDB or PostgreSQL.
# The user data includes hashed passwords, so it's compliant with data protection principles.
USERS = {}

# We use scrypt for password hashing. It is a modern, slow, memory-hard algorithm.
# This makes brute-force attacks extremely difficult, which is a key requirement for
# GDPR's "security by design" principle.
SCRYPT_SALT_LENGTH = 16
SCRYPT_KEY_LENGTH = 32
SCRYPT_N = 2**14  # A high iteration count to make it slow
SCRYPT_R = 8      # Block size
SCRYPT_P = 1      # Parallelization factor

# A secret key for signing JWT tokens. This MUST be kept secret.
# In a production environment, use an environment variable or a secure vault.
JWT_SECRET_KEY = secrets.token_urlsafe(32)

# Token expiration time. Shorter times are more secure.
# This is a key principle of data minimization and security by design.
JWT_EXPIRATION_DELTA = timedelta(hours=1)

def hash_password(password):
    """
    Hashes a password using a unique salt and the scrypt algorithm.
    The salt is stored with the hashed password.
    """
    salt = os.urandom(SCRYPT_SALT_LENGTH)
    kdf = Scrypt(
        salt=salt,
        length=SCRYPT_KEY_LENGTH,
        n=SCRYPT_N,
        r=SCRYPT_R,
        p=SCRYPT_P,
        backend=default_backend()
    )
    hashed_password = kdf.derive(password.encode('utf-8'))
    return salt + hashed_password

def verify_password(password, hashed_password_with_salt):
    """
    Verifies a password against the stored hash.
    """
    salt = hashed_password_with_salt[:SCRYPT_SALT_LENGTH]
    stored_hashed_password = hashed_password_with_salt[SCRYPT_SALT_LENGTH:]

    kdf = Scrypt(
        salt=salt,
        length=SCRYPT_KEY_LENGTH,
        n=SCRYPT_N,
        r=SCRYPT_R,
        p=SCRYPT_P,
        backend=default_backend()
    )
    try:
        kdf.verify(password.encode('utf-8'), stored_hashed_password)
        return True
    except Exception:
        return False

def generate_jwt_token(user_id, roles):
    """
    Generates a secure JSON Web Token (JWT) with user data and expiration.
    The token is short-lived to minimize the risk of a breach.
    """
    payload = {
        'sub': user_id,  # Subject
        'roles': roles,
        'iat': datetime.now().timestamp(),  # Issued at
        'exp': (datetime.now() + JWT_EXPIRATION_DELTA).timestamp() # Expiration time
    }
    # HS256 is a standard and secure algorithm for this use case
    return jwt.encode(payload, JWT_SECRET_KEY, algorithm='HS256')

def decode_jwt_token(token):
    """
    Decodes and validates a JWT token.
    Returns the payload if valid, otherwise None.
    """
    try:
        # The JWT library handles verification of the signature and expiration time
        payload = jwt.decode(token, JWT_SECRET_KEY, algorithms=['HS256'])
        return payload
    except jwt.ExpiredSignatureError:
        print("Erreur : Le jeton a expiré.")
        return None
    except jwt.InvalidTokenError:
        print("Erreur : Jeton invalide.")
        return None

def register_user(user_id, password, roles):
    """
    Registers a new user, securely hashing the password.
    """
    if user_id in USERS:
        print(f"Erreur : L'utilisateur '{user_id}' existe déjà.")
        return False
    
    hashed_password = hash_password(password)
    USERS[user_id] = {
        'hashed_password': hashed_password,
        'roles': roles
    }
    print(f"Succès : L'utilisateur '{user_id}' a été enregistré avec les rôles {roles}.")
    return True

def login_user(user_id, password):
    """
    Authenticates a user and generates a JWT token upon success.
    """
    user_data = USERS.get(user_id)
    if not user_data:
        print("Erreur : Nom d'utilisateur ou mot de passe incorrect.")
        return None
    
    if verify_password(password, user_data['hashed_password']):
        token = generate_jwt_token(user_id, user_data['roles'])
        print(f"Succès : Connexion de '{user_id}'. Jeton généré.")
        return token
    else:
        print("Erreur : Nom d'utilisateur ou mot de passe incorrect.")
        return None

def protected_route(token, required_roles):
    """
    A simple function to demonstrate role-based access control.
    """
    payload = decode_jwt_token(token)
    if not payload:
        print("Accès refusé : Jeton invalide ou expiré.")
        return False
    
    user_roles = payload.get('roles', [])
    if not any(role in required_roles for role in user_roles):
        print(f"Accès refusé : Rôle insuffisant. Rôles requis : {required_roles}. Rôles de l'utilisateur : {user_roles}.")
        return False
        
    user_id = payload.get('sub')
    print(f"Accès accordé pour l'utilisateur '{user_id}' avec les rôles {user_roles}.")
    return True

# --- Démonstration du flux de travail ---

if __name__ == "__main__":
    print("--- Démonstration d'un système d'authentification sécurisé ---")
    print("\n1. Enregistrement des utilisateurs...")
    register_user("admin", "admin_secure_pass123", ["admin", "user"])
    register_user("user_standard", "pass_faible", ["user"])
    register_user("admin", "tentative", ["admin"]) # Ceci devrait échouer

    print("\n2. Connexion des utilisateurs...")
    token_admin = login_user("admin", "admin_secure_pass123")
    token_user = login_user("user_standard", "pass_faible")
    login_user("admin", "mauvais_mot_de_passe") # Échec de la connexion

    print("\n3. Accès aux ressources protégées (Contrôle d'accès basé sur les rôles)...")
    if token_admin:
        print("\nTentative d'accès à la ressource d'administration par l'administrateur :")
        protected_route(token_admin, ["admin"])

        print("\nTentative d'accès à la ressource utilisateur par l'administrateur :")
        protected_route(token_admin, ["user"])

    if token_user:
        print("\nTentative d'accès à la ressource d'administration par un utilisateur standard :")
        protected_route(token_user, ["admin"])

        print("\nTentative d'accès à la ressource utilisateur par un utilisateur standard :")
        protected_route(token_user, ["user"])

    print("\n4. Test d'un jeton invalide ou expiré...")
    if token_admin:
        # Simuler un jeton expiré en modifiant le temps d'expiration
        expired_payload = {
            'sub': 'admin',
            'roles': ['admin', 'user'],
            'iat': (datetime.now() - timedelta(hours=2)).timestamp(),
            'exp': (datetime.now() - timedelta(hours=1)).timestamp()
        }
        expired_token = jwt.encode(expired_payload, JWT_SECRET_KEY, algorithm='HS256')
        
        print("\nTentative d'accès avec un jeton expiré :")
        protected_route(expired_token, ["admin"])

        # -*- coding: utf-8 -*-

mise en place de l’authentification et les différents rôles utilisateurs

import os
import bcrypt
import jwt
from datetime import datetime, timedelta

# Clé secrète pour signer les jetons JWT.
# IMPORTANT : Dans un environnement de production, utilisez une variable d'environnement !
JWT_SECRET_KEY = os.environ.get('JWT_SECRET_KEY', 'votre_clé_secrète_ici')

# Base de données in-memory pour la démo.
# Dans un vrai projet, utilisez une base de données comme MongoDB ou PostgreSQL.
USERS_DB = {}

def hash_password(password):
    """
    Hache un mot de passe en utilisant un sel généré de manière aléatoire.
    Cette approche est conforme aux meilleures pratiques de sécurité.
    """
    salt = bcrypt.gensalt()
    hashed_password = bcrypt.hashpw(password.encode('utf-8'), salt)
    return hashed_password

def verify_password(password, hashed_password):
    """
    Vérifie si un mot de passe en texte clair correspond au mot de passe haché.
    """
    return bcrypt.checkpw(password.encode('utf-8'), hashed_password)

def create_user(username, password, roles=None):
    """

    
    Crée un nouvel utilisateur avec un mot de passe haché et des rôles.
    """
    if roles is None:
        roles = ['user']  # Rôle par défaut
    
    if username in USERS_DB:
        print(f"Erreur : L'utilisateur '{username}' existe déjà.")
        return None
    
    hashed_password = hash_password(password)
    user_data = {
        'username': username,
        'password': hashed_password,
        'roles': roles
    }
    USERS_DB[username] = user_data
    print(f"Utilisateur '{username}' créé avec succès. Rôles : {roles}.")
    return user_data

def login(username, password):
    """
    Authentifie un utilisateur et retourne un jeton JWT s'il réussit.
    """
    user_data = USERS_DB.get(username)
    if not user_data:
        return None
    
    if verify_password(password, user_data['password']):
        payload = {
            'username': user_data['username'],
            'roles': user_data['roles'],
            'exp': datetime.utcnow() + timedelta(minutes=30)  # Le jeton expire après 30 minutes
        }
        token = jwt.encode(payload, JWT_SECRET_KEY, algorithm='HS256')
        print(f"Connexion réussie pour '{username}'. Jeton généré.")
        return token
    else:
        return None

def protected_route_check(token, required_roles):
    """
    Fonction de vérification d'accès pour les routes protégées.
    """
    try:
        payload = jwt.decode(token, JWT_SECRET_KEY, algorithms=['HS256'])
        user_roles = payload.get('roles', [])
        
        # Vérifie si l'utilisateur a au moins un des rôles requis
        if any(role in user_roles for role in required_roles):
            print(f"Accès accordé. Utilisateur : {payload['username']}, Rôles : {user_roles}.")
            return True
        else:
            print(f"Accès refusé. Rôles insuffisants. Rôles de l'utilisateur : {user_roles}.")
            return False
            
    except jwt.ExpiredSignatureError:
        print("Accès refusé. Le jeton a expiré.")
        return False
    except jwt.InvalidTokenError:
        print("Accès refusé. Jeton invalide.")
        return False

# --- Démonstration ---

if __name__ == "__main__":


    # 1. Création des utilisateurs avec différents rôles
    print("--- Création des utilisateurs ---")
    create_user('admin_user', 'mot_de_passe_admin', ['admin', 'user'])
    create_user('john_doe', 'mot_de_passe_simple', ['user'])
    create_user('guest_user', 'mot_de_passe_invite', ['guest'])

    # 2. Tentatives de connexion
    print("\n--- Tentatives de connexion ---")
    admin_token = login('admin_user', 'mot_de_passe_admin')
    user_token = login('john_doe', 'mot_de_passe_simple')
    invalid_login = login('john_doe', 'mauvais_mot_de_passe')

    # 3. Accès aux routes protégées
    print("\n--- Accès aux routes protégées ---")
    print("Vérification de l'accès à la page d'administration :")
    protected_route_check(admin_token, ['admin'])
    protected_route_check(user_token, ['admin'])

    print("\nVérification de l'accès à la page utilisateur :")
    protected_route_check(admin_token, ['user'])
    protected_route_check(user_token, ['user'])

    print("\nVérification de l'accès d'un invité à la page utilisateur :")
    guest_token = login('guest_user', 'mot_de_passe_invite')
    if guest_token:
        protected_route_check(guest_token, ['user'])


        Schéma Relationnel pour la base de données healthcare.csv

Ce schéma est basé sur une modélisation entité-relation, où les données sont organisées en tables.
1. Table Patients

Cette table stocke les informations démographiques de chaque patient.

    patient_id (INTEGER, PRIMARY KEY)

    age (INTEGER)

    sex (VARCHAR)

2. Table Doctors

Cette table stocke les informations sur les médecins.

    doctor_id (INTEGER, PRIMARY KEY)

    name (VARCHAR)

    specialty (VARCHAR)

3. Table Hospitals

Cette table stocke les informations sur les hôpitaux.

    hospital_id (INTEGER, PRIMARY KEY)

    name (VARCHAR)

4. Table Visits

Cette table est la plus importante ; elle stocke les détails de chaque visite médicale et sert de lien entre les autres tables.

    visit_id (INTEGER, PRIMARY KEY)

    patient_id (INTEGER, FOREIGN KEY vers Patients.patient_id)

    doctor_id (INTEGER, FOREIGN KEY vers Doctors.doctor_id)

    hospital_id (INTEGER, FOREIGN KEY vers Hospitals.hospital_id)

    visit_date (DATE)

    blood_pressure (VARCHAR)

    cholesterol (INTEGER)

    heart_rate (INTEGER)

    medication (VARCHAR)

    diagnosis_primary (VARCHAR)

    diagnosis_secondary (VARCHAR)

    notes (TEXT)

5. Table Lab_Results

Cette table stocke les résultats de laboratoire, en les liant à la table Visits.

    result_id (INTEGER, PRIMARY KEY)

    visit_id (INTEGER, FOREIGN KEY vers Visits.visit_id)

    test_name (VARCHAR)

    value (FLOAT)

    unit (VARCHAR)

    status (VARCHAR)
    


### URL de l'API publique

Votre API est maintenant déployée et accessible via l'URL suivante :
[API de Données de Seattle](https://seattle-data-api-250346361499.europe-west9.run.app)
