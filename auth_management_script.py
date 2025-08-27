# -*- coding: utf-8 -*-
# =========================================================================
# === Script de gestion des utilisateurs et des rôles                   ===
# =========================================================================
# Ce script permet de gérer des utilisateurs et leurs rôles en utilisant
# le hachage de mot de passe pour la sécurité.

import json
from hashlib import sha256

# Fichier pour stocker les utilisateurs de manière persistante
USERS_FILE = "users.json"

def hash_password(password):
    """Hache un mot de passe en utilisant SHA-256."""
    return sha256(password.encode('utf-8')).hexdigest()

def load_users():
    """Charge les utilisateurs depuis un fichier JSON."""
    try:
        with open(USERS_FILE, 'r', encoding='utf-8') as f:
            return json.load(f)
    except (FileNotFoundError, json.JSONDecodeError):
        # Retourne un dictionnaire vide si le fichier n'existe pas ou est corrompu
        return {}

def save_users(users):
    """Sauvegarde les utilisateurs dans un fichier JSON."""
    with open(USERS_FILE, 'w', encoding='utf-8') as f:
        json.dump(users, f, indent=4)

def create_user(username, password, role):
    """Crée un nouvel utilisateur et le sauvegarde."""
    users = load_users()
    if username in users:
        print(f"Erreur: L'utilisateur '{username}' existe déjà.")
        return
    
    users[username] = {
        "password": hash_password(password),
        "role": role
    }
    save_users(users)
    print(f"L'utilisateur '{username}' avec le rôle '{role}' a été créé avec succès.")

def authenticate_user(username, password):
    """Vérifie l'utilisateur et retourne son rôle."""
    users = load_users()
    user = users.get(username)
    
    if user and user["password"] == hash_password(password):
        print(f"Authentification réussie pour l'utilisateur '{username}'.")
        return user["role"]
    else:
        print("Échec de l'authentification. Nom d'utilisateur ou mot de passe incorrect.")
        return None

# =========================================================================
# === Interface en ligne de commande                                    ===
# =========================================================================
def main_menu():
    """Affiche le menu principal et gère les actions de l'utilisateur."""
    while True:
        print("\n--- Menu de gestion des utilisateurs ---")
        print("1. Authentification")
        print("2. Créer un nouvel utilisateur")
        print("3. Quitter")
        
        choice = input("Votre choix : ")
        
        if choice == '1':
            username = input("Nom d'utilisateur : ")
            password = input("Mot de passe : ")
            role = authenticate_user(username, password)
            if role:
                print(f"Connecté en tant que {role}.")
        elif choice == '2':
            username = input("Nom d'utilisateur à créer : ")
            password = input("Mot de passe : ")
            role = input("Rôle (admin, operator, viewer) : ")
            if role not in ["admin", "operator", "viewer"]:
                print("Rôle invalide. Les rôles possibles sont : admin, operator, viewer.")
            else:
                create_user(username, password, role)
        elif choice == '3':
            print("Au revoir.")
            break
        else:
            print("Choix invalide. Veuillez réessayer.")

if __name__ == "__main__":
    main_menu()
