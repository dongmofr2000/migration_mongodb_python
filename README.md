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
