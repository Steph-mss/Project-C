# Application de messagerie sécurisée

## Description

Ceci une application en langage **C** permettant une communication sécurisée entre un serveur et plusieurs clients.  
Elle utilise **OpenSSL** pour la gestion des certificats et des clés, garantissant ainsi la confidentialité des échanges.

## Installation

### Compilation et installation des certificats et clés

Utilisez la commande suivante pour compiler le projet via le **Makefile** :

```sh
make
```

### Exécution

Pour exécuter l'application :

1. **Démarrer le serveur** :

   ```sh
   ./main server
   ```

2. **Se connecter en tant qu'admin** :

   ```sh
   ./main admin
   ```

3. **Lancer un ou plusieurs clients** (dans d'autres terminaux) :
   ```sh
   ./main userID
   ```

### Nettoyage

Pour supprimer les fichiers compilés et nettoyer le projet :

```sh
make clean
```

---

**Auteur :** Steph-mss
