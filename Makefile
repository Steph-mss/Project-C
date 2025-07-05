# Variables de configuration
CC       = gcc
LIBS     = -lssl -lcrypto -lpthread

TARGET   = main
SRC      = main.c

# Taille certifs/clefs
CERTS_LENGHT = 2048

# Dossiers des certificats
CERT_DIR    = certificates_keys
SERVER_DIR  = $(CERT_DIR)/server
ADMIN_DIR   = $(CERT_DIR)/admin
USERA_DIR   = $(CERT_DIR)/userA
USERB_DIR   = $(CERT_DIR)/userB

# Fichiers des certifs/clefs
SERVER_CERT = $(SERVER_DIR)/server_cert.pem
SERVER_KEY  = $(SERVER_DIR)/server_key.pem

ADMIN_PRIV  = $(ADMIN_DIR)/admin_priv.pem
ADMIN_PUB   = $(ADMIN_DIR)/admin_pub.pem

USERA_PRIV  = $(USERA_DIR)/userA_priv.pem
USERA_PUB   = $(USERA_DIR)/userA_pub.pem

USERB_PRIV  = $(USERB_DIR)/userB_priv.pem
USERB_PUB   = $(USERB_DIR)/userB_pub.pem

UNAME_S := $(shell uname -s)
ifeq ($(UNAME_S),Darwin)
  CC       := /opt/homebrew/Cellar/gcc/*/bin/gcc-14
  CFLAGS   := -I/opt/homebrew/opt/openssl/include
  LDFLAGS  := -L/opt/homebrew/opt/openssl/lib
endif

# Cible par défaut
all: install_deps deps certs $(TARGET)

# Vérification de la présence d'openssl
.PHONY: deps
deps:
ifeq ($(UNAME_S),Darwin)
	@echo "[+] Installation des dépendances sur macOS (ARM64)..."
	@echo "Exécution: brew install --formula gcc openssl"
	brew install --formula gcc openssl
else
	@command -v openssl >/dev/null 2>&1 || { echo "openssl n'est pas installé. Veuillez l'installer."; exit 1; }
endif

# Installation des deps en fonction de la distrib
.PHONY: install_deps
install_deps:
ifeq ($(UNAME_S),Darwin)
	@echo "[+] macOS détecté, assurez-vous d'avoir Homebrew installé."
else
	@echo "[+] Vérification de la distribution et installation des paquets requis..."
	@if [ -f /etc/os-release ]; then \
	  . /etc/os-release; \
	  if [ "$$ID" = "debian" ] || [ "$$ID" = "ubuntu" ]; then \
	    echo "Distribution détectée: $$ID"; \
	    echo "Exécution: sudo apt update -y && sudo apt install -y libssl-dev build-essential"; \
	    sudo apt update -y && sudo apt install -y libssl-dev build-essential; \
	  elif [ "$$ID" = "fedora" ]; then \
	    echo "Distribution détectée: Fedora"; \
	    echo "Exécution: sudo dnf install -y openssl-devel gcc make"; \
	    sudo dnf install -y openssl-devel gcc make; \
	  elif [ "$$ID" = "arch" ]; then \
	    echo "Distribution détectée: Arch"; \
	    echo "Exécution: sudo pacman -Sy --noconfirm openssl base-devel"; \
	    sudo pacman -Sy --noconfirm openssl base-devel; \
	  else \
	    echo "Distribution non reconnue. Veuillez installer manuellement les dépendances (openssl et gcc/clang)"; \
	  fi; \
	else \
	  echo "Fichier /etc/os-release introuvable. Veuillez installer manuellement les dépendances (openssl et gcc/clang)"; \
	fi
endif

# Création des dossiers de certifs + clefs
$(CERT_DIR):
	mkdir -p $(CERT_DIR)

$(SERVER_DIR):
	mkdir -p $(SERVER_DIR)

$(ADMIN_DIR):
	mkdir -p $(ADMIN_DIR)

$(USERA_DIR):
	mkdir -p $(USERA_DIR)

$(USERB_DIR):
	mkdir -p $(USERB_DIR)

# Génération des certifs/clefs
.PHONY: certs
certs: $(SERVER_CERT) $(SERVER_KEY) $(ADMIN_PRIV) $(ADMIN_PUB) $(USERA_PRIV) $(USERA_PUB) $(USERB_PRIV) $(USERB_PUB)
	@echo "[+] Tous les certificats ont été générés."

# --- Serveur ---
$(SERVER_CERT) $(SERVER_KEY): | $(SERVER_DIR)
	@echo "[+] Génération des certificats du serveur..."
	@openssl req -newkey rsa:$(CERTS_LENGHT) -nodes -keyout $(SERVER_KEY) -x509 -days 365 -out $(SERVER_CERT) -subj "/CN=localhost"

# --- Admin ---
$(ADMIN_PRIV): | $(ADMIN_DIR)
	@echo "[+] Génération de la clé privée de l'admin..."
	@openssl genrsa -out $(ADMIN_PRIV) $(CERTS_LENGHT)

$(ADMIN_PUB): $(ADMIN_PRIV)
	@echo "[+] Extraction de la clé publique de l'admin..."
	@openssl rsa -in $(ADMIN_PRIV) -RSAPublicKey_out -out $(ADMIN_PUB)

# --- User A ---
$(USERA_PRIV): | $(USERA_DIR)
	@echo "[+] Génération de la clé privée de userA..."
	@openssl genrsa -out $(USERA_PRIV) $(CERTS_LENGHT)

$(USERA_PUB): $(USERA_PRIV)
	@echo "[+] Extraction de la clé publique de userA..."
	@openssl rsa -in $(USERA_PRIV) -RSAPublicKey_out -out $(USERA_PUB)

# --- User B ---
$(USERB_PRIV): | $(USERB_DIR)
	@echo "[+] Génération de la clé privée de userB..."
	@openssl genrsa -out $(USERB_PRIV) $(CERTS_LENGHT)

$(USERB_PUB): $(USERB_PRIV)
	@echo "[+] Extraction de la clé publique de userB..."
	@openssl rsa -in $(USERB_PRIV) -RSAPublicKey_out -out $(USERB_PUB)

# Compilation
$(TARGET): $(SRC)
ifeq ($(UNAME_S),Darwin)
	@echo "[+] Compilation sur macOS avec gcc de Homebrew..."
	$(CC) $(CFLAGS) -o $(TARGET) $(SRC) $(LDFLAGS) $(LIBS)
else
	$(CC) -o $(TARGET) $(SRC) $(LIBS)
endif

# Nettoyage des fichiers générés (make clean)
.PHONY: clean
clean:
	@echo "[-] Suppression des fichiers compilés..."
	rm -f $(TARGET)
	@echo "[-] Nettoyage des certificats..."
	rm -rf $(CERT_DIR)
	@echo "[-] DONE"