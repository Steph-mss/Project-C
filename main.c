#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>
#include <pthread.h>

#include <sys/types.h>
#include <sys/socket.h>
#include <netinet/in.h>
#include <arpa/inet.h>
#include <netdb.h>

#include <openssl/bio.h>
#include <openssl/ssl.h>
#include <openssl/err.h>
#include <openssl/x509.h>
#include <openssl/x509_vfy.h>
#include <openssl/rsa.h>
#include <openssl/pem.h>
#include <openssl/rand.h>
#include <openssl/evp.h>

#define SERVER_PORT          4433
#define MAX_CONN_QUEUE       5
#define MAX_STORED_MESSAGES  100

#define MAX_USERNAME_LEN     32
#define MAX_PASSWORD_LEN     128

/*  B = Bit | b = bytes
    2048B = 256b
    OEAP/Header = 42b
    256b - 42b = 214 char max */
#define MAX_MESSAGE_LEN      2048
#define MAX_FILE_CONTENT_LEN 2048
#define MAX_LEN_ALL          214

#define NB_USERS 2

#define ADMIN_USERNAME       "admin"
#define ADMIN_MDP            "a"

#define USER_A_USERNAME      "userA"
#define USER_A_MDP           "a"

#define USER_B_USERNAME      "userB"
#define USER_B_MDP           "a"

#define SERVER_CERT_FILE   "certificates_keys/server/server_cert.pem"
#define SERVER_KEY_FILE    "certificates_keys/server/server_key.pem"
#define ADMIN_PRIV_FILE    "certificates_keys/admin/admin_priv.pem"
#define ADMIN_PUB_FILE     "certificates_keys/admin/admin_pub.pem"
#define USERA_PRIV_FILE    "certificates_keys/userA/userA_priv.pem"
#define USERA_PUB_FILE     "certificates_keys/userA/userA_pub.pem"
#define USERB_PRIV_FILE    "certificates_keys/userB/userB_priv.pem"
#define USERB_PUB_FILE     "certificates_keys/userB/userB_pub.pem"

typedef enum
{
    MSG_TYPE_TEXT = 1,
    MSG_TYPE_FILE = 2
} MessageType;

typedef struct
{
    char sender[MAX_USERNAME_LEN];
    char recipient[MAX_USERNAME_LEN];
    MessageType type;
    size_t data_len;
    unsigned char data[4096];
    int validated;
} EncryptedMessage;

static EncryptedMessage g_messages[MAX_STORED_MESSAGES];
static int g_message_count = 0;
static pthread_mutex_t g_messages_lock = PTHREAD_MUTEX_INITIALIZER;

static const char * g_users[NB_USERS] = { USER_A_USERNAME, USER_B_USERNAME };
static const char * g_users_password[NB_USERS] = { USER_A_MDP, USER_B_MDP };

/* Stockage de 32-byte PBKDF2-derived hash pour chaque user et l'admin */
static unsigned char g_users_password_hash[NB_USERS][32];
static unsigned char g_admin_password_hash[32];

static SSL_CTX * create_server_ssl_ctx(void);
static SSL_CTX * create_client_ssl_ctx(void);
static void * client_thread(void * arg);
static void run_server(void);
static void run_client(const char * username, const char * server_ip);

static void init_users_passwords(void);
static int verify_user_password(const char * username, const char * password);

static int store_encrypted_message(const char * sender,
                                   const char * recipient,
                                   MessageType type,
                                   const unsigned char * cipher_data,
                                   size_t cipher_len);

static void derive_key_pbkdf2_sha256(const char * password,
                                     const unsigned char * salt,
                                     size_t salt_len,
                                     int iterations,
                                     unsigned char * out_key,
                                     size_t out_key_len);
static int secure_compare(const unsigned char * a, const unsigned char * b, size_t len);
static EVP_PKEY * load_rsa_private_key_from_file(const char * filename);
static EVP_PKEY * load_rsa_public_key_from_file(const char * filename);
static int rsa_encrypt_with_public_key(EVP_PKEY * pubkey,
                                       const unsigned char * plaintext,
                                       size_t plaintext_len,
                                       unsigned char * out_cipher,
                                       size_t * out_cipher_len);
static int rsa_decrypt_with_private_key(EVP_PKEY * privkey,
                                        const unsigned char * cipher,
                                        size_t cipher_len,
                                        unsigned char * out_plain,
                                        size_t * out_plain_len);

/* --- main() --- */
int main(int argc, char * argv[])
{
    init_users_passwords();

    if (argc < 2)
    {
        fprintf(stderr, "Usage: %s server|admin|userA|userB [server_ip]\n", argv[0]);
        exit(EXIT_FAILURE);
    }

    if (strcmp(argv[1], "server") == 0)
        run_server();
    else if (strcmp(argv[1], ADMIN_USERNAME) == 0)
    {
        const char * ip = (argc >= 3) ? argv[2] : "127.0.0.1";
        run_client(ADMIN_USERNAME, ip);
    }
    else if (strcmp(argv[1], USER_A_USERNAME) == 0)
    {
        const char * ip = (argc >= 3) ? argv[2] : "127.0.0.1";
        run_client(USER_A_USERNAME, ip);
    }
    else if (strcmp(argv[1], USER_B_USERNAME) == 0)
    {
        const char * ip = (argc >= 3) ? argv[2] : "127.0.0.1";
        run_client(USER_B_USERNAME, ip);
    }
    else
    {
        fprintf(stderr, "Unknown mode: %s\n", argv[1]);
        fprintf(stderr, "Usage: %s server|admin|userA|userB [server_ip]\n", argv[0]);
        exit(EXIT_FAILURE);
    }

    return 0;
}

/* --- Définitions des fonctions --- */

/* RSA + PBKDF2 functions */
static void derive_key_pbkdf2_sha256(const char * password,
                                     const unsigned char * salt,
                                     size_t salt_len,
                                     int iterations,
                                     unsigned char * out_key,
                                     size_t out_key_len)
{
    if (!PKCS5_PBKDF2_HMAC(password, strlen(password),
                           salt, (int)salt_len,
                           iterations,
                           EVP_sha256(),
                           (int)out_key_len,
                           out_key))
    {
        fprintf(stderr, "PKCS5_PBKDF2_HMAC error.\n");
        exit(EXIT_FAILURE);
    }
}

static int secure_compare(const unsigned char * a, const unsigned char * b, size_t len)
{
    unsigned char diff = 0;
    for (size_t i = 0; i < len; i++)
        diff |= (a[i] ^ b[i]);
    return (diff == 0) ? 1 : 0;
}

static EVP_PKEY * load_rsa_private_key_from_file(const char * filename)
{
    FILE *fp = fopen(filename, "r");
    if (!fp)
    {
        perror("fopen (private key)");
        return NULL;
    }
    EVP_PKEY * pkey = PEM_read_PrivateKey(fp, NULL, NULL, NULL);
    fclose(fp);
    return pkey;
}

static EVP_PKEY * load_rsa_public_key_from_file(const char * filename)
{
    FILE *fp = fopen(filename, "r");
    if (!fp)
    {
        perror("fopen (public key)");
        return NULL;
    }

    EVP_PKEY * pkey = PEM_read_PUBKEY(fp, NULL, NULL, NULL);
    fclose(fp);
    return pkey;
}

static int rsa_encrypt_with_public_key(EVP_PKEY * pubkey,
                                       const unsigned char * plaintext,
                                       size_t plaintext_len,
                                       unsigned char * out_cipher,
                                       size_t * out_cipher_len)
{
    if (!pubkey) return 0;

    EVP_PKEY_CTX * ctx = EVP_PKEY_CTX_new(pubkey, NULL);
    if (!ctx)
        return 0;
    if (EVP_PKEY_encrypt_init(ctx) <= 0)
    {
        EVP_PKEY_CTX_free(ctx);
        return 0;
    }
    if (EVP_PKEY_CTX_set_rsa_padding(ctx, RSA_PKCS1_OAEP_PADDING) <= 0)
    {
        EVP_PKEY_CTX_free(ctx);
        return 0;
    }

    /* Determine la taille du buffer */
    if (EVP_PKEY_encrypt(ctx, NULL, out_cipher_len, plaintext, plaintext_len) <= 0)
    {
        EVP_PKEY_CTX_free(ctx);
        return 0;
    }
    if (EVP_PKEY_encrypt(ctx, out_cipher, out_cipher_len, plaintext, plaintext_len) <= 0)
    {
        EVP_PKEY_CTX_free(ctx);
        return 0;
    }
    EVP_PKEY_CTX_free(ctx);
    return 1;
}

static int rsa_decrypt_with_private_key(EVP_PKEY * privkey,
                                        const unsigned char * cipher,
                                        size_t cipher_len,
                                        unsigned char * out_plain,
                                        size_t * out_plain_len)
{
    if (!privkey) return 0;

    EVP_PKEY_CTX * ctx = EVP_PKEY_CTX_new(privkey, NULL);
    if (!ctx)
        return 0;
    if (EVP_PKEY_decrypt_init(ctx) <= 0)
    {
        EVP_PKEY_CTX_free(ctx);
        return 0;
    }
    if (EVP_PKEY_CTX_set_rsa_padding(ctx, RSA_PKCS1_OAEP_PADDING) <= 0)
    {
        EVP_PKEY_CTX_free(ctx);
        return 0;
    }

    if (EVP_PKEY_decrypt(ctx, NULL, out_plain_len, cipher, cipher_len) <= 0)
    {
        EVP_PKEY_CTX_free(ctx);
        return 0;
    }
    if (EVP_PKEY_decrypt(ctx, out_plain, out_plain_len, cipher, cipher_len) <= 0)
    {
        EVP_PKEY_CTX_free(ctx);
        return 0;
    }
    EVP_PKEY_CTX_free(ctx);
    return 1;
}

/* --- Initialisation et vérification des mots de passe --- */

static void init_users_passwords(void)
{
    for (int i = 0; i < NB_USERS; i++)
    {
        unsigned char salt[8];
        memset(salt, 0, sizeof(salt));
        snprintf((char *)salt, sizeof(salt), "%s", g_users[i]);
        derive_key_pbkdf2_sha256(g_users_password[i],
                                 salt,
                                 strlen((const char *)salt),
                                 10000,
                                 g_users_password_hash[i],
                                 32);
    }

    /* Admin */
    {
        unsigned char salt[8];
        memset(salt, 0, sizeof(salt));
        snprintf((char *)salt, sizeof(salt), "%s", ADMIN_USERNAME);
        derive_key_pbkdf2_sha256(ADMIN_MDP,
                                 salt,
                                 strlen((const char *)salt),
                                 10000,
                                 g_admin_password_hash,
                                 32);
    }
}

static int verify_user_password(const char * username, const char * password)
{
    if (strcmp(username, ADMIN_USERNAME) == 0)
    {
        unsigned char test_hash[32];
        unsigned char salt[8];
        memset(salt, 0, sizeof(salt));
        snprintf((char *)salt, sizeof(salt), "%s", ADMIN_USERNAME);
        derive_key_pbkdf2_sha256(password,
                                 salt,
                                 strlen((const char *)salt),
                                 10000,
                                 test_hash,
                                 32);
        return secure_compare(test_hash, g_admin_password_hash, 32);
    }

    for (int i = 0; i < NB_USERS; i++)
    {
        if (strcmp(username, g_users[i]) == 0)
        {
            unsigned char test_hash[32];
            unsigned char salt[8];
            memset(salt, 0, sizeof(salt));
            snprintf((char *)salt, sizeof(salt), "%s", g_users[i]);
            derive_key_pbkdf2_sha256(password,
                                     salt,
                                     strlen((const char *)salt),
                                     10000,
                                     test_hash,
                                     32);
            return secure_compare(test_hash, g_users_password_hash[i], 32);
        }
    }
    return 0;
}

/* --- Stockage des messages chiffrés --- */

static int store_encrypted_message(const char * sender,
                                   const char * recipient,
                                   MessageType type,
                                   const unsigned char * cipher_data,
                                   size_t cipher_len)
{
    pthread_mutex_lock(&g_messages_lock);
    if (g_message_count >= MAX_STORED_MESSAGES)
    {
        pthread_mutex_unlock(&g_messages_lock);
        fprintf(stderr, "Storage full!\n");
        return 0;
    }
    EncryptedMessage * msg = &g_messages[g_message_count++];
    memset(msg, 0, sizeof(*msg));
    strncpy(msg->sender, sender, MAX_USERNAME_LEN - 1);
    strncpy(msg->recipient, recipient, MAX_USERNAME_LEN - 1);
    msg->type = type;
    msg->data_len = cipher_len;
    memcpy(msg->data, cipher_data, cipher_len);
    msg->validated = 0;
    pthread_mutex_unlock(&g_messages_lock);
    return 1;
}

/* --- Création des contextes SSL --- */

static SSL_CTX * create_server_ssl_ctx(void)
{
    SSL_CTX * ctx = SSL_CTX_new(TLS_server_method());
    if (!ctx)
    {
        fprintf(stderr, "Unable to create SSL_CTX (server).\n");
        return NULL;
    }

    SSL_CTX_set_options(ctx, SSL_OP_SINGLE_DH_USE | SSL_OP_SINGLE_ECDH_USE);
    SSL_CTX_set_cipher_list(ctx, "ECDHE-RSA-AES256-GCM-SHA384:ECDHE-RSA-AES128-GCM-SHA256");

    if (SSL_CTX_use_certificate_file(ctx, SERVER_CERT_FILE, SSL_FILETYPE_PEM) <= 0)
    {
        fprintf(stderr, "SSL_CTX_use_certificate_file error.\n");
        SSL_CTX_free(ctx);
        return NULL;
    }

    if (SSL_CTX_use_PrivateKey_file(ctx, SERVER_KEY_FILE, SSL_FILETYPE_PEM) <= 0)
    {
        fprintf(stderr, "SSL_CTX_use_PrivateKey_file error.\n");
        SSL_CTX_free(ctx);
        return NULL;
    }

    if (!SSL_CTX_check_private_key(ctx))
    {
        fprintf(stderr, "Private key does not match certificate.\n");
        SSL_CTX_free(ctx);
        return NULL;
    }

    SSL_CTX_set_ecdh_auto(ctx, 1);
    return ctx;
}

static SSL_CTX * create_client_ssl_ctx(void)
{
    SSL_CTX * ctx = SSL_CTX_new(TLS_client_method());
    if (!ctx)
    {
        fprintf(stderr, "Unable to create SSL_CTX (client).\n");
        return NULL;
    }
    SSL_CTX_set_cipher_list(ctx, "ECDHE-RSA-AES256-GCM-SHA384:ECDHE-RSA-AES128-GCM-SHA256");
    SSL_CTX_set_verify(ctx, SSL_VERIFY_NONE, NULL);
    return ctx;
}

/* --- Thread côté serveur pour gérer chaque client --- */

static void * client_thread(void * arg)
{
    SSL * ssl = (SSL *)arg;
    if (SSL_accept(ssl) <= 0)
    {
        fprintf(stderr, "[Server] SSL_accept error.\n");
        SSL_shutdown(ssl);
        SSL_free(ssl);
        pthread_exit(NULL);
    }

    char buffer[1024];
    memset(buffer, 0, sizeof(buffer));
    int r = SSL_read(ssl, buffer, sizeof(buffer) - 1);
    if (r <= 0)
    {
        SSL_shutdown(ssl);
        SSL_free(ssl);
        pthread_exit(NULL);
    }
    buffer[r] = '\0';

    if (strncmp(buffer, "LOGIN ", 6) != 0)
    {
        SSL_write(ssl, "Invalid protocol.\n", 18);
        SSL_shutdown(ssl);
        SSL_free(ssl);
        pthread_exit(NULL);
    }

    char username[64];
    memset(username, 0, sizeof(username));
    sscanf(buffer + 6, "%63s", username);

    SSL_write(ssl, "PASSWORD?\n", 10);

    memset(buffer, 0, sizeof(buffer));
    r = SSL_read(ssl, buffer, sizeof(buffer) - 1);
    if (r <= 0)
    {
        SSL_shutdown(ssl);
        SSL_free(ssl);
        pthread_exit(NULL);
    }
    buffer[r] = '\0';

    char password[128];
    memset(password, 0, sizeof(password));
    sscanf(buffer, "%127s", password);

    if (!verify_user_password(username, password))
    {
        SSL_write(ssl, "AUTH ERROR\n", 11);
        SSL_shutdown(ssl);
        SSL_free(ssl);
        pthread_exit(NULL);
    }

    SSL_write(ssl, "AUTH OK\n", 8);

    if (strcmp(username, ADMIN_USERNAME) == 0)
    {
        for (;;)
        {
            char cmd[128];
            memset(cmd, 0, sizeof(cmd));
            int x = SSL_read(ssl, cmd, sizeof(cmd) - 1);
            if (x <= 0)
                break;
            cmd[x] = '\0';

            if (strncmp(cmd, "LIST", 4) == 0)
            {
                char outbuf[4096];
                pthread_mutex_lock(&g_messages_lock);
                int pending_count = 0;
                for (int i = 0; i < g_message_count; i++)
                {
                    if (g_messages[i].validated == 0)
                        pending_count++;
                }
                pthread_mutex_unlock(&g_messages_lock);

                if (pending_count == 0)
                {
                    snprintf(outbuf, sizeof(outbuf), "No messages/files pending.\n");
                    SSL_write(ssl, outbuf, strlen(outbuf));
                }
                else
                {
                    snprintf(outbuf, sizeof(outbuf), "Pending messages/files:\n");
                    SSL_write(ssl, outbuf, strlen(outbuf));

                    pthread_mutex_lock(&g_messages_lock);
                    for (int i = 0; i < g_message_count; i++)
                    {
                        if (g_messages[i].validated == 0)
                        {
                            snprintf(outbuf, sizeof(outbuf),
                                     "  [%d] From=%s, To=%s, Type=%s, Size=%zu\n",
                                     i, g_messages[i].sender,
                                     g_messages[i].recipient,
                                     (g_messages[i].type == MSG_TYPE_TEXT ? "Text" : "File"),
                                     g_messages[i].data_len);
                            SSL_write(ssl, outbuf, strlen(outbuf));
                        }
                    }
                    pthread_mutex_unlock(&g_messages_lock);
                }
            }
            else if (strncmp(cmd, "REVIEW ", 7) == 0)
            {
                int idx = atoi(cmd + 7);
                char outbuf[128];
                snprintf(outbuf, sizeof(outbuf), "Reviewing message %d...\n", idx);
                SSL_write(ssl, outbuf, strlen(outbuf));

                EVP_PKEY * admin_priv = load_rsa_private_key_from_file(ADMIN_PRIV_FILE);
                if (!admin_priv)
                {
                    SSL_write(ssl, "ERROR: Unable to load admin private key.\n", 42);
                    continue;
                }
                pthread_mutex_lock(&g_messages_lock);
                if (idx < 0 || idx >= g_message_count)
                {
                    pthread_mutex_unlock(&g_messages_lock);
                    EVP_PKEY_free(admin_priv);
                    SSL_write(ssl, "ERROR: Invalid index.\n", 23);
                    continue;
                }
                EncryptedMessage * msg = &g_messages[idx];
                if (msg->validated != 0)
                {
                    pthread_mutex_unlock(&g_messages_lock);
                    EVP_PKEY_free(admin_priv);
                    SSL_write(ssl, "ERROR: Message already validated or rejected.\n", 48);
                    continue;
                }
                unsigned char cipher_data[4096];
                size_t cipher_len = msg->data_len;
                memcpy(cipher_data, msg->data, cipher_len);
                MessageType mtype = msg->type;
                char sender_copy[MAX_USERNAME_LEN];
                strncpy(sender_copy, msg->sender, MAX_USERNAME_LEN);
                char recipient_copy[MAX_USERNAME_LEN];
                strncpy(recipient_copy, msg->recipient, MAX_USERNAME_LEN);
                pthread_mutex_unlock(&g_messages_lock);

                unsigned char plain[4096];
                size_t plain_len = 0;
                if (!rsa_decrypt_with_private_key(admin_priv, cipher_data, cipher_len, plain, &plain_len))
                {
                    EVP_PKEY_free(admin_priv);
                    SSL_write(ssl, "ERROR: Decryption failed.\n", 26);
                    continue;
                }
                EVP_PKEY_free(admin_priv);
                plain[plain_len] = '\0';

                if (mtype == MSG_TYPE_TEXT)
                {
                    char outbuf2[4600];
                    snprintf(outbuf2, sizeof(outbuf2),
                             "----- MESSAGE #%d -----\nFrom: %s\nTo: %s\nContent:\n%s\n-----------------------\n",
                             idx, sender_copy, recipient_copy, plain);
                    SSL_write(ssl, outbuf2, strlen(outbuf2));
                }
                else
                {
                    char outbuf2[512];
                    snprintf(outbuf2, sizeof(outbuf2),
                             "----- FILE #%d -----\nFrom: %s\nTo: %s\nSize: %zu bytes\nBinary content follows...\n",
                             idx, sender_copy, recipient_copy, plain_len);
                    SSL_write(ssl, outbuf2, strlen(outbuf2));
                    SSL_write(ssl, plain, plain_len);
                    SSL_write(ssl, "\n-----------------------\n", 25);
                }
                SSL_write(ssl, "Enter decision: A (accept) or R (reject):\n", 43);
                char decision[16];
                memset(decision, 0, sizeof(decision));
                int d = SSL_read(ssl, decision, sizeof(decision)-1);
                if (d <= 0)
                    continue;
                decision[d] = '\0';
                if (decision[0]=='A' || decision[0]=='a')
                {
                    EVP_PKEY * dest_pub = NULL;
                    if (strcmp(recipient_copy, USER_A_USERNAME) == 0)
                        dest_pub = load_rsa_public_key_from_file(USERA_PUB_FILE);
                    else if (strcmp(recipient_copy, USER_B_USERNAME) == 0)
                        dest_pub = load_rsa_public_key_from_file(USERB_PUB_FILE);
                    else
                    {
                        SSL_write(ssl, "ERROR: Unknown recipient.\n", 26);
                        continue;
                    }
                    if (!dest_pub)
                    {
                        SSL_write(ssl, "ERROR: Unable to load recipient's public key.\n", 47);
                        continue;
                    }
                    unsigned char re_cipher[4096];
                    size_t re_cipher_len = 0;
                    if (!rsa_encrypt_with_public_key(dest_pub, plain, plain_len,
                                                     re_cipher, &re_cipher_len))
                    {
                        SSL_write(ssl, "ERROR: Re-encryption failed.\n", 29);
                        EVP_PKEY_free(dest_pub);
                        continue;
                    }
                    EVP_PKEY_free(dest_pub);
                    pthread_mutex_lock(&g_messages_lock);
                    memcpy(msg->data, re_cipher, re_cipher_len);
                    msg->data_len = re_cipher_len;
                    msg->validated = 1; // Valide
                    pthread_mutex_unlock(&g_messages_lock);
                    SSL_write(ssl, "Message/file accepted and re-encrypted for recipient.\n", 55);
                }
                else
                {
                    pthread_mutex_lock(&g_messages_lock);
                    msg->validated = -1; // Rejeté
                    pthread_mutex_unlock(&g_messages_lock);
                    SSL_write(ssl, "Message/file rejected.\n", 23);
                }
            }
            else if (strncmp(cmd, "QUIT", 4) == 0)
            {
                SSL_write(ssl, "Goodbye.\n", 9);
                break;
            }
            else
            {
                SSL_write(ssl, "Commands: LIST, REVIEW <n>, QUIT\n", 33);
            }
        }
    }
    else  // Non-admin user
    {
        for (;;)
        {
            char cmd[128];
            memset(cmd, 0, sizeof(cmd));
            int x = SSL_read(ssl, cmd, sizeof(cmd) - 1);
            if (x <= 0)
                break;
            cmd[x] = '\0';

            if (strncmp(cmd, "SENDMSG ", 8) == 0)
            {
                char recipient[64];
                memset(recipient, 0, sizeof(recipient));
                sscanf(cmd + 8, "%63s", recipient);

                SSL_write(ssl, "CONTENT?\n", 9);
                char msg_text[MAX_MESSAGE_LEN];
                memset(msg_text, 0, sizeof(msg_text));
                x = SSL_read(ssl, msg_text, sizeof(msg_text) - 1);
                if (x <= 0) break;
                msg_text[x] = '\0';

                EVP_PKEY * admin_pub = load_rsa_public_key_from_file(ADMIN_PUB_FILE);
                if (!admin_pub)
                {
                    SSL_write(ssl, "ERROR: admin public key not found.\n", 36);
                    continue;
                }

                unsigned char cipher[4096];
                size_t cipher_len = 0;
                if (!rsa_encrypt_with_public_key(admin_pub,
                                                 (unsigned char *)msg_text,
                                                 strlen(msg_text),
                                                 cipher,
                                                 &cipher_len))
                {
                    SSL_write(ssl, "ERROR: encryption failed.\n", 27);
                    EVP_PKEY_free(admin_pub);
                    continue;
                }
                EVP_PKEY_free(admin_pub);

                if (!store_encrypted_message(username, recipient,
                                             MSG_TYPE_TEXT,
                                             cipher, cipher_len))
                {
                    SSL_write(ssl, "ERROR: storage failed.\n", 23);
                    continue;
                }
                SSL_write(ssl, "Message sent (awaiting admin validation).\n", 43);
            }
            else if (strncmp(cmd, "SENDFILE ", 9) == 0)
            {
                char recipient[64];
                memset(recipient, 0, sizeof(recipient));
                sscanf(cmd + 9, "%63s", recipient);

                SSL_write(ssl, "FILESIZE?\n", 10);
                char sizestr[32];
                memset(sizestr, 0, sizeof(sizestr));
                x = SSL_read(ssl, sizestr, sizeof(sizestr) - 1);
                if (x <= 0) break;
                sizestr[x] = '\0';
                int file_size = atoi(sizestr);
                if (file_size <= 0 || file_size > MAX_LEN_ALL)
                {
                    SSL_write(ssl, "ERROR: invalid size.\n", 22);
                    continue;
                }
                SSL_write(ssl, "SENDDATA\n", 9);

                unsigned char filebuf[MAX_FILE_CONTENT_LEN];
                memset(filebuf, 0, sizeof(filebuf));
                int received = 0;
                while (received < file_size)
                {
                    int to_read = file_size - received;
                    if (to_read > 1024) to_read = 1024;

                    int rr = SSL_read(ssl, filebuf + received, to_read);
                    if (rr <= 0) break;
                    received += rr;
                }
                if (received < file_size)
                {
                    SSL_write(ssl, "ERROR: incomplete file reception.\n", 34);
                    continue;
                }

                EVP_PKEY * admin_pub = load_rsa_public_key_from_file(ADMIN_PUB_FILE);
                if (!admin_pub)
                {
                    SSL_write(ssl, "ERROR: admin public key not found.\n", 36);
                    continue;
                }

                unsigned char cipher[4096];
                size_t cipher_len = 0;
                if (!rsa_encrypt_with_public_key(admin_pub, filebuf, received,
                                                 cipher, &cipher_len))
                {
                    SSL_write(ssl, "ERROR: encryption failed.\n", 27);
                    EVP_PKEY_free(admin_pub);
                    continue;
                }
                EVP_PKEY_free(admin_pub);

                if (!store_encrypted_message(username, recipient,
                                             MSG_TYPE_FILE,
                                             cipher, cipher_len))
                {
                    SSL_write(ssl, "ERROR: storage failed.\n", 23);
                    continue;
                }
                SSL_write(ssl, "File sent (awaiting admin validation).\n", 39);
            }
            else if (strncmp(cmd, "RECV", 4) == 0)
            {
                EVP_PKEY * user_priv = NULL;
                if (strcmp(username, USER_A_USERNAME) == 0)
                    user_priv = load_rsa_private_key_from_file(USERA_PRIV_FILE);
                else if (strcmp(username, USER_B_USERNAME) == 0)
                    user_priv = load_rsa_private_key_from_file(USERB_PRIV_FILE);
                else
                {
                    SSL_write(ssl, "Error: unknown user key.\n", 25);
                    continue;
                }

                if (!user_priv)
                {
                    SSL_write(ssl, "Error: unable to load user private key.\n", 40);
                    continue;
                }

                pthread_mutex_lock(&g_messages_lock);
                int count_for_user = 0;
                for (int i = 0; i < g_message_count; i++)
                {
                    EncryptedMessage * msg = &g_messages[i];
                    if (msg->validated == 1 && strcmp(msg->recipient, username) == 0)
                    {
                        unsigned char plain[4096];
                        size_t plain_len = 0;
                        if (!rsa_decrypt_with_private_key(user_priv,
                                                          msg->data,
                                                          msg->data_len,
                                                          plain,
                                                          &plain_len))
                        {
                            continue;
                        }

                        if (msg->type == MSG_TYPE_TEXT)
                        {
                            char outbuf[4600];
                            snprintf(outbuf, sizeof(outbuf),
                                     "----- MESSAGE #%d -----\nFrom: %s\nContent:\n%s\n-----------------------\n",
                                     i, msg->sender, (char *)plain);
                            SSL_write(ssl, outbuf, strlen(outbuf));
                        }
                        else
                        {
                            char header[256];
                            snprintf(header, sizeof(header), "FILEMSG %d %s %zu\n", i, msg->sender, plain_len);
                            SSL_write(ssl, header, strlen(header));
                            SSL_write(ssl, plain, plain_len);
                            SSL_write(ssl, "\nENDOFFILE\n", 12);
                        }
                        count_for_user++;
                    }
                }
                pthread_mutex_unlock(&g_messages_lock);

                if (count_for_user == 0)
                    SSL_write(ssl, "No validated messages/files waiting.\n", 38);
                else
                {
                    char tmp[100];
                    snprintf(tmp, sizeof(tmp), "End of list (%d).\n", count_for_user);
                    SSL_write(ssl, tmp, strlen(tmp));
                }
                EVP_PKEY_free(user_priv);
            }
            else if (strncmp(cmd, "QUIT", 4) == 0)
            {
                SSL_write(ssl, "Goodbye.\n", 9);
                break;
            }
            else
            {
                SSL_write(ssl, "Commands: SENDMSG <user>, SENDFILE <user>, RECV, QUIT\n", 54);
            }
        }
    }

    SSL_shutdown(ssl);
    SSL_free(ssl);
    pthread_exit(NULL);
}

/* --- run_server() --- */

static void run_server(void)
{
    SSL_library_init();
    SSL_load_error_strings();
    OpenSSL_add_all_algorithms();

    SSL_CTX * ctx = create_server_ssl_ctx();
    if (!ctx)
    {
        fprintf(stderr, "Unable to create SSL context (server).\n");
        exit(EXIT_FAILURE);
    }

    int sockfd = socket(AF_INET, SOCK_STREAM, 0);
    if (sockfd < 0)
    {
        perror("socket");
        SSL_CTX_free(ctx);
        exit(EXIT_FAILURE);
    }

    int opt = 1;
    setsockopt(sockfd, SOL_SOCKET, SO_REUSEADDR, &opt, sizeof(opt));

    struct sockaddr_in serv_addr;
    memset(&serv_addr, 0, sizeof(serv_addr));
    serv_addr.sin_family      = AF_INET;
    serv_addr.sin_addr.s_addr = htonl(INADDR_ANY);
    serv_addr.sin_port        = htons(SERVER_PORT);

    if (bind(sockfd, (struct sockaddr *)&serv_addr, sizeof(serv_addr)) < 0)
    {
        perror("bind");
        close(sockfd);
        SSL_CTX_free(ctx);
        exit(EXIT_FAILURE);
    }

    if (listen(sockfd, MAX_CONN_QUEUE) < 0)
    {
        perror("listen");
        close(sockfd);
        SSL_CTX_free(ctx);
        exit(EXIT_FAILURE);
    }

    printf("[Server] Started on port %d (TLS).\n", SERVER_PORT);

    for (;;)
    {
        struct sockaddr_in cli_addr;
        socklen_t clilen = sizeof(cli_addr);
        int newsock = accept(sockfd, (struct sockaddr *)&cli_addr, &clilen);
        if (newsock < 0)
        {
            perror("accept");
            continue;
        }

        SSL * ssl = SSL_new(ctx);
        if (!ssl)
        {
            close(newsock);
            continue;
        }
        SSL_set_fd(ssl, newsock);

        pthread_t tid;
        if (pthread_create(&tid, NULL, client_thread, ssl) != 0)
        {
            perror("pthread_create");
            SSL_free(ssl);
            close(newsock);
            continue;
        }
        pthread_detach(tid);
    }

    close(sockfd);
    SSL_CTX_free(ctx);
}

/* --- run_client() --- */

static void run_client(const char * username, const char * server_ip)
{
    SSL_library_init();
    SSL_load_error_strings();
    OpenSSL_add_all_algorithms();

    SSL_CTX * ctx = create_client_ssl_ctx();
    if (!ctx)
    {
        fprintf(stderr, "Unable to create SSL context (client).\n");
        exit(EXIT_FAILURE);
    }

    int sockfd = socket(AF_INET, SOCK_STREAM, 0);
    if (sockfd < 0)
    {
        perror("socket");
        SSL_CTX_free(ctx);
        exit(EXIT_FAILURE);
    }

    struct sockaddr_in srv_addr;
    memset(&srv_addr, 0, sizeof(srv_addr));
    srv_addr.sin_family = AF_INET;
    srv_addr.sin_port   = htons(SERVER_PORT);
    
    if(inet_pton(AF_INET, server_ip, &srv_addr.sin_addr) <= 0)
    {
        fprintf(stderr, "Invalid server IP address: %s\n", server_ip);
        close(sockfd);
        SSL_CTX_free(ctx);
        exit(EXIT_FAILURE);
    }

    if (connect(sockfd, (struct sockaddr *)&srv_addr, sizeof(srv_addr)) < 0)
    {
        perror("connect");
        close(sockfd);
        SSL_CTX_free(ctx);
        exit(EXIT_FAILURE);
    }

    SSL * ssl = SSL_new(ctx);
    if (!ssl)
    {
        fprintf(stderr, "SSL_new error (client).\n");
        close(sockfd);
        SSL_CTX_free(ctx);
        exit(EXIT_FAILURE);
    }
    SSL_set_fd(ssl, sockfd);

    if (SSL_connect(ssl) <= 0)
    {
        fprintf(stderr, "SSL_connect error (client).\n");
        SSL_free(ssl);
        close(sockfd);
        SSL_CTX_free(ctx);
        exit(EXIT_FAILURE);
    }

    /* 1) Send: LOGIN <username> */
    char login_line[128];
    snprintf(login_line, sizeof(login_line), "LOGIN %s\n", username);
    SSL_write(ssl, login_line, strlen(login_line));

    /* 2) Wait for "PASSWORD?" */
    char buffer[2048];
    memset(buffer, 0, sizeof(buffer));
    int r = SSL_read(ssl, buffer, sizeof(buffer) - 1);
    if (r <= 0)
    {
        fprintf(stderr, "Server closed?\n");
        goto cleanup;
    }
    buffer[r] = '\0';

    if (strncmp(buffer, "PASSWORD?", 9) != 0)
    {
        fprintf(stderr, "Unknown protocol from server: %s\n", buffer);
        goto cleanup;
    }

    printf("Password for %s: ", username);
    fflush(stdout);

    char passwd[128];
    if (!fgets(passwd, sizeof(passwd), stdin))
    {
        fprintf(stderr, "stdin read error.\n");
        goto cleanup;
    }
    passwd[strcspn(passwd, "\n")] = '\0';
    strcat(passwd, "\n");

    SSL_write(ssl, passwd, strlen(passwd));

    /* 3) Check for "AUTH OK" */
    memset(buffer, 0, sizeof(buffer));
    r = SSL_read(ssl, buffer, sizeof(buffer) - 1);
    if (r <= 0)
    {
        fprintf(stderr, "Server closed?\n");
        goto cleanup;
    }
    buffer[r] = '\0';

    if (strncmp(buffer, "AUTH OK", 7) != 0)
    {
        fprintf(stderr, "Authentication failed: %s\n", buffer);
        goto cleanup;
    }

    printf("Authenticated successfully.\n");
    printf("Type HELP to see commands.\n");

    /* Command loop */
    for (;;)
    {
        printf("> ");
        fflush(stdout);

        char line[4096];
        if (!fgets(line, sizeof(line), stdin))
            break;

        line[strcspn(line, "\n")] = '\0';

        if (strncmp(line, "QUIT", 4) == 0)
        {
            SSL_write(ssl, "QUIT\n", 5);
            break;
        }
        else if (strcmp(line, "HELP") == 0)
        {
            if (strcmp(username, ADMIN_USERNAME) == 0)
            {
                printf("Admin commands:\n");
                printf("  LIST                -> list pending messages\n");
                printf("  REVIEW <index>      -> review/validate a message\n");
                printf("  QUIT                -> quit\n");
            }
            else
            {
                printf("User commands:\n");
                printf("  SENDMSG <user>      -> send a text message\n");
                printf("  SENDFILE <user>     -> send a file\n");
                printf("  RECV                -> retrieve validated messages/files\n");
                printf("  QUIT                -> quit\n");
            }
            continue;
        }
        else
        {
            strcat(line, "\n");
            SSL_write(ssl, line, strlen(line));

            /* For SENDFILE and SENDMSG, handle additional input */
            if (strncmp(line, "SENDMSG ", 8) == 0)
            {
                memset(buffer, 0, sizeof(buffer));
                r = SSL_read(ssl, buffer, sizeof(buffer) - 1);
                if (r <= 0)
                    break;
                buffer[r] = '\0';
                if (strncmp(buffer, "CONTENT?", 8) != 0)
                {
                    printf("Unexpected response: %s\n", buffer);
                    continue;
                }

                printf("Enter message text:  ");
                fflush(stdout);
                char message[2048];
                if (!fgets(message, sizeof(message), stdin))
                    break;
                message[strcspn(message, "\n")] = '\0';
                strcat(message, "\n");

                SSL_write(ssl, message, strlen(message));
            }
            else if (strncmp(line, "SENDFILE ", 9) == 0)
            {
                memset(buffer, 0, sizeof(buffer));
                r = SSL_read(ssl, buffer, sizeof(buffer) - 1);
                if (r <= 0)
                    break;
                buffer[r] = '\0';
                if (strncmp(buffer, "FILESIZE?", 9) != 0)
                {
                    printf("Unexpected response: %s\n", buffer);
                    continue;
                }

                char filepath[256];
                printf("Enter the file path to send: ");
                fflush(stdout);
                if (!fgets(filepath, sizeof(filepath), stdin))
                    break;
                filepath[strcspn(filepath, "\n")] = '\0';

                FILE *fp = fopen(filepath, "rb");
                if (!fp)
                {
                    perror("fopen");
                    continue;
                }

                fseek(fp, 0, SEEK_END);
                long file_size = ftell(fp);
                fseek(fp, 0, SEEK_SET);
                if (file_size <= 0 || file_size > MAX_FILE_CONTENT_LEN)
                {
                    printf("Invalid file size (must be >0 and <= %d bytes).\n", MAX_FILE_CONTENT_LEN);
                    fclose(fp);
                    continue;
                }

                char sizestr[32];
                snprintf(sizestr, sizeof(sizestr), "%ld", file_size);
                strcat(sizestr, "\n");
                SSL_write(ssl, sizestr, strlen(sizestr));

                memset(buffer, 0, sizeof(buffer));
                r = SSL_read(ssl, buffer, sizeof(buffer) - 1);
                if (r <= 0)
                {
                    fclose(fp);
                    break;
                }
                buffer[r] = '\0';
                if (strncmp(buffer, "SENDDATA", 8) != 0)
                {
                    printf("Unexpected response: %s\n", buffer);
                    fclose(fp);
                    continue;
                }

                unsigned char filebuf[MAX_FILE_CONTENT_LEN];
                size_t read_bytes = fread(filebuf, 1, file_size, fp);
                fclose(fp);
                if (read_bytes != (size_t)file_size)
                {
                    printf("Error reading file.\n");
                    continue;
                }

                SSL_write(ssl, filebuf, read_bytes);
            }

            if (strncmp(line, "RECV", 4) == 0)
            {
                printf("Receiving messages...\n");
                while (1)
                {
                    memset(buffer, 0, sizeof(buffer));
                    r = SSL_read(ssl, buffer, sizeof(buffer) - 1);
                    if (r <= 0)
                        break;
                    buffer[r] = '\0';

                    if (strncmp(buffer, "FILEMSG", 7) == 0)
                    {
                        int msgIndex;
                        char sender[64];
                        size_t fsize;
                        if (sscanf(buffer, "FILEMSG %d %63s %zu", &msgIndex, sender, &fsize) != 3)
                        {
                            printf("Error: could not parse file header.\n");
                            continue;
                        }
                        printf("File message from %s (message #%d) of size %zu bytes received.\n", sender, msgIndex, fsize);

                        unsigned char *filedata = malloc(fsize);
                        if (!filedata)
                        {
                            printf("Memory allocation failed.\n");
                            break;
                        }
                        size_t totalRead = 0;
                        while (totalRead < fsize)
                        {
                            r = SSL_read(ssl, filedata + totalRead, fsize - totalRead);
                            if (r <= 0)
                                break;
                            totalRead += r;
                        }
                        if (totalRead < fsize)
                        {
                            printf("Incomplete file data received.\n");
                            free(filedata);
                            break;
                        }

                        memset(buffer, 0, sizeof(buffer));
                        r = SSL_read(ssl, buffer, sizeof(buffer) - 1);
                        buffer[r] = '\0';
                        if (strstr(buffer, "ENDOFFILE") == NULL)
                        {
                            printf("Did not receive proper end marker.\n");
                            free(filedata);
                            continue;
                        }

                        char filename[256];
                        printf("Enter filename to save the file: ");
                        fflush(stdout);
                        if (!fgets(filename, sizeof(filename), stdin))
                        {
                            free(filedata);
                            break;
                        }
                        filename[strcspn(filename, "\n")] = '\0';
                        FILE *fp = fopen(filename, "wb");
                        if (!fp)
                        {
                            printf("Error: could not open file %s for writing.\n", filename);
                        }
                        else
                        {
                            fwrite(filedata, 1, fsize, fp);
                            fclose(fp);
                            printf("File saved as %s\n", filename);
                        }
                        free(filedata);
                    }
                    else
                    {
                        printf("%s", buffer);
                    }
                    if (strstr(buffer, "End of list") != NULL)
                        break;
                }
            }
            else
            {
                while (1)
                {
                    fd_set fds;
                    FD_ZERO(&fds);
                    FD_SET(sockfd, &fds);

                    struct timeval tv;
                    tv.tv_sec = 0;
                    tv.tv_usec = 200000;

                    int sel = select(sockfd + 1, &fds, NULL, NULL, &tv);
                    if (sel <= 0)
                        break;

                    if (FD_ISSET(sockfd, &fds))
                    {
                        memset(buffer, 0, sizeof(buffer));
                        r = SSL_read(ssl, buffer, sizeof(buffer) - 1);
                        if (r <= 0)
                            break;
                        buffer[r] = '\0';
                        printf("%s", buffer);
                    }
                    else
                    {
                        break;
                    }
                }
            }
        }
    }

cleanup:
    SSL_shutdown(ssl);
    SSL_free(ssl);
    close(sockfd);
    SSL_CTX_free(ctx);
}