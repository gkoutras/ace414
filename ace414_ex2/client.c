#include <stdio.h>
#include <errno.h>
#include <unistd.h>
#include <malloc.h>
#include <string.h>
#include <sys/socket.h>
#include <resolv.h>
#include <netdb.h>
#include <openssl/ssl.h>
#include <openssl/err.h>

#define FAIL -1

int OpenConnection(const char *hostname, int port) {

    int sd;
    struct sockaddr_in addr;
    struct hostent *host;

    if ((host = gethostbyname(hostname)) == NULL) {
        perror(hostname);
        abort();
    }

    sd = socket(PF_INET, SOCK_STREAM, 0);
    bzero(&addr, sizeof(addr));

    addr.sin_family = AF_INET;
    addr.sin_port = htons(port);
    addr.sin_addr.s_addr = *(long*)(host -> h_addr);

    if (connect(sd, (struct sockaddr*)&addr, sizeof(addr)) != 0) {
        close(sd);
        perror(hostname);
        abort();
    }

    return sd;
}

SSL_CTX* InitCTX(void) {

    SSL_METHOD *method;
    SSL_CTX *ctx;

    // Load cryptos, et.al.
    OpenSSL_add_all_algorithms();

    // Bring in and register error messages
    SSL_load_error_strings();

    // Create new client-method instance
    method = (SSL_METHOD *)TLS_client_method();

    // Create new context
    ctx = SSL_CTX_new(method);

    if (ctx == NULL) {
        ERR_print_errors_fp(stderr);
        abort();
    }

    return ctx;
}

void ShowCerts(SSL* ssl) {

    char *line;
    X509 *cert;
    
    // get the server's certificate
    cert = SSL_get_peer_certificate(ssl);
    
    if (cert != NULL) {

        printf("Server certificates:\n");

        line = X509_NAME_oneline(X509_get_subject_name(cert), 0, 0);
        printf("Subject: %s\n", line);
        free(line);

        line = X509_NAME_oneline(X509_get_issuer_name(cert), 0, 0);
        printf("Issuer: %s\n", line);
        free(line);

        X509_free(cert);
    }
    else
        printf("Info: No client certificates configured.\n");
}

int main(int count, char *strings[]) {

    int server, bytes;
    char buff[1024], acClientRequest[1024] = {0};
    char *hostname, *port_number;
    SSL_CTX *ctx;
    SSL *ssl;

    if (count != 3) {
        printf("usage: %s <hostname> <port_number>\n", strings[0]);
        exit(0);
    }

    SSL_library_init();
    hostname = strings[1];
    port_number = strings[2];

    ctx = InitCTX();
    
    server = OpenConnection(hostname, atoi(port_number));

    // create new SSL connection state
    ssl = SSL_new(ctx);

    // attach the socket descriptor
    SSL_set_fd(ssl, server);
    
    // perform the connection
    if (SSL_connect(ssl) == FAIL)
        ERR_print_errors_fp(stderr);
    else {

        char acUsername[16] = {0};
        char acPassword[16] = {0};

        const char *cpRequestMessage = "<Body>\n\t<UserName>%s</UserName>\n\t<Password>%s</Password>\n</Body>";

        printf("Enter the User Name : ");
        scanf("%s",acUsername);

        printf("\n\nEnter the Password : ");
        scanf("%s",acPassword);

        // construct reply
        sprintf(acClientRequest, cpRequestMessage, acUsername, acPassword);
        
        printf("\n\nConnected with %s encryption\n", SSL_get_cipher(ssl));

        // get any certs
        ShowCerts(ssl);
        
        // encrypt & send message
        SSL_write(ssl,acClientRequest, strlen(acClientRequest));

        // get reply & decrypt
        bytes = SSL_read(ssl, buff, sizeof(buff));
        buff[bytes] = 0;

        printf("Received: \"%s\"\n", buff);

        // release connection state
        SSL_free(ssl);
    }

    // close socket
    close(server);

    // release context
    SSL_CTX_free(ctx);
    
    return 0;
}
