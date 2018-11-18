//
// Created by muman on 11/18/18.
//
#include <iostream>
#include <cstdio>
#include <cerrno>
#include <unistd.h>
#include <malloc.h>
#include <cstring>
#include <sys/socket.h>
#include <resolv.h>
#include <netdb.h>
#include <openssl/ssl.h>
#include <openssl/err.h>
#include <string>

using namespace std;

#define FAIL    (-1)

int OpenConnection(const string & hostname, int port) {
    struct hostent *host = nullptr;
    struct sockaddr_in addr = {0};

    if ((host = gethostbyname(hostname.c_str())) == nullptr) {
        perror(hostname.c_str());
        abort();
    }

    int sd = socket(PF_INET, SOCK_STREAM, 0);
    bzero(&addr, sizeof(addr));
    addr.sin_family = AF_INET;
    addr.sin_port = htons(port);
    addr.sin_addr.s_addr = *(long *) (host->h_addr);

    if (connect(sd, (struct sockaddr *) &addr, sizeof(addr)) != 0) {
        close(sd);
        perror(hostname.c_str());
        abort();
    }

    return sd;
}

SSL_CTX *InitCTX() {
    SSL_METHOD *method = nullptr;
    SSL_CTX *ctx = nullptr;

    OpenSSL_add_all_algorithms();   /* Load cryptos, et.al. */
    SSL_load_error_strings();       /* Bring in and register error messages */
    method = const_cast<SSL_METHOD *>(TLS_client_method());  /* Create new client-method instance */
    ctx = SSL_CTX_new(method);      /* Create new context */

    if (ctx == nullptr) {
        ERR_print_errors_fp(stderr);
        abort();
    }

    return ctx;
}

void ShowCerts(SSL *ssl) {
    X509 *cert = nullptr;
    char *line = nullptr;

    cert = SSL_get_peer_certificate(ssl); /* get the server's certificate */
    if (cert) {
        printf("Server certificates:\n");
        line = X509_NAME_oneline(X509_get_subject_name(cert), nullptr, 0);
        printf("Subject: %s\n", line);
        free(line);       /* free the malloc'ed string */
        line = X509_NAME_oneline(X509_get_issuer_name(cert), nullptr, 0);
        printf("Issuer: %s\n", line);
        free(line);       /* free the malloc'ed string */
        X509_free(cert);     /* free the malloc'ed certificate copy */
    } else
        printf("Info: No client certificates configured.\n");
}

int main(int argc, char *argv[]) {
    SSL_CTX *ctx = nullptr;
    int server = 0;
    SSL *ssl = nullptr;
    char buf[1024] = {0};
    char acClientRequest[1024] = {0};
    int bytes = 0;

    string hostname, portnum;

    /* Check for correct arguments */
    if (argc != 3) {
        printf("usage: %s <hostname> <portnum>\n", argv[0]);
        exit(0);
    }
    /* Get user supplied parameters from arguments */
    hostname = argv[1];
    portnum = argv[2];

    SSL_library_init();

    ctx = InitCTX();
    server = OpenConnection(hostname, std::stoi(portnum));
    ssl = SSL_new(ctx);             /* create new SSL connection state */
    SSL_set_fd(ssl, server);        /* attach the socket descriptor */
    if (SSL_connect(ssl) == FAIL) { /* perform the connection */
        ERR_print_errors_fp(stderr);
    } else {
        string username, password;
        const char *cpRequestMessage =          \
            "<Body>\n"                          \
            "\t<UserName>%s</UserName>\n"      \
            "\t<Password>%s</Password>\n"      \
            "</Body>";

        cout << "Enter the User Name : ";
        getline(cin, username);
        cout << "Enter the Password : ";
        getline(cin, password);

        sprintf(acClientRequest, cpRequestMessage, username.c_str(), password.c_str());   /* construct reply */
        printf("\n\nConnected with %s encryption\n", SSL_get_cipher(ssl));
        ShowCerts(ssl);        /* get any certs */
        SSL_write(ssl, acClientRequest, (int)strlen(acClientRequest));   /* encrypt & send message */
        bytes = SSL_read(ssl, buf, sizeof(buf)); /* get reply & decrypt */
        buf[bytes] = 0;
        printf("Received: \"%s\"\n", buf);
        SSL_free(ssl);          /* release connection state */
    }
    close(server);              /* close socket */
    SSL_CTX_free(ctx);          /* release context */
    return 0;
}