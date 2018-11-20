#include <iostream>
#include <string>
#include <cerrno>
#include <unistd.h>
#include <malloc.h>
#include <cstring>
#include <arpa/inet.h>
#include <sys/socket.h>
#include <sys/types.h>
#include <netinet/in.h>
#include <resolv.h>
#include <libgen.h>
#include "openssl/ssl.h"
#include "openssl/err.h"
#include <libxml/parser.h>

#define FAIL    (-1)

using namespace std;

// Relative path to external files (assuming exe is in ./cmake-build-debug/demo1/server)
const string db_path    = "../../../db/db.xml";
const string cert_path  = "../../../ssl_certs/mycert.pem";
string       cmd_path;


/**
 * Retrieve <response> child node text content for username/password pair.
 *
 * @param doc
 * @param root
 * @param name
 * @param pass
 * @param response
 * @return
 */
static bool get_response_from_xml(xmlDocPtr doc, xmlNodePtr root, const string & name,
                                  const string & pass, string & response)
{
    xmlNodePtr thisNode = root->children;

    while (thisNode) {
        if ((thisNode->type == XML_ELEMENT_NODE) && (xmlStrcasecmp(thisNode->name, BAD_CAST "user") == 0)) {
            string user_name, user_password;
            xmlNodePtr response_node = nullptr;

            xmlNodePtr subNode = thisNode->children;

            while (subNode) {
                if (subNode->type == XML_ELEMENT_NODE) {
                    if (xmlStrcasecmp(subNode->name, BAD_CAST "name") == 0) {
                        user_name = (const char *)xmlNodeGetContent(subNode->children);
                    } else if (xmlStrcasecmp(subNode->name, BAD_CAST "password") == 0) {
                        user_password = (const char *)xmlNodeGetContent(subNode->children);
                    } else if (xmlStrcasecmp(subNode->name, BAD_CAST "response") == 0) {
                        response_node = subNode->children->next;
                    } else {
                        break;
                    }
                }

                subNode = subNode->next;
            }

            if ((user_name == name) && (user_password == pass) && (response_node != nullptr)) {
                xmlBufferPtr buf = xmlBufferCreate();

                if (xmlNodeDump(buf, doc, response_node, 4, 1) != -1) {
                    response = (const char *) buf->content;
                    return true;
                }
            }
        }

        thisNode = thisNode->next;
    }
}

static bool get_response_for_user(const string & dbpath, const string & user, const string & pass, string & resp) {
    xmlDocPtr doc = nullptr;

    doc = xmlParseFile(dbpath.c_str());
    if (doc) {
        xmlNodePtr rootNode = xmlDocGetRootElement(doc);
        if (rootNode) {
            return get_response_from_xml(doc, rootNode, user, pass, resp);
        } else {

        }
    } else {

    }

    return false;
}

// Create the SSL socket and initialize the socket address structure
static int OpenListener(int port) {
    struct sockaddr_in addr = {0};

    int sd = socket(PF_INET, SOCK_STREAM, 0);
    int enable = 1;
    setsockopt(sd, SOL_SOCKET, SO_REUSEADDR, &enable, sizeof(int));

    bzero(&addr, sizeof(addr));
    addr.sin_family = AF_INET;
    addr.sin_port = htons(port);
    addr.sin_addr.s_addr = INADDR_ANY;

    if (bind(sd, (struct sockaddr *) &addr, sizeof(addr)) != 0) {
        perror("can't bind port");
        return -1;
    }

    if (listen(sd, 10) != 0) {
        perror("Can't configure listening port");
        return -1;
    }

    return sd;
}

/**
 * Initialize SSL server context.
 * @return
 */
static SSL_CTX *InitServerCTX() {
    SSL_METHOD *method;
    SSL_CTX *ctx;
    OpenSSL_add_all_algorithms();  /* load & register all cryptos, etc. */
    SSL_load_error_strings();   /* load all error messages */
    method = const_cast<SSL_METHOD *>(TLS_server_method());  /* create new server-method instance */
    ctx = SSL_CTX_new(method);   /* create new context from method */
    if (ctx == nullptr) {
        ERR_print_errors_fp(stderr);
        abort();
    }
    return ctx;
}

static bool LoadCertificates(SSL_CTX *ctx, const char *CertFile, const char *KeyFile) {
/* set the local certificate from CertFile */
    if (SSL_CTX_use_certificate_file(ctx, CertFile, SSL_FILETYPE_PEM) <= 0) {
        ERR_print_errors_fp(stderr);
        return false;
    }
/* set the private key from KeyFile (may be the same as CertFile) */
    if (SSL_CTX_use_PrivateKey_file(ctx, KeyFile, SSL_FILETYPE_PEM) <= 0) {
        ERR_print_errors_fp(stderr);
        return false;
    }
/* verify private key */
    if (!SSL_CTX_check_private_key(ctx)) {
        fprintf(stderr, "Private key does not match the public certificate\n");
        return false;
    }

    return true;
}

static void ShowCerts(SSL *ssl) {
    X509 *cert;
    char *line;
    cert = SSL_get_peer_certificate(ssl); /* Get certificates (if available) */
    if (cert) {
        printf("Server certificates:\n");
        line = X509_NAME_oneline(X509_get_subject_name(cert), nullptr, 0);
        printf("Subject: %s\n", line);
        free(line);
        line = X509_NAME_oneline(X509_get_issuer_name(cert), nullptr, 0);
        printf("Issuer: %s\n", line);
        free(line);
        X509_free(cert);
    } else
        printf("No certificates.\n");

    fflush(stdout);
}

/**
 * Extract value from an XML element.
 * @param node
 * @param tag
 * @param value
 * @return Returns true if the element was found and sets value to its content.
 */
static bool getTextFromElement(xmlNodePtr node, const char * tag, string & value) {
    xmlNodePtr thisNode = node;

    while (thisNode) {
        if ((thisNode->type == XML_ELEMENT_NODE) && (xmlStrcasecmp(thisNode->name, BAD_CAST tag) == 0)) {
            value = (const char *)xmlNodeGetContent(thisNode->children);
            return true;
        }
        thisNode = thisNode->next;
    }

    return false;
}

static bool parse_request_xml(const char * xmlBuf, string & name, string & password) {
    bool bRes = false;
    xmlDocPtr doc = xmlParseDoc(BAD_CAST xmlBuf);
    if (doc) {
        xmlNodePtr rootNode = xmlDocGetRootElement(doc);
        // Validate root node is a <body> tag
        if (xmlStrcasecmp(rootNode->name, BAD_CAST "body") == 0) {
            if (getTextFromElement(rootNode->children, "username", name) &&
                getTextFromElement(rootNode->children, "password", password))
            {
                bRes = true;
            }
        } else {
            // this is not a valid request
        }
        xmlFreeDoc(doc);
    }

    return bRes;
}

/**
 * Handle the connection to the socket.
 * @param ssl
 * @return
 */
static bool Servlet(SSL *ssl) /* Serve the connection -- threadable */
{
    char buf[1024] = {0};
    int sd, bytes;

    if (SSL_accept(ssl) == FAIL)     /* do SSL-protocol accept */
        ERR_print_errors_fp(stderr);
    else {
        ShowCerts(ssl);        /* get any certificates */
        bytes = SSL_read(ssl, buf, sizeof(buf)); /* get request */
        buf[bytes] = '\0';

        printf("Client msg:\n%s\n", buf);
        fflush(stdout);

        if (bytes > 0) {
            string user, pw, resp;

            if (parse_request_xml(buf, user, pw)) {
                string db_fullpath = cmd_path + db_path;

                if (get_response_for_user(db_fullpath, user, pw, resp)) {
                    SSL_write(ssl, resp.c_str(), static_cast<int>(resp.length()));
                } else {
                    SSL_write(ssl, "Invalid password", static_cast<int>(strlen("Invalid password")));
                }
            } else {
                SSL_write(ssl, "Invalid Message", static_cast<int>(strlen("Invalid Message"))); /* send reply */
            }
        } else {
            ERR_print_errors_fp(stderr);
        }
    }

    sd = SSL_get_fd(ssl);       /* get socket connection */
    SSL_free(ssl);              /* release SSL state */
    close(sd);                  /* close connection */

    return true;
}



void get_path(char * cmdPath) {
    char * dir_name = dirname(cmdPath);
    if (dir_name) {
        char * real_path = realpath(dir_name, nullptr);
        if (real_path) {
            cmd_path = string(real_path) + "/";
            free(real_path);
        }
    }
}

bool bRunning = false;

int main(int argc, char *argv[]) {
    SSL_CTX *ctx = nullptr;
    int server;
    string portnum;

    get_path(argv[0]);

    if (argc != 2) {
        printf("Usage: %s <portnum>\n", argv[0]);
        exit(0);
    }

    // Initialize the SSL library
    SSL_library_init();
    portnum = argv[1];

    ctx = InitServerCTX();                          /* initialize SSL */

    /* load certs */
    string cert_fullpath = cmd_path + cert_path;

    if (!LoadCertificates(ctx, cert_fullpath.c_str(), cert_fullpath.c_str())) {
        fprintf(stderr, "ERROR: Unable to load certificate '%s'\n", cert_fullpath.c_str());
        SSL_CTX_free(ctx);
        return 1;
    }

    server = OpenListener(std::stoi(portnum));      /* create server socket */
    if (server != -1) {

        bRunning = true;

        printf("demo1_server is running...\n");
        fflush(stdout);

        while (bRunning) {
            struct sockaddr_in addr = {0};
            socklen_t len = sizeof(addr);
            SSL *ssl;
            int client = accept(server, (struct sockaddr *) &addr, &len);  /* accept connection as usual */

            printf("Connection: %s:%d\n", inet_ntoa(addr.sin_addr), ntohs(addr.sin_port));

            ssl = SSL_new(ctx);                 /* get new SSL state with context */
            SSL_set_fd(ssl, client);            /* set connection socket to SSL state */
            bRunning = Servlet(ssl);            /* service connection */
        }

        close(server);          /* close server socket */
    }

    SSL_CTX_free(ctx);         /* release context */
    return 0;
}
