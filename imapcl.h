#ifndef IMAP_H
#define IMAP_H

#include "config_parser.h"
#include <string.h>
#include <unistd.h> 
#include <fstream>
#include <iostream>
#include <string>
#include <algorithm>
#include <netdb.h> 
#include <sys/socket.h>
#include <netinet/in.h>
#include <sys/types.h>
#include <openssl/bio.h>
#include <openssl/ssl.h>
#include <openssl/err.h>

/* Struktura na ulozenie pripojenia k IMAP serveru */
struct IMAPConnection {
    unsigned errorCode = 0;         // Kod chyby
    std::string errorMessage;       // Popis chyby (default prazdny string)
    bool isSecure = false;          // Priznak, ci je spojenie sifrovane
    unsigned MessageId = 0;         // ID aktualnej spravy

    SSL_CTX* sslContext = nullptr;  // SSL kontext (inicializovany na nullptr)
    int socketConnection = -1;      // Socket pripojenia (inicializovany na -1, co znamena neplatne spojenie)
    BIO* secureSocketConnection = nullptr; // Pripojenie so sifrovanim (inicializovane na nullptr)
};

// Funkcie na pripojenie a komunikaciu so serverom 
SSL_CTX* initializeSSLContext(const std::string& certFile, const std::string& certDir);
BIO* setupBIOConnection(SSL_CTX* context, const std::string& host, int port);
bool connectToServer(IMAPConnection& imap, const std::string& serverHost, int serverPort);
bool connectToSecureServer(IMAPConnection& imap, const std::string& serverHost, int serverPort, const std::string& certFile, const std::string& certDir);
bool performLogin(IMAPConnection& imap, const std::string& userLogin, const std::string& userPassword);
bool logout(IMAPConnection& imap);
void disconnect(IMAPConnection& imap);

// Funkcie na spracovanie sprav 
std::string sendMessage(IMAPConnection& imap, const std::string& messageContent);
std::string sendSecureMessage(IMAPConnection& imap, const std::string& messageContent);
void receiveResponse(int socket, std::string& serverResponse, const std::string& messageId);
std::string receiveSecureResponse(IMAPConnection& imap, const std::string& messageId);
bool sendToServer(int socket, const std::string& fullMessage);
bool secureSendToServer(IMAPConnection& imap, const std::string& fullMessage);
bool isMessageComplete(const std::string& receivedMessage, const std::string& messageId);
void parseResponseStatus(IMAPConnection& imap, const std::string& serverResponse, const std::string& messageId);
std::string parseSecureResponseStatus(IMAPConnection& imap, const std::string& serverResponse, const std::string& messageId);

// IMAP prikazy 
std::string executeCommand(IMAPConnection& imap, const std::string& command, const std::string& args);
std::string fetchMessage(IMAPConnection& imap, const std::string& messageIds, const std::string& dataType);
std::string searchMessages(IMAPConnection& connection, const std::string& searchCriteria);


#endif // IMAP_H


