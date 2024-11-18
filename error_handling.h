#ifndef ERROR_HANDLING_H
#define ERROR_HANDLING_H

#include "imapcl.h"
#include <string>
#include <map>
#include <iostream>
#include <openssl/bio.h>
#include <openssl/ssl.h>
#include <openssl/err.h>

// Enum trieda reprezentujuca rozne typy chyb v IMAP pripojeni
enum class IMAPError {
    ConnectionFailed = 1,
    HostResolutionFailed,
    CertificateLoadFailed,
    SSLContextCreationFailed,
    MessageSendFailed,
    AuthenticationFailed,
    LogoutFailed,
    InvalidMailbox,
    AuthFileNotFound,
    AuthFileInvalid,
    DirectoryNotWritable,
    Unknown
};

// Funkcie na spracovanie chyb
void handleError(IMAPConnection& imap, IMAPError error, const std::string& message); // Spracuje chybu a vypise popis
void setError(IMAPConnection& imap, const std::string& errorDescription, unsigned errorNumber); // Nastavi chybovy kod a popis
void clearError(IMAPConnection& imap); // Vymaze chybovy stav
bool hasErrorOccurred(const IMAPConnection& imap); // Zisti, ci nastala chyba
std::string getErrorMessage(const IMAPConnection& imap); // Vrati popis poslednej chyby

#endif // ERROR_HANDLING_H

