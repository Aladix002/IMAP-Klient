#include "error_handling.h"

// Funkcia na spracovanie chyb
void handleError(IMAPConnection& imap, IMAPError error, const std::string& message) {
    static const std::map<IMAPError, unsigned> errorCodes = {
        {IMAPError::ConnectionFailed, 1},
        {IMAPError::HostResolutionFailed, 2},
        {IMAPError::CertificateLoadFailed, 3},
        {IMAPError::SSLContextCreationFailed, 4},
        {IMAPError::MessageSendFailed, 5},
        {IMAPError::AuthenticationFailed, 6},
        {IMAPError::LogoutFailed, 7},
        {IMAPError::InvalidMailbox, 8},
        {IMAPError::AuthFileNotFound, 9},
        {IMAPError::AuthFileInvalid, 10},
        {IMAPError::DirectoryNotWritable, 11},
        {IMAPError::Unknown, 99}
    };

    // Nastavi kod chyby a spravu
    imap.errorCode = errorCodes.at(error);
    imap.errorMessage = message;

    // Vypise chybovu spravu na standardny chybovy vystup
    std::cerr << "Error: " << message << " (Code: " << imap.errorCode << ")" << std::endl;

    // Ak ide o kriticku chybu, ukonci program s chybovym kodom
    if (error == IMAPError::ConnectionFailed || error == IMAPError::SSLContextCreationFailed ||
        error == IMAPError::CertificateLoadFailed || error == IMAPError::AuthFileNotFound) {
        exit(imap.errorCode);  // kriticy error
    }
}

// Funkcia na nastavenie chyby
void setError(IMAPConnection& imap, const std::string& errorDescription, unsigned errorNumber) {
    imap.errorCode = errorNumber;
    imap.errorMessage = errorDescription;
}

// Funkcia na vycistenie chyboveho stavu
void clearError(IMAPConnection& imap) {
    imap.errorCode = 0;
    imap.errorMessage.clear();
}

// Funkcia na overenie, ci nastala chyba
bool hasErrorOccurred(const IMAPConnection& imap) {
    return imap.errorCode != 0;
}

// Funkcia na ziskanie spravy o chybe
std::string getErrorMessage(const IMAPConnection& imap) {
    return imap.errorMessage;
}

