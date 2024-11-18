// Projekt do Predmetu ISA - Klient IMAP s podporou TLS 
// Datum: 17.11. 2024
// Filip Botlo, xbotlo01

#include "error_handling.h"
#include "config_parser.h"
#include "imapcl.h"
#include <filesystem>
#include <regex>


/*
 * Funkcia na inicializaciu a nastavenie SSL kontextu.
 *
 * Parametre:
 *  - certFile: Cesta k suboru s certifikatmi
 *  - certDir: Adresar s certifikatmi
 *
 * Vrati:
 *  - Inicializovany SSL_CTX* kontext, alebo nullptr pri zlyhani
 *
 * Inspiracia: https://www.openssl.org/docs/man1.1.1/man3/SSL_CTX_new.html
 */
SSL_CTX* initializeSSLContext(const std::string& certFile, const std::string& certDir) {
    SSL_CTX* context = SSL_CTX_new(SSLv23_client_method());
    if (!context) {
        return nullptr;
    }

    SSL_CTX_set_default_verify_paths(context);
    if (!SSL_CTX_load_verify_locations(context, certFile.empty() ? nullptr : certFile.c_str(),
                                       certDir.empty() ? nullptr : certDir.c_str())) {
        SSL_CTX_free(context);
        return nullptr;
    }

    return context;
}

/*
 * Nastavenie SSL BIO spojenia
 *
 * Parametre:
 *  - context: SSL kontext pre spojenie
 *  - host: Nazov servera
 *  - port: Port pre spojenie
 *
 * Vrati:
 *  - BIO* pre spojenie alebo nullptr pri zlyhani
 */
BIO* setupBIOConnection(SSL_CTX* context, const std::string& host, int port) {
    BIO* bio = BIO_new_ssl_connect(context);
    if (!bio) return nullptr;

    std::string address = host + ":" + std::to_string(port);
    BIO_set_conn_hostname(bio, address.c_str());

    SSL* ssl;
    BIO_get_ssl(bio, &ssl);
    SSL_set_mode(ssl, SSL_MODE_AUTO_RETRY);

    return bio;
}

/*
 * Pripojenie na server cez zabezpecene SSL/TLS spojenie.
 *
 * Parametre:
 *  - imap: Struktura spojenia
 *  - serverHost: Nazov servera
 *  - serverPort: Port na pripojenie
 *  - certFile: Subor s certifikatmi
 *  - certDir: Adresar s certifikatmi
 *
 * Vrati:
 *  - true ak bolo spojenie uspesne, inak false
 */
bool connectToSecureServer(IMAPConnection& imap, const std::string& serverHost, int serverPort, 
                           const std::string& certFile, const std::string& certDir) {
    // Inicializacia SSL pre bezpecne pripojenie
    imap.isSecure = true;

    SSL_load_error_strings();
    OpenSSL_add_ssl_algorithms();

    // Vytvorenie noveho SSL/TLS kontextu
    imap.sslContext = initializeSSLContext(certFile, certDir);
    if (!imap.sslContext) {
        handleError(imap, IMAPError::SSLContextCreationFailed, "Zlyhanie pri vytvarani SSL kontextu.");
        return false;
    }

    // Vytvorenie noveho BIO s SSL pripojenim
    imap.secureSocketConnection = setupBIOConnection(imap.sslContext, serverHost, serverPort);
    if (!imap.secureSocketConnection) {
        handleError(imap, IMAPError::ConnectionFailed, "Zlyhanie pri vytvarani BIO pripojenia.");
        SSL_CTX_free(imap.sslContext);
        imap.sslContext = nullptr;
        return false;
    }

    // Pokus o pripojenie
    if (BIO_do_connect(imap.secureSocketConnection) <= 0) {
        handleError(imap, IMAPError::ConnectionFailed, ERR_reason_error_string(ERR_get_error()));
        disconnect(imap);  // Cisti zdroje pri chybe
        return false;
    }

    return true;
}

/*
 * Vytvori socket a pripoji sa na server bez sifrovania
 *
 * Parametre:
 *  - info: Adresova struktura pre pripojenie
 *
 * Vrati:
 *  - Socket identifikator alebo -1 pri zlyhani
 */
int createAndConnectSocket(const struct addrinfo* info) {
    int socketFd = -1;
    for (const struct addrinfo* ptr = info; ptr != nullptr; ptr = ptr->ai_next) {
        socketFd = socket(ptr->ai_family, ptr->ai_socktype, ptr->ai_protocol);
        if (socketFd == -1) {
            continue;
        }

        if (connect(socketFd, ptr->ai_addr, ptr->ai_addrlen) == -1) {
            close(socketFd);
            socketFd = -1;
            continue;
        }

        break;
    }
    return socketFd;
}

/*
 * Pripojenie na server bez sifrovania
 *
 * Parametre:
 *  - imap: Struktura spojenia
 *  - serverHost: Nazov servera
 *  - serverPort: Port pre spojenie
 *
 * Vrati:
 *  - true ak bolo pripojenie uspesne, inak false
 * 
 * 
 *  Inspiracia: https://beej.us/guide/bgnet/html/#socket
 */
bool connectToServer(IMAPConnection& imap, const std::string& serverHost, int serverPort) {
    struct addrinfo hints{}, *result;

    hints.ai_family = AF_UNSPEC;
    hints.ai_socktype = SOCK_STREAM;

    std::string portStr = std::to_string(serverPort);
    if (getaddrinfo(serverHost.c_str(), portStr.c_str(), &hints, &result) != 0) {
        handleError(imap, IMAPError::HostResolutionFailed, "Nepodarilo sa pripojit k hostitelovi");
        return false;
    }

    int socketFd = createAndConnectSocket(result);
    freeaddrinfo(result);

    if (socketFd == -1) {
        handleError(imap, IMAPError::ConnectionFailed, "Nejde sa pripojit k serveru");
        return false;
    }

    imap.socketConnection = socketFd;
    imap.isSecure = false;
    return true;
}



/*
 * Pokusi sa prihlasit na server s danym pouzivatelskym menom a heslom.
 *
 * Parametre:
 *  - imap: IMAP spojenie
 *  - userLogin: pouzivatelske meno
 *  - userPassword: pouzivatelske heslo
 */
bool performLogin(IMAPConnection& imap, const std::string& userLogin, const std::string& userPassword) {
    clearError(imap);
    std::ostringstream loginCommand;
    loginCommand << "LOGIN " << userLogin << " " << userPassword;
    sendMessage(imap, loginCommand.str());
    return !hasErrorOccurred(imap);
}


/*
 * Overi, ci prijata sprava obsahuje posledny riadok s ukoncenim.
 *
 * receivedMessage - prijata sprava doteraz
 * messageId       - ID spravy
 */
bool isMessageComplete(const std::string& receivedMessage, const std::string& messageId) {
    // Ziska poziciu posledneho riadku v prijatej sprave
    std::size_t lastLineBegin = receivedMessage.find_last_of("\n", receivedMessage.size() - 2);

    std::string lastLine = (lastLineBegin == std::string::npos) 
                           ? receivedMessage 
                           : receivedMessage.substr(lastLineBegin + 1);

    // Overenie, ci posledny riadok zacina ID spravy a nasleduje medzera
    return lastLine.rfind(messageId + " ", 0) == 0;
}



// Odosle spravu na server a vrati stav uspechu
bool sendToServer(int socket, const std::string& fullMessage) {
    return send(socket, fullMessage.c_str(), fullMessage.size(), 0) != -1;
}

// Prijima odpoved zo servera po castiach a pripoji ju k serverResponse
void receiveResponse(int socket, std::string& serverResponse, const std::string& messageId) {
    char buffer[1024];
    int bytesRead;
    
    do {
        bytesRead = recv(socket, buffer, sizeof(buffer), 0);
        if (bytesRead > 0) {
            serverResponse.append(buffer, bytesRead);
        }
    } while (bytesRead > 0 && (!isMessageComplete(serverResponse, messageId) || bytesRead == sizeof(buffer)));
}

// Spracuje posledny riadok odpovede zo servera na identifikovanie stavu prikazu
void parseResponseStatus(IMAPConnection& imap, const std::string& serverResponse, const std::string& messageId) {
    size_t lastLineStart = serverResponse.rfind("\n", serverResponse.size() - 2);
    std::string commandStatus = (lastLineStart != std::string::npos)
                                ? serverResponse.substr(lastLineStart + 1)
                                : serverResponse;

    // Ak odpoved obsahuje chybu "NO" alebo "BAD" spolu s ID spravy, spracuje chybu
    if (commandStatus.find(messageId + " NO") == 0) {
        handleError(imap, IMAPError::AuthenticationFailed, serverResponse);
    } else if (commandStatus.find(messageId + " BAD") == 0) {
        handleError(imap, IMAPError::Unknown, serverResponse);
    }
}

/*
 * Hlavna funkcia na odoslanie spravy a spracovanie odpovede.
 * 
 * Parametre:
 *  - imap: Struktura obsahujuca stav a nastavenia IMAP spojenia.
 *  - messageContent: Text spravy, ktora sa ma odoslat na server.
 * 
 * Vracia:
 *  - Odpoved od servera bez posledneho riadku, alebo prazdny retazec ak doslo k chybe.
 */
std::string sendMessage(IMAPConnection& imap, const std::string& messageContent) {
    // Ak je spojenie zabezpecene, pouzijeme funkciu pre TLS spojenie
    if (imap.isSecure) {
        return sendSecureMessage(imap, messageContent);
    }

    // Vygeneruje ID pre spravu a vytvorime jej kompletne telo
    std::string messageId = "A" + std::to_string(imap.MessageId++);
    std::string fullMessage = messageId + " " + messageContent + "\r\n";

    // Odoslanie spravy na server
    if (!sendToServer(imap.socketConnection, fullMessage)) {
        handleError(imap, IMAPError::MessageSendFailed, "Nepodarilo sa poslat spravu");
        return "";
    }

    // Prijimanie odpovede od servera
    std::string serverResponse;
    receiveResponse(imap.socketConnection, serverResponse, messageId);

    // Ak je odpoved prazdna alebo doslo k chybe, vratime prazdny retazec
    if (serverResponse.empty()) {
        return "";
    }

    // Parsovanie odpovede a kontrola stavu na zaklade posledneho riadku
    parseResponseStatus(imap, serverResponse, messageId);

    // Vybratie odpovede bez posledneho riadku, ak existuje
    size_t lastLineStart = serverResponse.rfind("\n", serverResponse.size() - 2);
    return (lastLineStart != std::string::npos) 
           ? serverResponse.substr(0, lastLineStart - 1) 
           : serverResponse;
}



/*
 * Posle zabezpecenu spravu na server.
 *
 * Parametre:
 *  - imap: IMAP spojenie.
 *  - fullMessage: Kompletna sprava na odoslanie, vratane ID.
 * 
 * Vracia:
 *  - true ak sa sprava podarilo odoslat, inak false.
 * 
 *  Inspiracia pre sendall: https://beej.us/guide/bgnet/html/#sendall
 */
bool secureSendToServer(IMAPConnection& imap, const std::string& fullMessage) {
    while (BIO_write(imap.secureSocketConnection, fullMessage.c_str(), fullMessage.size()) <= 0) {
        if (!BIO_should_retry(imap.secureSocketConnection)) {
            handleError(imap, IMAPError::MessageSendFailed, "Nepodarilo sa poslat zabezpecenu spravu");
            return false;
        }
    }
    return true;
}

/*
 * Prijme odpoved zo servera pre zabezpecene spojenie.
 *
 * Parametre:
 *  - imap: IMAP spojenie.
 *  - messageId: ID spravy pre kontrolu ukoncenia.
 * 
 * Vracia:
 *  - Retazec obsahujuci odpoved od servera.
 */
std::string receiveSecureResponse(IMAPConnection& imap, const std::string& messageId) {
    char buffer[1024];
    std::string serverResponse;
    int bytesRead;

    // Citame odpoved
    while ((bytesRead = BIO_read(imap.secureSocketConnection, buffer, sizeof(buffer))) > 0) {
        serverResponse.append(buffer, bytesRead);
        if (isMessageComplete(serverResponse, messageId)) {
            break;
        }
    }
    return serverResponse;
}

/*
 * Spracuje posledny riadok odpovede a overi stav spravy.
 *
 * Parametre:
 *  - imap: IMAP spojenie.
 *  - serverResponse: Kompletny text odpovede.
 *  - messageId: ID spravy pre kontrolu ukoncenia.
 * 
 * Vracia:
 *  - Upraveny text odpovede bez posledneho riadku.
 */
std::string parseSecureResponseStatus(IMAPConnection& imap, const std::string& serverResponse, const std::string& messageId) {
    std::size_t lastLineBegin = serverResponse.find_last_of("\n", serverResponse.size() - 2);
    std::string commandCompleted = lastLineBegin != std::string::npos
                                   ? serverResponse.substr(lastLineBegin + 1)
                                   : serverResponse;
    std::string finalResponse = lastLineBegin != std::string::npos
                                ? serverResponse.substr(0, lastLineBegin - 1)
                                : serverResponse;

    std::size_t startPos = messageId.size() + 2;
    if (commandCompleted.find("NO") == startPos) {
        handleError(imap, IMAPError::AuthenticationFailed, serverResponse);
    } else if (commandCompleted.find("BAD") == startPos) {
        handleError(imap, IMAPError::Unknown, serverResponse);
    }
    return finalResponse;
}

/*
 * Hlavna funkcia na zabezpecenu komunikaciu so serverom.
 *
 * Viac info v sendMessage metode.
 */
std::string sendSecureMessage(IMAPConnection& imap, const std::string& messageContent) {
    std::string messageId = "A" + std::to_string(imap.MessageId++);
    std::string fullMessage = messageId + " " + messageContent + "\r\n";

    // Posleme zabezpecenu spravu
    if (!secureSendToServer(imap, fullMessage)) {
        return "";
    }

    // Prijmeme odpoved
    std::string serverResponse = receiveSecureResponse(imap, messageId);

    // Spracujeme odpoved a overime stav
    return parseSecureResponseStatus(imap, serverResponse, messageId);
}


/*
 * Vykona prikaz na serveri.
 *
 * command - IMAP prikaz
 * args    - argumenty prikazu
 */
std::string executeCommand(IMAPConnection& imap, const std::string& command, const std::string& args) {
    clearError(imap);
    std::ostringstream commandStream;
    commandStream << command;
    if (!args.empty()) {
        commandStream << " " << args;
    }

    return sendMessage(imap, commandStream.str());
}

/*
 * Ziska spravy zo servera.
 *
 * ids  - ID alebo rozsah ID sprav
 * type - typ dat na stiahnutie
 */
std::string fetchMessage(IMAPConnection& imap, const std::string& messageIds, const std::string& dataType) {
    clearError(imap);

    std::ostringstream fetchStream;
    fetchStream << "FETCH " << messageIds << " " << dataType;

    return sendMessage(imap, fetchStream.str());
}


/*
 * Odhlasi sa z uctu.
 */
bool logout(IMAPConnection& imap) {
    clearError(imap);
    sendMessage(imap, "LOGOUT");
    return !hasErrorOccurred(imap);
}

/*
 * Uvolni zdroje pred ukoncenim.
 */
void disconnect(IMAPConnection& imap) {
    if (imap.isSecure && (imap.secureSocketConnection || imap.sslContext)) {
        if (imap.secureSocketConnection != nullptr) {
            BIO_free_all(imap.secureSocketConnection);
            imap.secureSocketConnection = nullptr;
        }
        if (imap.sslContext != nullptr) {
            SSL_CTX_free(imap.sslContext);
            imap.sslContext = nullptr;
        }
    }
}

/*
 * Zisti dlzku nasledujucej spravy.
 * 
 * msg - prijata sprava
 * r   - regularny vyraz na extrakciu dlzky
 */
int messageLength(const std::string& message, std::regex regexPattern) {
    std::smatch match;
    if (std::regex_search(message.begin(), message.end(), match, regexPattern))
        return std::stoi(match[1]);
    else {
        return 0;
    }
}

/*
 * Overi, ci existuje vystupny adresar.
 */
bool checkOutputDirectory(IMAPConnection& connection, const IMAPConfig& config) {
    if (!std::filesystem::exists(config.outputDir)) {
        handleError(connection, IMAPError::DirectoryNotWritable, "Adresar neexistuje alebo nie je zapisovatelny.");
        return false;
    }
    return true;
}

/*
 * Vykona vyhladavanie sprav a vrati ID sprav.
 */
std::string searchMessages(IMAPConnection& connection, const std::string& searchCriteria) {
    std::string messageIds = executeCommand(connection, "SEARCH", searchCriteria);
    if (messageIds.find("*") == std::string::npos) {
        std::cout << "* Ziadne spravy zodpovedajuce kriteriam na stiahnutie." << std::endl;
    }
    return messageIds;
}

/*
 * Ziska telo spravy podla ID.
 */
std::string getMessageBody(IMAPConnection& connection, const std::string& messageId, const std::string& fetchType, const std::regex& lengthRegex) {
    std::string fetchResponse = fetchMessage(connection, messageId, fetchType);
    if (fetchResponse.empty()) return "";

    int length = messageLength(fetchResponse, lengthRegex);
    size_t headerEnd = fetchResponse.find("\n") + 1;
    return fetchResponse.substr(headerEnd, length);
}

/*
 * Ulozi spravu do suboru.
 */
void saveMessageToFile(const std::string& outputFileNameBase, const std::string& messageId, const std::string& messageBody, IMAPConnection& connection) {
    std::ofstream outputFile(outputFileNameBase + messageId + ".eml");
    if (!outputFile.is_open()) {
        handleError(connection, IMAPError::DirectoryNotWritable, "Adresar neexistuje alebo nie je zapisovatelny");
    } else {
        outputFile << messageBody;
        outputFile.close();
    }
}

/*
 * Hlavna funkcia na stahovanie sprav
 *
 * connection - Struktura s informaciami o spojeni na IMAP server
 * searchCriteria - Kriterium vyhladavania (napr. "UNSEEN" alebo "ALL")
 * config - Konfiguracia stahovania (obsahuje nastavenia ako adresar pre vystup, rezim iba hlavicky a pod.)
 *
 */
void downloadMessages(IMAPConnection& connection, const std::string& searchCriteria, const IMAPConfig& config) {
    if (!checkOutputDirectory(connection, config)) return;

    std::string messageIds = searchMessages(connection, searchCriteria);
    if (messageIds.empty()) return;

    std::string outputFileNameBase = config.outputDir + config.mailbox + "_";
    int messageCount = 0;
    std::regex lengthRegex(".*\\{(\\d*)\\}");
    std::string fetchType = config.headersOnly 
                            ? "(BODY.PEEK[HEADER.FIELDS (DATE FROM TO SUBJECT CC BCC MESSAGE-ID)])" 
                            : "RFC822";

    size_t pos = 0;
    messageIds.erase(0, 9);
    messageIds.append(" ");

    while ((pos = messageIds.find(" ")) != std::string::npos) {
        std::string messageId = messageIds.substr(0, pos);
        messageIds.erase(0, pos + 1);

        std::string messageBody = getMessageBody(connection, messageId, fetchType, lengthRegex);
        if (!messageBody.empty()) {
            saveMessageToFile(outputFileNameBase, messageId, messageBody, connection);
            messageCount++;
        }
    }

    std::string messageWord = (messageCount == 1) ? "sprava" : (messageCount <= 4 ? "spravy" : "sprav");
    std::cout << "Stiahnute " << messageCount << " " << messageWord << (config.headersOnly ? " (iba hlavicky)" : "") 
              << " zo schranky " << config.mailbox << "." << std::endl;
}


/*
 * Spracuje prikaz zadany v interaktivnom rezime.
 *
 * connection - IMAP spojenie
 * command - prikaz na vykonanie
 * config - konfiguracna struktura
 */
void handleInteractiveCommand(std::string& command, IMAPConnection& connection, IMAPConfig& config) {
    std::string originalMailbox = config.mailbox;
    std::string mailbox = config.mailbox;
    size_t spacePos = command.find(' ');

    // Rozdelenie prikazu a nazvu schranky, ak je zadany
    if (spacePos != std::string::npos) {
        mailbox = command.substr(spacePos + 1);
        command = command.substr(0, spacePos);
    }

    config.mailbox = mailbox;

    // Overenie existencie schranky, ak je to potrebne
    if (command == "DOWNLOADNEW" || command == "DOWNLOADALL" || command == "READNEW") {
        std::string mailboxInfo = executeCommand(connection, "SELECT", mailbox);
        if (hasErrorOccurred(connection)) {
            std::cout << "* Neplatny nazov schranky: " << mailbox << std::endl;
            config.mailbox = originalMailbox;
            return;
        }
    }

    // Vykonanie prikazov podla zadania
    if (command == "DOWNLOADNEW") {
        downloadMessages(connection, "UNSEEN", config);
    } else if (command == "DOWNLOADALL") {
        downloadMessages(connection, "ALL", config);
    } else if (command == "READNEW") {
        std::string allMessageIds = executeCommand(connection, "SEARCH", "UNSEEN");
        if (allMessageIds.empty()) {
            std::cout << "* Ziadne nove spravy na oznacenie ako precitane." << std::endl;
        } else {
            std::cout << "* Oznacujem nove spravy ako precitane v schranke " << mailbox << "." << std::endl;
            executeCommand(connection, "STORE", allMessageIds + " +FLAGS \\Seen");
            std::cout << "* Oznacene " << allMessageIds << " spravy ako precitane v schranke " << mailbox << "." << std::endl;
        }
    } else {
        std::cout << "* Neznamy prikaz." << std::endl;
    }

    // Obnovenie povodnej schranky po vykonani prikazu
    config.mailbox = originalMailbox;
}

/*
 * Spusti interaktivny rezim.
 * V tomto rezime uzivatel moze vykonavat rozne IMAP prikazy, ako je stahovanie
 * sprav alebo ich oznacenie ako precitane.
 */
void runInteractive(IMAPConfig& config) {
    IMAPConnection connection;

    // Pripojenie k serveru podla nastaveni
    if (config.useTLS) {
        connectToSecureServer(connection, config.server, config.port, config.certFile, config.certDir);
    } else {
        connectToServer(connection, config.server, config.port);
    }

    // Kontrola, ci bolo pripojenie uspesne
    if (hasErrorOccurred(connection)) {
        handleError(connection, IMAPError::ConnectionFailed, "Pripojenie k serveru zlyhalo: " + getErrorMessage(connection));
    }

    // Otvorenie autentifikacneho suboru
    std::ifstream authFile(config.authFile);
    if (!authFile.is_open()) {
        handleError(connection, IMAPError::AuthFileNotFound, "Autentifikacny subor neexistuje");
    }

    std::string line;
    std::string username;
    std::string password;

    // Parsovanie prihlasovacich udajov
    getline(authFile, line);
    if (line.compare(0, 11, "username = ") == 0) {
        username = line.substr(line.find("=") + 2);
    } else {
        handleError(connection, IMAPError::AuthFileInvalid, "Neplatny autentifikacny subor");
    }

    getline(authFile, line);
    if (line.compare(0, 11, "password = ") == 0) {
        password = line.substr(line.find("=") + 2);
    } else {
        handleError(connection, IMAPError::AuthFileInvalid, "Neplatny autentifikacny subor");
    }

    // Prihlasenie na server
    if (!performLogin(connection, username, password)) {
        handleError(connection, IMAPError::AuthenticationFailed, "Nepodarilo sa prihlasit na server");
    }
    else{
        std::cout << "* Uspesne pripojenie k serveru a prihlasenie." << std::endl;
        std::string command;

    // Hlavny cyklus pre spracovanie prikazov
    while (true) {
        std::cout << "imapcl> ";
        std::getline(std::cin, command);

        // Ukoncenie interaktivneho rezimu
        if (command == "QUIT") {
            break;
        }

        handleInteractiveCommand(command, connection, config);
    }

    // Odhlasenie zo servera
    if (!logout(connection)) {
        std::cerr << "Odhlasenie zlyhalo: " << getErrorMessage(connection) << std::endl;
    } else {
        std::cout << "Odhlasenie uspesne." << std::endl;
    }

    // Odpojenie od servera
    disconnect(connection);
    }
}


int main(int argc, char* argv[]) {
    // Nacitanie konfiguracie z argumentov prikazoveho riadka
    IMAPConfig config = createConfig(argc, argv);

    // Kontrola, ci je interaktivny rezim povoleny
    if (config.interactive) {
        if (config.server.empty() || config.port == 0) {
            std::cerr << "Chyba: Interaktivny rezim vyzaduje platny server a port." << std::endl;
            return 1;
        }
        runInteractive(config);
        return 0;
    }

    // IMAP objekt pre komunikaciu so serverom
    IMAPConnection connection;

    // Pripojenie k IMAP serveru
    bool connected = config.useTLS
                         ? connectToSecureServer(connection, config.server, config.port, config.certFile, config.certDir)
                         : connectToServer(connection, config.server, config.port);

    // Kontrola pripojenia
    if (!connected || hasErrorOccurred(connection)) {
        handleError(connection, IMAPError::ConnectionFailed, "Pripojenie k serveru zlyhalo: " + getErrorMessage(connection));
        disconnect(connection);
        return 1;
    }

    // Nacitanie autentifikacneho suboru
    std::ifstream auth_file(config.authFile);
    if (!auth_file.is_open()) {
        handleError(connection, IMAPError::AuthFileNotFound, "Autentifikacny subor neexistuje");
        disconnect(connection);
        return 1;
    }

    // Parsovanie prihlasovacich udajov
    std::string login = parseAuthFile(auth_file, "username");
    std::string passwd = parseAuthFile(auth_file, "password");

    // Prihlasenie na server
    if (!performLogin(connection, login, passwd) || hasErrorOccurred(connection)) {
        handleError(connection, IMAPError::AuthenticationFailed, "Nepodarilo sa prihlasit na server: " + getErrorMessage(connection));
        disconnect(connection);
        return 1;
    }

    // Vyber schranky
    if (executeCommand(connection, "SELECT", config.mailbox).empty() || hasErrorOccurred(connection)) {
        handleError(connection, IMAPError::InvalidMailbox, "Neplatny nazov schranky: " + getErrorMessage(connection));
        disconnect(connection);
        return 1;
    }

    // Nastavenie vyhladavacieho retazca podla parametrov
    std::string search_string = config.unreadOnly ? "UNSEEN" : "ALL";

    // Stiahnutie sprav
    downloadMessages(connection, search_string, config);

    // Odhlasenie zo servera
    if (!logout(connection) || hasErrorOccurred(connection)) {
        handleError(connection, IMAPError::LogoutFailed, "Nepodarilo sa odhlasit zo servera: " + getErrorMessage(connection));
        disconnect(connection);
        return 1;
    }

    // Uvolnenie zdrojov
    disconnect(connection);
    return 0;
}

 

