#ifndef CONFIG_PARSER_H
#define CONFIG_PARSER_H

#include <string>
#include <fstream>
#include <iostream>
#include <getopt.h>

// Struktura na ulozenie konfiguracie z prikazoveho riadka
struct IMAPConfig {
    bool help = false;          // Zobrazenie napovedy
    bool interactive = false;    // Interaktivny rezim
    bool unreadOnly = false;     // Iba neprecitane spravy
    bool headersOnly = false;    // Iba hlavicky sprav
    bool useTLS = false;         // Pouzitie sifrovania TLS

    std::string authFile;        // Cesta k autentifikacnemu suboru
    std::string outputDir;       // Vystupny adresar
    std::string certFile;        // Subor s certifikatmi
    std::string certDir = "/etc/ssl/certs"; // Adresar s certifikatmi

    std::string server;          // Nazov servera
    int port = 143;              // Port servera (predvoleny)
    std::string mailbox = "INBOX"; // Predvolena schranka
};

// Funkcie na parsovanie argumentov prikazoveho riadka a konfiguracii
IMAPConfig createConfig(int argc, char* argv[]); // Vytvori konfiguraciu z argumentov
std::string parseAuthFile(std::ifstream& file, const std::string& key); // Parsuje autentifikacny subor
void printHelp(); // Zobrazi napovedu
void runInteractive(IMAPConfig& config); // Spusti interaktivny rezim

#endif // CONFIG_PARSER_H

