#include "config_parser.h"

/*
 * Vytvori konfiguraciu z argumentov prikazoveho riadka.
 * Funkcia pouziva getopt_long na spracovanie dlhych a kratkych argumentov.
 * Zdroj inspiracie: https://man7.org/linux/man-pages/man3/getopt.3.html
 */
IMAPConfig createConfig(int argc, char* argv[]) {
    IMAPConfig config;
    int opt;
    int optionIndex = 0;

    static struct option long_options[] = {
        {"help", no_argument, nullptr, 'H'},             // Argument pre napovedu
        {"certfile", required_argument, nullptr, 'c'},   // Argument pre cestu k certifikatu
        {"certaddr", required_argument, nullptr, 'C'},   // Argument pre cestu k adresaru s certifikatmi
        {nullptr, 0, nullptr, 0}                         // Koniec pola s moznostami
    };

    if (argc < 2) {
        std::cerr << "Nespravne argumenty, pouzite --help pre viac informacii.\n";
        exit(6);
    }

    while ((opt = getopt_long(argc, argv, "p:Thinic:C:a:b:o:", long_options, &optionIndex)) != -1) {
        switch (opt) {
            case 'H':
                printHelp();
                break;
            case 'p':
                config.port = std::stoi(optarg);         // Nastavi port
                break;
            case 'T':
                config.useTLS = true;                    // Zapne sifrovanie TLS
                config.port = 993;                       // Predvoleny port pre IMAPS
                break;
            case 'h':
                config.headersOnly = true;               // Iba hlavicky sprav
                break;
            case 'n':
                config.unreadOnly = true;                // Iba neprecitane spravy
                break;
            case 'i':
                config.interactive = true;               // Interaktivny rezim
                break;
            case 'c':
                config.certFile = optarg;                // Subor s certifikatmi
                break;
            case 'C':
                config.certDir = optarg;                 // Adresar s certifikatmi
                break;
            case 'a':
                config.authFile = optarg;                // Cesta k autentifikacnemu suboru
                break;
            case 'b':
                config.mailbox = optarg;                 // Nazov schranky
                break;
            case 'o':
                config.outputDir = optarg;               // Vystupny adresar
                if (config.outputDir.back() != '/') {
                    config.outputDir += '/';
                }
                break;
            default:
                std::cerr << "Neplatny argument. Pouzite --help pre viac informacii.\n";
                exit(6);
        }
    }

    if (optind < argc) {
        config.server = argv[optind++];
    } else {
        std::cerr << "Server nebol specifikovany.\n";
        exit(1);
    }

    if (config.authFile.empty()) {
        std::cerr << "Autentifikacny subor nebol specifikovany\n";
        exit(4);
    }

    return config;
}

/*
 * Parsuje autentifikacny subor a extrahuje hodnotu podla kluca.
 * Vracia hodnotu pre zadany kluc, ak existuje.
 */
std::string parseAuthFile(std::ifstream& file, const std::string& key) {
    std::string line;
    if (getline(file, line) && line.compare(0, key.length() + 3, key + " = ") == 0) {
        return line.substr(line.find(" =") + 3);
    }
    return "";
}

/*
 * Vypise napovedu pre pouzitie programu a ukonci ho.
 */
void printHelp() {
    std::cout << "\nPouzitie:\n";
    std::cout << "     imapcl --help   -> zobrazi tuto napovedu a ukonci sa\n";
    std::cout << "     imapcl server [-p port] [-T [-c certfile] [-C certaddr]] [-n] [-h] -a auth_file [-b MAILBOX] -o dir [-i]\n";
    exit(0);
}



