#include <iostream>
#include <string>
#include <vector>
#include <unistd.h>
#include <getopt.h>
#include <fstream>
#include <sstream>
#include <ctime>
#include "scanner.h"

// Helper to print usage
void print_usage(const char* prog_name) {
    std::cerr << "Usage: " << prog_name << " [options]\n"
              << "Options:\n"
              << "  --scan-all          Scan all running processes\n"
              << "  --pid <pid>         Scan a specific PID\n"
              << "  --whitelist <file>  Path to whitelist file (one PID/Name per line)\n"
              << "  --help              Show this help message\n";
}

// Load whitelist from file
std::vector<std::string> load_whitelist(const std::string& path) {
    std::vector<std::string> whitelist;
    std::ifstream file(path);
    if (!file.is_open()) {
        std::cerr << "[WARN] Could not open whitelist file: " << path << std::endl;
        return whitelist;
    }
    std::string line;
    while (std::getline(file, line)) {
        if (!line.empty() && line[0] != '#') {
            whitelist.push_back(line);
        }
    }
    return whitelist;
}

int main(int argc, char* argv[]) {
    // 1. Root privilege check
    if (geteuid() != 0) {
        std::cerr << "[ERROR] MemScanner must be run as root (or with CAP_SYS_PTRACE)." << std::endl;
        return 1;
    }

    int opt;
    int option_index = 0;
    static struct option long_options[] = {
        {"scan-all", no_argument, 0, 'a'},
        {"pid", required_argument, 0, 'p'},
        {"whitelist", required_argument, 0, 'w'},
        {"help", no_argument, 0, 'h'},
        {0, 0, 0, 0}
    };

    bool mode_scan_all = false;
    int target_pid = -1;
    std::string whitelist_path;

    while ((opt = getopt_long(argc, argv, "ap:w:h", long_options, &option_index)) != -1) {
        switch (opt) {
            case 'a':
                mode_scan_all = true;
                break;
            case 'p':
                target_pid = std::stoi(optarg);
                break;
            case 'w':
                whitelist_path = optarg;
                break;
            case 'h':
                print_usage(argv[0]);
                return 0;
            default:
                print_usage(argv[0]);
                return 1;
        }
    }

    if (!mode_scan_all && target_pid == -1) {
        std::cerr << "[ERROR] Must specify either --scan-all or --pid <pid>" << std::endl;
        print_usage(argv[0]);
        return 1;
    }

    // Load whitelist
    std::vector<std::string> whitelist;
    if (!whitelist_path.empty()) {
        whitelist = load_whitelist(whitelist_path);
    }

    // Initialize scanner
    MemScanner scanner(whitelist);

    // Execute scan
    try {
        if (target_pid != -1) {
            scanner.scan_pid(target_pid);
        } else if (mode_scan_all) {
            scanner.scan_all();
        }
    } catch (const std::exception& e) {
        std::cerr << "[CRITICAL] Unhandled exception: " << e.what() << std::endl;
        return 2;
    }

    return 0;
}
