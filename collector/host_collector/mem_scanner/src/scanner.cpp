#include "scanner.h"
#include <iostream>
#include <fstream>
#include <sstream>
#include <filesystem>
#include <algorithm>
#include <ctime>

namespace fs = std::filesystem;

// Constructor
MemScanner::MemScanner(const std::vector<std::string>& whitelist) : whitelist_(whitelist) {}

// Convert RiskLevel to string
std::string risk_to_string(RiskLevel level) {
    switch (level) {
        case RiskLevel::LOW: return "LOW";
        case RiskLevel::MEDIUM: return "MEDIUM";
        case RiskLevel::HIGH: return "HIGH";
        case RiskLevel::CRITICAL: return "CRITICAL";
        default: return "UNKNOWN";
    }
}

// Check if PID or Name is in whitelist
bool MemScanner::is_whitelisted(int pid, const std::string& comm) {
    std::string pid_str = std::to_string(pid);
    for (const auto& item : whitelist_) {
        if (item == pid_str || item == comm) {
            return true;
        }
    }
    return false;
}

// Get process command name from /proc/pid/comm
std::string get_process_name(int pid) {
    std::string path = "/proc/" + std::to_string(pid) + "/comm";
    std::ifstream file(path);
    std::string name;
    if (file.is_open()) {
        std::getline(file, name);
        // Remove trailing newline
        name.erase(std::remove(name.begin(), name.end(), '\n'), name.end());
    }
    return name;
}

// Parse /proc/pid/maps line
// Format: 00400000-00452000 r-xp 00000000 08:02 173521      /usr/bin/dbus-daemon
struct MapEntry {
    unsigned long start;
    unsigned long end;
    std::string perms;
    unsigned long long offset;
    std::string dev;
    unsigned long inode;
    std::string pathname;
};

MapEntry parse_map_line(const std::string& line) {
    MapEntry entry;
    std::stringstream ss(line);
    std::string range, perms, offset, dev, inode, pathname;
    
    ss >> range >> perms >> offset >> dev >> inode;
    // Pathname is optional and might contain spaces
    std::getline(ss, pathname);
    
    // Trim leading spaces from pathname
    size_t first = pathname.find_first_not_of(' ');
    if (std::string::npos != first) {
        pathname = pathname.substr(first);
    } else {
        pathname = "";
    }

    size_t dash = range.find('-');
    entry.start = std::stoul(range.substr(0, dash), nullptr, 16);
    entry.end = std::stoul(range.substr(dash + 1), nullptr, 16);
    entry.perms = perms;
    entry.inode = std::stoul(inode);
    entry.pathname = pathname;

    return entry;
}

// Inspect a single process
ScanResult MemScanner::inspect_process(int pid) {
    ScanResult result;
    result.pid = pid;
    result.exe_path = fs::read_symlink("/proc/" + std::to_string(pid) + "/exe").string();
    result.timestamp = std::time(nullptr);
    
    // Safety check: Don't scan self
    if (pid == getpid()) return result;

    std::ifstream maps_file("/proc/" + std::to_string(pid) + "/maps");
    if (!maps_file.is_open()) return result;

    std::string line;
    while (std::getline(maps_file, line)) {
        MapEntry entry = parse_map_line(line);
        
        // --- DETECTION LOGIC ---
        
        // 1. RWX Detection (Read + Write + Execute)
        // vm_flags usually needed, but perms in maps is a good first indicator
        bool is_rwx = (entry.perms.find("rwx") != std::string::npos);
        bool is_wx = (entry.perms.find("wx") != std::string::npos); // Write + Exec is always bad

        // 2. Memfd Execution Detection
        bool is_memfd = (entry.pathname.find("/memfd:") != std::string::npos);
        bool is_exec = (entry.perms.find('x') != std::string::npos);
        
        // 3. Anonymous Execution Detection
        bool is_anon = (entry.pathname.empty() || entry.pathname == "[anon]");
        
        // 4. Stack/Heap Execution
        bool is_stack = (entry.pathname.find("[stack]") != std::string::npos);
        bool is_heap = (entry.pathname.find("[heap]") != std::string::npos);

        if (is_exec) {
            Anomaly anomaly;
            anomaly.address = line.substr(0, line.find(' ')); // Store range string
            anomaly.size = entry.end - entry.start;
            anomaly.perms = entry.perms;
            anomaly.path = entry.pathname;
            anomaly.is_elf = false;
            anomaly.risk_level = RiskLevel::LOW;
            anomaly.confidence = 0.0;

            // --- Risk Scoring ---

            // Check ELF Header (Fingerprinting)
            // Only check if it's suspicious to avoid performance hit on valid libs
            if (is_memfd || is_anon || is_rwx) {
                 if (check_elf_header(pid, entry.start)) {
                     anomaly.is_elf = true;
                 }
            }

            // Scenario A: Memfd + Exec (Fileless Malware)
            if (is_memfd) {
                anomaly.type = "MEMFD_EXEC";
                if (anomaly.is_elf) {
                    anomaly.risk_level = RiskLevel::CRITICAL;
                    anomaly.confidence = 1.0;
                    anomaly.details = "Executable memfd with valid ELF header (Reflective Loading)";
                } else {
                    anomaly.risk_level = RiskLevel::HIGH;
                    anomaly.confidence = 0.8;
                    anomaly.details = "Executable memfd region";
                }
                result.anomalies.push_back(anomaly);
                continue;
            }

            // Scenario B: RWX Region (Shellcode / JIT)
            if (is_rwx || is_wx) {
                anomaly.type = "RWX_REGION";
                if (anomaly.is_elf) {
                    anomaly.risk_level = RiskLevel::CRITICAL;
                    anomaly.confidence = 1.0;
                    anomaly.details = "RWX region containing ELF header";
                } else if (is_anon) {
                    // RWX + Anon = High Risk (Shellcode)
                    anomaly.risk_level = RiskLevel::HIGH;
                    anomaly.confidence = 0.85;
                    anomaly.details = "Anonymous RWX region (Potential Shellcode)";
                } else if (is_stack || is_heap) {
                     anomaly.risk_level = RiskLevel::CRITICAL;
                     anomaly.confidence = 0.95;
                     anomaly.details = "Executable Stack/Heap (Buffer Overflow Exploit)";
                } else {
                    // RWX + File Backed (Could be JIT or packed binary)
                    anomaly.risk_level = RiskLevel::MEDIUM;
                    anomaly.confidence = 0.5;
                    anomaly.details = "File-backed RWX region (Possible JIT/Packer)";
                }
                result.anomalies.push_back(anomaly);
                continue;
            }
            
            // Scenario C: Anonymous Executable (Potential Mapped Code)
            if (is_anon && !is_rwx && anomaly.is_elf) {
                 anomaly.type = "ANON_ELF";
                 anomaly.risk_level = RiskLevel::HIGH;
                 anomaly.confidence = 0.9;
                 anomaly.details = "Anonymous region with ELF header (Process Hollowing/Reflective)";
                 result.anomalies.push_back(anomaly);
                 continue;
            }
        }
    }

    return result;
}

// Scan a single PID wrapper
void MemScanner::scan_pid(int pid) {
    try {
        std::string comm = get_process_name(pid);
        if (is_whitelisted(pid, comm)) return;

        ScanResult result = inspect_process(pid);
        
        // Output JSON only if anomalies found
        if (!result.anomalies.empty()) {
            std::cout << "{\"pid\": " << result.pid 
                      << ", \"exe\": \"" << result.exe_path << "\""
                      << ", \"timestamp\": " << result.timestamp 
                      << ", \"anomalies\": [";
            
            for (size_t i = 0; i < result.anomalies.size(); ++i) {
                const auto& a = result.anomalies[i];
                std::cout << "{\"type\": \"" << a.type << "\""
                          << ", \"address\": \"" << a.address << "\""
                          << ", \"size\": " << a.size
                          << ", \"perms\": \"" << a.perms << "\""
                          << ", \"path\": \"" << a.path << "\""
                          << ", \"is_elf\": " << (a.is_elf ? "true" : "false")
                          << ", \"risk_level\": \"" << risk_to_string(a.risk_level) << "\""
                          << ", \"confidence\": " << a.confidence
                          << ", \"details\": \"" << a.details << "\"}";
                if (i < result.anomalies.size() - 1) std::cout << ",";
            }
            std::cout << "]}" << std::endl;
        }
    } catch (...) {
        // Ignore errors for single PID scan (race conditions etc)
    }
}

// Scan all processes
void MemScanner::scan_all() {
    // Iterate over /proc
    for (const auto& entry : fs::directory_iterator("/proc")) {
        if (!entry.is_directory()) continue;
        
        std::string pid_str = entry.path().filename().string();
        if (std::all_of(pid_str.begin(), pid_str.end(), ::isdigit)) {
            int pid = std::stoi(pid_str);
            scan_pid(pid);
        }
    }
}
