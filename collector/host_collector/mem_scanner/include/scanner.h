#ifndef SCANNER_H
#define SCANNER_H

#include <string>
#include <vector>
#include <iostream>

// Risk levels for anomaly classification
enum class RiskLevel {
    LOW,
    MEDIUM,
    HIGH,
    CRITICAL
};

// Structure to hold information about a memory region anomaly
struct Anomaly {
    std::string type;         // e.g., "RWX", "MEMFD_EXEC", "STACK_EXEC"
    std::string address;      // Start address hex string
    size_t size;              // Size in bytes
    std::string perms;        // Permissions string (e.g., "rwxp")
    std::string path;         // Mapping path (if any)
    bool is_elf;              // True if ELF header detected
    RiskLevel risk_level;     // Calculated risk level
    double confidence;        // 0.0 to 1.0
    std::string details;      // Human-readable description
};

// Structure for a process scan result
struct ScanResult {
    int pid;
    std::string exe_path;
    long timestamp;
    std::vector<Anomaly> anomalies;
};

// Core scanner class
class MemScanner {
public:
    MemScanner(const std::vector<std::string>& whitelist);
    
    // Scan all processes
    void scan_all();
    
    // Scan a single process
    void scan_pid(int pid);

private:
    std::vector<std::string> whitelist_;
    
    // Internal helper to scan a specific PID
    ScanResult inspect_process(int pid);
    
    // Check if a process is whitelisted
    bool is_whitelisted(int pid, const std::string& comm);
};

// Helper to check ELF header via process_vm_readv
bool check_elf_header(int pid, unsigned long start_addr);

// Helper to convert RiskLevel to string
std::string risk_to_string(RiskLevel level);

#endif // SCANNER_H
