#include "scanner.h"
#include <sys/uio.h>
#include <vector>
#include <cstring>
#include <iostream>

// Helper to check ELF header via process_vm_readv
// Returns true if the memory region starts with \x7fELF
bool check_elf_header(int pid, unsigned long start_addr) {
    char buffer[4];
    struct iovec local[1];
    struct iovec remote[1];

    local[0].iov_base = buffer;
    local[0].iov_len = sizeof(buffer);

    remote[0].iov_base = (void*)start_addr;
    remote[0].iov_len = sizeof(buffer);

    ssize_t nread = process_vm_readv(pid, local, 1, remote, 1, 0);
    
    if (nread == 4) {
        // Check for ELF magic bytes: 0x7f 'E' 'L' 'F'
        if (buffer[0] == 0x7f && buffer[1] == 'E' && buffer[2] == 'L' && buffer[3] == 'F') {
            return true;
        }
    }
    
    return false;
}
