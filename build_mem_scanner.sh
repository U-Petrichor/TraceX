#!/bin/bash

# Configuration
SCRIPT_DIR="$( cd "$( dirname "${BASH_SOURCE[0]}" )" &> /dev/null && pwd )"
MEM_SCANNER_DIR="$SCRIPT_DIR/collector/host_collector/mem_scanner"
TARGET_BIN="$MEM_SCANNER_DIR/bin/scanner"

# Colors
GREEN='\033[0;32m'
RED='\033[0;31m'
YELLOW='\033[1;33m'
NC='\033[0m' # No Color

echo -e "${GREEN}[*] Starting TraceX MemScanner Build...${NC}"

# 1. Check OS
if [[ "$OSTYPE" == "msys" || "$OSTYPE" == "cygwin" || "$OSTYPE" == "win32" ]]; then
    echo -e "${YELLOW}[!] Windows detected. Skipping MemScanner build (Linux only).${NC}"
    exit 0
fi

# 2. Check for g++
if ! command -v g++ &> /dev/null; then
    echo -e "${RED}[-] Error: g++ not found. Please install build-essential or g++.${NC}"
    echo "    Ubuntu/Debian: sudo apt-get install build-essential"
    echo "    CentOS/RHEL:   sudo yum groupinstall 'Development Tools'"
    exit 1
fi

# 3. Build
echo -e "[*] Building MemScanner..."
cd "$MEM_SCANNER_DIR" || exit 1

# Clean previous build
make clean > /dev/null 2>&1

# Make
if make all; then
    echo -e "${GREEN}[+] Build successful: $TARGET_BIN${NC}"
else
    echo -e "${RED}[-] Build failed.${NC}"
    exit 1
fi

# 4. Permissions check
if [ -f "$TARGET_BIN" ]; then
    chmod +x "$TARGET_BIN"
    echo -e "[*] Set executable permissions."
    
    # Optional: Set capability if setcap exists
    if command -v setcap &> /dev/null; then
        echo -e "[*] Setting capabilities (cap_sys_ptrace)..."
        # We try, but if it fails (non-root), we just warn
        if sudo setcap cap_sys_ptrace+ep "$TARGET_BIN" 2>/dev/null; then
             echo -e "${GREEN}[+] Capabilities set.${NC}"
        else
             echo -e "${YELLOW}[!] Could not set capabilities (sudo required). Run as root for full features.${NC}"
        fi
    fi
else
    echo -e "${RED}[-] Binary not found after build.${NC}"
    exit 1
fi

echo -e "${GREEN}[+] TraceX MemScanner setup complete.${NC}"
exit 0
