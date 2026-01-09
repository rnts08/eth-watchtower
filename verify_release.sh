#!/bin/bash
# verify_release.sh
# Automates the verification of ETH Watchtower release artifacts.

set -e

RED='\033[0;31m'
GREEN='\033[0;32m'
YELLOW='\033[1;33m'
NC='\033[0m' # No Color

echo "ETH Watchtower Release Verification"
echo "==================================="

# Check dependencies
if ! command -v gpg &> /dev/null; then
    echo -e "${RED}Error: gpg is not installed.${NC}"
    exit 1
fi

HAS_SHA256SUM=false
if command -v sha256sum &> /dev/null; then
    HAS_SHA256SUM=true
elif ! command -v shasum &> /dev/null; then
    echo -e "${RED}Error: sha256sum or shasum is not installed.${NC}"
    exit 1
fi

# Check files
if [ ! -f "checksums.txt" ] || [ ! -f "checksums.txt.asc" ]; then
    echo -e "${RED}Error: checksums.txt or checksums.txt.asc not found.${NC}"
    echo "Please download them from the release page."
    exit 1
fi

# Verify Signature
echo -n "Verifying GPG signature... "
if gpg --verify checksums.txt.asc checksums.txt 2>/dev/null; then
    echo -e "${GREEN}Signature OK${NC}"
else
    echo -e "${RED}Signature FAILED${NC}"
    echo "Please ensure you have the signer's public key imported."
    exit 1
fi

# Verify Checksums
echo "Verifying artifacts..."
failed=0
checked=0

while read -r line; do
    # Skip empty lines
    [ -z "$line" ] && continue

    checksum=$(echo "$line" | awk '{print $1}')
    filename=$(echo "$line" | awk '{print $2}')
    
    # Remove asterisk if present (binary mode indicator)
    filename="${filename#\*}"

    if [ -f "$filename" ]; then
        echo -n "  $filename: "
        
        if [ "$HAS_SHA256SUM" = true ]; then
            local_hash=$(sha256sum "$filename" | awk '{print $1}')
        else
            local_hash=$(shasum -a 256 "$filename" | awk '{print $1}')
        fi

        if [ "$local_hash" = "$checksum" ]; then
            echo -e "${GREEN}OK${NC}"
            checked=$((checked + 1))
        else
            echo -e "${RED}FAILED${NC}"
            failed=1
        fi
    fi
done < checksums.txt

if [ $checked -eq 0 ]; then
    echo -e "${YELLOW}Warning: No release binaries found in current directory to verify.${NC}"
elif [ $failed -eq 0 ]; then
    echo -e "${GREEN}Success: All present artifacts verified successfully.${NC}"
else
    echo -e "${RED}Error: Verification failed for some artifacts.${NC}"
    exit 1
fi