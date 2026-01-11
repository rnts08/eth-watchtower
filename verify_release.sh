#!/bin/bash
# verify_release.sh
# Automates the verification of ETH Watchtower release artifacts.

set -e

RED='\033[0;31m'
GREEN='\033[0;32m'
YELLOW='\033[1;33m'
NC='\033[0m' # No Color

CHECKSUMS_FILE="checksums.txt"
TARGET_FILE=""

while [[ "$#" -gt 0 ]]; do
    case $1 in
        -c|--checksums) CHECKSUMS_FILE="$2"; shift ;;
        *) TARGET_FILE="$1" ;;
    esac
    shift
done

echo "ETH Watchtower Release Verification"
echo "==================================="

# Check dependencies
if ! command -v gpg &> /dev/null; then
    echo -e "${RED}Error: gpg is not installed.${NC}"
    exit 1
fi

HAS_SHA256SUM=false
HAS_SHA512SUM=false
HAS_SHASUM=false

if command -v sha256sum &> /dev/null; then HAS_SHA256SUM=true; fi
if command -v sha512sum &> /dev/null; then HAS_SHA512SUM=true; fi
if command -v shasum &> /dev/null; then HAS_SHASUM=true; fi

if [ "$HAS_SHA256SUM" = false ] && [ "$HAS_SHA512SUM" = false ] && [ "$HAS_SHASUM" = false ]; then
    echo -e "${RED}Error: No checksum tools found (sha256sum, sha512sum, or shasum).${NC}"
    exit 1
fi

# Check files
if [ ! -f "$CHECKSUMS_FILE" ] || [ ! -f "${CHECKSUMS_FILE}.asc" ]; then
    echo -e "${RED}Error: $CHECKSUMS_FILE or ${CHECKSUMS_FILE}.asc not found.${NC}"
    echo "Please download them from the release page."
    exit 1
fi

# Verify Signature
echo -n "Verifying GPG signature... "
if gpg --verify "${CHECKSUMS_FILE}.asc" "$CHECKSUMS_FILE" 2>/dev/null; then
    echo -e "${GREEN}Signature OK${NC}"
else
    echo -e "${RED}Signature FAILED${NC}"
    echo "Please ensure you have the signer's public key imported."
    exit 1
fi

# Verify Checksums
if [ -n "$TARGET_FILE" ]; then
    echo "Verifying specific file: $TARGET_FILE"
else
    echo "Verifying artifacts..."
fi
failed=0
checked=0

while read -r line; do
    # Skip empty lines
    [ -z "$line" ] && continue

    checksum=$(echo "$line" | awk '{print $1}')
    filename=$(echo "$line" | awk '{print $2}')
    
    # Remove asterisk if present (binary mode indicator)
    filename="${filename#\*}"

    # Filter if target specified
    if [ -n "$TARGET_FILE" ] && [ "$filename" != "$TARGET_FILE" ]; then
        continue
    fi

    if [ -f "$filename" ]; then
        echo -n "  $filename: "
        
        local_hash=""
        if [ "${#checksum}" -eq 64 ]; then
            if [ "$HAS_SHA256SUM" = true ]; then
                local_hash=$(sha256sum "$filename" | awk '{print $1}')
            elif [ "$HAS_SHASUM" = true ]; then
                local_hash=$(shasum -a 256 "$filename" | awk '{print $1}')
            fi
        elif [ "${#checksum}" -eq 128 ]; then
            if [ "$HAS_SHA512SUM" = true ]; then
                local_hash=$(sha512sum "$filename" | awk '{print $1}')
            elif [ "$HAS_SHASUM" = true ]; then
                local_hash=$(shasum -a 512 "$filename" | awk '{print $1}')
            fi
        fi

        if [ -z "$local_hash" ]; then
            echo -e "${RED}Error: No suitable tool found to verify checksum length ${#checksum}.${NC}"
            failed=1
        else
            if [ "$local_hash" = "$checksum" ]; then
                echo -e "${GREEN}OK${NC}"
                checked=$((checked + 1))
            else
                echo -e "${RED}FAILED${NC}"
                failed=1
            fi
        fi
    elif [ -n "$TARGET_FILE" ] && [ -z "$CHECKSUMS_FILE" ]; then
        echo -e "${RED}Error: File '$filename' not found locally.${NC}"
        failed=1
    fi
done < "$CHECKSUMS_FILE"

if [ $checked -eq 0 ]; then
    if [ -n "$TARGET_FILE" ] && [ $failed -eq 0 ]; then
        echo -e "${RED}Error: File '$TARGET_FILE' not found in $CHECKSUMS_FILE.${NC}"
        exit 1
    elif [ -z "$TARGET_FILE" ]; then
        echo -e "${YELLOW}Warning: No release binaries found in current directory to verify.${NC}"
    else
        exit 1
    fi
elif [ $failed -eq 0 ]; then
    echo -e "${GREEN}Success: All present artifacts verified successfully.${NC}"
else
    echo -e "${RED}Error: Verification failed for some artifacts.${NC}"
    exit 1
fi