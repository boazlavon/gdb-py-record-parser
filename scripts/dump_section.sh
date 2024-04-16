#!/bin/bash
set -x
# Check if the correct number of arguments is provided
if [ "$#" -ne 3 ]; then
    echo "Usage: $0 <elf_file> <section_name> <output_file>"
    exit 1
fi

# Assign arguments to variables
elf_file="$1"
section_name="$2"
output_file="$3"

# Extract hexadecimal dump of the section
hex_dump=$(readelf -x "$section_name" "$elf_file")

# Convert hexadecimal dump to binary
echo "$hex_dump" | xxd -r -p > "$output_file"

echo "Binary output saved to $output_file"
