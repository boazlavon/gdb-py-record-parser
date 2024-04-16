import struct
import argparse
from elftools.elf.elffile import ELFFile

RECORD_FULL_FILE_MAGIC = 0x20091016  # Define the magic value
record_full_end = 0
record_full_reg = 1
record_full_mem = 2

def find_section(elf_file_path, section_name):
    f = open(elf_file_path, 'rb')
    elf_file = ELFFile(f)
        
    # Find the section by name
    return elf_file.get_section_by_name(section_name)
        
def main():
    # Create argument parser
    parser = argparse.ArgumentParser(description='Read content of a section from an ELF file')
    
    # Add argument for ELF file path
    parser.add_argument('elf_file', metavar='elf_file', type=str, help='Path to the ELF file')
    parser.add_argument('output_path', metavar='output_path', type=str, help='Output path to the ELF file')
    
    # Parse arguments
    args = parser.parse_args()
    
    # Read content of the section
    section_name = 'precord'
    section = find_section(args.elf_file, section_name)
    with open(args.output_path, 'wb') as f:
        f.write(section.data())
    print(f"Section offset: {section.header.sh_offset}\nsection size: {section.header.sh_size}")

if __name__ == "__main__":
    main()
