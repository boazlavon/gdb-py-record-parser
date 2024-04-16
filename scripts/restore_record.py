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
        
        # if section:
        #     # Get the offset of the section
        #     section_offset = section['sh_offset']
            
        #     # Seek to the offset in the file
        #     f.seek(section_offset)
            
        #     # Read the content of the section
        #     section_content = f.read(section['sh_size'])
            
        #     return section_content
        # else:
        #     return None


def record_full_reg_alloc(regnum):
    rec = {}  # Create a new record_full_entry structure (Python dictionary)
    rec['type'] = 'record_full_reg'  # Set the type to record_full_reg
    rec['u'] = {}  # Create a nested dictionary for the 'u' field

    # Set the fields specific to record_full_reg
    rec['u']['reg'] = {
        'num': regnum,
        'len': 8, # Assuming register size is always 8 bytes
        'u' : { 'ptr' : None } # Initialize ptr to None since we don't need dynamic memory allocation
    }

    return rec

def record_full_mem_alloc(addr, len_val):
    rec = {}  # Create a new record_full_entry structure (Python dictionary)
    rec['type'] = 'record_full_mem'  # Set the type to record_full_mem
    rec['addr'] = addr
    rec['len'] = len_val
    
    # Check if dynamic memory allocation is required
    if len_val > struct.calcsize('P'):
        # Allocate memory for the memory value
        rec['u'] = {'ptr': bytearray(len_val)}
    else:
        rec['u'] = {'buf': bytearray(struct.calcsize('P'))}

    return rec

def record_full_end_alloc():
    rec = {}
    rec['type'] = 'record_full_end'
    rec['u'] = {'end': {'sigval': None, 'insn_num': None}}
    return rec


def record_full_restore(core_file_path, initial_bfd_offset, osec_size, record_debug=True):
    # Initialize variables
    record_full_arch_list_head = None
    record_full_arch_list_tail = None
    record_full_insn_num = 0
    bfd_offset = initial_bfd_offset
    record_full_arch_list = []
    
    # Open the core file
    with open(core_file_path, 'rb') as core_file:
        # Check if there is a core BFD associated with the current program space
        
        # Check the magic code
        core_file.seek(bfd_offset)
        magic = struct.unpack("!I", core_file.read(4))[0]
        bfd_offset += 4  # Update bfd_offset by the number of bytes read
        if magic != RECORD_FULL_FILE_MAGIC:
            raise Exception("Version mis-match or file format error in core file.")
        if record_debug:
            print(f"  Reading 4-byte magic cookie RECORD_FULL_FILE_MAGIC (0x{magic:08X})")
        
        # Restore entries from core file
        try:
            while bfd_offset < initial_bfd_offset + osec_size:
                rec = None
                # Read entry type
                rectype = struct.unpack("B", core_file.read(1))[0]
                bfd_offset += 1  # Update bfd_offset by the number of bytes read
                
                if rectype == record_full_reg:  # Register entry
                    # Get register number
                    regnum_val = core_file.read(4)
                    assert len(regnum_val) == 4 
                    bfd_offset += 4  # Update bfd_offset by the number of bytes read

                    regnum = struct.unpack("!I", regnum_val)[0]
                    rec = record_full_reg_alloc(regnum)
                    if regnum == 17:
                        rec['u']['reg']['len'] = 4
                    
                    # Read value
                    val_len = rec['u']['reg']['len']
                    val = core_file.read(val_len)
                    assert len(val) == val_len
                    bfd_offset += val_len  # Update bfd_offset by the number of bytes read

                    rec['u']['reg']['u']['ptr'] = val
                    
                    if record_debug:
                        print(f"  Reading register #{rec['u']['reg']['num']} = {rec['u']['reg']['u']['ptr']}")
                
                elif rectype == record_full_mem:  # Memory entry
                    # Get length
                    
                    len_val = struct.unpack("!I", core_file.read(4))[0]
                    bfd_offset += 4  # Update bfd_offset by the number of bytes read
                    
                    # Get address
                    
                    addr = struct.unpack("!Q", core_file.read(8))[0]
                    bfd_offset += 8  # Update bfd_offset by the number of bytes read
                    
                    rec = record_full_mem_alloc(addr, len_val)
                    
                    # Read value
                    val_len = rec['len']
                    
                    val = core_file.read(val_len)
                    bfd_offset += val_len  # Update bfd_offset by the number of bytes read
                    if len(val) > struct.calcsize('P'):
                        rec['u']['ptr'] = val
                    else:
                        rec['u']['buf'] = val
                    
                    if record_debug:
                        print(f"  Reading memory {hex(addr)}={val}")
                
                elif rectype == record_full_end:  # End entry
                    rec = record_full_end_alloc()
                    record_full_insn_num += 1

                    # Get signal value
                    
                    sigval = struct.unpack(">i", core_file.read(4))[0]  # Assuming signal value is a signed integer
                    bfd_offset += 4  # Update bfd_offset by the number of bytes read
                    rec['u']['end']['sigval'] = sigval

                    # Get instruction count
                    
                    insn_num = struct.unpack(">i", core_file.read(4))[0]  # Assuming instruction count is an unsigned long long
                    bfd_offset += 4  # Update bfd_offset by the number of bytes read
                    rec['u']['end']['insn_num'] = insn_num
                    if record_debug:
                        print(f"  Reading record_full_end instruction_number={insn_num}, offset={bfd_offset}")
                        print()
                
                if rec is None:
                    raise Exception('Invalid rec')
                # Add rec to record arch list
                record_full_arch_list.append(rec)
                
        except Exception as e:
            print(e)
            
        # Print success message
        print(f"Restored records from core file {core_file_path}.")
        return record_full_arch_list

def main():
    # Create argument parser
    parser = argparse.ArgumentParser(description='Read content of a section from an ELF file')
    
    # Add argument for ELF file path
    parser.add_argument('elf_file', metavar='elf_file', type=str, help='Path to the ELF file')
    
    # Parse arguments
    args = parser.parse_args()
    
    # Read content of the section
    section_name = 'precord'
    section = find_section(args.elf_file, section_name)
    record_full_restore(args.elf_file, section.header.sh_offset, section.header.sh_size)   
    # if section_content:
    #     print("Section content:")
    #     print(section_content.decode('utf-8'))  # Assuming the content is text
    # else:
    #     print("Section not found.")

if __name__ == "__main__":
    main()
