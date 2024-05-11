import struct
import argparse
from elftools.elf.elffile import ELFFile
from enum import Enum
import io
from abc import ABC, abstractmethod

RECORDS_SECTION_NAME = "precord"
RECORD_FULL_FILE_MAGIC = 0x20091016  # Define the magic value
RECORD_FULL_FILE_MAGIC_STRUCT = "!I"
RECORD_FULL_FILE_MAGIC_SIZE = struct.calcsize(RECORD_FULL_FILE_MAGIC_STRUCT)


class RecordType(Enum):
    RECORD_FULL_END = 0
    RECORD_FULL_REG = 1
    RECORD_FULL_MEM = 2


RECORD_TYPE_STRUCT = "B"
RECORD_TTPE_SIZE = struct.calcsize(RECORD_TYPE_STRUCT)


def find_section_by_name(elf_file_path, section_name):
    f = open(elf_file_path, "rb")
    elf_file = ELFFile(f)

    # Find the section by name
    return elf_file.get_section_by_name(section_name)


class BaseRecord(ABC):
    @abstractmethod
    def from_file(cls, core_file):
        pass

    def from_bytes(cls, bytes):
        io_bytes = io.BytesIO(bytes)
        return cls.from_file(io_bytes)

    def __repr__(self):
        return str(self)


class RegisterRecord(BaseRecord):
    RECORD_TYPE = RecordType.RECORD_FULL_REG
    REGNUM_STRUCT = "!I"
    REGNUM_SIZE = struct.calcsize(REGNUM_STRUCT)

    def __init__(self, regnum, reglen, regval, raw_record):
        self.regnum = regnum
        self.reglen = reglen
        self.regval = regval
        self.raw_record = raw_record

    def __str__(self):
        return f"RegisterValue(regnum={self.regnum}, reglen={self.reglen}, regval={self.regval})"

    @classmethod
    def from_file(cls, core_file):
        # Get register number
        regnum_raw = core_file.read(RegisterRecord.REGNUM_SIZE)
        assert len(regnum_raw) == RegisterRecord.REGNUM_SIZE
        regnum = struct.unpack(RegisterRecord.REGNUM_STRUCT, regnum_raw)[0]

        # TODO: should be fixed with a table or adding to the struct
        # Register size
        reglen = 8
        if regnum == 17:
            reglen = 4

        # Read value
        regval = core_file.read(reglen)
        assert len(regval) == reglen

        raw_record = regnum_raw + regval
        return cls(regnum, reglen, regval, raw_record)


class MemoryRecord(BaseRecord):
    RECORD_TYPE = RecordType.RECORD_FULL_MEM
    MEMLEN_STRUCT = "!I"
    MEMLEN_SIZE = struct.calcsize(MEMLEN_STRUCT)

    MEMADDR_STRUCT = "!Q"
    MEMADDR_SIZE = struct.calcsize(MEMADDR_STRUCT)

    def __init__(self, memaddr, memlen, memval, raw_record):
        self.memaddr = memaddr
        self.memlen = memlen
        self.memval = memval
        self.raw_record = raw_record

    def __str__(self):
        return f"MemoryValue(memaddr={hex(self.memaddr)}, memlen={self.memlen}, memval={self.memval})"

    @classmethod
    def from_file(cls, core_file):
        memlen_raw = core_file.read(4)
        assert len(memlen_raw) == MemoryRecord.MEMLEN_SIZE
        memlen = struct.unpack("!I", memlen_raw)[0]

        memaddr_raw = core_file.read(MemoryRecord.MEMADDR_SIZE)
        assert len(memaddr_raw) == MemoryRecord.MEMADDR_SIZE
        memaddr = struct.unpack("!Q", memaddr_raw)[0]

        memval = core_file.read(memlen)
        raw_record = memlen_raw + memaddr_raw + memval
        return cls(memaddr, memlen, memval, raw_record)


class RecordFullEnd(BaseRecord):
    SIGVAL_STRUCT = "!I"
    SIGVAL_SIZE = struct.calcsize(SIGVAL_STRUCT)

    INSN_NUM_STRUCT = "!I"
    INSN_NUM_SIZE = struct.calcsize(INSN_NUM_STRUCT)

    def __init__(self, sigval, insn_num, raw_record):
        self.sigval = sigval
        self.insn_num = insn_num
        self.raw_record = raw_record

    def __str__(self):
        return f"RecordFullEnd(sigval={self.sigval}, insn_num={self.insn_num})"

    @classmethod
    def from_file(cls, core_file):
        sigval_raw = core_file.read(RecordFullEnd.SIGVAL_SIZE)
        assert len(sigval_raw) == RecordFullEnd.SIGVAL_SIZE
        sigval = struct.unpack(RecordFullEnd.SIGVAL_STRUCT, sigval_raw)[0]

        insn_num_raw = core_file.read(RecordFullEnd.INSN_NUM_SIZE)
        assert len(insn_num_raw) == RecordFullEnd.INSN_NUM_SIZE
        insn_num = struct.unpack(RecordFullEnd.INSN_NUM_STRUCT, insn_num_raw)[0]

        raw_record = sigval_raw + insn_num_raw
        return cls(sigval, insn_num, raw_record)


RECORD_BUILDERS = {
    RecordType.RECORD_FULL_END.value: RecordFullEnd,
    RecordType.RECORD_FULL_REG.value: RegisterRecord,
    RecordType.RECORD_FULL_MEM.value: MemoryRecord,
}


def parse_records_from_section(core_file_path, initial_bfd_offset, osec_size, record_debug=True):
    # Initialize variables
    record_full_insn_idx = 1  # Start from 1
    bfd_offset = initial_bfd_offset
    record_full_arch_list = []

    # Open the core file
    with open(core_file_path, "rb") as core_file:
        # Check the magic code
        core_file.seek(initial_bfd_offset)
        magic_raw = core_file.read(RECORD_FULL_FILE_MAGIC_SIZE)
        magic = struct.unpack(RECORD_FULL_FILE_MAGIC_STRUCT, magic_raw)[0]
        assert len(magic_raw) == RECORD_FULL_FILE_MAGIC_SIZE
        assert magic == RECORD_FULL_FILE_MAGIC, "Version mis-match or file format error in core file."
        bfd_offset += RECORD_FULL_FILE_MAGIC_SIZE  # Update bfd_offset by the number of bytes read

        if record_debug:
            print(f"  Reading 4-byte magic cookie RECORD_FULL_FILE_MAGIC (0x{magic:08X})")

        # Restore entries from core file
        while bfd_offset < initial_bfd_offset + osec_size:
            # Read entry type
            record_type_raw = core_file.read(RECORD_TTPE_SIZE)
            record_type = struct.unpack(RECORD_TYPE_STRUCT, record_type_raw)[0]
            bfd_offset += RECORD_TTPE_SIZE

            record_builder = RECORD_BUILDERS.get(record_type)
            if record_builder is None:
                raise ValueError(f"Unknown record type: {record_type}")

            record = record_builder.from_file(core_file)
            record_len = len(record.raw_record)
            bfd_offset += record_len
            if record_debug:
                print(record)

            if record_type == RecordType.RECORD_FULL_END.value:
                if record.insn_num != record_full_insn_idx:
                    print(f"Warning: insn_num mismatch: {record.insn_num} != {record_full_insn_idx}")
                print()
                record_full_insn_idx += 1

            record_full_arch_list.append(record)

        # Print success message
        print(f"Successfully restored records from core file {core_file_path}.")
        print(f"In Total, {record_full_insn_idx - 1} instructions were restored. (records: {len(record_full_arch_list)})")
        return record_full_arch_list


def main():
    # Create argument parser
    parser = argparse.ArgumentParser(description="Read content of a section from an ELF file")

    # Add argument for ELF file path
    parser.add_argument("elf_file", metavar="elf_file", type=str, help="Path to the ELF file")

    # Parse arguments
    args = parser.parse_args()

    # Read content of the section
    section = find_section_by_name(args.elf_file, RECORDS_SECTION_NAME)
    initial_bfd_offset, osec_size = section.header.sh_offset, section.header.sh_size
    records = parse_records_from_section(args.elf_file, initial_bfd_offset, osec_size)
    return records


if __name__ == "__main__":
    main()
