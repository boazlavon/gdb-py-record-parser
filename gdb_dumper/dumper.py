import gdb
import struct
import sys
import pprint

WORD_SIZE_BYTES = 8

# Global counter for dump files
dump_counter = 1

# Dictionaries to keep track of executed instructions and source lines per frame level
executed_instructions = {}
executed_source_lines = {}

ALL_FRAMES = []


class FullDisassembly(gdb.Command):
    """Disassemble the entire text section of the binary."""

    def __init__(self):
        super(FullDisassembly, self).__init__("full_disassembly_text_section", gdb.COMMAND_USER)

    def invoke(self, arg, from_tty):
        gdb.execute("set disassembly-flavor intel")
        file_info = gdb.execute("info files", to_string=True)

        text_start, text_end = None, None
        for line in file_info.split("\n"):
            if ".text" in line:
                parts = line.split()
                text_start = int(parts[0], 16)
                text_end = int(parts[2], 16)
                break

        if text_start is not None and text_end is not None:
            print(gdb.execute(f"disassemble {text_start}, {text_end}", to_string=True))
        else:
            print("No .text section found in the executable.")


class BreakpointHandler(gdb.Breakpoint):
    def __init__(self, spec):
        super().__init__(spec)

    def stop(self):
        global dump_counter
        # print(dump_counter)

        # Dump the current state
        self.dump_state()
        dump_counter += 1

    def validate_frames(self, frames, registers_dict):
        i = 1
        frames = [None] + frames + [None]
        while frames[i]:
            cur_frame = frames[i]
            assert cur_frame["previous_sp"] == cur_frame["stack_frame_address"]

            newer_frame = frames[i - 1]
            if newer_frame is None:
                assert cur_frame["level"] == 0
                cur_frame["rsp"] = registers_dict["rsp"]

            else:
                cur_frame["rsp"] = newer_frame["previous_sp"]
                if cur_frame["caller_of"]:
                    assert cur_frame["caller_of"] == newer_frame["stack_frame_address"]

            older_frame = frames[i + 1]
            if older_frame is not None:
                assert cur_frame["saved_rip"] == older_frame["rip"]
                saved_rip_content_raw = gdb.selected_inferior().read_memory(
                    int(cur_frame["saved_rip_address"], 16), WORD_SIZE_BYTES
                )
                saved_rip_content = self._convert_to_16x(
                    struct.unpack("<Q", saved_rip_content_raw.tobytes())[0]
                )
                assert saved_rip_content == cur_frame["saved_rip"]
                if cur_frame["called_by"]:
                    assert cur_frame["called_by"] == older_frame["stack_frame_address"]
            i += 1

    def dump_state(self):
        registers_dict = self.parse_registers()

        frames = []
        frame = gdb.newest_frame()
        while frame:
            frame_info_dict = self.extract_frame_info(frame)
            frames.append(frame_info_dict)
            frame = frame.older()
        self.validate_frames(frames, registers_dict)
        for frame_info_dict in frames:
            frame_info_dict["memory"] = self.dump_frame_memory(frame_info_dict)

        global ALL_FRAMES
        ALL_FRAMES.append((dump_counter, registers_dict, frames))

    def parse_registers(self):
        registers_output = gdb.execute("info registers", to_string=True)
        registers_dict = {}
        lines = registers_output.split("\n")
        for line in lines:
            if line.strip():
                parts = line.split()
                reg_name = parts[0].strip()
                reg_value = parts[1].strip()
                registers_dict[reg_name] = reg_value
        return registers_dict

    def dump_frame_memory(self, frame_info_dict):
        stack_frame_address, rsp = int(frame_info_dict["stack_frame_address"], 16), int(
            frame_info_dict["rsp"], 16
        )
        memory = []
        word_size = WORD_SIZE_BYTES
        for address in list(range(stack_frame_address + word_size, rsp - word_size, -word_size)):
            content = gdb.selected_inferior().read_memory(address, word_size)
            content_be = struct.unpack("<Q", content.tobytes())[0]
            content_str = f"{content_be:016x}"
            address_str = f"{address:016x}"
            memory.append((address_str, content_str))
        return memory

    def _convert_to_16x(self, address):
        return f"0x{address:016x}"

    def extract_frame_info(self, frame):
        frame_info = gdb.execute(f"info frame {frame.level()}", to_string=True)
        frame_info_dict = {
            "level": frame.level(),
            "frame_info": frame_info,
            "stack_frame_address": None,
            "locals": {"address": None, "variables": {}},
            "args": {"address": None, "variables": {}},
            "previous_sp": None,
            "saved_rbp_address": None,
            "rip": None,
            "saved_rip": None,
            "saved_rip_address": None,
            "called_by": None,
            "caller_of": None,
            "current_c_source": None,
            "current_c_inst": None,
            "current_asm_source": None,
            "current_asm_inst": None,
            "memory": None,
            "function_name": None,
            "source_location": None,
        }

        lines = frame_info.split("\n")
        for line in lines:
            if line.startswith("Stack frame at"):
                parts = line.split()
                frame_info_dict["stack_frame_address"] = self._convert_to_16x(
                    int(parts[3].replace(":", ""), 16)
                )
            if line.strip().startswith("Arglist at"):
                parts = line.split()
                frame_info_dict["args"]["address"] = self._convert_to_16x(int(parts[2].replace(",", ""), 16))
            if line.strip().startswith("Locals at"):
                parts = line.split()
                frame_info_dict["locals"]["address"] = self._convert_to_16x(
                    int(parts[2].replace(",", ""), 16)
                )
            if "Previous frame's sp is" in line:
                parts = line.split()
                frame_info_dict["previous_sp"] = self._convert_to_16x(int(parts[-1], 16))
            if "rbp at" in line:
                parts = line.split()
                frame_info_dict["saved_rbp_address"] = self._convert_to_16x(
                    int(parts[2].replace(",", ""), 16)
                )
            if "rip at" in line:
                parts = line.split()
                frame_info_dict["saved_rip_address"] = self._convert_to_16x(int(parts[-1], 16))
            if "saved rip =" in line:
                parts = line.split()
                frame_info_dict["saved_rip"] = self._convert_to_16x(int(parts[-1], 16))
                frame_info_dict["rip"] = self._convert_to_16x(int(parts[2], 16))
                frame_info_dict["function_name"] = parts[4]
                frame_info_dict["source_location"] = parts[5].strip("();")
            if "called by frame at" in line:
                parts = line.split()
                frame_info_dict["called_by"] = self._convert_to_16x(int(parts[-1], 16))
            if "caller of frame at" in line:
                parts = line.split()
                frame_info_dict["caller_of"] = self._convert_to_16x(int(parts[-1], 16))

        # Extract variables in locals and args
        locals_output = gdb.execute("info locals", to_string=True)
        args_output = gdb.execute("info args", to_string=True)

        for line in locals_output.split("\n"):
            if line.strip():
                parts = line.split("=", 1)
                if len(parts) == 2:
                    var_name = parts[0].strip()
                    var_value = parts[1].strip()
                    frame_info_dict["locals"]["variables"][var_name] = hex(int(var_value))

        for line in args_output.split("\n"):
            if line.strip():
                parts = line.split("=", 1)
                if len(parts) == 2:
                    var_name = parts[0].strip()
                    var_value = parts[1].strip()
                    frame_info_dict["args"]["variables"][var_name] = hex(int(var_value))

        if frame_info_dict['level'] == 0:
            rip = frame_info_dict["rip"]
            gdb.execute("set listsize 30")
            frame_info_dict["current_c_source"] = gdb.execute(f"list *{rip}", to_string=True)
            frame_info_dict["current_c_source"] = f'rip: {frame_info_dict["current_c_source"]}'
            frame_info_dict["current_asm_source"] = gdb.execute(f"disassemble {rip}", to_string=True)
            frame_info_dict["current_asm_source"] = frame_info_dict["current_asm_source"].replace("=>", "rip =>")
            frame_info_dict["current_asm_source"] = frame_info_dict["current_asm_source"].replace(
                "   0x", "       0x"
            )
            try:
                frame_info_dict["current_asm_inst"] = gdb.execute(f"x/i {rip}", to_string=True)
            except:
                frame_info_dict["current_asm_inst"] = 'NO_ACCESS'

            gdb.execute("set listsize 1")
            frame_info_dict["current_c_inst"] = gdb.execute(f"list *{rip}", to_string=True)
        return frame_info_dict


class BreakEveryInstruction(gdb.Command):
    """Set a breakpoint at every instruction in user-defined functions in the text section."""

    def __init__(self):
        super(BreakEveryInstruction, self).__init__("break_every_instruction", gdb.COMMAND_USER)

    def invoke(self, arg, from_tty):
        # Get all functions
        functions_info = gdb.execute("info functions", to_string=True)

        # Extract function names from source files
        user_defined_functions = {}
        source_file = False
        for line in functions_info.split("\n"):
            if line.startswith("File"):
                source_file = True
                continue
            elif line.startswith("Non-debugging symbols:"):
                source_file = False
                continue

            if source_file and line:
                parts = line.split(":")
                if len(parts) == 2:
                    func_name = parts[1].strip().split()[1]
                    # Remove parameter part and parentheses to get the function name
                    func_name = func_name.split("(")[0]
                    user_defined_functions[func_name] = None

        # Disassemble the entire text section
        file_info = gdb.execute("info files", to_string=True)
        text_start, text_end = None, None
        for line in file_info.split("\n"):
            if ".text" in line:
                parts = line.split()
                text_start = int(parts[0], 16)
                text_end = int(parts[2], 16)
                break

        if text_start is not None and text_end is not None:
            disassembly_output = gdb.execute(f"disassemble {text_start}, {text_end}", to_string=True)
            for line in disassembly_output.split("\n"):
                if line.strip().startswith("0x"):
                    parts = line.split()
                    address = int(parts[0], 16)
                    if len(parts) > 1:
                        label = parts[1].strip("<>").split("+")[0]
                        if label in user_defined_functions:
                            BreakpointHandler(f"*{parts[0]}")

        #print(f"Breakpoints set at instructions of user-defined functions.")
        info_breakpoint = gdb.execute(f"info breakpoints", to_string=True)
        #print(info_breakpoint)

def print_state(idx, registers, frames):
    for frame_info_dict in frames:
        print(f"#{idx}")
        print("===================================================================")
        pprint.pprint(registers)
        print_frame_info_dict = dict(frame_info_dict)
        del print_frame_info_dict["current_c_source"]
        del print_frame_info_dict["current_c_inst"]
        del print_frame_info_dict["current_asm_source"]
        del print_frame_info_dict["current_asm_inst"]
        del print_frame_info_dict["memory"]
        del print_frame_info_dict["frame_info"]
        print()
        print(frame_info_dict["frame_info"])
        pprint.pprint(print_frame_info_dict)
        print()
        print()
        print(frame_info_dict["current_c_source"])
        print(frame_info_dict["current_c_inst"])
        print(frame_info_dict["current_asm_source"])
        print()
        print(frame_info_dict["current_asm_inst"])
        for address, value in frame_info_dict["memory"]:
            print(f"{address} : {value}")
        print()
    print("===================================================================")
    sys.stdout.flush()

# def aggregate_history(all_frames):
#     for idx in range(len(all_frames) - 1):
#         cur_dump_id, cur_registers, cur_frames = all_frames[idx]
#         next_dump_id, next_registers, next_frames = all_frames[idx + 1]
#         assert cur_dump_id + 1 == next_dump_id
        # if current frame dont have any history, create a new one or just append

        # new frame is in top of next_frames
        # if len(next_frames) > len(cur_frames):
        
        
FullDisassembly()
BreakEveryInstruction()

# Set the breakpoints and handlers
gdb.execute("set disassembly-flavor intel")
gdb.execute("set listsize 1")
gdb.execute("break_every_instruction")
gdb.execute("full_disassembly_text_section")

# Start the program
gdb.execute("run")

for state in ALL_FRAMES:
    print_state(*state)

gdb.execute("q")
