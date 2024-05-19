import gdb
import struct
import pprint
import os
import io

WORD_SIZE_BYTES = 8

# Global counter for dump files
dump_counter = 1

class FrameState:
    def __init__(self, level):
        self.level = level
        self.frame_info = None
        self.stack_frame_address = None
        self.locals = {"address": None, "variables": {}}
        self.args = {"address": None, "variables": {}}
        self.previous_sp = None
        self.saved_rbp_address = None
        self.rip = None
        self.saved_rip = None
        self.saved_rip_address = None
        self.called_by = None
        self.caller_of = None
        self.current_c_source = None
        self.current_c_inst = None
        self.current_asm_source = None
        self.current_asm_inst = None
        self.next_asm_inst = None
        self.memory = None
        self.function_name = None
        self.source_location = None
        self.frame_info = None

    def __dict__(self):
        return {
            "level": self.level,
            "frame_info": self.frame_info,
            "stack_frame_address": self.stack_frame_address,
            "locals": self.locals,
            "args": self.args,
            "previous_sp": self.previous_sp,
            "saved_rbp_address": self.saved_rbp_address,
            "rip": self.rip,
            "saved_rip": self.saved_rip,
            "saved_rip_address": self.saved_rip_address,
            #"called_by": self.called_by,
            #"caller_of": self.caller_of,
            "current_c_source": self.current_c_source,
            "current_c_inst": self.current_c_inst,
            "current_asm_source": self.current_asm_source,
            "current_asm_inst": self.current_asm_inst,
            "next_asm_inst": self.current_asm_inst,
            "memory": self.memory,
            "function_name": self.function_name,
            "source_location": self.source_location,
        }

    def __str__(self):
        output_str = io.StringIO()
        props = {
            "level": self.level,
            #"frame_info": self.frame_info,
            "stack_frame_address": self.stack_frame_address,
            "locals": self.locals,
            "args": self.args,
            "previous_sp": self.previous_sp,
            "saved_rbp_address": self.saved_rbp_address,
            "rip": self.rip,
            "saved_rip": self.saved_rip,
            "saved_rip_address": self.saved_rip_address,
            #"called_by": self.called_by,
            #"caller_of": self.caller_of,
            #"current_c_source": self.current_c_source,
            #"current_c_inst": self.current_c_inst,
            #"current_asm_source": self.current_asm_source,
            #"current_asm_inst": self.current_asm_inst,
            #"memory": self.memory,
            # "memory": self.memory,
            "function_name": self.function_name,
            "source_location": self.source_location,
        } 
        pprint.pprint(props, stream=output_str)
        print(file=output_str)

        print(self.current_c_source, file=output_str)
        print(self.current_c_inst, file=output_str)
        print(self.current_asm_source, file=output_str)
        print(f"Current ASM Instruction:\n{self.current_asm_inst}", file=output_str)
        print(f"Next ASM Instruction:\n{self.next_asm_inst}\n", file=output_str)
        print(f"Stack Frame Memory:", file=output_str)
        for (address, value) in self.memory:
            print(f'{address} : {value}', file=output_str)
        print(file=output_str)
        result = output_str.getvalue()
        output_str.close()
        return result


class ProgramState:
    def __init__(self, idx, registers, frames):
        self.idx = idx
        self.registers = registers
        self.frames = frames

    def __dict__(self):
        return {
            "idx": self.idx,
            "registers": self.registers,
            "frames": [frame.__dict__() for frame in self.frames],
        }

    def __str__(self):
        output_str = io.StringIO()
        props = {
            "idx": self.idx,
            "registers": self.registers,
        }
        pprint.pprint(props, stream=output_str)

        print('frames:', file=output_str)
        result = output_str.getvalue()
        output_str.close()

        for frame in self.frames:
            result += f'level: {frame.level}\n'
            result += str(frame)

        return result


class FullExecution:
    def __init__(self):
        self.program_states = []
        
    def finish_execution(self):
        self._fill_next_asm_instruction()

    def _fill_next_asm_instruction(self): 
        for state_idx in range(len(self.program_states) - 1):
            assert self.program_states[state_idx].idx + 1 == self.program_states[state_idx + 1].idx
            # branching problem solution!
            self.program_states[state_idx].frames[0].next_asm_inst = self.program_states[state_idx + 1].frames[0].current_asm_inst
    
    @property
    def dumps_counter(self):
        return len(self.program_states)
    
EXECUTION = FullExecution()

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
        # Dump the current state
        global EXECUTION
        self.dump_state(EXECUTION.dumps_counter)

    def validate_frames(self, frames, registers_dict):
        i = 1
        frames = [None] + frames + [None]
        while frames[i]:
            cur_frame = frames[i]
            assert cur_frame.previous_sp == cur_frame.stack_frame_address

            newer_frame = frames[i - 1]
            if newer_frame is None:
                assert cur_frame.level == 0
                cur_frame.rsp = registers_dict["rsp"]

            else:
                cur_frame.rsp = newer_frame.previous_sp
                if cur_frame.caller_of:
                    assert cur_frame.caller_of == newer_frame.stack_frame_address

            older_frame = frames[i + 1]
            if older_frame is not None:
                assert cur_frame.saved_rip == older_frame.rip
                saved_rip_content_raw = gdb.selected_inferior().read_memory(
                    int(cur_frame.saved_rip_address, 16), WORD_SIZE_BYTES
                )
                saved_rip_content = self._convert_to_16x(
                    struct.unpack("<Q", saved_rip_content_raw.tobytes())[0]
                )
                assert saved_rip_content == cur_frame.saved_rip
                if cur_frame.called_by:
                    assert cur_frame.called_by == older_frame.stack_frame_address
            i += 1

    def dump_state(self, idx):
        registers_dict = self.parse_registers()

        frames = []
        frame = gdb.newest_frame()
        while frame:
            frame_info = self.extract_frame_info(frame)
            frames.append(frame_info)
            frame = frame.older()
        self.validate_frames(frames, registers_dict)

        for frame_info in frames:
            frame_info.memory = self.dump_frame_memory(frame_info)

        program_state = ProgramState(idx, registers_dict, frames)
        global EXECUTION
        EXECUTION.program_states.append(program_state)

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

    def dump_frame_memory(self, frame_info):
        stack_frame_address, rsp = int(frame_info.stack_frame_address, 16), int(frame_info.rsp, 16)
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
        frame_state = FrameState(frame.level())
        frame_state.frame_info = frame_info

        lines = frame_info.split("\n")
        for line in lines:
            if line.startswith("Stack frame at"):
                parts = line.split()
                frame_state.stack_frame_address = self._convert_to_16x(int(parts[3].replace(":", ""), 16))
            if line.strip().startswith("Arglist at"):
                parts = line.split()
                frame_state.args["address"] = self._convert_to_16x(int(parts[2].replace(",", ""), 16))
            if line.strip().startswith("Locals at"):
                parts = line.split()
                frame_state.locals["address"] = self._convert_to_16x(int(parts[2].replace(",", ""), 16))
            if "Previous frame's sp is" in line:
                parts = line.split()
                frame_state.previous_sp = self._convert_to_16x(int(parts[-1], 16))
            if "rbp at" in line:
                parts = line.split()
                frame_state.saved_rbp_address = self._convert_to_16x(int(parts[2].replace(",", ""), 16))
            if "rip at" in line:
                parts = line.split()
                frame_state.saved_rip_address = self._convert_to_16x(int(parts[-1], 16))
            if "saved rip =" in line:
                parts = line.split()
                frame_state.saved_rip = self._convert_to_16x(int(parts[-1], 16))
                frame_state.rip = self._convert_to_16x(int(parts[2], 16))
                frame_state.function_name = parts[4]
                frame_state.source_location = parts[5].strip("();")
            if "called by frame at" in line:
                parts = line.split()
                frame_state.called_by = self._convert_to_16x(int(parts[-1], 16))
            if "caller of frame at" in line:
                parts = line.split()
                frame_state.caller_of = self._convert_to_16x(int(parts[-1], 16))

        # Extract variables in locals and args
        locals_output = gdb.execute("info locals", to_string=True)
        args_output = gdb.execute("info args", to_string=True)

        for line in locals_output.split("\n"):
            if line.strip():
                parts = line.split("=", 1)
                if len(parts) == 2:
                    var_name = parts[0].strip()
                    var_value = parts[1].strip()
                    frame_state.locals["variables"][var_name] = hex(int(var_value))

        for line in args_output.split("\n"):
            if line.strip():
                parts = line.split("=", 1)
                if len(parts) == 2:
                    var_name = parts[0].strip()
                    var_value = parts[1].strip()
                    frame_state.args["variables"][var_name] = hex(int(var_value))

        if frame_state.level == 0:
            rip = frame_state.rip
            gdb.execute("set listsize 30")
            frame_state.current_c_source = gdb.execute(f"list *{rip}", to_string=True)
            frame_state.current_c_source = f"rip: {frame_state.current_c_source}"
            frame_state.current_asm_source = gdb.execute(f"disassemble {rip}", to_string=True)
            frame_state.current_asm_source = frame_state.current_asm_source.replace("=>", "rip =>")
            frame_state.current_asm_source = frame_state.current_asm_source.replace("   0x", "       0x")
            try:
                frame_state.current_asm_inst = gdb.execute(f"x/i {rip}", to_string=True)
            except:
                frame_state.current_asm_inst = "NO_ACCESS"

            gdb.execute("set listsize 1")
            frame_state.current_c_inst = gdb.execute(f"list *{rip}", to_string=True)
        return frame_state


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

        print(f"Breakpoints set at instructions of user-defined functions.")
        info_breakpoint = gdb.execute(f"info breakpoints", to_string=True)
        print(info_breakpoint)


FullDisassembly()
BreakEveryInstruction()

# Set the breakpoints and handlers
gdb.execute("set disassembly-flavor intel")
gdb.execute("set listsize 1")
gdb.execute("break_every_instruction")
gdb.execute("full_disassembly_text_section")

# Start the program
gdb.execute("run")

EXECUTION.finish_execution()

for state in EXECUTION.program_states:
    print(f"state: {state.idx}")
    print(str(state))

gdb.execute("q")
