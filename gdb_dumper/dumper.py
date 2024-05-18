import gdb
import struct

WORD_SIZE_BYTES = 8

# Global counter for dump files
dump_counter = 1

# Dictionaries to keep track of executed instructions and source lines per frame level
executed_instructions = {}
executed_source_lines = {}

class FullDisassembly(gdb.Command):
    """Disassemble the entire text section of the binary."""

    def __init__(self):
        super(FullDisassembly, self).__init__("full_disassembly_text_section", gdb.COMMAND_USER)

    def invoke(self, arg, from_tty):
        gdb.execute("set disassembly-flavor intel")
        file_info = gdb.execute("info files", to_string=True)
        
        text_start, text_end = None, None
        for line in file_info.split('\n'):
            if ".text" in line:
                parts = line.split()
                text_start = int(parts[0], 16)
                text_end = int(parts[2], 16)
                break

        print(gdb.execute(f"disassemble {text_start}, {text_end}", to_string=True))
        if text_start is not None and text_end is not None:
            print(gdb.execute(f"disassemble {text_start}, {text_end}", to_string=True))
        else:
            print("No .text section found in the executable.")


class BreakpointHandler(gdb.Breakpoint):
    def __init__(self, spec):
        super().__init__(spec)

    def stop(self):
        global dump_counter
        print(dump_counter)

        # Dump the current state
        self.dump_state()
        dump_counter += 1

    def dump_state(self):
        frame = gdb.newest_frame()

        # Print registers
        print("===================================================================")
        registers_dict = self.parse_registers()
        print(f"Register contents: {registers_dict}")
        frames = []
        while frame:
            frame_info_dict = self.extract_frame_info(frame, registers_dict)
            frames.append(frame_info_dict)

            # pc = frame.pc()
            # print(f"Currently executing at {pc}:")
            # print(gdb.execute(f"list *{pc}", to_string=True))
            frame = frame.older() 

        i = 1
        frames = [None] + frames + [None]
        while frames[i]:
            cur_frame  = frames[i]
            assert cur_frame['previous_sp'] == cur_frame['frame_base']

            newer_frame = frames[i - 1]
            if newer_frame is None:
                assert cur_frame['level'] == 0
                cur_frame['rsp'] = registers_dict['rsp']
                # cur_frame['rbp'] = int(registers_dict['rbp'], 16)
                # cur_frame['rbp'] = f'0x{cur_frame["rbp"]:016x}'
                    
            else:
                cur_frame['rsp'] = newer_frame['previous_sp']
                # saved_rbp_content_raw = gdb.selected_inferior().read_memory(cur_frame['saved_rbp_address'], WORD_SIZE_BYTES)
                # saved_rbp_content = struct.unpack('<Q', saved_rbp_content_raw.tobytes())[0]
                # cur_frame['saved_rbp_content'] = saved_rbp_content

                # try:
                #     rbp_content_raw = gdb.selected_inferior().read_memory(newer_frame['rbp'], WORD_SIZE_BYTES)
                #     rbp_content = struct.unpack('<Q', rbp_content_raw.tobytes())[0]
                #     cur_frame['rbp'] = f'0x{rbp_content:016x}'
                # except Exception as e:
                #     cur_frame['rbp'] = 'NO_ACCESS'
                #     print(e)

            if cur_frame['caller_of'] and newer_frame:
                assert cur_frame['caller_of'] == newer_frame['frame_base']
            
            older_frame = frames[i + 1]
            if cur_frame['called_by'] and older_frame:
                assert cur_frame['called_by'] == older_frame['frame_base']
            
            if older_frame:
                assert cur_frame['saved_rip'] == older_frame['rip']
                saved_rip_content_raw = gdb.selected_inferior().read_memory(cur_frame['saved_rip_address'], WORD_SIZE_BYTES)
                saved_rip_content = struct.unpack('<Q', saved_rip_content_raw.tobytes())[0]
                assert saved_rip_content == cur_frame['saved_rip']

            i += 1
                
        
        # print(frames)
        for frame_info_dict in frames:
            print(frame_info_dict)
            self.print_frame_info(frame_info_dict)
        print("===================================================================")

    def parse_registers(self):
        registers_output = gdb.execute("info registers", to_string=True)
        registers_dict = {}
        lines = registers_output.split('\n')
        for line in lines:
            if line.strip():
                parts = line.split()
                reg_name = parts[0].strip()
                reg_value = parts[1].strip()
                registers_dict[reg_name] = reg_value
        return registers_dict

    def dump_frame_memory(self, frame_base, rsp):
        memory = []
        word_size = WORD_SIZE_BYTES
        print(f"frame_base: {frame_base:016x} rsp: {rsp:016x}")
        for address in range(frame_base, rsp - word_size, -word_size):
            content = gdb.selected_inferior().read_memory(address, word_size)
            content_be = struct.unpack('<Q', content.tobytes())[0]
            content_str = f"{content_be:016x}"
            memory.append((address, content_str))
        print()
        return memory
    
    def extract_frame_info(self, frame, registers_dict):
        frame_info = gdb.execute(f"info frame {frame.level()}", to_string=True)
        print(frame_info)
        frame_info_dict = {
            'level': frame.level(),
            'frame_base': None,
            'rsp': None,
            'rbp': None,
            'frame_size': None,
            'locals': {
                'address': None,
                'variables': {}
            },
            'args': {
                'address': None,
                'variables': {}
            },
            'memory': [],
            'previous_sp': None,
            'saved_rbp_address': None,
            'rip': None,
            'saved_rip': None,
            'saved_rip_address': None,
            'called_by': None,
            'caller_of': None
        }

        lines = frame_info.split('\n')
        for line in lines:
            if line.startswith("Stack frame at"):
                parts = line.split()
                frame_info_dict['frame_base'] = int(parts[3].replace(':',''), 16)
            if line.strip().startswith("Arglist at"):
                parts = line.split()
                frame_info_dict['args']['address'] = int(parts[2].replace(',', ''), 16)
            if line.strip().startswith("Locals at"):
                parts = line.split()
                frame_info_dict['locals']['address'] = int(parts[2].replace(',', ''), 16)
            if "Previous frame's sp is" in line:
                parts = line.split()
                frame_info_dict['previous_sp'] = int(parts[-1], 16)
            if "rbp at" in line:
                parts = line.split()
                frame_info_dict['saved_rbp_address'] = int(parts[-1], 16)
            if "rip at" in line:
                parts = line.split()
                frame_info_dict['saved_rip_address'] = int(parts[-1], 16)
            if "saved rip =" in line:
                parts = line.split()
                frame_info_dict['saved_rip'] = int(parts[-1], 16)
                frame_info_dict['rip'] = int(parts[2], 16)
            if "called by frame at" in line:
                parts = line.split()
                frame_info_dict['called_by'] = int(parts[-1], 16)
            if "caller of frame at" in line:
                parts = line.split()
                frame_info_dict['caller_of'] = int(parts[-1], 16)

        # frame_info_dict['frame_size'] = frame_info_dict['frame_base'] - frame_info_dict['RSP']
        # frame_info_dict['frame_size_words'] = frame_info_dict['frame_size'] // WORD_SIZE_BYTES

        # Extract variables in locals and args
        locals_output = gdb.execute("info locals", to_string=True)
        args_output = gdb.execute("info args", to_string=True)
        
        for line in locals_output.split('\n'):
            if line.strip():
                parts = line.split('=', 1)
                if len(parts) == 2:
                    var_name = parts[0].strip()
                    var_value = parts[1].strip()
                    frame_info_dict['locals']['variables'][var_name] = hex(int(var_value))
        
        for line in args_output.split('\n'):
            if line.strip():
                parts = line.split('=', 1)
                if len(parts) == 2:
                    var_name = parts[0].strip()
                    var_value = parts[1].strip()
                    frame_info_dict['args']['variables'][var_name] = hex(int(var_value))
        
        # frame_info_dict['memory'] = self.dump_frame_memory(frame_info_dict['previous_sp'], frame_info_dict['RSP'])

        return frame_info_dict

    def print_frame_info(self, frame_info_dict):
        return
        # for (key, value)  in frame_info_dict.items():
        #     if value is None:
        #         print(f'{key}: None')
        #     else:
        #         print(f'{key}: {value:016x}')
        # return
                
        # print(frame_info_dict)
        print(f"frame: {frame_info_dict['level']}")
        print(f"Frame base: 0x{frame_info_dict['frame_base']:016x}")
        print(f"Previous frame's sp: 0x{frame_info_dict['previous_sp']:016x}")
        # print(f"RBP: 0x{frame_info_dict['RBP']:016x}")
        # print(f"RSP: 0x{frame_info_dict['RSP']:016x}")
        # print(f"Frame size: {frame_info_dict['frame_size']} bytes = {frame_info_dict['frame_size_words']} words")
        print(f"RIP: 0x{frame_info_dict['rip']:016x}")
        print(f"Saved RIP: 0x{frame_info_dict['saved_rip_address']:016x} = 0x{frame_info_dict['saved_rip']:016x}")
        print(f"Locals At: 0x{frame_info_dict['locals']['address']:016x}")
        print(f"Locals variables: {frame_info_dict['locals']['variables']}")
        print(f"Args At: 0x{frame_info_dict['args']['address']:016x}")
        print(f"Arguments variables: {frame_info_dict['args']['variables']}")

        # print(f"RBP: 0x{frame_info_dict['rbp']:016x}")
        # print(f"Memory:")
        # for address, value in frame_info_dict['memory']:
        #     print(f"0x{address:016x}: 0x{value}")


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
        for line in functions_info.split('\n'):
            if line.startswith("File"):
                source_file = True
                continue
            elif line.startswith("Non-debugging symbols:"):
                source_file = False
                continue

            if source_file and line:
                parts = line.split(':')
                if len(parts) == 2:
                    func_name = parts[1].strip().split()[1]
                    # Remove parameter part and parentheses to get the function name
                    func_name = func_name.split('(')[0]
                    user_defined_functions[func_name] = None

        # Disassemble the entire text section
        file_info = gdb.execute("info files", to_string=True)
        text_start, text_end = None, None
        for line in file_info.split('\n'):
            if ".text" in line:
                parts = line.split()
                text_start = int(parts[0], 16)
                text_end = int(parts[2], 16)
                break

        if text_start is not None and text_end is not None:
            disassembly_output = gdb.execute(f"disassemble {text_start}, {text_end}", to_string=True)
            for line in disassembly_output.split('\n'):
                if line.strip().startswith("0x"):
                    parts = line.split()
                    address = int(parts[0], 16)
                    if len(parts) > 1:
                        label = parts[1].strip('<>').split('+')[0]
                        if label in user_defined_functions:
                            BreakpointHandler(f"*{parts[0]}")

        print(f"Breakpoints set at instructions of user-defined functions.")
        info_breakpoint = gdb.execute(f"info breakpoints", to_string=True)
        print(info_breakpoint)

FullDisassembly()
BreakEveryInstruction()

# Set the breakpoints and handlers
gdb.execute("set disassembly-flavor intel")
gdb.execute("break_every_instruction")
gdb.execute("full_disassembly_text_section")

# Start the program
gdb.execute("run")
gdb.execute("q")
