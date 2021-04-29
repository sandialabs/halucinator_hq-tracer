# Copyright 2021 National Technology & Engineering Solutions of Sandia, LLC (NTESS). 
# Under the terms of Contract DE-NA0003525 with NTESS, 
# the U.S. Government retains certain rights in this software.
# #This is part of HQTrace. Don't run this script, run hqtrace_start.py
#@Christopher Wright
#@category HQTracer
#@menupath HQTrace
#@description Trace HALucinator/Qemu addrlist file

import logging
import os
import random
import sys

import ghidra.app.services.GoToService
from __main__ import *
from ghidra.program.flatapi import FlatProgramAPI

import yaml


def read_yaml(filename):
    '''Takes in filename and reads yaml file into dict'''
    with open(filename, 'r') as stream:
        try:
            db = yaml.safe_load(stream)
            return db
        except:
            print("Error reading yaml file!")
            sys.exit()


def get_address(address=None, program=None):
    """ Take an integer/string address and turn it into a ghidra address
        If not address provided, get the current address """
    if address is None:
        if program is not None:
            if program != getState().getCurrentProgram():
                raise Exception(
                    "Using current address, but have specified not current program")
        return getState().getCurrentAddress()

    if isinstance(address, ghidra.program.model.address.GenericAddress):
        return address

    if program is None:
        program = getState().getCurrentProgram()

    if not isinstance(address, str) and not isinstance(address, unicode):
        address = hex(address)
        if address.endswith("L"):
            address = address[:-1]

    return program.getAddressFactory().getAddress(address)


class HQTrace(object):
    '''This does the real work for the plugin. See cmd handlers for more details'''
    def __init__(self, plugin, state=None, logger_fname="ghidra_trace.txt"):
        self.plugin = plugin
        self.monitor = self.plugin.get_monitor()
        if state is None:
            state = self.plugin.get_ghidra_state()
        self.program = state.getCurrentProgram()
        self.model_addr_set = ghidra.program.model.address.AddressSet()
        self.addr_set = ghidra.program.model.address.AddressSet()
        self.serial_instrs = []
        self.return_stack = []
        self.instr_idx = None
        self.cur_address = state.getCurrentAddress()
        self.state = state
        self.program = state.getCurrentProgram()
        self.init_logger(logger_fname)
        self.logger.info("Program: %s", self.program)
        self.init_hqtrace()
        self.init_cmd_handlers()
        self.flatapi = FlatProgramAPI(self.program)
        self.track_stack = False
        self.registers = "None"

    def init_logger(self, fname):
        '''Ask for trace file, load up and highlight trace and current instruction'''
        self.logger_fname = fname
        self.logger = logging.getLogger(str(random.random()).replace(".","_"))
        self.logger.setLevel(logging.INFO)
        h_stdout = logging.StreamHandler(sys.stdout)
        h_stdout.setLevel(logging.INFO)
        self.logger.addHandler(h_stdout)
        if self.logger_fname:
            h_file = logging.FileHandler(self.logger_fname)
            h_file.setLevel(logging.INFO)
            self.logger.addHandler(h_file)

    def init_hqtrace(self):
        ''' Ask for qemu_asm.log and stats.yaml file and load the instructions '''
        filename = askString("QEMU Log File",
            "Enter QEMU asm.log file (e.g. tmp/example/qemu_asm.log)")

        #If HALucinator, experimental stack tracking we want the stats
        # file to see what we intercepted. If QEMU, we don't have this
        is_halucinator = askYesNo("HALucinator?", "Do you have a HALucinator stats file?")
        if is_halucinator:
            stats_filename = askString("Halucinator Stats File",
                "Enter Halucinator stats.yaml file (e.g. tmp/example/stats.yaml)")
            intercepted_config = read_yaml(stats_filename)
            for intr in intercepted_config['bypassed_funcs']:
                func_list = getGlobalFunctions(intr)
                if func_list:
                    for func in func_list:
                        self.model_addr_set.add(func.getBody())
        registers = ["R00", "R01", "R02", "R03", "R04", "R05", 
                    "R06", "R07", "R08", "R09", "R10", "R11", 
                    "R12", "R13", "R14", "R15"]
        # for reg in currentProgram.getLanguage().getRegisters():
        #     registers.append(str(reg))
        cur_func = None
        prev_func = None
        prev_func_list = []
        instr = None
        prev_instr = None
        reg_values = ""
        reading_reg = False
        with open(filename, "r") as addr_file:
            #This is a lot of code that does the essential loading the address into a list
            #It also does experimental adding of actions for stack tracing.
            for _, line in enumerate(addr_file):
                if line.startswith('0x'):
                    reading_reg = False
                    insert_action = False #Used for stack tracking
                    int_addr = int(line.split()[0][2:-1], 16)
                    addr = get_address(int_addr, self.program)

                    if addr:
                        self.addr_set.add(addr)
                        func = getFunctionContaining(addr)
                        prev_instr = instr
                        instr = getInstructionContaining(addr)
                        if not instr: #If ghidra fails, try to continue anyways
                            continue
                        ################################################################
                        ######Experimental Used for stack tracking######################
                        ################################################################
                        action = ("pass", (addr, func))
                        if func != cur_func:
                            if not prev_instr or (prev_instr and prev_instr.getNext() != instr):
                                action = ("add", (addr, func))

                        if len(self.serial_instrs)> 2:
                            if func == prev_func:
                                action = ("del", (addr, func))

                        if self.model_addr_set.contains(addr):
                            insert_action = True

                        if func and len(prev_func_list) > 1:
                            mnemonic = instr.getMnemonicString()
                            if mnemonic == "b":
                                #overwrite don't want to put on stack, doesn't have a return
                                new_action = ("del", (addr, func))
                                self.serial_instrs.append((addr, new_action, reg_values))
                                cur_func = prev_func_list[-1]
                                prev_func = prev_func_list[-2]
                                del prev_func_list[-1]
                        ################################################################
                        ######END Experimental Used for stack tracking##################
                        ################################################################

                        #Need this either way
                        self.serial_instrs.append((addr, action, reg_values))

                        ################################################################
                        ######Experimental Used for stack tracking######################
                        ################################################################
                        if action[0] != "pass":
                            prev_func_list.insert(0, cur_func)
                            del prev_func_list[10:]
                            prev_func = cur_func
                            cur_func = func
                        if insert_action:
                            new_action = ("del", (addr, func))
                            self.serial_instrs.append((addr, new_action, reg_values))
                            if action[0] != "pass":
                                prev_func_list.insert(0, cur_func)
                                del prev_func_list[10:]
                                prev_func = cur_func
                                cur_func = func
                        ################################################################
                        ######END Experimental Used for stack tracking##################
                        ################################################################
                elif line.split("=")[0] in registers:
                    if reading_reg:
                        reg_values += line
                    else:
                        reg_values = line
                        reading_reg = True
                else:
                    reading_reg = False
        if self.instr_idx is None:
            self.instr_idx = 0

        #Highlight all the instructions from the trace in yellow
        self.highlight_addr_set(self.addr_set)
        self.logger.info("Loaded %d addresses from file", len(self.serial_instrs))

    def reset_highlight(self):
        self.highlight_addr_set(self.addr_set)

    def highlight_addr_set(self, addr_set):
        prog_selection = ghidra.program.util.ProgramSelection(addr_set)
        service = self.plugin.getTool().getService(ghidra.app.services.GoToService)
        if service:
            self.navigatable = service.getDefaultNavigatable()
            if self.navigatable:
                self.navigatable.setHighlight(prog_selection)
    
    def highlight_diff(self):
        curr_selection = self.plugin.get_ghidra_state().getCurrentHighlight()
        diff_addr_set = curr_selection.subtract(self.addr_set)
        self.highlight_addr_set(diff_addr_set)

    def highlight_same(self):
        curr_selection = self.plugin.get_ghidra_state().getCurrentHighlight()
        same_addr_set = curr_selection.intersect(self.addr_set)
        self.highlight_addr_set(same_addr_set)
        
    def execute_cmds(self, cmds):
        '''Take the command typed in, parse and execute the cmd'''
        cmds = cmds.strip().split(', ')
        for cmd_id, cmd in enumerate(cmds):
            cmd = cmd.strip().split()
            if not cmd:
                continue

            if cmd[0] not in self.cmd_handlers:
                self.logger.error("Unknown command %s (%r)", cmd[0], cmd)
                self.cmd_help()
                break

            res = self.cmd_handlers[cmd[0]](cmd)

            if res:
                self.last_result = res

            self.update_ui()

        self.logger.debug('HQTrace currently at %s', self.cur_address)

    def update_ui(self):
        '''update the highlight inside ghidra'''
        if self.instr_idx:
            self.cur_address = self.serial_instrs[self.instr_idx][0]

        self.plugin.sync_view(self.cur_address)

    def init_cmd_handlers(self):
        '''This is a list of all the commands, initialize in dict'''
        self.cmd_handlers = {
            'e': self.cmd_eval,
            'h': self.cmd_help,
            'n': self.cmd_next,
            'o': self.cmd_exit_func,
            'p': self.cmd_prev,
            'pr': self.cmd_print_regs,
            'q': self.cmd_quit,
            's': self.cmd_step_over,
            't': self.cmd_toggle_stack,
            'sn': self.cmd_search_next,
            'sp': self.cmd_search_previous,
        }

    def cmd_exit_func(self, cmd):
        '''next until out of function.
        Perform the `next` command until we leave this function
        Will stop at first function call or the return '''
        c_func = getFunctionContaining(self.cur_address)
        n_func = c_func
        while c_func == n_func:
            self.cmd_next(["n", 1])
            n_func = getFunctionContaining(self.cur_address)

    def cmd_print_regs(self, cmd):
        '''Print the associated registers with this instruction.
        It prints the previous registers right before this instruction.'''
        print("Printing Registers")
        print(self.serial_instrs[self.instr_idx][2])

    def cmd_step_over(self, cmd):
        '''Step Over - Get next instruction in address order,
        perform `next` command until we reach this instr
        If the next instruction is not in the trace it will fail. '''
        c_instr = getInstructionContaining(self.cur_address)
        n_instr = c_instr.getNext()
        if self.addr_set.contains(n_instr.getAddress()):
            while c_instr != n_instr:
                self.cmd_next(["n", 1])
                c_instr = getInstructionContaining(self.cur_address)
        else:
            self.logger.info("Could Not Step Over Instruction!")

    def cmd_search_next(self,cmd):
        '''search next (sn) - search for the specified address going forward.
        example: "sn 0x0" or "sn 0" will search for the address 0 '''
        found = False
        search_addr = get_address(cmd[1], currentProgram)
        #search forward
        if not found:
            for ind in range(self.instr_idx, len(self.serial_instrs)):
                if self.serial_instrs[ind][0] == search_addr:
                    self.cmd_next(["n", ind - self.instr_idx])
                    found = True
                    break
        if self.cur_address == search_addr:
            found = True
        if found:
            self.logger.info("Found %s at index %s", search_addr, self.instr_idx)
        else:
            self.logger.info("Could not find %s", search_addr)

    def cmd_search_previous(self,cmd):
        '''search prev (sp) - search for the specified address going backward.
        example: "sp 0x0" or "sp 0" will search for the address 0 '''
        found = False
        search_addr = get_address(cmd[1], currentProgram)
        #search backward
        if not found:
            for ind in reversed(range(0, self.instr_idx)):
                if self.serial_instrs[ind][0] == search_addr:
                    self.cmd_prev(["p", self.instr_idx - ind])
                    found = True
                    break
        if found:
            self.logger.info("Found %s at index %s", search_addr, self.instr_idx)
        else:
            self.logger.info("Could not find %s", search_addr)

    def cmd_eval(self, cmd):
        '''executes your command (useful for debugging this plugin)
        example: e print("Hello World")'''
        exec(' '.join(cmd[1:]))

    def cmd_prev(self, cmd):
        ''' step backward
        example: "p" will move backward 1 instruction in the hq trace.
        "p 10" will move backward 10 instructions in the hq trace.
        '''
        num_instr = 1
        if len(cmd) > 1:
            num_instr = int(cmd[1])
        if self.instr_idx - num_instr < 0:
            old_num_instr = num_instr
            num_instr = self.instr_idx
            self.logger.info("CAN'T STEP BACKWARD %d instructions", old_num_instr)
            self.logger.info("Stepping backward %d instead", num_instr)
        if self.instr_idx - num_instr >= 0:
            for i in range(0, num_instr):
                self.instr_idx -= 1
                self.cur_address = self.serial_instrs[self.instr_idx][0]

                ################################################################
                ######Experimental Used for stack tracking######################
                ################################################################
                tuple_action = self.serial_instrs[self.instr_idx + 1][1]
                if tuple_action and self.track_stack:
                    action = tuple_action[0]
                    element = (self.cur_address, getFunctionContaining(self.cur_address))
                    if action == "add":
                        if len (self.return_stack) > 0:
                            del self.return_stack[-1]
                    elif action == "del":
                        self.return_stack.append(element)
                        #Do some cleanup if our stack is messed up
                        while len(self.return_stack) > 2:
                            if self.return_stack[-1][1] == self.return_stack[-3][1]:
                                del self.return_stack[-2:]
                            elif self.return_stack[-1][1] == self.return_stack[-2][1]:
                                del self.return_stack[-1]
                            else:
                                break
                    else:
                        pass
                ################################################################
                ######END Experimental Used for stack tracking##################
                ################################################################
            #Update the registers
            if self.instr_idx < len(self.serial_instrs):
                self.registers = self.serial_instrs[self.instr_idx+1][2]
            else:
                self.registers = self.serial_instrs[self.instr_idx][2]
            self.plugin.set_registers(self.registers)
        else:
            self.logger.info("CAN'T STEP BACKWARD %d instructions", num_instr)

    def cmd_next(self, cmd):
        ''' step over/next
        example: "n" will move forward 1 instruction in the hq trace.
        "n 10" will move forward 10 instructions in the hq trace.
        '''
        num_instr = 1
        if len(cmd) > 1:
            num_instr = int(cmd[1])

        if self.instr_idx + num_instr >= len(self.serial_instrs):
            old_num_instr = num_instr
            num_instr = len(self.serial_instrs) - self.instr_idx -1
            self.logger.info("CAN'T STEP FORWARD %d instructions", old_num_instr)
            self.logger.info("Stepping forward %d instead", num_instr)

        if self.instr_idx + num_instr < len(self.serial_instrs):
            for i in range(0, num_instr):
                self.instr_idx += 1
                self.cur_address = self.serial_instrs[self.instr_idx][0]

                ################################################################
                ######Experimental Used for stack tracking######################
                ################################################################
                tuple_action = self.serial_instrs[self.instr_idx][1]
                if tuple_action and self.track_stack:
                    action = tuple_action[0]
                    element = tuple_action[1]
                    if action == "add":
                        self.return_stack.append(element)
                        #Do some cleanup if our stack is messed up
                        while len(self.return_stack) > 2:
                            if self.return_stack[-1][1] == self.return_stack[-3][1]:
                                del self.return_stack[-2:]
                            elif self.return_stack[-1][1] == self.return_stack[-2][1]:
                                del self.return_stack[-1]
                            else:
                                break
                    elif action == "del":
                        if len (self.return_stack) > 0:
                            del self.return_stack[-1]
                    else: pass
                    ################################################################
                    ######END Experimental Used for stack tracking##################
                    ################################################################
            #Update the registers
            if self.instr_idx + 1 < len(self.serial_instrs):
                self.registers = self.serial_instrs[self.instr_idx+1][2]
            else:
                self.registers = self.serial_instrs[self.instr_idx][2]
            self.plugin.set_registers(self.registers)
        else:
            self.logger.info("CAN'T STEP FORWARD %d instructions", num_instr)

    def cmd_quit(self, cmd):
        '''quit'''
        self.serial_instrs = []
        self.instr_idx = None
        self.cur_address = None
        self.return_stack = []
        empty_addr_set = ghidra.program.model.address.AddressSet()
        null_selection = ghidra.program.util.ProgramSelection(empty_addr_set)
        self.state.setCurrentHighlight(null_selection)
        self.navigatable = None
        self.plugin.quit_trace()

    def cmd_help(self, _):
        '''help'''
        self.logger.info("Commands:")
        for k,v in self.cmd_handlers.items():
            self.logger.info("\t%s: %s", k, v.__doc__)

    def cmd_toggle_stack(self, cmd):
        '''toggle stack tracing. If multithreading is enabled, tracing will sometimes crash.'''
        self.track_stack = not self.track_stack
        self.logger.info("Toggled stack tracking")
        if self.track_stack:
            self.logger.info("Stack tracking ON")
        else:
            self.logger.info("Stack tracking OFF")
