# Copyright 2021 National Technology & Engineering Solutions of Sandia, LLC (NTESS). 
# Under the terms of Contract DE-NA0003525 with NTESS, 
# the U.S. Government retains certain rights in this software.
#This is part of HQTrace. Don't run this script, run hqtrace_start.py
#@Christopher Wright
#@category HQTracer
#@menupath HQTrace
#@description Trace HALucinator/Qemu addrlist file
from __main__ import *
from ghidra.app.plugin import ProgramPlugin
from ghidra.app.script import GhidraState
from ghidra.program.model.address import AddressSet
from ghidra.program.util import ProgramSelection
from ghidra.util.exception import CancelledException

from hqtrace import HQTrace
from hqtrace_gui import HQTraceComponentProvider


class HQTracePlugin(ProgramPlugin):
    '''This is the handler between the code and the GUI'''
    def __init__(self, tool, *args):
        super(HQTracePlugin, self).__init__(tool, *args)
        self.parent_tool = tool
        self.monitor = monitor.initialize(1)
        self.hq_trace = None
        self.state = None
        self.component = HQTraceComponentProvider(self)
        tool.addComponentProvider(self.component, True)

    def get_monitor(self):
        '''helper for other classes to get monitor'''
        return self.monitor

    def get_ghidra_state(self):
        '''helper to get the ghidra state'''
        return GhidraState(self.getTool(),
                            self.getTool().getProject(),
                            self.getCurrentProgram(),
                            self.getProgramLocation(),
                            self.getProgramSelection(),
                            self.getProgramHighlight())

    def sync_view(self, address=None):
        '''set the color cursor in ghidra ui'''
        if address is None:
            address = self.state.getCurrentAddress()
        self.state.setCurrentAddress(address)
        self.state.setCurrentSelection(ProgramSelection(AddressSet(address)))

    def do_start(self):
        '''handle the start button action'''
        try:
            self.state = self.get_ghidra_state()
            self.component.set_status("Initializing")
            self.hq_trace = HQTrace(self, self.state)
            self.sync_view()
            self.component.set_status("Started")
            self.component.set_stack(self.hq_trace.return_stack)
            self.set_registers(self.hq_trace.registers)
        except CancelledException:
            pass
    
    def set_registers(self, registers):
        self.component.set_registers(registers)

    def do_cmd(self):
        '''Take the command from the input and call correct handler'''
        cmds = self.component.panel_input.getText()
        if cmds and cmds[0] == 'q':
            self.quit_trace()
            return
        if self.hq_trace is None:
            self.do_start()
        self.hq_trace.execute_cmds(cmds)
        self.component.panel_input.selectAll()
        try:
            self.component.set_stack(self.hq_trace.return_stack)
        except:
            pass

    def quit_trace(self):
        '''Quit the trace and close the plugin'''
        self.hq_trace = None
        self.parent_tool.removeComponentProvider(self.component)
