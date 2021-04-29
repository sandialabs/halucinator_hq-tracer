# Copyright 2021 National Technology & Engineering Solutions of Sandia, LLC (NTESS). 
# Under the terms of Contract DE-NA0003525 with NTESS, 
# the U.S. Government retains certain rights in this software.
# #This script starts the HQTrace Plugin
#@Christopher Wright
#@category HQTracer
#@keybinding alt shift t
#@menupath HQTrace
#@description Trace HALucinator/Qemu addrlist file

from hqtrace_plugin import HQTracePlugin
if __name__ == "__main__":
    tool = state.getTool()
    hq_trace_plugin = HQTracePlugin(tool, True, True, True)
    tool.addPlugin(hq_trace_plugin)
