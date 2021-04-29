# Copyright 2021 National Technology & Engineering Solutions of Sandia, LLC (NTESS). 
# Under the terms of Contract DE-NA0003525 with NTESS, 
# the U.S. Government retains certain rights in this software.
#This is part of HQTrace. Don't run this script, run hqtrace_start.py
#@Christopher Wright
#@category HQTracer
#@menupath HQTrace
#@description Trace HALucinator/Qemu addrlist file

from ghidra.framework.plugintool import ComponentProviderAdapter
from java.awt import Dimension, GridBagConstraints, GridBagLayout
from javax.swing import (AbstractAction, DefaultListModel, JButton,
                         JLabel, JList, JPanel, JScrollPane, JTextArea,
                         JTextField)


class HQTraceInputAction(AbstractAction):
    '''Used for sending typed command to the plugin'''
    def __init__(self, ec):
        self.ec = ec
    def actionPerformed(self, e):
        self.ec.plugin.do_cmd()


class HQTraceStartBtnAction(AbstractAction):
    '''Used to handle when the start button in ui clicked'''
    def __init__(self, ec):
        self.ec = ec
    def actionPerformed(self, e):
        self.ec.plugin.do_start()


class HQTraceQuitBtnAction(AbstractAction):
    '''Used to handle when the quit button in ui clicked'''
    def __init__(self, ec):
        self.ec = ec
    def actionPerformed(self, ec):
        self.ec.plugin.quit_trace()


class HQTraceComponentProvider(ComponentProviderAdapter):
    '''The GUI layout of the plugin'''
    def __init__(self, plugin):
        super(HQTraceComponentProvider, self).__init__(
            plugin.getTool(),
            "HQTrace",
            "trace_hal-qemu_log")
        self.plugin = plugin

        self.panel = JPanel(GridBagLayout())
        c = GridBagConstraints()
        c.fill = GridBagConstraints.HORIZONTAL
        c.gridy = 0
        c.gridx = 0
        c.weightx = 0.3
        self.panel_btn = JButton("Start")
        self.panel_btn.addActionListener(HQTraceStartBtnAction(self))
        self.panel.add(self.panel_btn, c)

        c.gridy = 1
        c.weightx = 0.3
        self.quit_panel_btn = JButton("Quit")
        self.quit_panel_btn.addActionListener(HQTraceQuitBtnAction(self))
        self.panel.add(self.quit_panel_btn, c)

        c.gridy = 2
        self.panel_label = JLabel("")
        self.panel.add(self.panel_label, c)

        c.gridy = 3
        c.gridwidth = 1
        text_string =   "For commands, type `h` then enter"
        self.panel_help = JLabel(text_string)
        self.panel.add(self.panel_help, c)

        c.gridy = 4
        self.panel_input = JTextField()
        self.panel_input.addActionListener(HQTraceInputAction(self))
        self.panel.add(self.panel_input, c)

        c.gridy = 5
        c.gridwidth = 1
        self.reg_label = JTextArea("")
        self.reg_label.setBorder(None)
        self.reg_label.setEditable(False)
        self.reg_label.setBackground(None)
        self.reg_label.setOpaque(True)
        self.panel.add(self.reg_label, c)

        c.gridx = 2
        c.gridy = 0
        c.weightx = 0.2
        self.ret_stack_label = JLabel("Return Address Stack")
        self.panel.add(self.ret_stack_label, c)

        c.gridx = 2
        c.gridy = 1
        c.gridheight = 5
        list_model = DefaultListModel()
        list_model.setSize(300)
        self.ret_stack_list = JList(list_model)

        self.ret_stack_scroll = JScrollPane(
                                self.ret_stack_list,
                                JScrollPane.VERTICAL_SCROLLBAR_ALWAYS,
                                JScrollPane.HORIZONTAL_SCROLLBAR_AS_NEEDED)
        self.panel.add(self.ret_stack_scroll, c)

        self.set_status("Stopped")

    def getComponent(self):
        '''return component panel'''
        return self.panel

    def set_status(self, status):
        '''Update the component status'''
        self.panel_label.setText(status)

    def set_registers(self, registers):
        '''update the register values'''
        self.reg_label.setText(registers)
    
    def set_stack(self, ret_stack):
        '''Update the stack trace box'''
        list_model = DefaultListModel()
        for element in ret_stack:
            list_model.addElement(element)
        list_model.setSize(len(ret_stack))
        self.ret_stack_list.setModel(list_model)
