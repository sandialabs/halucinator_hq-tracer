Copyright 2021 National Technology & Engineering Solutions of Sandia, LLC (NTESS). 
Under the terms of Contract DE-NA0003525 with NTESS, 
the U.S. Government retains certain rights in this software.

# License
BSD, see LICENSE file

# Usage:
First, get the QEMU/HALucinator log/stats file that we will use for the plugin:

This will trace a qemu_asm.log file through Ghidra. For example, when running the example included with HALucinator:

Make sure your python virtual environment is active and cd to the base HALucinator folder, then open 2 terminals (both with the pyenv active):

In the first terminal (we refer to this as the UART_Terminal from here on out), start the external device uart:
`python -m halucinator.external_devices.uart -i=1073811456`

Then, in the second terminal (we refer to this as the HALucinator_Terminal from here on out) we are going to run the actual firmware:
`test/STM32/example/run.sh` 

This will run for a second or two, and inside the UART_Terminal you will see that it says something like: `UART-Hyperterminal communication based on IT. Enter 10 characters using keyboard :`
At this point you will enter any 10 or more characters to the terminal and press enter.

This will echo 10 characters to both terminals (though the HALucinator_Terminal will have things with HAL_LOG|INFO| that shows it as well). Pressing enter on the UART_Terminal will finish that terminal, and in the HALucinator_Terminal you will need to press Ctrl-C to finish.

During execution of this, QEMU will save a QEMU log (`qemu_asm.log`) and a HAlucinator stats file (`stats.yaml`) to (relative from your HALucinator path) `tmp/Uart_Example/`. These are the files that we will import into Ghidra with this plugin.

# Note on tracing options:
QEMU allows for multiple logging options. There are a bunch of options for `-d` in QEMU. Built-in options that are available in HALucinator that pass through these options to QEMU can be done by adding: 

`--log-blocks=irq` --> `-d in_asm,exec,int,cpu,guest_errors,avatar,trace:nvic*`
`--log-blocks=regs` --> `-d in_asm,exec,cpu`
`--log-blocks=regs-nochain` --> `-d in_asm,exec,cpu,nochain`
`--log-blocks=exec` --> `-d exec`
`--log-blocks=trace-nochain` --> `-d in_asm,exec,nochain`
`--log-blocks=trace` --> `-d in_asm,exec`

We have found that while debugging it is useful to use `--log-blocks=regs --singlestep` is useful. This will be slower during execution, but it will break up the basic blocks during execution and save the register state at each instruction. Using the `--log-blocks=regs-nochain --singlestep` will take up a LOT of memory and a LOT of time for the HALucinator as well as the HQ-Tracer. If you just care about getting the blocks/instructions with no register values, `--log-blocks=trace-nochain` or `--log-blocks=trace` work well.

# Running the Plugin in Ghidra
Add the folder to your Ghidra scripts directory in Ghidra (press the green play button at the top, then inside the script manager click on the icon with the 3 lines to the left of the red cross at the very right. Then click the green plus button and navigate to the HQ-Tracer base folder and click OK.) Then type hqtrace inside the filter for the Script Manager browser. This will pull up 4 files that are part of the plugin. Only run the `hqtrace_start.py`. Running the others will fail and won't do anything for you.

It will pull up a new window in Ghidra. You can dock this window just like other Ghidra windows. Click `Start` and you will be prompted to enter the files mentioned above (qemu_asm.log and stats.yaml). You will want to enter the full path to them, something like `/home/someUser/halucinator/tmp/UART_Example/qemu_asm.log`. It will then ask if you used HALucinator to generate the log or just QEMU. If you used HALucinator, select `Yes` and then put in the full path to the stats file, something like `/home/someUser/halucinator/tmp/UART_Example/stats.yaml`.

This will load the files, parse them and create a highlighted selection that is then navigatable using commands below. You can display the help message below by typing `h` then enter.


Commands Available (type into the text box right below `Start` and push enter):
	e: executes your command (useful for debugging this plugin)
    	example: e print("Hello World")
	h: help
	n:  step over/next 
    	example: "n" will move forward 1 instruction in the qemu trace.
    	"n 10" will move forward 10 instructions in the qemu trace.
    
	o: next until out of function.
    	Perform the `next` command until we leave this function
    	Will stop at first function call or the return 
	p:  step backward 
    	example: "p" will move backward 1 instruction in the qemu trace. 
    	"p 10" will move backward 10 instructions in the qemu trace.
    
	q: quit
	s: Step Over - Get next instruction in address order, 
    	perform `next` command until we reach this instr
    	If the next instruction is not in the trace it will fail. 
	sn: search next (sn) - search for the specified address going forward. 
    	example: "sn 0x0" or "sn 0" will search for the address 0 
	sp: search prev (sp) - search for the specified address going backward. 
    	example: "sp 0x0" or "sp 0" will search for the address 0 
 

# Troubleshooting
If you get an error `ImportError: cannot import name HQTracePlugin`, remove the script location from your script directories, then re-add it. Not sure why this happens (It only happens for me when I run multiple plugins that are written with Python in Ghidra < 9.1)

# Optional setup if you want to use your own version of PyYaml:
(For ease of readability, ```alias jython='java -jar $GHIDRA_HOME/Ghidra/Features/Python/lib/jython-standalone-2.7.2.jar'``` 
Also note that jython was changed to `2.7.2` in Ghidra 9.2, so if you use an older version, this will be `....-2.7.1.jar` )

## YAML
### This is not necessary, as we include the yaml(v5.2) folder here so it should work
### This is one way we can add python packages though to jython to work with external libraries
You can try to use the pip or easy install to install the pyyaml, but most likely it won't work (depends on your proxy, firewall, etc)
`jython -m pip install pyyaml`
If this fails, try:
`jython -m easy_install pyyaml` 
If this also fails, download pyyaml and cd to the directory of the downloaded pyyaml
`git clone https://github.com/yaml/pyyaml.git`
`cd pyyaml`
`jython setup.py --without-libyaml install`

## If you have not linked site-packages previously into the right spot, do this. If you have, ignore it:
Now get these site packages to appear where ghidra will look for them
Delete empty folder first
`rm $GHIDRA_HOME/Ghidra/Features/Python/data/jython-2.7.2/Lib/site-packages -r`
Then link the site-packages to the right spot
`ln -s $GHIDRA_HOME/Ghidra/Features/Python/lib/Lib/site-packages  $GHIDRA_HOME/Ghidra/Features/Python/data/jython-2.7.2/Lib/site-packages`

