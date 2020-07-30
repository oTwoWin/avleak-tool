# AVLeak Tool
This tool is used to exfiltrate data from anti-virus.  Data can be used later as a fingerprint for detecting anti-virus sandbox environments. 

The tool is based on [AVLeak white paper][1] and written in Python and C.



## Requirements

To use the tool, you need :

- An isolated Windows 10 VM
- Python 3.8 (You can download it from Microsoft Store)
- One of the anti-virus available



## Available anti-virus

At the moment, only two anti-virus are available with the tool.

- Kaspersky
- Windows Defender



## How to use

#### First utilization

Once you have installed Python, the anti-virus and pull the tool, you can use the command :

```bash
python3 agent.py --leak --new
```

You only need to choose the wanted anti-virus and the data to exfiltrate.

It's really important to use the option `--new` the first time the tool is used. 

#### Change malware's set and create new malware table

If you wish to change the malware's set, use the command :

```bash
python3 agent.py --malware -s path/to/malw/directory
```

It will create a new malware's set and update the malware table respectively.

!!! You need to use this command when using a different anti-virus than Kaspersky or when you change the selected anti-virus !!!

## Adding more test scenarios

If you wish to add more test scenarios, you need to follow the following steps :

1. Copy one of the existing directory and rename it
2. Remove every file and folder in the subdirectory "cmake-build-debug"
3. Edit the file "poc.c" 
   1. Recover the data you want to exfiltrate
   2. Call the method leak(data, size of data)
4. Edit the file "agent.py" to add it to the list of program choice 



[1]: https://www.usenix.org/conference/woot16/workshop-program/presentation/blackthorne	"AVLeak White paper"

