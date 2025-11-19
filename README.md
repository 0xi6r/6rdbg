# Windows TUI Debugger

A GDB-inspired interactive debugger for Windows with real-time visual feedback.

## Features

- **Real-time Assembly View**: Display disassembled instructions with current instruction highlighting
- **Register Panel**: Live register values with change tracking
- **Memory Inspector**: Hexadecimal memory dump with ASCII representation
- **Breakpoints**: Set, enable, disable, and delete breakpoints
- **Single-Stepping**: Step through instructions with trap flag
- **Command Interface**: GDB-compatible command syntax

## Building

### Requirements
- Windows 10 or later
- MinGW or Visual Studio
- Debug Help Library (dbghelp.lib)

### Compilation

Using MinGW:
```bash
gcc -o debugger.exe main.c debugger.c ui.c command_parser.c -ldbghelp -lpsapi -lws2_32
```
Using Visual Studio:
```
cl main.c debugger.c ui.c command_parser.c dbghelp.lib psapi.lib ws2_32.lib
```

## Usage
```
6rdbg.exe C:\path\to\executable.exe
```

## Commands
### Execution Control
run / r - Start execution
continue / c - Continue from breakpoint
step / s - Step one instruction
next / n - Step over function call
finish / fin - Execute until return
Breakpoints
break <addr> / b <addr> - Set breakpoint at address
delete <n> - Delete breakpoint by number
disable <n> - Disable breakpoint
enable <n> - Enable breakpoint
info breakpoints - List all breakpoints
Inspection
info registers - Display all registers
examine <addr> [size] / x <addr> - Examine memory
print <expr> / p <expr> - Print expression value
Navigation
ESC - Cycle between panels
ENTER - Focus command prompt
Arrow keys - Navigate within panel


this is minimal implemntation, expect it to be buggy, feel free to contribute.