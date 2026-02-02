# 6rdbg - Cross-Platform TUI Debugger

A GDB-inspired interactive debugger for Windows and Linux with real-time visual feedback.

## Features

- **Real-time Assembly View**: Display disassembled instructions with current instruction highlighting
- **Register Panel**: Live register values with change tracking
- **Memory Inspector**: Hexadecimal memory dump with ASCII representation
- **Breakpoints**: Set, enable, disable, and delete breakpoints
- **Single-Stepping**: Step through instructions with trap flag
- **Command Interface**: GDB-compatible command syntax

## Building

### Requirements

#### Windows
- Windows 10 or later
- MinGW or Visual Studio
- Debug Help Library (dbghelp.lib)

#### Linux
- GCC or Clang
- ncursesw library
- ptrace support
- libpthread

### Cross-Platform Build with CMake

```bash
mkdir build
cd build
cmake ..
make
```

### Platform-Specific Builds

#### Windows (MinGW):
```bash
gcc -o 6rdbg.exe main.c debugger_platform.c ui_platform.c ui_common.c disasm.c command_parser.c -ldbghelp -lpsapi
```

#### Linux:
```bash
gcc -o 6rdbg main.c debugger_platform.c ui_platform.c ui_common.c disasm.c command_parser.c -lncursesw -lpthread
```

## Usage

### Windows
```
6rdbg.exe C:\path\to\executable.exe
```

### Linux
```
./6rdbg /path/to/executable
```

Note: On Linux, you may need to run with appropriate permissions for ptrace:
```
./6rdbg /path/to/executable
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