# 6rdbg - Cross-Platform TUI Debugger

A lightweight, fast debugger designed to show exactly what you need to know with minimal overhead. Now supports both Windows and Linux with a unified interface.

## Philosophy

> "Show you program execution state, memory and CPU as quick as possible"

6rdbg focuses on essential debugging information without feature bloat. It launches instantly, shows you what matters, and gets out of your way.

## 🚀 Key Features

### Cross-Platform Support
- **Windows**: Native Win32 API with Debug Help Library
- **Linux**: ptrace-based debugging with ncurses UI
- **Identical Experience**: Same commands, shortcuts, and layout on both platforms

### Real-Time Visual Feedback
- **Assembly Panel**: Disassembled code with current instruction highlighting
- **Register Panel**: Live CPU register values with color coding
- **Memory Panel**: Hexadecimal memory dump with ASCII representation
- **Command Interface**: GDB-compatible commands for familiarity

### Essential Debugging Capabilities
- **Step Into** (`step`/`s`): Execute one instruction
- **Step Over** (`next`/`n`): Execute entire function call
- **Finish** (`finish`/`fin`): Execute until function return
- **Breakpoints**: Set, manage, and automatically restore
- **Memory Inspection**: Hex dump with ASCII preview
- **Register Monitoring**: Real-time register state

### Enhanced Disassembler
- x86/x64 instruction decoding
- Support for common instructions: MOV, ADD, PUSH, POP, CALL, JMP, RET
- REX prefix handling for x64
- Symbol resolution (Windows)

## 🏗️ Architecture

```
6rdbg/
├── src/
│   ├── platform.h           # Cross-platform abstractions
│   ├── debugger_platform.c  # Windows/Linux debugging engines
│   ├── ui_platform.c        # Platform-specific UI rendering
│   ├── ui_common.c         # Shared UI logic and layout
│   ├── disasm.c            # Cross-platform instruction decoder
│   ├── command_parser.c     # GDB-compatible command interface
│   └── main.c              # Application entry point
├── CMakeLists.txt          # Cross-platform build system
└── test_program.c         # Debugging test target
```

## 🔧 Building

### Requirements

#### Windows
- Windows 10 or later
- MinGW-w64 or Visual Studio 2019+
- Debug Help Library (dbghelp.lib), PSAPI

#### Linux
- GCC 8+ or Clang 10+
- ncursesw (wide character support)
- ptrace support (standard on most distributions)
- libpthread

### Quick Start with CMake

```bash
git clone https://github.com/0xi6r/6rdbg.git
cd 6rdbg
mkdir build && cd build
cmake ..
make
```

### Manual Compilation

#### Windows (MinGW-w64):
```bash
gcc -o 6rdbg.exe src/*.c -Isrc -ldbghelp -lpsapi -luser32 -lkernel32
```

#### Linux:
```bash
gcc -o 6rdbg src/*.c -Isrc -lncursesw -lpthread -DLINUX_BUILD
```

## 📖 Usage

### Basic Usage

```bash
# Windows
.\6rdbg.exe C:\path\to\program.exe

# Linux
./6rdbg /path/to/program
```

### Quick Demo

```bash
# Build test program
gcc -o test_program test_program.c

# Debug it
./6rdbg ./test_program
```

## ⌨️ Commands

### Execution Control
- `run`/`r` - Start program execution
- `continue`/`c` - Continue from breakpoint
- `step`/`s` - Step one instruction (step into)
- `next`/`n` - Step over function call
- `finish`/`fin` - Execute until current function returns

### Breakpoints
- `break <addr>`/`b <addr>` - Set breakpoint at address
- `delete <n>` - Remove breakpoint number `n`
- `info breakpoints` - List all breakpoints

### Inspection
- `info registers` - Display CPU registers
- `examine <addr>`/`x <addr>` - Examine memory at address

### Other
- `quit`/`q` - Exit debugger

## 🎮 Interface Navigation

- **ESC** - Cycle between panels (Assembly → Registers → Memory → Command)
- **ENTER** - Focus command prompt from any panel
- **Arrow Keys** - Navigate within active panel
  - **Up/Down** in Assembly: Scroll disassembly
  - **Up/Down** in Memory: Scroll memory view
  - **Left/Right** in Memory: Navigate memory pages
  - **Up/Down** in Command: Navigate command history

## 🖥️ Panel Layout

```
┌─ Assembly (0x401000+20) ─────────────────────────┐
│ 0x00401000  55                 push rbp     │
│ 0x00401001  48 89 e5           mov rbp, rsp │
│ 0x00401004  c7 45 fc 00 00 00 00 mov [rbp-4], 0│
>│ 0x0040100b  e8 1a 00 00 00    call 0x40102a│ ← Current instruction
│ 0x00401010  89 45 f8           mov [rbp-8], eax│
├─ Registers ──────────────┬─ Memory (0x7fffffffe000) ──┤
│ RAX: 0x0000000000000000 │ 7fff e000  48 89 e5 c7 45 │
│ RBX: 0x00007fffffffe000 │ fc 00 00 00 00 e8 1a 00 │
│ RCX: 0x0000000000000001 │ 00 00 89 45 f8 e8 10 00 │
│ RDX: 0x0000000000000000 │ 00 00 c3 55 48 89 e5 c7 │
├─ Command ────────────────────────────────────────────┤
│ (gdb) step                                           │
└─────────────────────────────────────────────────────────────┘
```

## 🔍 Technical Details

### Windows Implementation
- **Debug Engine**: Win32 Debug API
- **Symbols**: Debug Help Library (dbghelp)
- **UI**: Console API with custom buffer management
- **Breakpoints**: Software breakpoints using INT3 (0xCC)

### Linux Implementation  
- **Debug Engine**: ptrace system calls
- **Signals**: Comprehensive signal handling
- **UI**: ncursesw for wide character support
- **Breakpoints**: Memory patching with original byte restoration

### Cross-Platform Features
- **Disassembler**: Hand-written x86/x64 decoder
- **Command Parser**: GDB-compatible syntax
- **Memory Access**: Abstracted read/write operations
- **Error Handling**: Platform-specific error reporting

## 🎯 Design Goals

1. **Speed**: Launch instantly, minimal overhead
2. **Clarity**: Show only essential information
3. **Simplicity**: Intuitive interface, familiar commands
4. **Portability**: Work identically everywhere
5. **Reliability**: Robust error handling and recovery

## 🧪 Testing

A test program is included to validate functionality:

```c
// test_program.c - demonstrates debugging scenarios
int global_var = 42;
int add_numbers(int a, int b);  // Function call testing
int main();                     // Entry point breakpoint
```

Run `./6rdbg ./test_program` to experiment with:
- Function stepping
- Variable inspection
- Memory navigation
- Breakpoint management

## 🐛 Known Limitations

- **Linux**: No symbol resolution yet (hex addresses only)
- **Threads**: Single-threaded debugging only
- **Conditional Breakpoints**: Not yet implemented
- **Expression Evaluation**: Basic address parsing only

## 🤝 Contributing

This is a minimal implementation focused on core functionality. Areas for improvement:
- Linux symbol resolution (ELF parsing)
- Multi-threaded debugging
- Conditional breakpoints
- Watchpoints
- Call stack visualization

Pull requests are welcome for core functionality improvements over feature additions.

## 📄 License

[Your license here - consider MIT for debugging tools]

---

**6rdbg**: The debugger that shows you what you need to know, as quickly as possible.