#pragma once

#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <stdbool.h>
#include <stdint.h>
#include <inttypes.h>

#ifdef _WIN32
    #define PLATFORM_WINDOWS 1
    #include <windows.h>
    #include <dbghelp.h>
    #include <psapi.h>
#else
    #define PLATFORM_WINDOWS 0
    #include <unistd.h>
    #include <sys/types.h>
    #include <sys/ptrace.h>
    #include <sys/wait.h>
    #include <signal.h>
    #include <errno.h>
    #include <fcntl.h>
    #include <pthread.h>
#endif

// Cross-platform type definitions
#if PLATFORM_WINDOWS
    typedef HANDLE ProcessHandle;
    typedef HANDLE ThreadHandle;
    typedef DWORD ProcessId;
    typedef DWORD ThreadId;
    typedef CONTEXT ThreadContext;
    typedef BYTE byte;
    typedef WORD word;
    typedef DWORD dword;
    typedef DWORD64 qword;
#else
    typedef pid_t ProcessHandle;
    typedef pid_t ThreadHandle;  
    typedef pid_t ProcessId;
    typedef pid_t ThreadId;
    
    // Linux register structures (x86_64)
    #ifdef __x86_64__
    typedef struct {
        uint64_t r15, r14, r13, r12, rbp, rbx, r11, r10;
        uint64_t r9, r8, rax, rcx, rdx, rsi, rdi, orig_rax;
        uint64_t rip, cs, eflags, rsp, ss, fs_base, gs_base, ds, es, fs, gs;
    } ThreadContext;
    #else
    typedef struct {
        uint32_t ebx, ecx, edx, esi, edi, ebp, eax, xds, xes, xfs, xgs;
        uint32_t orig_eax, eip, xcs, eflags, esp, xss;
    } ThreadContext;
    #endif
    
    typedef unsigned char byte;
    typedef unsigned short word;
    typedef unsigned int dword;
    typedef unsigned long long qword;
#endif

// Console color definitions for cross-platform use
#ifndef FOREGROUND_BLACK
#define FOREGROUND_BLACK          0x0000
#define FOREGROUND_BLUE           0x0001
#define FOREGROUND_GREEN          0x0002
#define FOREGROUND_CYAN           0x0003
#define FOREGROUND_RED            0x0004
#define FOREGROUND_MAGENTA        0x0005
#define FOREGROUND_YELLOW         0x0006
#define FOREGROUND_WHITE          0x0007
#define FOREGROUND_INTENSITY      0x0008
#define BACKGROUND_BLUE           0x0010
#define BACKGROUND_GREEN          0x0020
#define BACKGROUND_RED            0x0040
#define BACKGROUND_INTENSITY      0x0080
#define BACKGROUND_GRAY           (BACKGROUND_BLUE | BACKGROUND_GREEN | BACKGROUND_RED)
#endif

// Architecture detection
#if defined(_M_X64) || defined(__x86_64__)
#define TARGET_X64 1
#else
#define TARGET_X64 0
#endif

// UI constants
#define ASSEMBLY_LINES 16
#define REGISTER_ROWS 8
#define MEMORY_ROWS 8
#define MEMORY_COLS 16
#define MAX_BREAKPOINTS 64
#define CMD_HISTORY_SIZE 50

// Panel IDs
typedef enum {
    PANEL_ASSEMBLY,
    PANEL_REGISTERS,
    PANEL_MEMORY,
    PANEL_COMMAND,
    PANEL_COUNT
} PanelId;

// Breakpoint structure
typedef struct {
    bool enabled;
    uintptr_t address;
    byte original_byte;
    char symbol[256];
} Breakpoint;

// Cross-platform debugger state
typedef struct {
    ProcessHandle hProcess;
    ThreadHandle hThread;
    ProcessId pid;
    ThreadId tid;
    ThreadContext ctx;
    bool is_running;
    bool exit_debugger;
    
    // UI state
    PanelId active_panel;
    int assembly_offset;
    uintptr_t memory_base;
    
    // Breakpoints
    Breakpoint breakpoints[MAX_BREAKPOINTS];
    int breakpoint_count;
    
    // Command interface
    char command_line[512];
    int command_cursor;
    char history[CMD_HISTORY_SIZE][512];
    int history_count;
    int history_index;
    
    // Platform-specific UI data
#if PLATFORM_WINDOWS
    HANDLE hStdout;
    HANDLE hStdin;
    void* csbi;  // CONSOLE_SCREEN_BUFFER_INFO
    struct { int X, Y; } buffer_size;
    void* back_buffer;  // CHAR_INFO*
#else
    // ncurses data
    void* stdscr;
    void* windows[PANEL_COUNT];
    struct { int X, Y; } buffer_size;
    bool needs_refresh;
#endif
} Debugger;

// Instruction structure for disassembler
typedef struct {
    size_t size;
    char mnemonic[16];
    char operands[64];
    bool is_jump;
    bool is_call;
    bool is_ret;
} Instruction;