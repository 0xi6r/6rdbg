#ifndef DEBUGGER_H
#define DEBUGGER_H

#include <windows.h>
#include <stdint.h>

#define MAX_BREAKPOINTS 32
#define MAX_WATCHES 16
#define MAX_THREADS 64
#define MAX_MODULES 128

typedef enum {
    DBG_STOPPED,
    DBG_RUNNING,
    DBG_STEPPED,
    DBG_BREAKPOINT,
    DBG_EXCEPTION
} DebuggerState;

typedef struct {
    DWORD address;
    BOOL enabled;
    DWORD hitCount;
    char condition[256];
} Breakpoint;

typedef struct {
    DWORD address;
    DWORD size;
    DWORD flags;
    BOOL isWrite;
} Watchpoint;

typedef struct {
    HANDLE hProcess;
    HANDLE hThread;
    DWORD dwProcessId;
    DWORD dwThreadId;
    CONTEXT threadContext;
    DebuggerState state;
    
    Breakpoint breakpoints[MAX_BREAKPOINTS];
    int breakpointCount;
    
    Watchpoint watches[MAX_WATCHES];
    int watchCount;
    
    DWORD64 memoryBase;
    BYTE memoryDump[512];
    
    HANDLE hDebugEvent;
} DebuggerSession;

// Core debugger functions
BOOL InitializeDebugger(void);
BOOL AttachToProcess(const char* exePath);
BOOL SetBreakpoint(DWORD address);
BOOL RemoveBreakpoint(int index);
BOOL ContinueExecution(void);
BOOL StepInstruction(void);
BOOL GetThreadContext(void);
BOOL SetThreadContext(void);
BOOL ReadMemoryDump(DWORD64 address, int size);
void HandleDebugEvent(DEBUG_EVENT* pEvent);
void CleanupDebugger(void);

extern DebuggerSession g_debugger;

#endif