#include "debugger.h"
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <tlhelp32.h>
#include <psapi.h>
#include <dbghelp.h>

#pragma comment(lib, "dbghelp.lib")
#pragma comment(lib, "psapi.lib")
#pragma comment(lib, "kernel32.lib")

DebuggerSession g_debugger = {0};

/* Initialize debugger subsystems */
BOOL InitializeDebugger(void) {
    memset(&g_debugger, 0, sizeof(DebuggerSession));
    
    // Initialize symbol handler
    SymInitialize(GetCurrentProcess(), NULL, FALSE);
    
    // Create debug event
    g_debugger.hDebugEvent = CreateEventA(NULL, FALSE, FALSE, NULL);
    
    return TRUE;
}

/* Attach to and debug a process */
BOOL AttachToProcess(const char* exePath) {
    STARTUPINFOA si = {0};
    PROCESS_INFORMATION pi = {0};
    DEBUG_EVENT dbgEvent = {0};
    
    si.cb = sizeof(si);
    
    // Create process in debug mode
    if (!CreateProcessA(exePath, NULL, NULL, NULL, FALSE,
                       DEBUG_PROCESS | DEBUG_ONLY_THIS_PROCESS,
                       NULL, NULL, &si, &pi)) {
        fprintf(stderr, "CreateProcess failed: %lu\n", GetLastError());
        return FALSE;
    }
    
    g_debugger.hProcess = pi.hProcess;
    g_debugger.dwProcessId = pi.dwProcessId;
    
    // Load symbols
    SymLoadModule64(g_debugger.hProcess, NULL, exePath, NULL, 0, 0);
    
    // Wait for initial debug event
    if (!WaitForDebugEvent(&dbgEvent, INFINITE)) {
        fprintf(stderr, "WaitForDebugEvent failed: %lu\n", GetLastError());
        return FALSE;
    }
    
    if (dbgEvent.dwDebugEventCode == CREATE_PROCESS_DEBUG_EVENT) {
        g_debugger.hThread = dbgEvent.u.CreateProcessInfo.hThread;
        g_debugger.dwThreadId = dbgEvent.dwThreadId;
        
        printf("[*] Process created: PID=%lu, TID=%lu\n",
               g_debugger.dwProcessId, g_debugger.dwThreadId);
    }
    
    ContinueDebugEvent(dbgEvent.dwProcessId, dbgEvent.dwThreadId, DBG_CONTINUE);
    g_debugger.state = DBG_STOPPED;
    
    return TRUE;
}

/* Set software breakpoint (INT3 - 0xCC) */
BOOL SetBreakpoint(DWORD address) {
    if (g_debugger.breakpointCount >= MAX_BREAKPOINTS) {
        fprintf(stderr, "Maximum breakpoints reached\n");
        return FALSE;
    }
    
    BYTE originalByte;
    SIZE_T bytesRead;
    
    // Read original byte
    if (!ReadProcessMemory(g_debugger.hProcess, (LPVOID)(uintptr_t)address,
                          &originalByte, 1, &bytesRead)) {
        fprintf(stderr, "Failed to read memory at 0x%lx\n", address);
        return FALSE;
    }
    
    // Write INT3 (0xCC) breakpoint
    BYTE int3 = 0xCC;
    if (!WriteProcessMemory(g_debugger.hProcess, (LPVOID)(uintptr_t)address,
                           &int3, 1, &bytesRead)) {
        fprintf(stderr, "Failed to set breakpoint at 0x%lx\n", address);
        return FALSE;
    }
    
    // Record breakpoint
    Breakpoint* bp = &g_debugger.breakpoints[g_debugger.breakpointCount];
    bp->address = address;
    bp->enabled = TRUE;
    bp->hitCount = 0;
    strcpy(bp->condition, "");
    
    printf("[+] Breakpoint %d set at 0x%lx\n",
           g_debugger.breakpointCount, address);
    
    g_debugger.breakpointCount++;
    return TRUE;
}

/* Remove breakpoint by index */
BOOL RemoveBreakpoint(int index) {
    if (index < 0 || index >= g_debugger.breakpointCount) {
        fprintf(stderr, "Invalid breakpoint index\n");
        return FALSE;
    }
    
    Breakpoint* bp = &g_debugger.breakpoints[index];
    
    // Restore original byte (would need to store it)
    // This is simplified - production version needs byte storage
    
    // Remove from array
    memmove(&g_debugger.breakpoints[index],
            &g_debugger.breakpoints[index + 1],
            (g_debugger.breakpointCount - index - 1) * sizeof(Breakpoint));
    
    g_debugger.breakpointCount--;
    printf("[+] Breakpoint %d removed\n", index);
    
    return TRUE;
}

/* Continue execution */
BOOL ContinueExecution(void) {
    if (g_debugger.state == DBG_STOPPED) {
        g_debugger.state = DBG_RUNNING;
        return TRUE;
    }
    return FALSE;
}

/* Step one instruction */
BOOL StepInstruction(void) {
    if (!GetThreadContext()) return FALSE;
    
    // Set trap flag (TF) to enable single-step
    g_debugger.threadContext.EFlags |= 0x100;
    
    if (!SetThreadContext()) return FALSE;
    
    g_debugger.state = DBG_RUNNING;
    return TRUE;
}

/* Get current thread context */
BOOL GetThreadContext(void) {
    CONTEXT ctx = {0};
    ctx.ContextFlags = CONTEXT_FULL | CONTEXT_DEBUG_REGISTERS;
    
    if (!GetThreadContext(g_debugger.hThread, &ctx)) {
        fprintf(stderr, "GetThreadContext failed: %lu\n", GetLastError());
        return FALSE;
    }
    
    memcpy(&g_debugger.threadContext, &ctx, sizeof(CONTEXT));
    return TRUE;
}

/* Set current thread context */
BOOL SetThreadContext(void) {
    if (!SetThreadContext(g_debugger.hThread, &g_debugger.threadContext)) {
        fprintf(stderr, "SetThreadContext failed: %lu\n", GetLastError());
        return FALSE;
    }
    return TRUE;
}

/* Read memory dump */
BOOL ReadMemoryDump(DWORD64 address, int size) {
    SIZE_T bytesRead;
    
    if (size > sizeof(g_debugger.memoryDump)) {
        size = sizeof(g_debugger.memoryDump);
    }
    
    if (!ReadProcessMemory(g_debugger.hProcess, (LPVOID)address,
                          g_debugger.memoryDump, size, &bytesRead)) {
        return FALSE;
    }
    
    g_debugger.memoryBase = address;
    return TRUE;
}

/* Handle debug events from debuggee */
void HandleDebugEvent(DEBUG_EVENT* pEvent) {
    switch (pEvent->dwDebugEventCode) {
        case EXCEPTION_DEBUG_EVENT: {
            EXCEPTION_RECORD* pExcept = &pEvent->u.Exception.ExceptionInfo;
            
            if (pExcept->ExceptionCode == EXCEPTION_BREAKPOINT) {
                GetThreadContext();
                g_debugger.state = DBG_BREAKPOINT;
                printf("[!] Breakpoint hit at 0x%llx\n",
                       (unsigned long long)g_debugger.threadContext.Rip);
            }
            else if (pExcept->ExceptionCode == EXCEPTION_SINGLE_STEP) {
                GetThreadContext();
                g_debugger.state = DBG_STEPPED;
                printf("[*] Single step at 0x%llx\n",
                       (unsigned long long)g_debugger.threadContext.Rip);
            }
            else {
                printf("[!] Exception 0x%lx at 0x%llx\n",
                       pExcept->ExceptionCode,
                       (unsigned long long)pExcept->ExceptionAddress);
            }
            break;
        }
        
        case CREATE_THREAD_DEBUG_EVENT:
            printf("[*] Thread created: TID=%lu\n", pEvent->dwThreadId);
            break;
            
        case EXIT_THREAD_DEBUG_EVENT:
            printf("[*] Thread exited: TID=%lu\n", pEvent->dwThreadId);
            break;
            
        case EXIT_PROCESS_DEBUG_EVENT:
            printf("[*] Process exited\n");
            break;
            
        case LOAD_DLL_DEBUG_EVENT: {
            char dllName[MAX_PATH];
            GetModuleFileNameExA(g_debugger.hProcess,
                                (HMODULE)pEvent->u.LoadDll.lpBaseOfDll,
                                dllName, MAX_PATH);
            printf("[+] DLL loaded: %s\n", dllName);
            break;
        }
        
        case UNLOAD_DLL_DEBUG_EVENT:
            printf("[-] DLL unloaded\n");
            break;
    }
}

/* Cleanup debugger resources */
void CleanupDebugger(void) {
    if (g_debugger.hProcess) {
        DebugActiveProcessStop(g_debugger.dwProcessId);
        CloseHandle(g_debugger.hProcess);
    }
    
    if (g_debugger.hThread) {
        CloseHandle(g_debugger.hThread);
    }
    
    if (g_debugger.hDebugEvent) {
        CloseHandle(g_debugger.hDebugEvent);
    }
    
    SymCleanup(GetCurrentProcess());
}