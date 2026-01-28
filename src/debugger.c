#include "debugger.h"

// Forward declarations
static bool handle_debug_event(Debugger* dbg, DEBUG_EVENT* evt);
static bool set_software_breakpoint(Debugger* dbg, uintptr_t addr);
static bool remove_software_breakpoint(Debugger* dbg, uintptr_t addr, BYTE original_byte);

bool dbg_initialize(Debugger* dbg, const char* exe_path) {
    ZeroMemory(dbg, sizeof(Debugger));
    
    // Create suspended process for debugging
    STARTUPINFO si = {0};
    PROCESS_INFORMATION pi = {0};
    si.cb = sizeof(si);
    
    char cmd_line[MAX_PATH];
    snprintf(cmd_line, sizeof(cmd_line), "\"%s\"", exe_path);
    
    if (!CreateProcessA(
        NULL, 
        cmd_line, 
        NULL, 
        NULL, 
        FALSE, 
        DEBUG_PROCESS | DEBUG_ONLY_THIS_PROCESS | CREATE_SUSPENDED,
        NULL, 
        NULL, 
        &si, 
        &pi)) {
        printf("CreateProcess failed (err=%lu)\n", GetLastError());
        return false;
    }
    
    dbg->hProcess = pi.hProcess;
    dbg->hThread = pi.hThread;
    dbg->pid = pi.dwProcessId;
    dbg->tid = pi.dwThreadId;
    dbg->is_running = false;
    dbg->active_panel = PANEL_ASSEMBLY;
    dbg->memory_base = 0x400000; // Default base address
    
    // Initialize context
    dbg->ctx.ContextFlags = CONTEXT_FULL;
    if (!GetThreadContext(dbg->hThread, &dbg->ctx)) {
        printf("GetThreadContext failed (err=%lu)\n", GetLastError());
        TerminateProcess(dbg->hProcess, 1);
        CloseHandle(pi.hThread);
        CloseHandle(pi.hProcess);
        return false;
    }
    
    return true;
}

void dbg_cleanup(Debugger* dbg) {
    if (dbg->hThread) CloseHandle(dbg->hThread);
    if (dbg->hProcess) {
        // Remove all breakpoints before termination
        for (int i = 0; i < dbg->breakpoint_count; i++) {
            if (dbg->breakpoints[i].enabled) {
                remove_software_breakpoint(dbg, dbg->breakpoints[i].address, 
                                         dbg->breakpoints[i].original_byte);
            }
        }
        TerminateProcess(dbg->hProcess, 0);
        CloseHandle(dbg->hProcess);
    }
}

bool dbg_run(Debugger* dbg) {
    DEBUG_EVENT evt;
    DWORD continue_status = DBG_CONTINUE;
    
    dbg->is_running = true;
    
    // Resume suspended thread
    ResumeThread(dbg->hThread);
    
    while (dbg->is_running && !dbg->exit_debugger) {
        if (!WaitForDebugEvent(&evt, 100)) {
            if (GetLastError() == ERROR_SEM_TIMEOUT) {
                continue; // No event yet
            }
            printf("WaitForDebugEvent failed (err=%lu)\n", GetLastError());
            dbg->is_running = false;
            return false;
        }
        
        if (!handle_debug_event(dbg, &evt)) {
            dbg->is_running = false;
            return false;
        }
        
        ContinueDebugEvent(evt.dwProcessId, evt.dwThreadId, continue_status);
    }
    
    SuspendThread(dbg->hThread); // Ensure thread is suspended when stopped
    dbg_update_context(dbg);
    return true;
}

bool dbg_continue(Debugger* dbg) {
    // Remove single-step flag if set
    dbg->ctx.EFlags &= ~0x100;
    if (!SetThreadContext(dbg->hThread, &dbg->ctx)) {
        printf("SetThreadContext failed (err=%lu)\n", GetLastError());
        return false;
    }
    
    return dbg_run(dbg);
}

bool dbg_step(Debugger* dbg) {
    // Set trap flag for single-step
    dbg->ctx.EFlags |= 0x100;
    if (!SetThreadContext(dbg->hThread, &dbg->ctx)) {
        printf("SetThreadContext failed (err=%lu)\n", GetLastError());
        return false;
    }
    
    return dbg_run(dbg);
}

bool dbg_set_breakpoint(Debugger* dbg, uintptr_t addr) {
    if (dbg->breakpoint_count >= MAX_BREAKPOINTS) {
        printf("Maximum breakpoints reached\n");
        return false;
    }
    
    // Check if breakpoint already exists
    for (int i = 0; i < dbg->breakpoint_count; i++) {
        if (dbg->breakpoints[i].address == addr) {
            dbg->breakpoints[i].enabled = true;
            return set_software_breakpoint(dbg, addr);
        }
    }
    
    // Create new breakpoint
    Breakpoint* bp = &dbg->breakpoints[dbg->breakpoint_count];
    bp->enabled = true;
    bp->address = addr;
    
    // Read original byte
    if (!ReadProcessMemory(dbg->hProcess, (LPCVOID)addr, &bp->original_byte, 1, NULL)) {
        printf("Failed to read memory at 0x%p (err=%lu)\n", (void*)addr, GetLastError());
        return false;
    }
    
    // Try to get symbol name
    SYMBOL_INFO* symbol = (SYMBOL_INFO*)calloc(sizeof(SYMBOL_INFO) + 256, 1);
    if (symbol) {
        symbol->SizeOfStruct = sizeof(SYMBOL_INFO);
        symbol->MaxNameLen = 255;
        
        if (SymFromAddr(GetCurrentProcess(), addr, NULL, symbol)) {
            strncpy(bp->symbol, symbol->Name, sizeof(bp->symbol) - 1);
        } else {
            bp->symbol[0] = '\0';
        }
        free(symbol);
    }
    
    // Set breakpoint in process memory
    if (!set_software_breakpoint(dbg, addr)) {
        return false;
    }
    
    dbg->breakpoint_count++;
    return true;
}

bool dbg_remove_breakpoint(Debugger* dbg, int bp_num) {
    if (bp_num < 1 || bp_num > dbg->breakpoint_count) {
        printf("Invalid breakpoint number %d\n", bp_num);
        return false;
    }
    
    Breakpoint* bp = &dbg->breakpoints[bp_num - 1];
    if (!bp->enabled) {
        printf("Breakpoint %d already disabled\n", bp_num);
        return false;
    }
    
    // Remove from process memory
    if (!remove_software_breakpoint(dbg, bp->address, bp->original_byte)) {
        return false;
    }
    
    bp->enabled = false;
    return true;
}

void dbg_update_context(Debugger* dbg) {
    dbg->ctx.ContextFlags = CONTEXT_FULL;
    if (!GetThreadContext(dbg->hThread, &dbg->ctx)) {
        printf("GetThreadContext failed (err=%lu)\n", GetLastError());
    }
}

// Private helpers
static bool handle_debug_event(Debugger* dbg, DEBUG_EVENT* evt) {
    switch (evt->dwDebugEventCode) {
        case CREATE_PROCESS_DEBUG_EVENT:
            // Process created, let it run until first breakpoint
            dbg_update_context(dbg);
            return true;
            
        case EXCEPTION_DEBUG_EVENT: {
            DWORD exc_code = evt->u.Exception.ExceptionRecord.ExceptionCode;
            uintptr_t exc_addr = (uintptr_t)evt->u.Exception.ExceptionRecord.ExceptionAddress;
            
            if (exc_code == EXCEPTION_BREAKPOINT) {
                // Handle software breakpoint
                bool found = false;
                for (int i = 0; i < dbg->breakpoint_count; i++) {
                    Breakpoint* bp = &dbg->breakpoints[i];
                    if (bp->enabled && bp->address == exc_addr) {
                        // Decrement EIP/RIP to point to the breakpoint instruction
                        #if TARGET_X64
                            dbg->ctx.Rip--;
                        #else
                            dbg->ctx.Eip--;
                        #endif
                        if (!SetThreadContext(dbg->hThread, &dbg->ctx)) {
                            printf("SetThreadContext failed (err=%lu)\n", GetLastError());
                        }
                        found = true;
                        break;
                    }
                }
                
                if (!found) {
                    // First breakpoint at entry point
                    dbg_update_context(dbg);
                }
                
                dbg->is_running = false;
                SuspendThread(dbg->hThread);
                return true;
            }
            else if (exc_code == EXCEPTION_SINGLE_STEP) {
                // Single-step completed
                dbg_update_context(dbg);
                dbg->is_running = false;
                SuspendThread(dbg->hThread);
                return true;
            }
            else if (exc_code == EXCEPTION_ACCESS_VIOLATION) {
                printf("Access violation at 0x%p\n", (void*)exc_addr);
                dbg->is_running = false;
                SuspendThread(dbg->hThread);
                return false;
            }
            break;
        }
        
        case EXIT_PROCESS_DEBUG_EVENT:
            printf("\nProcess exited with code %lu\n", evt->u.ExitProcess.dwExitCode);
            dbg->exit_debugger = true;
            dbg->is_running = false;
            return false;
            
        case LOAD_DLL_DEBUG_EVENT:
            // Load symbols for new DLL
            if (evt->u.LoadDll.lpBaseOfDll) {
                SymLoadModule64(GetCurrentProcess(), evt->u.LoadDll.hFile, NULL, NULL, 
                              (DWORD64)evt->u.LoadDll.lpBaseOfDll, 0);
            }
            break;
    }
    
    return true;
}

static bool set_software_breakpoint(Debugger* dbg, uintptr_t addr) {
    BYTE cc = 0xCC; // INT3 instruction
    SIZE_T written;
    if (!WriteProcessMemory(dbg->hProcess, (LPVOID)addr, &cc, 1, &written) || written != 1) {
        printf("Failed to set breakpoint at 0x%p (err=%lu)\n", (void*)addr, GetLastError());
        return false;
    }
    return true;
}

static bool remove_software_breakpoint(Debugger* dbg, uintptr_t addr, BYTE original_byte) {
    SIZE_T written;
    if (!WriteProcessMemory(dbg->hProcess, (LPVOID)addr, &original_byte, 1, &written) || written != 1) {
        printf("Failed to remove breakpoint at 0x%p (err=%lu)\n", (void*)addr, GetLastError());
        return false;
    }
    return true;
}