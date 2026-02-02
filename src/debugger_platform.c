#include "platform.h"
#include "debugger.h"

// Forward declarations for Linux functions
#if !PLATFORM_WINDOWS
static uintptr_t get_instruction_pointer(Debugger* dbg);
static void set_instruction_pointer(Debugger* dbg, uintptr_t ip);
static bool set_software_breakpoint(Debugger* dbg, uintptr_t addr);
static bool remove_software_breakpoint(Debugger* dbg, uintptr_t addr, byte original_byte);
#endif

#if PLATFORM_WINDOWS

// Windows-specific implementation
#include <tlhelp32.h>

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
                byte original = dbg->breakpoints[i].original_byte;
                remove_software_breakpoint(dbg, dbg->breakpoints[i].address, original);
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

// Private helpers for Windows
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
    byte cc = 0xCC; // INT3 instruction
    SIZE_T written;
    if (!WriteProcessMemory(dbg->hProcess, (LPVOID)addr, &cc, 1, &written) || written != 1) {
        printf("Failed to set breakpoint at 0x%p (err=%lu)\n", (void*)addr, GetLastError());
        return false;
    }
    return true;
}

static bool remove_software_breakpoint(Debugger* dbg, uintptr_t addr, byte original_byte) {
    SIZE_T written;
    if (!WriteProcessMemory(dbg->hProcess, (LPVOID)addr, &original_byte, 1, &written) || written != 1) {
        printf("Failed to remove breakpoint at 0x%p (err=%lu)\n", (void*)addr, GetLastError());
        return false;
    }
    return true;
}

#else

// Linux/Unix implementation using ptrace
#include <sys/user.h>
#include <sys/ptrace.h>
#include <sys/wait.h>
#include <elf.h>

static bool set_software_breakpoint(Debugger* dbg, uintptr_t addr);
static bool remove_software_breakpoint(Debugger* dbg, uintptr_t addr, byte original_byte);

bool dbg_initialize(Debugger* dbg, const char* exe_path) {
    memset(dbg, 0, sizeof(Debugger));
    
    pid_t pid = fork();
    if (pid == 0) {
        // Child process - attach ptrace and exec
        if (ptrace(PTRACE_TRACEME, 0, NULL, NULL) < 0) {
            perror("ptrace");
            exit(1);
        }
        
        // Stop ourselves so parent can set breakpoints
        raise(SIGSTOP);
        
        // Execute the target
        execl(exe_path, exe_path, NULL);
        perror("execl");
        exit(1);
    } else if (pid > 0) {
        // Parent process - debugger
        dbg->hProcess = pid;
        dbg->hThread = pid; // Linux uses same ID for process and main thread
        dbg->pid = pid;
        dbg->tid = pid;
        dbg->is_running = false;
        dbg->active_panel = PANEL_ASSEMBLY;
        dbg->memory_base = 0x400000; // Default base address
        
        // Wait for child to stop
        int status;
        if (waitpid(pid, &status, 0) < 0) {
            perror("waitpid");
            return false;
        }
        
        if (!WIFSTOPPED(status) || WSTOPSIG(status) != SIGSTOP) {
            printf("Child didn't stop as expected\n");
            return false;
        }
        
        // Update initial context
        dbg_update_context(dbg);
        
        return true;
    } else {
        perror("fork");
        return false;
    }
}

void dbg_cleanup(Debugger* dbg) {
    if (dbg->hProcess > 0) {
        // Remove all breakpoints
        for (int i = 0; i < dbg->breakpoint_count; i++) {
            if (dbg->breakpoints[i].enabled) {
                remove_software_breakpoint(dbg, dbg->breakpoints[i].address, 
                                         dbg->breakpoints[i].original_byte);
            }
        }
        
        // Kill the debugged process
        kill(dbg->hProcess, SIGKILL);
        waitpid(dbg->hProcess, NULL, 0);
    }
}

bool dbg_run(Debugger* dbg) {
    dbg->is_running = true;
    
    // Continue execution
    if (ptrace(PTRACE_CONT, dbg->hProcess, NULL, NULL) < 0) {
        perror("ptrace CONT");
        dbg->is_running = false;
        return false;
    }
    
    while (dbg->is_running && !dbg->exit_debugger) {
        int status;
        pid_t pid = waitpid(dbg->hProcess, &status, 0);
        
        if (pid < 0) {
            perror("waitpid");
            dbg->is_running = false;
            return false;
        }
        
        if (WIFEXITED(status)) {
            printf("\nProcess exited with code %d\n", WEXITSTATUS(status));
            dbg->exit_debugger = true;
            dbg->is_running = false;
            return false;
        }
        
        if (WIFSIGNALED(status)) {
            printf("\nProcess killed by signal %d\n", WTERMSIG(status));
            dbg->exit_debugger = true;
            dbg->is_running = false;
            return false;
        }
        
        if (WIFSTOPPED(status)) {
            int sig = WSTOPSIG(status);
            
            if (sig == SIGTRAP) {
                // Check if this is a breakpoint
                siginfo_t si;
                if (ptrace(PTRACE_GETSIGINFO, dbg->hProcess, NULL, &si) == 0) {
                    if (si.si_code == SI_KERNEL || si.si_code == 1 /* TRAP_BRKPT */) {
                        // Handle breakpoint - check if it's one of ours
                        uintptr_t ip = get_instruction_pointer(dbg);
                        bool found_bp = false;
                        
                        for (int i = 0; i < dbg->breakpoint_count; i++) {
                            Breakpoint* bp = &dbg->breakpoints[i];
                            if (bp->enabled && bp->address == ip) {
                                // Restore original instruction and step back
                                remove_software_breakpoint(dbg, ip, bp->original_byte);
                                set_instruction_pointer(dbg, ip);
                                
                                // Single step to execute the original instruction
                                if (ptrace(PTRACE_SINGLESTEP, dbg->hProcess, NULL, NULL) < 0) {
                                    perror("ptrace SINGLESTEP");
                                }
                                waitpid(dbg->hProcess, &status, 0);
                                
                                // Restore breakpoint
                                set_software_breakpoint(dbg, ip);
                                found_bp = true;
                                break;
                            }
                        }
                        
                        dbg_update_context(dbg);
                        dbg->is_running = false;
                        return true;
                    }
                }
            } else if (sig == SIGSEGV) {
                printf("Segmentation fault\n");
                dbg_update_context(dbg);
                dbg->is_running = false;
                return false;
            } else {
                // Other signal - deliver it
                if (ptrace(PTRACE_CONT, dbg->hProcess, NULL, (void*)sig) < 0) {
                    perror("ptrace CONT with signal");
                    dbg->is_running = false;
                    return false;
                }
            }
        }
    }
    
    dbg_update_context(dbg);
    return true;
}

bool dbg_continue(Debugger* dbg) {
    return dbg_run(dbg);
}

bool dbg_step(Debugger* dbg) {
    dbg->is_running = true;
    
    if (ptrace(PTRACE_SINGLESTEP, dbg->hProcess, NULL, NULL) < 0) {
        perror("ptrace SINGLESTEP");
        dbg->is_running = false;
        return false;
    }
    
    int status;
    if (waitpid(dbg->hProcess, &status, 0) < 0) {
        perror("waitpid");
        dbg->is_running = false;
        return false;
    }
    
    dbg_update_context(dbg);
    dbg->is_running = false;
    return true;
}

bool dbg_step_over(Debugger* dbg) {
    // Get current instruction
    #if TARGET_X64
        uintptr_t ip = dbg->ctx.rip;
    #else
        uintptr_t ip = dbg->ctx.eip;
    #endif
    
    // Read current instruction
    byte code[16];
    size_t read = 0;
    
    for (size_t i = 0; i < sizeof(code); i++) {
        errno = 0;
        long data = ptrace(PTRACE_PEEKDATA, dbg->hProcess, (void*)(ip + i), NULL);
        if (errno != 0) break;
        code[i] = (byte)(data & 0xFF);
        read++;
    }
    
    Instruction instr = {0};
    size_t instr_size = disasm_instruction(code, read, ip, &instr);
    
    if (instr_size == 0) {
        printf("Failed to disassemble current instruction\n");
        return false;
    }
    
    // If it's a call instruction, set breakpoint after it
    if (instr.is_call) {
        uintptr_t next_ip = ip + instr_size;
        printf("Step over: setting temporary breakpoint at 0x%lx\n", (unsigned long)next_ip);
        
        // Save current breakpoints
        int temp_bp_index = dbg->breakpoint_count;
        if (temp_bp_index < MAX_BREAKPOINTS) {
            Breakpoint* temp_bp = &dbg->breakpoints[temp_bp_index];
            temp_bp->address = next_ip;
            temp_bp->enabled = true;
            
            // Read original byte
            errno = 0;
            long original = ptrace(PTRACE_PEEKDATA, dbg->hProcess, (void*)next_ip, NULL);
            if (errno != 0) {
                printf("Failed to read memory for temporary breakpoint: %s\n", strerror(errno));
                return false;
            }
            temp_bp->original_byte = (byte)(original & 0xFF);
            
            // Set breakpoint
            errno = 0;
            long current = ptrace(PTRACE_PEEKDATA, dbg->hProcess, (void*)next_ip, NULL);
            if (errno != 0) {
                printf("Failed to read memory for temporary breakpoint: %s\n", strerror(errno));
                return false;
            }
            long modified = (current & ~0xFF) | 0xCC;
            if (ptrace(PTRACE_POKEDATA, dbg->hProcess, (void*)next_ip, (void*)modified) < 0) {
                printf("Failed to set temporary breakpoint: %s\n", strerror(errno));
                return false;
            }
            
            dbg->breakpoint_count++;
            
            // Continue execution
            return dbg_continue(dbg);
        }
    } else {
        // Not a call, just single step
        return dbg_step(dbg);
    }
}

bool dbg_finish(Debugger* dbg) {
    // Set breakpoint at return address
    #if TARGET_X64
        uintptr_t return_addr = (uintptr_t)dbg->ctx.rsp; // Simple heuristic
    #else
        uintptr_t return_addr = (uintptr_t)dbg->ctx.esp;
    #endif
    
    // Read return address from stack
    byte addr_bytes[8] = {0};
    for (int i = 0; i < (TARGET_X64 ? 8 : 4); i++) {
        errno = 0;
        long data = ptrace(PTRACE_PEEKDATA, dbg->hProcess, (void*)(return_addr + i), NULL);
        if (errno != 0) break;
        addr_bytes[i] = (byte)(data & 0xFF);
    }
    
    uintptr_t target_addr = 0;
    if (TARGET_X64) {
        target_addr = *(uint64_t*)addr_bytes;
    } else {
        target_addr = *(uint32_t*)addr_bytes;
    }
    
    printf("Finish: setting temporary breakpoint at 0x%lx\n", (unsigned long)target_addr);
    
    // Set temporary breakpoint
    int temp_bp_index = dbg->breakpoint_count;
    if (temp_bp_index < MAX_BREAKPOINTS) {
        Breakpoint* temp_bp = &dbg->breakpoints[temp_bp_index];
        temp_bp->address = target_addr;
        temp_bp->enabled = true;
        
        // Read original byte
        errno = 0;
        long original = ptrace(PTRACE_PEEKDATA, dbg->hProcess, (void*)target_addr, NULL);
        if (errno != 0) {
            printf("Failed to read memory for finish breakpoint: %s\n", strerror(errno));
            return false;
        }
        temp_bp->original_byte = (byte)(original & 0xFF);
        
        // Set breakpoint
        errno = 0;
        long current = ptrace(PTRACE_PEEKDATA, dbg->hProcess, (void*)target_addr, NULL);
        if (errno != 0) {
            printf("Failed to read memory for finish breakpoint: %s\n", strerror(errno));
            return false;
        }
        long modified = (current & ~0xFF) | 0xCC;
        if (ptrace(PTRACE_POKEDATA, dbg->hProcess, (void*)target_addr, (void*)modified) < 0) {
            printf("Failed to set finish breakpoint: %s\n", strerror(errno));
            return false;
        }
        
        dbg->breakpoint_count++;
        return dbg_continue(dbg);
    }
    
    return false;
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
    errno = 0;
    long original = ptrace(PTRACE_PEEKDATA, dbg->hProcess, (void*)addr, NULL);
    if (errno != 0) {
        printf("Failed to read memory at 0x%p: %s\n", (void*)addr, strerror(errno));
        return false;
    }
    bp->original_byte = (byte)(original & 0xFF);
    
    // Set breakpoint
    if (!set_software_breakpoint(dbg, addr)) {
        return false;
    }
    
    bp->symbol[0] = '\0'; // Symbol resolution not implemented yet
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
    
    if (!remove_software_breakpoint(dbg, bp->address, bp->original_byte)) {
        return false;
    }
    
    bp->enabled = false;
    return true;
}

void dbg_update_context(Debugger* dbg) {
    // Get registers
    #if defined(__x86_64__)
        struct user_regs_struct regs;
        if (ptrace(PTRACE_GETREGS, dbg->hProcess, NULL, &regs) == 0) {
            dbg->ctx.r15 = regs.r15;
            dbg->ctx.r14 = regs.r14;
            dbg->ctx.r13 = regs.r13;
            dbg->ctx.r12 = regs.r12;
            dbg->ctx.rbp = regs.rbp;
            dbg->ctx.rbx = regs.rbx;
            dbg->ctx.r11 = regs.r11;
            dbg->ctx.r10 = regs.r10;
            dbg->ctx.r9 = regs.r9;
            dbg->ctx.r8 = regs.r8;
            dbg->ctx.rax = regs.rax;
            dbg->ctx.rcx = regs.rcx;
            dbg->ctx.rdx = regs.rdx;
            dbg->ctx.rsi = regs.rsi;
            dbg->ctx.rdi = regs.rdi;
            dbg->ctx.rip = regs.rip;
            dbg->ctx.eflags = regs.eflags;
            dbg->ctx.rsp = regs.rsp;
        }
    #else
        struct user_regs_struct regs;
        if (ptrace(PTRACE_GETREGS, dbg->hProcess, NULL, &regs) == 0) {
            dbg->ctx.ebx = regs.ebx;
            dbg->ctx.ecx = regs.ecx;
            dbg->ctx.edx = regs.edx;
            dbg->ctx.esi = regs.esi;
            dbg->ctx.edi = regs.edi;
            dbg->ctx.ebp = regs.ebp;
            dbg->ctx.eax = regs.eax;
            dbg->ctx.eip = regs.eip;
            dbg->ctx.eflags = regs.eflags;
            dbg->ctx.esp = regs.esp;
        }
    #endif
}

// Linux helper functions
static bool set_software_breakpoint(Debugger* dbg, uintptr_t addr) {
    errno = 0;
    long original = ptrace(PTRACE_PEEKDATA, dbg->hProcess, (void*)addr, NULL);
    if (errno != 0) {
        printf("Failed to read memory at 0x%p: %s\n", (void*)addr, strerror(errno));
        return false;
    }
    
    // Replace first byte with 0xCC (INT3)
    long modified = (original & ~0xFF) | 0xCC;
    if (ptrace(PTRACE_POKEDATA, dbg->hProcess, (void*)addr, (void*)modified) < 0) {
        printf("Failed to set breakpoint at 0x%p: %s\n", (void*)addr, strerror(errno));
        return false;
    }
    
    return true;
}

static bool remove_software_breakpoint(Debugger* dbg, uintptr_t addr, byte original_byte) {
    errno = 0;
    long current = ptrace(PTRACE_PEEKDATA, dbg->hProcess, (void*)addr, NULL);
    if (errno != 0) {
        printf("Failed to read memory at 0x%p: %s\n", (void*)addr, strerror(errno));
        return false;
    }
    
    // Restore original byte
    long restored = (current & ~0xFF) | original_byte;
    if (ptrace(PTRACE_POKEDATA, dbg->hProcess, (void*)addr, (void*)restored) < 0) {
        printf("Failed to remove breakpoint at 0x%p: %s\n", (void*)addr, strerror(errno));
        return false;
    }
    
    return true;
}

static uintptr_t get_instruction_pointer(Debugger* dbg) {
    #if defined(__x86_64__)
        return dbg->ctx.rip;
    #else
        return dbg->ctx.eip;
    #endif
}

static void set_instruction_pointer(Debugger* dbg, uintptr_t ip) {
    #if defined(__x86_64__)
        dbg->ctx.rip = ip;
    #else
        dbg->ctx.eip = ip;
    #endif
    
    // Write back to process
    #if defined(__x86_64__)
        struct user_regs_struct regs;
        if (ptrace(PTRACE_GETREGS, dbg->hProcess, NULL, &regs) == 0) {
            regs.rip = ip;
            ptrace(PTRACE_SETREGS, dbg->hProcess, NULL, &regs);
        }
    #else
        struct user_regs_struct regs;
        if (ptrace(PTRACE_GETREGS, dbg->hProcess, NULL, &regs) == 0) {
            regs.eip = ip;
            ptrace(PTRACE_SETREGS, dbg->hProcess, NULL, &regs);
        }
    #endif
}

#endif

