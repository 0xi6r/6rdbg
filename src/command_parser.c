#include "debugger.h"

void cmd_execute(Debugger* dbg, const char* cmd) {
    if (!cmd || !*cmd) return;
    
    char command[512];
    strncpy(command, cmd, sizeof(command) - 1);
    command[sizeof(command) - 1] = '\0';
    
    // Tokenize command
    char* tokens[16];
    int token_count = 0;
    char* token = strtok(command, " \t");
    
    while (token && token_count < 16) {
        tokens[token_count++] = token;
        token = strtok(NULL, " \t");
    }
    
    if (token_count == 0) return;
    
    // Command aliases
    if (strcmp(tokens[0], "r") == 0 || strcmp(tokens[0], "run") == 0) {
        dbg->is_running = false; // Ensure we're stopped
        dbg_run(dbg);
    }
    else if (strcmp(tokens[0], "c") == 0 || strcmp(tokens[0], "continue") == 0) {
        dbg_continue(dbg);
    }
    else if (strcmp(tokens[0], "s") == 0 || strcmp(tokens[0], "step") == 0) {
        dbg_step(dbg);
    }
    else if (strcmp(tokens[0], "b") == 0 || strcmp(tokens[0], "break") == 0) {
        cmd_parse_break(dbg, token_count > 1 ? tokens[1] : NULL);
    }
    else if (strcmp(tokens[0], "del") == 0 || strcmp(tokens[0], "delete") == 0) {
        cmd_parse_delete(dbg, token_count > 1 ? tokens[1] : NULL);
    }
    else if (strcmp(tokens[0], "x") == 0 || strcmp(tokens[0], "examine") == 0) {
        cmd_parse_examine(dbg, token_count > 1 ? tokens[1] : NULL);
    }
    else if (strcmp(tokens[0], "info") == 0 && token_count > 1) {
        cmd_parse_info(dbg, tokens[1]);
    }
    else if (strcmp(tokens[0], "q") == 0 || strcmp(tokens[0], "quit") == 0) {
        dbg->exit_debugger = true;
    }
    else {
        printf("Unknown command: %s\n", tokens[0]);
    }
}

void cmd_parse_break(Debugger* dbg, char* args) {
    if (!args) {
        printf("Usage: break <address>\n");
        return;
    }
    
    // Try to parse as hex address
    uintptr_t addr = 0;
    if (sscanf(args, "%llx", &addr) != 1) {
        // Try symbol resolution
        SYMBOL_INFO* symbol = (SYMBOL_INFO*)calloc(sizeof(SYMBOL_INFO) + 256, 1);
        if (!symbol) {
            printf("Memory allocation failed\n");
            return;
        }
        
        symbol->SizeOfStruct = sizeof(SYMBOL_INFO);
        symbol->MaxNameLen = 255;
        
        if (SymFromName(GetCurrentProcess(), args, symbol)) {
            addr = (uintptr_t)symbol->Address;
            printf("Breakpoint at symbol '%s' (0x%p)\n", args, (void*)addr);
        } else {
            printf("Unknown symbol or invalid address: %s (err=%lu)\n", args, GetLastError());
            free(symbol);
            return;
        }
        free(symbol);
    }
    
    if (dbg_set_breakpoint(dbg, addr)) {
        printf("Breakpoint set at 0x%p\n", (void*)addr);
    }
}

void cmd_parse_delete(Debugger* dbg, char* args) {
    if (!args) {
        printf("Usage: delete <breakpoint-number>\n");
        return;
    }
    
    int bp_num = atoi(args);
    if (bp_num <= 0) {
        printf("Invalid breakpoint number\n");
        return;
    }
    
    if (dbg_remove_breakpoint(dbg, bp_num)) {
        printf("Breakpoint %d deleted\n", bp_num);
    }
}

void cmd_parse_examine(Debugger* dbg, char* args) {
    if (!args) {
        printf("Usage: x <address>\n");
        return;
    }
    
    uintptr_t addr = 0;
    if (sscanf(args, "%llx", &addr) != 1) {
        printf("Invalid address\n");
        return;
    }
    
    dbg->memory_base = addr;
    printf("Memory view set to 0x%p\n", (void*)addr);
}

void cmd_parse_info(Debugger* dbg, char* subcmd) {
    if (!subcmd) return;
    
    if (strcmp(subcmd, "registers") == 0 || strcmp(subcmd, "r") == 0) {
        // Registers already visible in UI panel
        dbg_update_context(dbg);
        printf("Registers updated\n");
    }
    else if (strcmp(subcmd, "breakpoints") == 0 || strcmp(subcmd, "b") == 0) {
        if (dbg->breakpoint_count == 0) {
            printf("No breakpoints set.\n");
            return;
        }
        
        printf("Num\tType\tDisp\tEnb\tAddress\t\t\tWhat\n");
        for (int i = 0; i < dbg->breakpoint_count; i++) {
            Breakpoint* bp = &dbg->breakpoints[i];
            if (!bp->enabled) continue;
            
            printf("%d\tbreakpoint\tkeep\t%s\t0x%016llx\t%s\n",
                i + 1,
                bp->enabled ? "y" : "n",
                (unsigned long long)bp->address,
                bp->symbol[0] ? bp->symbol : "<no symbol>");
        }
    }
    else {
        printf("Unknown info subcommand: %s\n", subcmd);
    }
}