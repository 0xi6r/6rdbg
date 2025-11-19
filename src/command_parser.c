#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <ctype.h>
#include "debugger.h"
#include "ui.h"

#define MAX_ARGS 10

typedef struct {
    char* name;
    char* shortName;
    void (*handler)(int argc, char* argv[]);
    char* description;
} Command;

/* Command handlers */

void cmd_break(int argc, char* argv[]) {
    if (argc < 2) {
        printf("Usage: break <address>\n");
        return;
    }
    
    DWORD addr = strtoul(argv[1], NULL, 16);
    SetBreakpoint(addr);
}

void cmd_continue(int argc, char* argv[]) {
    ContinueExecution();
    printf("[*] Continuing execution...\n");
}

void cmd_step(int argc, char* argv[]) {
    StepInstruction();
    printf("[*] Stepping...\n");
}

void cmd_info(int argc, char* argv[]) {
    if (argc < 2) {
        printf("Usage: info <breakpoints|registers|locals>\n");
        return;
    }
    
    if (strcmp(argv[1], "breakpoints") == 0) {
        printf("Breakpoints:\n");
        for (int i = 0; i < g_debugger.breakpointCount; i++) {
            printf("[%d] 0x%lx %s (hits: %lu)\n",
                   i,
                   g_debugger.breakpoints[i].address,
                   g_debugger.breakpoints[i].enabled ? "enabled" : "disabled",
                   g_debugger.breakpoints[i].hitCount);
        }
    }
    else if (strcmp(argv[1], "registers") == 0) {
        GetThreadContext();
        printf("RAX=0x%llx RBX=0x%llx RCX=0x%llx RDX=0x%llx\n",
               (unsigned long long)g_debugger.threadContext.Rax,
               (unsigned long long)g_debugger.threadContext.Rbx,
               (unsigned long long)g_debugger.threadContext.Rcx,
               (unsigned long long)g_debugger.threadContext.Rdx);
    }
}

void cmd_examine(int argc, char* argv[]) {
    if (argc < 2) {
        printf("Usage: examine <address> [size]\n");
        return;
    }
    
    DWORD64 addr = strtoull(argv[1], NULL, 16);
    int size = (argc > 2) ? atoi(argv[2]) : 64;
    
    ReadMemoryDump(addr, size);
    
    for (int i = 0; i < size; i += 16) {
        printf("0x%llx: ", (unsigned long long)(addr + i));
        for (int j = 0; j < 16 && (i + j) < size; j++) {
            printf("%02x ", g_debugger.memoryDump[i + j]);
        }
        printf("\n");
    }
}

void cmd_help(int argc, char* argv[]) {
    printf("Available Commands:\n");
    printf("  break/b <addr>         - Set breakpoint at address\n");
    printf("  delete <bp>            - Delete breakpoint\n");
    printf("  continue/c             - Continue execution\n");
    printf("  step/s                 - Step one instruction\n");
    printf("  info <type>            - Show information\n");
    printf("  examine/x <addr>       - Examine memory\n");
    printf("  print/p <expr>         - Print expression\n");
    printf("  quit/q                 - Exit debugger\n");
}

void cmd_quit(int argc, char* argv[]) {
    printf("Exiting debugger...\n");
    exit(0);
}

/* Command table */
Command commands[] = {
    {"break", "b", cmd_break, "Set breakpoint"},
    {"continue", "c", cmd_continue, "Continue execution"},
    {"step", "s", cmd_step, "Step instruction"},
    {"info", "i", cmd_info, "Show information"},
    {"examine", "x", cmd_examine, "Examine memory"},
    {"help", "h", cmd_help, "Show help"},
    {"quit", "q", cmd_quit, "Exit debugger"},
    {NULL, NULL, NULL, NULL}
};

/* Parse and execute command */
void ParseCommand(const char* cmdLine) {
    char* buffer = malloc(strlen(cmdLine) + 1);
    strcpy(buffer, cmdLine);
    
    char* argv[MAX_ARGS];
    int argc = 0;
    
    // Tokenize
    char* token = strtok(buffer, " ");
    while (token && argc < MAX_ARGS) {
        argv[argc++] = token;
        token = strtok(NULL, " ");
    }
    
    if (argc == 0) {
        free(buffer);
        return;
    }
    
    // Find and execute command
    for (int i = 0; commands[i].name; i++) {
        if (strcmp(argv[0], commands[i].name) == 0 ||
            strcmp(argv[0], commands[i].shortName) == 0) {
            commands[i].handler(argc, argv);
            free(buffer);
            return;
        }
    }
    
    printf("Unknown command: %s\n", argv[0]);
    free(buffer);
}