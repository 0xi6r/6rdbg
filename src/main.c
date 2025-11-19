#include <stdio.h>
#include <stdlib.h>
#include <windows.h>
#include "debugger.h"
#include "ui.h"

#define MAX_COMMAND_LENGTH 256

extern void ParseCommand(const char* cmdLine);

void DebuggerEventLoop(void) {
    DEBUG_EVENT dbgEvent = {0};
    BOOL debuggerRunning = TRUE;
    char command[MAX_COMMAND_LENGTH];
    
    while (debuggerRunning) {
        // Process debug events
        if (WaitForDebugEvent(&dbgEvent, 100)) {
            HandleDebugEvent(&dbgEvent);
            ContinueDebugEvent(dbgEvent.dwProcessId, dbgEvent.dwThreadId, DBG_CONTINUE);
            
            if (dbgEvent.dwDebugEventCode == EXIT_PROCESS_DEBUG_EVENT) {
                debuggerRunning = FALSE;
            }
        }
        
        // Render UI
        RenderUI();
        
        // Check for keyboard input
        if (_kbhit()) {
            int ch = _getch();
            
            if (ch == 27) {  // ESC - cycle panels
                CyclePanel();
            }
        }
    }
}

void InteractiveCommandLoop(void) {
    char command[MAX_COMMAND_LENGTH];
    BOOL running = TRUE;
    
    while (running) {
        RenderUI();
        
        printf("\n>> ");
        fflush(stdout);
        
        if (fgets(command, sizeof(command), stdin)) {
            // Remove newline
            command[strcspn(command, "\n")] = 0;
            
            if (strlen(command) > 0) {
                ParseCommand(command);
            }
        }
    }
}

int main(int argc, char* argv[]) {
    if (argc < 2) {
        printf("Windows TUI Debugger\n");
        printf("Usage: %s <executable_path>\n", argv[0]);
        printf("Example: %s C:\\path\\to\\program.exe\n", argv[0]);
        return 1;
    }
    
    printf("=== Windows TUI Debugger ===\n");
    printf("Target: %s\n\n", argv[1]);
    
    // Initialize subsystems
    if (!InitializeDebugger()) {
        fprintf(stderr, "Failed to initialize debugger\n");
        return 1;
    }
    
    InitializeUI();
    
    // Attach to target
    if (!AttachToProcess(argv[1])) {
        fprintf(stderr, "Failed to attach to process\n");
        return 1;
    }
    
    printf("[+] Successfully attached\n");
    printf("Type 'help' for available commands\n");
    printf("Press ENTER to continue...\n");
    getchar();
    
    // Start interactive command loop
    InteractiveCommandLoop();
    
    // Cleanup
    CleanupDebugger();
    
    printf("Debugger closed.\n");
    return 0;
}