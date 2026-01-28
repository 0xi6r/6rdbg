#include "debugger.h"

int main(int argc, char* argv[]) {
    if (argc < 2) {
        printf("Usage: %s <executable_path>\n", argv[0]);
        return 1;
    }

    Debugger dbg = {0};
    
    // Initialize symbol handler
    SymSetOptions(SYMOPT_UNDNAME | SYMOPT_DEFERRED_LOADS);
    if (!SymInitialize(GetCurrentProcess(), NULL, TRUE)) {
        printf("Failed to initialize symbol handler (err=%lu)\n", GetLastError());
        return 1;
    }

    // Initialize debugger
    if (!dbg_initialize(&dbg, argv[1])) {
        SymCleanup(GetCurrentProcess());
        return 1;
    }

    // Initialize UI
    if (!ui_initialize(&dbg)) {
        dbg_cleanup(&dbg);
        SymCleanup(GetCurrentProcess());
        return 1;
    }

    // Main debug loop
    while (!dbg.exit_debugger) {
        if (dbg.is_running) {
            if (!dbg_run(&dbg)) {
                break;
            }
        }
        ui_render(&dbg);
        ui_handle_input(&dbg);
    }

    // Cleanup
    ui_cleanup(&dbg);
    dbg_cleanup(&dbg);
    SymCleanup(GetCurrentProcess());
    
    return 0;
}