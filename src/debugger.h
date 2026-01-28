#pragma once

#define WIN32_LEAN_AND_MEAN
#include <windows.h>
#include <dbghelp.h>
#include <psapi.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <stdbool.h>
#include <stdint.h>
#include <inttypes.h>

// Console color constants (explicitly defined for portability)
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

// Architecture detection
#ifdef _M_X64
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
    BYTE original_byte;
    char symbol[256];
} Breakpoint;

// Debugger state
typedef struct {
    HANDLE hProcess;
    HANDLE hThread;
    DWORD pid;
    DWORD tid;
    CONTEXT ctx;
    bool is_running;
    bool exit_debugger;
    
    // UI state
    PanelId active_panel;
    int assembly_offset;   // Lines above current IP to display
    uintptr_t memory_base; // Base address for memory view
    
    // Breakpoints
    Breakpoint breakpoints[MAX_BREAKPOINTS];
    int breakpoint_count;
    
    // Command interface
    char command_line[512];
    int command_cursor;
    char history[CMD_HISTORY_SIZE][512];
    int history_count;
    int history_index;
    
    // UI buffers
    HANDLE hStdout;
    HANDLE hStdin;
    CONSOLE_SCREEN_BUFFER_INFO csbi;
    COORD buffer_size;
    CHAR_INFO* back_buffer;
} Debugger;

// Function declarations
// debugger.c
bool dbg_initialize(Debugger* dbg, const char* exe_path);
void dbg_cleanup(Debugger* dbg);
bool dbg_run(Debugger* dbg);
bool dbg_continue(Debugger* dbg);
bool dbg_step(Debugger* dbg);
bool dbg_set_breakpoint(Debugger* dbg, uintptr_t addr);
bool dbg_remove_breakpoint(Debugger* dbg, int bp_num);
void dbg_update_context(Debugger* dbg);

// ui.c
bool ui_initialize(Debugger* dbg);
void ui_cleanup(Debugger* dbg);
void ui_render(Debugger* dbg);
void ui_handle_input(Debugger* dbg);
void ui_draw_assembly(Debugger* dbg, SMALL_RECT area);
void ui_draw_registers(Debugger* dbg, SMALL_RECT area);
void ui_draw_memory(Debugger* dbg, SMALL_RECT area);
void ui_draw_command(Debugger* dbg, SMALL_RECT area);
void ui_draw_panel_border(Debugger* dbg, SMALL_RECT area, const char* title, bool focused);
void ui_clear_area(Debugger* dbg, SMALL_RECT area, WORD attributes);
void ui_render_to_screen(Debugger* dbg);

// command_parser.c
void cmd_execute(Debugger* dbg, const char* command);
void cmd_parse_break(Debugger* dbg, char* args);
void cmd_parse_delete(Debugger* dbg, char* args);
void cmd_parse_examine(Debugger* dbg, char* args);
void cmd_parse_info(Debugger* dbg, char* args);

// disasm.c
typedef struct {
    size_t size;
    char mnemonic[16];
    char operands[64];
    bool is_jump;
    bool is_call;
    bool is_ret;
} Instruction;

size_t disasm_instruction(BYTE* code, size_t max_size, uintptr_t address, Instruction* instr);