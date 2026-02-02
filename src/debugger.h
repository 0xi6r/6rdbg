#pragma once
#include "platform.h"

// Platform-specific rectangular area structure
#if PLATFORM_WINDOWS
typedef struct {
    SHORT Left, Top;
    SHORT Right, Bottom;
} Rect;
#else
typedef struct {
    short Left, Top;
    short Right, Bottom;
} Rect;
#endif

// Function declarations
// debugger.c
bool dbg_initialize(Debugger* dbg, const char* exe_path);
void dbg_cleanup(Debugger* dbg);
bool dbg_run(Debugger* dbg);
bool dbg_continue(Debugger* dbg);
bool dbg_step(Debugger* dbg);
bool dbg_step_over(Debugger* dbg);
bool dbg_finish(Debugger* dbg);
bool dbg_set_breakpoint(Debugger* dbg, uintptr_t addr);
bool dbg_remove_breakpoint(Debugger* dbg, int bp_num);
void dbg_update_context(Debugger* dbg);

// ui.c
bool ui_initialize(Debugger* dbg);
void ui_cleanup(Debugger* dbg);
void ui_render(Debugger* dbg);
void ui_handle_input(Debugger* dbg);
void ui_draw_assembly(Debugger* dbg, Rect area);
void ui_draw_registers(Debugger* dbg, Rect area);
void ui_draw_memory(Debugger* dbg, Rect area);
void ui_draw_command(Debugger* dbg, Rect area);
void ui_draw_panel_border(Debugger* dbg, Rect area, const char* title, bool focused);
void ui_clear_area(Debugger* dbg, Rect area, unsigned short attributes);
void ui_render_to_screen(Debugger* dbg);
void ui_draw_text(Debugger* dbg, int x, int y, const char* text, unsigned short attributes);

// command_parser.c
void cmd_execute(Debugger* dbg, const char* command);
void cmd_parse_break(Debugger* dbg, char* args);
void cmd_parse_delete(Debugger* dbg, char* args);
void cmd_parse_examine(Debugger* dbg, char* args);
void cmd_parse_info(Debugger* dbg, char* args);

// disasm.c
size_t disasm_instruction(byte* code, size_t max_size, uintptr_t address, Instruction* instr);
const char* get_register_name(int reg_index, bool is_64bit);

size_t disasm_instruction(byte* code, size_t max_size, uintptr_t address, Instruction* instr);
const char* get_register_name(int reg_index, bool is_64bit);