#include "platform.h"
#include "debugger.h"

#if !PLATFORM_WINDOWS
#include <ncurses.h>
#endif

// Common UI drawing functions (platform-agnostic logic)

#if PLATFORM_WINDOWS
#define SET_ATTR(w, attr) // Windows handles attributes differently
#else
#define SET_ATTR(w, attr) wattr_set((WINDOW*)w, 0, attr, NULL)
#endif

void ui_draw_assembly(Debugger* dbg, Rect area) {
    ui_draw_panel_border(dbg, area, "Assembly", dbg->active_panel == PANEL_ASSEMBLY);
    
    // Get current instruction pointer
    #if TARGET_X64
        uintptr_t ip = dbg->ctx.rip;
    #else
        uintptr_t ip = dbg->ctx.eip;
    #endif
    
    // Read memory around IP
    byte code[256];
    size_t read = 0;
    
    #if PLATFORM_WINDOWS
        SIZE_T windows_read;
        if (ReadProcessMemory(dbg->hProcess, (LPCVOID)(ip > 32 ? ip - 32 : 0), 
                              code, sizeof(code), &windows_read)) {
            read = windows_read;
        }
    #else
        // Linux: read memory using ptrace
        uintptr_t start_addr = ip > 32 ? ip - 32 : 0;
        for (size_t i = 0; i < sizeof(code) && i < 256; i++) {
            errno = 0;
            long data = ptrace(PTRACE_PEEKDATA, dbg->hProcess, (void*)(start_addr + i), NULL);
            if (errno != 0) break;
            code[i] = (byte)(data & 0xFF);
            read++;
        }
    #endif
    
    // Render instructions
    int y = area.Top + 1;
    int start_offset = -dbg->assembly_offset;
    
    for (int i = start_offset; i < start_offset + ASSEMBLY_LINES && y <= area.Bottom; i++) {
        uintptr_t addr = ip + i;
        int code_offset = (ip > 32 ? 32 : (int)ip) + i;
        
        if (code_offset < 0 || code_offset >= (int)read) {
            // Show placeholder for unreadable memory
            char line[256];
            snprintf(line, sizeof(line), "0x%016llx  ?? ?? ?? ?? ?? ?? ?? ??    ???", 
                    (unsigned long long)addr);
            
            unsigned short attr = FOREGROUND_WHITE;
            if (addr == ip) attr = FOREGROUND_WHITE | BACKGROUND_BLUE;
            
            ui_draw_text(dbg, area.Left + 2, y, line, attr);
            y++;
            continue;
        }
        
        // Disassemble instruction
        Instruction instr = {0};
        size_t size = disasm_instruction(&code[code_offset], 
                                       sizeof(code) - code_offset, 
                                       addr, &instr);
        
        if (size == 0) break;
        
        // Highlight current instruction
        unsigned short attr = (addr == ip) ? 
                    (FOREGROUND_WHITE | BACKGROUND_BLUE) : 
                    FOREGROUND_WHITE;
        
        // Format: address  bytes          mnemonic operands
        char line[256];
        snprintf(line, sizeof(line), "0x%016llx  ", (unsigned long long)addr);
        
        // Bytes column
        char bytes[24] = {0};
        for (size_t j = 0; j < size && j < 8; j++) {
            snprintf(bytes + strlen(bytes), sizeof(bytes) - strlen(bytes), 
                    "%02X ", code[code_offset + j]);
        }
        snprintf(line + strlen(line), sizeof(line) - strlen(line), 
                "%-24s", bytes);
        
        // Instruction
        snprintf(line + strlen(line), sizeof(line) - strlen(line), 
                "%s %s", instr.mnemonic, instr.operands);
        
        ui_draw_text(dbg, area.Left + 2, y, line, attr);
        y++;
    }
}

void ui_draw_registers(Debugger* dbg, Rect area) {
    ui_draw_panel_border(dbg, area, "Registers", dbg->active_panel == PANEL_REGISTERS);
    
    const char* reg_names_64[] = {
        "RAX", "RBX", "RCX", "RDX", "RSI", "RDI", "RBP", "RSP",
        "R8 ", "R9 ", "R10", "R11", "R12", "R13", "R14", "R15",
        "RIP", "EFL"
    };
    
    uint64_t values[18] = {0};
    #if TARGET_X64
        values[0] = dbg->ctx.rax; values[1] = dbg->ctx.rbx; values[2] = dbg->ctx.rcx;
        values[3] = dbg->ctx.rdx; values[4] = dbg->ctx.rsi; values[5] = dbg->ctx.rdi;
        values[6] = dbg->ctx.rbp; values[7] = dbg->ctx.rsp; values[8] = dbg->ctx.r8;
        values[9] = dbg->ctx.r9;  values[10] = dbg->ctx.r10; values[11] = dbg->ctx.r11;
        values[12] = dbg->ctx.r12; values[13] = dbg->ctx.r13; values[14] = dbg->ctx.r14;
        values[15] = dbg->ctx.r15; values[16] = dbg->ctx.rip; values[17] = dbg->ctx.eflags;
        const char** names = reg_names_64;
        int count = 18;
    #else
        values[0] = dbg->ctx.eax; values[1] = dbg->ctx.ebx; values[2] = dbg->ctx.ecx;
        values[3] = dbg->ctx.edx; values[4] = dbg->ctx.esi; values[5] = dbg->ctx.edi;
        values[6] = dbg->ctx.ebp; values[7] = dbg->ctx.esp; values[8] = dbg->ctx.eip;
        values[9] = dbg->ctx.eflags;
        const char** names = reg_names_32;
        int count = 10;
    #endif
    
    int rows = (area.Bottom - area.Top) / 2;
    if (rows < 1) rows = 1;
    int cols = 2;
    int per_col = (count + cols - 1) / cols;
    
    for (int i = 0; i < count && i < rows * cols; i++) {
        int col = i / per_col;
        int row = i % per_col;
        int y = area.Top + 1 + row;
        int x = area.Left + 2 + col * ((area.Right - area.Left) / cols);
        
        if (y > area.Bottom) continue;
        
        char line[64];
        snprintf(line, sizeof(line), "%s: 0x%016lx", names[i], (unsigned long)values[i]);
        
        unsigned short attr = FOREGROUND_GREEN | FOREGROUND_INTENSITY;
        if (i == count - 2) attr = FOREGROUND_CYAN | FOREGROUND_INTENSITY; // IP
        if (i == count - 1) attr = FOREGROUND_YELLOW | FOREGROUND_INTENSITY; // Flags
        
        ui_draw_text(dbg, x, y, line, attr);
    }
}

void ui_draw_memory(Debugger* dbg, Rect area) {
    ui_draw_panel_border(dbg, area, "Memory", dbg->active_panel == PANEL_MEMORY);
    
    // Read memory
    byte mem[MEMORY_ROWS * MEMORY_COLS];
    size_t read = 0;
    
    #if PLATFORM_WINDOWS
        SIZE_T windows_read;
        if (ReadProcessMemory(dbg->hProcess, (LPCVOID)dbg->memory_base, mem, sizeof(mem), &windows_read)) {
            read = windows_read;
        }
    #else
        // Linux: read memory using ptrace
        for (size_t i = 0; i < sizeof(mem); i++) {
            errno = 0;
            long data = ptrace(PTRACE_PEEKDATA, dbg->hProcess, (void*)(dbg->memory_base + i), NULL);
            if (errno != 0) break;
            mem[i] = (byte)(data & 0xFF);
            read++;
        }
    #endif
    
    // Render hex dump
    for (int row = 0; row < MEMORY_ROWS && (area.Top + 1 + row) <= area.Bottom; row++) {
        int y = area.Top + 1 + row;
        uintptr_t addr = dbg->memory_base + row * MEMORY_COLS;
        
        // Address column
        char addr_line[24];
        snprintf(addr_line, sizeof(addr_line), "0x%016llx: ", (unsigned long long)addr);
        
        ui_draw_text(dbg, area.Left + 2, y, addr_line, FOREGROUND_WHITE | FOREGROUND_INTENSITY);
        
        // Hex bytes
        int x = area.Left + 20;
        for (int col = 0; col < MEMORY_COLS; col++) {
            int offset = row * MEMORY_COLS + col;
            if (offset >= (int)read) break;
            
            char byte_str[4];
            snprintf(byte_str, sizeof(byte_str), "%02X ", mem[offset]);
            
            unsigned short attr = FOREGROUND_WHITE;
            // Highlight ASCII printable characters
            if (mem[offset] >= 0x20 && mem[offset] <= 0x7E) {
                attr = FOREGROUND_GREEN;
            }
            
            ui_draw_text(dbg, x, y, byte_str, attr);
            x += 3;
        }
        
        // ASCII representation
        x = area.Left + 20 + MEMORY_COLS * 3 + 2;
        for (int col = 0; col < MEMORY_COLS; col++) {
            int offset = row * MEMORY_COLS + col;
            if (offset >= (int)read) {
                // Fill remaining with spaces
                ui_draw_text(dbg, x + col, y, " ", FOREGROUND_WHITE);
                continue;
            }
            
            char ch = (mem[offset] >= 0x20 && mem[offset] <= 0x7E) ? mem[offset] : '.';
            
            char str[2] = {ch, '\0'};
            ui_draw_text(dbg, x + col, y, str, FOREGROUND_CYAN);
        }
    }
}

void ui_draw_command(Debugger* dbg, Rect area) {
    ui_draw_panel_border(dbg, area, "Command", dbg->active_panel == PANEL_COMMAND);
    
    // Draw prompt
    const char* prompt = "(gdb) ";
    ui_draw_text(dbg, area.Left + 2, area.Top + 1, prompt, FOREGROUND_GREEN | FOREGROUND_INTENSITY);
    
    // Draw command line
    int x = area.Left + 2 + (int)strlen(prompt);
    int y = area.Top + 1;
    
    ui_draw_text(dbg, x, y, dbg->command_line, FOREGROUND_WHITE);
    
    // Draw cursor (platform-specific)
    #if PLATFORM_WINDOWS
        if (dbg->active_panel == PANEL_COMMAND) {
            int cursor_x = x + dbg->command_cursor;
            if (cursor_x <= area.Right) {
                // Draw cursor as background
                char cursor_char = dbg->command_line[dbg->command_cursor] ? 
                                   dbg->command_line[dbg->command_cursor] : ' ';
                
                for (int idx = y * dbg->buffer_size.X + cursor_x; 
                     idx < dbg->buffer_size.X * dbg->buffer_size.Y; 
                     idx++) {
                    CHAR_INFO* buf = (CHAR_INFO*)dbg->back_buffer;
                    buf[idx].Char.UnicodeChar = cursor_char;
                    buf[idx].Attributes = FOREGROUND_BLACK | BACKGROUND_WHITE;
                    break;
                }
            }
        }
    #else
        if (dbg->active_panel == PANEL_COMMAND) {
            WINDOW* cmd_win = (WINDOW*)dbg->windows[PANEL_COMMAND];
            wmove(cmd_win, 1, strlen(prompt) + dbg->command_cursor);
            curs_set(1); // Show cursor
        } else {
            curs_set(0); // Hide cursor
        }
    #endif
}

void ui_draw_status_bar(Debugger* dbg) {
    Rect area;
    area.Left = 0;
    area.Top = dbg->buffer_size.Y - 2;
    area.Right = dbg->buffer_size.X - 1;
    area.Bottom = dbg->buffer_size.Y - 1;
    
    // Clear status area
    ui_clear_area(dbg, area, FOREGROUND_BLACK | BACKGROUND_GRAY);
    
    // Status text
    char status[256];
    #if TARGET_X64
        uintptr_t ip = dbg->ctx.rip;
    #else
        uintptr_t ip = dbg->ctx.eip;
    #endif
    
    snprintf(status, sizeof(status), 
            " PID:%u  TID:%u  IP:0x%016lx  %s | ESC:Panels  F1:Help",
            dbg->pid, dbg->tid, (unsigned long)ip,
            dbg->is_running ? "RUNNING" : "BREAK");
    
    ui_draw_text(dbg, area.Left, area.Top, status, 
                FOREGROUND_WHITE | BACKGROUND_GRAY | FOREGROUND_INTENSITY);
}

void ui_draw_panel_border(Debugger* dbg, Rect area, const char* title, bool focused) {
    unsigned short attr = focused ? 
                (FOREGROUND_WHITE | BACKGROUND_BLUE | FOREGROUND_INTENSITY) : 
                (FOREGROUND_WHITE | FOREGROUND_INTENSITY);
    
    #if PLATFORM_WINDOWS
        // Windows implementation using CHAR_INFO buffer
        CHAR_INFO* buffer = (CHAR_INFO*)dbg->back_buffer;
        
        // Top border
        for (SHORT x = area.Left; x <= area.Right; x++) {
            int idx = area.Top * dbg->buffer_size.X + x;
            if (idx < dbg->buffer_size.X * dbg->buffer_size.Y) {
                char ch = (x == area.Left) ? '+' : 
                         (x == area.Right) ? '+' : '-';
                buffer[idx].Char.AsciiChar = ch;
                buffer[idx].Attributes = attr;
            }
        }
        
        // Title
        if (title) {
            int title_len = (int)strlen(title);
            int start = area.Left + 2;
            if (start + title_len <= area.Right) {
                for (int i = 0; i < title_len; i++) {
                    int idx = area.Top * dbg->buffer_size.X + start + i;
                    if (idx < dbg->buffer_size.X * dbg->buffer_size.Y) {
                        buffer[idx].Char.AsciiChar = title[i];
                        buffer[idx].Attributes = attr;
                    }
                }
            }
        }
        
        // Side borders and bottom
        for (SHORT y = area.Top + 1; y <= area.Bottom; y++) {
            // Left border
            int left_idx = y * dbg->buffer_size.X + area.Left;
            if (left_idx < dbg->buffer_size.X * dbg->buffer_size.Y) {
                buffer[left_idx].Char.AsciiChar = '|';
                buffer[left_idx].Attributes = attr;
            }
            
            // Right border
            int right_idx = y * dbg->buffer_size.X + area.Right;
            if (right_idx < dbg->buffer_size.X * dbg->buffer_size.Y) {
                buffer[right_idx].Char.AsciiChar = '|';
                buffer[right_idx].Attributes = attr;
            }
            
            // Bottom border
            if (y == area.Bottom) {
                for (SHORT x = area.Left; x <= area.Right; x++) {
                    int idx = y * dbg->buffer_size.X + x;
                    if (idx < dbg->buffer_size.X * dbg->buffer_size.Y) {
                        char ch = (x == area.Left) ? '+' : 
                                 (x == area.Right) ? '+' : '-';
                        buffer[idx].Char.AsciiChar = ch;
                        buffer[idx].Attributes = attr;
                    }
                }
            }
        }
    #else
        // ncurses implementation
        WINDOW* win = NULL;
        
        // Find which window this area belongs to
        for (int i = 0; i < PANEL_COUNT; i++) {
            if (dbg->windows[i]) {
                int wy, wx, wy2, wx2;
                getbegyx((WINDOW*)dbg->windows[i], wy, wx);
                getmaxyx((WINDOW*)dbg->windows[i], wy2, wx2);
                
                if (area.Left >= wx && area.Right < wx + wx2 &&
                    area.Top >= wy && area.Bottom < wy + wy2) {
                    win = (WINDOW*)dbg->windows[i];
                    break;
                }
            }
        }
        
        if (!win) return;
        
        int width = area.Right - area.Left + 1;
        int height = area.Bottom - area.Top + 1;
        
        wattron(win, focused ? COLOR_PAIR(2) : COLOR_PAIR(1));
        
        // Draw box
        box(win, 0, 0);
        
        // Add title
        if (title) {
            mvwprintw(win, 0, 2, "[%s]", title);
        }
        
        wattroff(win, focused ? COLOR_PAIR(2) : COLOR_PAIR(1));
    #endif
}

void ui_clear_area(Debugger* dbg, Rect area, unsigned short attributes) {
    #if PLATFORM_WINDOWS
        CHAR_INFO* buffer = (CHAR_INFO*)dbg->back_buffer;
        
        for (SHORT y = area.Top; y <= area.Bottom; y++) {
            for (SHORT x = area.Left; x <= area.Right; x++) {
                int idx = y * dbg->buffer_size.X + x;
                if (idx < dbg->buffer_size.X * dbg->buffer_size.Y) {
                    buffer[idx].Char.UnicodeChar = L' ';
                    buffer[idx].Attributes = attributes;
                }
            }
        }
    #else
        // Find the window for this area
        WINDOW* win = NULL;
        for (int i = 0; i < PANEL_COUNT; i++) {
            if (dbg->windows[i]) {
                int wy, wx, wy2, wx2;
                getbegyx((WINDOW*)dbg->windows[i], wy, wx);
                getmaxyx((WINDOW*)dbg->windows[i], wy2, wx2);
                
                if (area.Left >= wx && area.Right < wx + wx2 &&
                    area.Top >= wy && area.Bottom < wy + wy2) {
                    win = (WINDOW*)dbg->windows[i];
                    break;
                }
            }
        }
        
        if (!win) return;
        
        wattron(win, COLOR_PAIR(1));
        for (int y = area.Top; y <= area.Bottom; y++) {
            for (int x = area.Left; x <= area.Right; x++) {
                mvwprintw(win, y, x, " ");
            }
        }
        wattroff(win, COLOR_PAIR(1));
    #endif
}

void ui_draw_text(Debugger* dbg, int x, int y, const char* text, unsigned short attributes) {
    #if PLATFORM_WINDOWS
        CHAR_INFO* buffer = (CHAR_INFO*)dbg->back_buffer;
        
        for (int i = 0; text[i] && x + i < dbg->buffer_size.X; i++) {
            int idx = y * dbg->buffer_size.X + x + i;
            if (idx < dbg->buffer_size.X * dbg->buffer_size.Y) {
                buffer[idx].Char.AsciiChar = text[i];
                buffer[idx].Attributes = attributes;
            }
        }
    #else
        // Find which window contains this coordinate
        WINDOW* win = NULL;
        for (int i = 0; i < PANEL_COUNT; i++) {
            if (dbg->windows[i]) {
                int wy, wx, wy2, wx2;
                getbegyx((WINDOW*)dbg->windows[i], wy, wx);
                getmaxyx((WINDOW*)dbg->windows[i], wy2, wx2);
                
                if (x >= wx && x < wx + wx2 && y >= wy && y < wy + wy2) {
                    win = (WINDOW*)dbg->windows[i];
                    // Convert global coordinates to window-local
                    x -= wx;
                    y -= wy;
                    break;
                }
            }
        }
        
        if (!win) return;
        
        // Set color based on attributes (simplified)
        int color_pair = 1; // Default
        if (attributes & FOREGROUND_GREEN) color_pair = 3;
        else if (attributes & FOREGROUND_CYAN) color_pair = 4;
        else if (attributes & FOREGROUND_YELLOW) color_pair = 5;
        else if (attributes & FOREGROUND_RED) color_pair = 6;
        else if (attributes & FOREGROUND_INTENSITY) color_pair = 1;
        
        wattron(win, COLOR_PAIR(color_pair));
        mvwprintw(win, y, x, "%s", text);
        wattroff(win, COLOR_PAIR(color_pair));
    #endif
}