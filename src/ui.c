#include "debugger.h"

static void ui_draw_status_bar(Debugger* dbg);

bool ui_initialize(Debugger* dbg) {
    dbg->hStdout = GetStdHandle(STD_OUTPUT_HANDLE);
    dbg->hStdin = GetStdHandle(STD_INPUT_HANDLE);
    
    if (dbg->hStdout == INVALID_HANDLE_VALUE || dbg->hStdin == INVALID_HANDLE_VALUE) {
        printf("Failed to get console handles\n");
        return false;
    }
    
    // Set console mode for input processing
    DWORD mode;
    if (!GetConsoleMode(dbg->hStdin, &mode)) {
        printf("GetConsoleMode failed\n");
        return false;
    }
    SetConsoleMode(dbg->hStdin, mode | ENABLE_WINDOW_INPUT | ENABLE_MOUSE_INPUT);
    
    // Get screen buffer info
    if (!GetConsoleScreenBufferInfo(dbg->hStdout, &dbg->csbi)) {
        printf("GetConsoleScreenBufferInfo failed\n");
        return false;
    }
    
    dbg->buffer_size.X = dbg->csbi.dwSize.X;
    dbg->buffer_size.Y = dbg->csbi.dwSize.Y;
    
    // Allocate back buffer
    dbg->back_buffer = (CHAR_INFO*)calloc(dbg->buffer_size.X * dbg->buffer_size.Y, sizeof(CHAR_INFO));
    if (!dbg->back_buffer) {
        printf("Failed to allocate back buffer\n");
        return false;
    }
    
    return true;
}

void ui_cleanup(Debugger* dbg) {
    if (dbg->back_buffer) {
        free(dbg->back_buffer);
        dbg->back_buffer = NULL;
    }
    
    // Restore console mode
    DWORD mode;
    if (GetConsoleMode(dbg->hStdin, &mode)) {
        SetConsoleMode(dbg->hStdin, mode & ~(ENABLE_WINDOW_INPUT | ENABLE_MOUSE_INPUT));
    }
}

void ui_render(Debugger* dbg) {
    // Clear back buffer
    for (int i = 0; i < dbg->buffer_size.X * dbg->buffer_size.Y; i++) {
        dbg->back_buffer[i].Char.UnicodeChar = L' ';
        dbg->back_buffer[i].Attributes = FOREGROUND_WHITE;
    }
    
    // Calculate panel dimensions
    SHORT width = dbg->buffer_size.X;
    SHORT height = dbg->buffer_size.Y - 3; // Reserve 3 lines for status/command
    
    if (height < 10) {
        // Screen too small - show error message
        char msg[] = "ERROR: Terminal too small (min 80x25 required)";
        int start_x = (width - (int)strlen(msg)) / 2;
        int y = dbg->buffer_size.Y / 2;
        
        for (size_t i = 0; i < strlen(msg); i++) {
            int idx = y * dbg->buffer_size.X + start_x + i;
            if (idx < dbg->buffer_size.X * dbg->buffer_size.Y) {
                dbg->back_buffer[idx].Char.AsciiChar = msg[i];
                dbg->back_buffer[idx].Attributes = FOREGROUND_RED | FOREGROUND_INTENSITY;
            }
        }
        ui_render_to_screen(dbg);
        return;
    }
    
    SHORT asm_height = (SHORT)(height * 0.4);
    SHORT reg_height = (SHORT)(height * 0.3);
    SHORT mem_height = height - asm_height - reg_height;
    
    // Assembly panel (top)
    ui_draw_assembly(dbg, (SMALL_RECT){
        0, 0, 
        width - 1, asm_height - 1
    });
    
    // Register panel (middle-left)
    ui_draw_registers(dbg, (SMALL_RECT){
        0, asm_height, 
        width / 2 - 1, asm_height + reg_height - 1
    });
    
    // Memory panel (middle-right)
    ui_draw_memory(dbg, (SMALL_RECT){
        width / 2, asm_height, 
        width - 1, asm_height + reg_height - 1
    });
    
    // Command panel (bottom)
    ui_draw_command(dbg, (SMALL_RECT){
        0, asm_height + reg_height, 
        width - 1, height - 1
    });
    
    // Status bar
    ui_draw_status_bar(dbg);
    
    // Render to screen
    ui_render_to_screen(dbg);
}

void ui_handle_input(Debugger* dbg) {
    INPUT_RECORD records[128];
    DWORD count;
    
    if (!GetNumberOfConsoleInputEvents(dbg->hStdin, &count) || count == 0) {
        return;
    }
    
    if (!ReadConsoleInput(dbg->hStdin, records, 128, &count)) {
        return;
    }
    
    for (DWORD i = 0; i < count; i++) {
        if (records[i].EventType != KEY_EVENT || !records[i].Event.KeyEvent.bKeyDown) {
            continue;
        }
        
        KEY_EVENT_RECORD* key = &records[i].Event.KeyEvent;
        WORD vk = key->wVirtualKeyCode;
        char ch = (char)key->uChar.AsciiChar;
        
        // Global shortcuts
        if (vk == VK_ESCAPE) {
            dbg->active_panel = (PanelId)((dbg->active_panel + 1) % PANEL_COUNT);
            return;
        }
        
        if (vk == VK_RETURN && dbg->active_panel != PANEL_COMMAND) {
            dbg->active_panel = PANEL_COMMAND;
            dbg->command_cursor = (int)strlen(dbg->command_line);
            return;
        }
        
        // Panel-specific navigation
        switch (dbg->active_panel) {
            case PANEL_ASSEMBLY:
                if (vk == VK_UP) dbg->assembly_offset++;
                else if (vk == VK_DOWN) dbg->assembly_offset--;
                break;
                
            case PANEL_MEMORY:
                if (vk == VK_UP) dbg->memory_base -= MEMORY_COLS;
                else if (vk == VK_DOWN) dbg->memory_base += MEMORY_COLS;
                else if (vk == VK_LEFT) dbg->memory_base -= 8;
                else if (vk == VK_RIGHT) dbg->memory_base += 8;
                break;
                
            case PANEL_COMMAND:
                if (vk == VK_UP) {
                    if (dbg->history_index > 0) {
                        dbg->history_index--;
                        strncpy(dbg->command_line, dbg->history[dbg->history_index], 
                               sizeof(dbg->command_line) - 1);
                        dbg->command_line[sizeof(dbg->command_line) - 1] = '\0';
                        dbg->command_cursor = (int)strlen(dbg->command_line);
                    }
                }
                else if (vk == VK_DOWN) {
                    if (dbg->history_index < dbg->history_count) {
                        dbg->history_index++;
                        if (dbg->history_index < dbg->history_count) {
                            strncpy(dbg->command_line, dbg->history[dbg->history_index], 
                                   sizeof(dbg->command_line) - 1);
                            dbg->command_line[sizeof(dbg->command_line) - 1] = '\0';
                        } else {
                            dbg->command_line[0] = '\0';
                        }
                        dbg->command_cursor = (int)strlen(dbg->command_line);
                    }
                }
                else if (vk == VK_LEFT && dbg->command_cursor > 0) {
                    dbg->command_cursor--;
                }
                else if (vk == VK_RIGHT && dbg->command_cursor < (int)strlen(dbg->command_line)) {
                    dbg->command_cursor++;
                }
                else if (vk == VK_BACK && dbg->command_cursor > 0) {
                    memmove(&dbg->command_line[dbg->command_cursor - 1], 
                           &dbg->command_line[dbg->command_cursor],
                           strlen(dbg->command_line) - dbg->command_cursor + 1);
                    dbg->command_cursor--;
                }
                else if (vk == VK_DELETE && dbg->command_line[dbg->command_cursor]) {
                    memmove(&dbg->command_line[dbg->command_cursor], 
                           &dbg->command_line[dbg->command_cursor + 1],
                           strlen(dbg->command_line) - dbg->command_cursor + 1);
                }
                else if (ch >= 0x20 && ch <= 0x7E && 
                        strlen(dbg->command_line) < sizeof(dbg->command_line) - 1) {
                    memmove(&dbg->command_line[dbg->command_cursor + 1], 
                           &dbg->command_line[dbg->command_cursor],
                           strlen(dbg->command_line) - dbg->command_cursor + 1);
                    dbg->command_line[dbg->command_cursor] = ch;
                    dbg->command_cursor++;
                    dbg->command_line[sizeof(dbg->command_line) - 1] = '\0';
                }
                else if (vk == VK_RETURN) {
                    // Execute command
                    if (strlen(dbg->command_line) > 0) {
                        // Save to history (avoid duplicates)
                        if (dbg->history_count == 0 || 
                            strcmp(dbg->history[dbg->history_count - 1], dbg->command_line) != 0) {
                            
                            if (dbg->history_count >= CMD_HISTORY_SIZE) {
                                // Shift history
                                for (int i = 0; i < CMD_HISTORY_SIZE - 1; i++) {
                                    strcpy(dbg->history[i], dbg->history[i + 1]);
                                }
                                dbg->history_count = CMD_HISTORY_SIZE - 1;
                            }
                            strcpy(dbg->history[dbg->history_count++], dbg->command_line);
                        }
                        dbg->history_index = dbg->history_count;
                        
                        // Execute
                        cmd_execute(dbg, dbg->command_line);
                        
                        // Clear command line
                        dbg->command_line[0] = '\0';
                        dbg->command_cursor = 0;
                    }
                }
                break;
        }
    }
}

void ui_draw_assembly(Debugger* dbg, SMALL_RECT area) {
    ui_draw_panel_border(dbg, area, "Assembly", dbg->active_panel == PANEL_ASSEMBLY);
    
    // Get current instruction pointer
    #if TARGET_X64
        uintptr_t ip = dbg->ctx.Rip;
    #else
        uintptr_t ip = dbg->ctx.Eip;
    #endif
    
    // Read memory around IP
    BYTE code[256];
    SIZE_T read;
    if (!ReadProcessMemory(dbg->hProcess, (LPCVOID)(ip > 32 ? ip - 32 : 0), 
                          code, sizeof(code), &read)) {
        read = 0;
    }
    
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
            
            WORD attr = FOREGROUND_WHITE;
            if (addr == ip) attr = FOREGROUND_WHITE | BACKGROUND_BLUE;
            
            for (int x = area.Left + 2; x <= area.Right && line[x - area.Left - 2]; x++) {
                int idx = y * dbg->buffer_size.X + x;
                if (idx < dbg->buffer_size.X * dbg->buffer_size.Y) {
                    dbg->back_buffer[idx].Char.AsciiChar = line[x - area.Left - 2];
                    dbg->back_buffer[idx].Attributes = attr;
                }
            }
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
        WORD attr = (addr == ip) ? 
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
        
        // Write to buffer
        for (int x = area.Left + 2; x <= area.Right && line[x - area.Left - 2]; x++) {
            int idx = y * dbg->buffer_size.X + x;
            if (idx < dbg->buffer_size.X * dbg->buffer_size.Y) {
                dbg->back_buffer[idx].Char.AsciiChar = line[x - area.Left - 2];
                dbg->back_buffer[idx].Attributes = attr;
            }
        }
        
        y++;
    }
}

void ui_draw_registers(Debugger* dbg, SMALL_RECT area) {
    ui_draw_panel_border(dbg, area, "Registers", dbg->active_panel == PANEL_REGISTERS);
    
    const char* reg_names_64[] = {
        "RAX", "RBX", "RCX", "RDX", "RSI", "RDI", "RBP", "RSP",
        "R8 ", "R9 ", "R10", "R11", "R12", "R13", "R14", "R15",
        "RIP", "EFL"
    };
    
    const char* reg_names_32[] = {
        "EAX", "EBX", "ECX", "EDX", "ESI", "EDI", "EBP", "ESP",
        "EIP", "EFL"
    };
    
    DWORD64 values[18] = {0};
    #if TARGET_X64
        values[0] = dbg->ctx.Rax; values[1] = dbg->ctx.Rbx; values[2] = dbg->ctx.Rcx;
        values[3] = dbg->ctx.Rdx; values[4] = dbg->ctx.Rsi; values[5] = dbg->ctx.Rdi;
        values[6] = dbg->ctx.Rbp; values[7] = dbg->ctx.Rsp; values[8] = dbg->ctx.R8;
        values[9] = dbg->ctx.R9;  values[10] = dbg->ctx.R10; values[11] = dbg->ctx.R11;
        values[12] = dbg->ctx.R12; values[13] = dbg->ctx.R13; values[14] = dbg->ctx.R14;
        values[15] = dbg->ctx.R15; values[16] = dbg->ctx.Rip; values[17] = dbg->ctx.EFlags;
        const char** names = reg_names_64;
        int count = 18;
    #else
        values[0] = dbg->ctx.Eax; values[1] = dbg->ctx.Ebx; values[2] = dbg->ctx.Ecx;
        values[3] = dbg->ctx.Edx; values[4] = dbg->ctx.Esi; values[5] = dbg->ctx.Edi;
        values[6] = dbg->ctx.Ebp; values[7] = dbg->ctx.Esp; values[8] = dbg->ctx.Eip;
        values[9] = dbg->ctx.EFlags;
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
        snprintf(line, sizeof(line), "%s: 0x%016llx", names[i], values[i]);
        
        WORD attr = FOREGROUND_GREEN | FOREGROUND_INTENSITY;
        if (i == count - 2) attr = FOREGROUND_CYAN | FOREGROUND_INTENSITY; // IP
        if (i == count - 1) attr = FOREGROUND_YELLOW | FOREGROUND_INTENSITY; // Flags
        
        for (int j = 0; line[j] && x + j <= area.Right; j++) {
            int idx = y * dbg->buffer_size.X + x + j;
            if (idx < dbg->buffer_size.X * dbg->buffer_size.Y) {
                dbg->back_buffer[idx].Char.AsciiChar = line[j];
                dbg->back_buffer[idx].Attributes = attr;
            }
        }
    }
}

void ui_draw_memory(Debugger* dbg, SMALL_RECT area) {
    ui_draw_panel_border(dbg, area, "Memory", dbg->active_panel == PANEL_MEMORY);
    
    // Read memory
    BYTE mem[MEMORY_ROWS * MEMORY_COLS];
    SIZE_T read;
    if (!ReadProcessMemory(dbg->hProcess, (LPCVOID)dbg->memory_base, mem, sizeof(mem), &read)) {
        read = 0;
    }
    
    // Render hex dump
    for (int row = 0; row < MEMORY_ROWS && (area.Top + 1 + row) <= area.Bottom; row++) {
        int y = area.Top + 1 + row;
        uintptr_t addr = dbg->memory_base + row * MEMORY_COLS;
        
        // Address column
        char addr_line[24];
        snprintf(addr_line, sizeof(addr_line), "0x%016llx: ", (unsigned long long)addr);
        
        for (int i = 0; addr_line[i] && i < 18; i++) {
            int idx = y * dbg->buffer_size.X + area.Left + 2 + i;
            if (idx < dbg->buffer_size.X * dbg->buffer_size.Y) {
                dbg->back_buffer[idx].Char.AsciiChar = addr_line[i];
                dbg->back_buffer[idx].Attributes = FOREGROUND_WHITE | FOREGROUND_INTENSITY;
            }
        }
        
        // Hex bytes
        int x = area.Left + 20;
        for (int col = 0; col < MEMORY_COLS; col++) {
            int offset = row * MEMORY_COLS + col;
            if (offset >= (int)read) break;
            
            char byte_str[4];
            snprintf(byte_str, sizeof(byte_str), "%02X ", mem[offset]);
            
            WORD attr = FOREGROUND_WHITE;
            // Highlight ASCII printable characters
            if (mem[offset] >= 0x20 && mem[offset] <= 0x7E) {
                attr = FOREGROUND_GREEN;
            }
            
            for (int i = 0; byte_str[i] && x + i <= area.Right; i++) {
                int idx = y * dbg->buffer_size.X + x + i;
                if (idx < dbg->buffer_size.X * dbg->buffer_size.Y) {
                    dbg->back_buffer[idx].Char.AsciiChar = byte_str[i];
                    dbg->back_buffer[idx].Attributes = attr;
                }
            }
            x += 3;
        }
        
        // ASCII representation
        x = area.Left + 20 + MEMORY_COLS * 3 + 2;
        for (int col = 0; col < MEMORY_COLS; col++) {
            int offset = row * MEMORY_COLS + col;
            if (offset >= (int)read) {
                // Fill remaining with spaces
                int idx = y * dbg->buffer_size.X + x + col;
                if (idx < dbg->buffer_size.X * dbg->buffer_size.Y) {
                    dbg->back_buffer[idx].Char.AsciiChar = ' ';
                    dbg->back_buffer[idx].Attributes = FOREGROUND_WHITE;
                }
                continue;
            }
            
            char ch = (mem[offset] >= 0x20 && mem[offset] <= 0x7E) ? mem[offset] : '.';
            
            int idx = y * dbg->buffer_size.X + x + col;
            if (idx < dbg->buffer_size.X * dbg->buffer_size.Y) {
                dbg->back_buffer[idx].Char.AsciiChar = ch;
                dbg->back_buffer[idx].Attributes = FOREGROUND_CYAN;
            }
        }
    }
}

void ui_draw_command(Debugger* dbg, SMALL_RECT area) {
    ui_draw_panel_border(dbg, area, "Command", dbg->active_panel == PANEL_COMMAND);
    
    // Draw prompt
    const char* prompt = "(gdb) ";
    int prompt_len = (int)strlen(prompt);
    
    for (int i = 0; i < prompt_len; i++) {
        int idx = (area.Top + 1) * dbg->buffer_size.X + area.Left + 2 + i;
        if (idx < dbg->buffer_size.X * dbg->buffer_size.Y) {
            dbg->back_buffer[idx].Char.AsciiChar = prompt[i];
            dbg->back_buffer[idx].Attributes = FOREGROUND_GREEN | FOREGROUND_INTENSITY;
        }
    }
    
    // Draw command line
    int x = area.Left + 2 + prompt_len;
    int y = area.Top + 1;
    
    for (int i = 0; dbg->command_line[i] && x + i <= area.Right; i++) {
        int idx = y * dbg->buffer_size.X + x + i;
        if (idx < dbg->buffer_size.X * dbg->buffer_size.Y) {
            dbg->back_buffer[idx].Char.AsciiChar = dbg->command_line[i];
            dbg->back_buffer[idx].Attributes = FOREGROUND_WHITE;
        }
    }
    
    // Draw cursor
    if (dbg->active_panel == PANEL_COMMAND) {
        int cursor_x = x + dbg->command_cursor;
        if (cursor_x <= area.Right) {
            int idx = y * dbg->buffer_size.X + cursor_x;
            if (idx < dbg->buffer_size.X * dbg->buffer_size.Y) {
                dbg->back_buffer[idx].Char.UnicodeChar = L' ';
                dbg->back_buffer[idx].Attributes = 
                    FOREGROUND_BLACK | BACKGROUND_WHITE;
            }
        }
    }
}

void ui_draw_panel_border(Debugger* dbg, SMALL_RECT area, const char* title, bool focused) {
    WORD attr = focused ? 
                (FOREGROUND_WHITE | BACKGROUND_BLUE | FOREGROUND_INTENSITY) : 
                (FOREGROUND_WHITE | FOREGROUND_INTENSITY);
    
    // Top border
    for (SHORT x = area.Left; x <= area.Right; x++) {
        int idx = area.Top * dbg->buffer_size.X + x;
        if (idx < dbg->buffer_size.X * dbg->buffer_size.Y) {
            char ch = (x == area.Left) ? '+' : 
                     (x == area.Right) ? '+' : '-';
            dbg->back_buffer[idx].Char.AsciiChar = ch;
            dbg->back_buffer[idx].Attributes = attr;
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
                    dbg->back_buffer[idx].Char.AsciiChar = title[i];
                    dbg->back_buffer[idx].Attributes = attr;
                }
            }
        }
    }
    
    // Side borders and bottom
    for (SHORT y = area.Top + 1; y <= area.Bottom; y++) {
        // Left border
        int left_idx = y * dbg->buffer_size.X + area.Left;
        if (left_idx < dbg->buffer_size.X * dbg->buffer_size.Y) {
            dbg->back_buffer[left_idx].Char.AsciiChar = '|';
            dbg->back_buffer[left_idx].Attributes = attr;
        }
        
        // Right border
        int right_idx = y * dbg->buffer_size.X + area.Right;
        if (right_idx < dbg->buffer_size.X * dbg->buffer_size.Y) {
            dbg->back_buffer[right_idx].Char.AsciiChar = '|';
            dbg->back_buffer[right_idx].Attributes = attr;
        }
        
        // Bottom border
        if (y == area.Bottom) {
            for (SHORT x = area.Left; x <= area.Right; x++) {
                int idx = y * dbg->buffer_size.X + x;
                if (idx < dbg->buffer_size.X * dbg->buffer_size.Y) {
                    char ch = (x == area.Left) ? '+' : 
                             (x == area.Right) ? '+' : '-';
                    dbg->back_buffer[idx].Char.AsciiChar = ch;
                    dbg->back_buffer[idx].Attributes = attr;
                }
            }
        }
    }
}

void ui_clear_area(Debugger* dbg, SMALL_RECT area, WORD attributes) {
    for (SHORT y = area.Top; y <= area.Bottom; y++) {
        for (SHORT x = area.Left; x <= area.Right; x++) {
            int idx = y * dbg->buffer_size.X + x;
            if (idx < dbg->buffer_size.X * dbg->buffer_size.Y) {
                dbg->back_buffer[idx].Char.UnicodeChar = L' ';
                dbg->back_buffer[idx].Attributes = attributes;
            }
        }
    }
}

void ui_draw_status_bar(Debugger* dbg) {
    SMALL_RECT area = {
        0, 
        dbg->buffer_size.Y - 2, 
        dbg->buffer_size.X - 1, 
        dbg->buffer_size.Y - 1
    };
    
    // Clear status area
    ui_clear_area(dbg, area, FOREGROUND_BLACK | BACKGROUND_GRAY);
    
    // Status text
    char status[256];
    #if TARGET_X64
        uintptr_t ip = dbg->ctx.Rip;
    #else
        uintptr_t ip = dbg->ctx.Eip;
    #endif
    
    snprintf(status, sizeof(status), 
            " PID:%lu  TID:%lu  IP:0x%016llx  %s | ESC:Panels  F1:Help",
            dbg->pid, dbg->tid, (unsigned long long)ip,
            dbg->is_running ? "RUNNING" : "BREAK");
    
    // Write status text
    for (int i = 0; status[i] && i < dbg->buffer_size.X; i++) {
        int idx = area.Top * dbg->buffer_size.X + i;
        if (idx < dbg->buffer_size.X * dbg->buffer_size.Y) {
            dbg->back_buffer[idx].Char.AsciiChar = status[i];
            dbg->back_buffer[idx].Attributes = 
                FOREGROUND_WHITE | BACKGROUND_GRAY | FOREGROUND_INTENSITY;
        }
    }
}

void ui_render_to_screen(Debugger* dbg) {
    // Write entire back buffer to console
    COORD origin = {0, 0};
    DWORD written;
    SMALL_RECT sr = dbg->csbi.srWindow;
    WriteConsoleOutput(dbg->hStdout, dbg->back_buffer, dbg->buffer_size, origin, &sr);
}