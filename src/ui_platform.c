#include "platform.h"
#include "debugger.h"

#if PLATFORM_WINDOWS

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
    CONSOLE_SCREEN_BUFFER_INFO* csbi = malloc(sizeof(CONSOLE_SCREEN_BUFFER_INFO));
    if (!csbi) {
        printf("Failed to allocate screen buffer info\n");
        return false;
    }
    dbg->csbi = csbi;
    
    if (!GetConsoleScreenBufferInfo(dbg->hStdout, csbi)) {
        printf("GetConsoleScreenBufferInfo failed\n");
        return false;
    }
    
    dbg->buffer_size.X = csbi->dwSize.X;
    dbg->buffer_size.Y = csbi->dwSize.Y;
    
    // Allocate back buffer
    CHAR_INFO* back_buffer = (CHAR_INFO*)calloc(dbg->buffer_size.X * dbg->buffer_size.Y, sizeof(CHAR_INFO));
    if (!back_buffer) {
        printf("Failed to allocate back buffer\n");
        return false;
    }
    dbg->back_buffer = back_buffer;
    
    return true;
}

void ui_cleanup(Debugger* dbg) {
    if (dbg->back_buffer) {
        free(dbg->back_buffer);
        dbg->back_buffer = NULL;
    }
    
    if (dbg->csbi) {
        free(dbg->csbi);
        dbg->csbi = NULL;
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
        ((CHAR_INFO*)dbg->back_buffer)[i].Char.UnicodeChar = L' ';
        ((CHAR_INFO*)dbg->back_buffer)[i].Attributes = FOREGROUND_WHITE;
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
                ((CHAR_INFO*)dbg->back_buffer)[idx].Char.AsciiChar = msg[i];
                ((CHAR_INFO*)dbg->back_buffer)[idx].Attributes = FOREGROUND_RED | FOREGROUND_INTENSITY;
            }
        }
        ui_render_to_screen(dbg);
        return;
    }
    
    SHORT asm_height = (SHORT)(height * 0.4);
    SHORT reg_height = (SHORT)(height * 0.3);
    SHORT mem_height = height - asm_height - reg_height;
    
    // Assembly panel (top)
    ui_draw_assembly(dbg, (Rect){
        0, 0, 
        width - 1, asm_height - 1
    });
    
    // Register panel (middle-left)
    ui_draw_registers(dbg, (Rect){
        0, asm_height, 
        width / 2 - 1, asm_height + reg_height - 1
    });
    
    // Memory panel (middle-right)
    ui_draw_memory(dbg, (Rect){
        width / 2, asm_height, 
        width - 1, asm_height + reg_height - 1
    });
    
    // Command panel (bottom)
    ui_draw_command(dbg, (Rect){
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

void ui_render_to_screen(Debugger* dbg) {
    // Write entire back buffer to console
    COORD origin = {0, 0};
    DWORD written;
    CONSOLE_SCREEN_BUFFER_INFO* csbi = (CONSOLE_SCREEN_BUFFER_INFO*)dbg->csbi;
    SMALL_RECT sr = csbi->srWindow;
    WriteConsoleOutput(dbg->hStdout, dbg->back_buffer, dbg->buffer_size, origin, &sr);
}

#else

// Linux/Unix implementation using ncurses
#include <ncurses.h>

bool ui_initialize(Debugger* dbg) {
    // Initialize ncurses
    initscr();
    cbreak();
    noecho();
    keypad(stdscr, TRUE);
    start_color();
    use_default_colors();
    
    // Initialize color pairs
    init_pair(1, COLOR_WHITE, COLOR_BLACK);      // Default
    init_pair(2, COLOR_BLACK, COLOR_BLUE);       // Focused panel
    init_pair(3, COLOR_GREEN, COLOR_BLACK);      // Registers
    init_pair(4, COLOR_CYAN, COLOR_BLACK);       // IP/Flags
    init_pair(5, COLOR_YELLOW, COLOR_BLACK);     // Flags
    init_pair(6, COLOR_RED, COLOR_BLACK);        // Error
    init_pair(7, COLOR_BLACK, COLOR_WHITE);      // Cursor
    
    dbg->stdscr = stdscr;
    dbg->needs_refresh = true;
    
    // Get screen dimensions
    getmaxyx(stdscr, dbg->buffer_size.Y, dbg->buffer_size.X);
    
    // Create panel windows
    int height = dbg->buffer_size.Y - 3;
    int asm_height = height * 0.4;
    int reg_height = height * 0.3;
    int mem_height = height - asm_height - reg_height;
    
    // Assembly window
    dbg->windows[PANEL_ASSEMBLY] = newwin(asm_height, dbg->buffer_size.X, 0, 0);
    
    // Register window
    dbg->windows[PANEL_REGISTERS] = newwin(reg_height, dbg->buffer_size.X / 2, asm_height, 0);
    
    // Memory window
    dbg->windows[PANEL_MEMORY] = newwin(mem_height, dbg->buffer_size.X / 2, asm_height, dbg->buffer_size.X / 2);
    
    // Command window
    dbg->windows[PANEL_COMMAND] = newwin(3, dbg->buffer_size.X, asm_height + reg_height, 0);
    
    return true;
}

void ui_cleanup(Debugger* dbg) {
    // Delete windows
    for (int i = 0; i < PANEL_COUNT; i++) {
        if (dbg->windows[i]) {
            delwin((WINDOW*)dbg->windows[i]);
            dbg->windows[i] = NULL;
        }
    }
    
    // End ncurses
    endwin();
}

void ui_render(Debugger* dbg) {
    // Update screen dimensions
    getmaxyx((WINDOW*)dbg->stdscr, dbg->buffer_size.Y, dbg->buffer_size.X);
    
    if (dbg->buffer_size.Y < 10 || dbg->buffer_size.X < 80) {
        clear();
        mvprintw(0, 0, "ERROR: Terminal too small (min 80x10 required)");
        refresh();
        return;
    }
    
    int height = dbg->buffer_size.Y - 3;
    int asm_height = height * 0.4;
    int reg_height = height * 0.3;
    int mem_height = height - asm_height - reg_height;
    
    // Resize windows if needed
    wresize((WINDOW*)dbg->windows[PANEL_ASSEMBLY], asm_height, dbg->buffer_size.X);
    wresize((WINDOW*)dbg->windows[PANEL_REGISTERS], reg_height, dbg->buffer_size.X / 2);
    wresize((WINDOW*)dbg->windows[PANEL_MEMORY], mem_height, dbg->buffer_size.X / 2);
    wresize((WINDOW*)dbg->windows[PANEL_COMMAND], 3, dbg->buffer_size.X);
    
    // Move windows if needed
    mvwin((WINDOW*)dbg->windows[PANEL_REGISTERS], asm_height, 0);
    mvwin((WINDOW*)dbg->windows[PANEL_MEMORY], asm_height, dbg->buffer_size.X / 2);
    mvwin((WINDOW*)dbg->windows[PANEL_COMMAND], asm_height + reg_height, 0);
    
    // Draw panels
    ui_draw_assembly(dbg, (Rect){0, 0, dbg->buffer_size.X - 1, asm_height - 1});
    ui_draw_registers(dbg, (Rect){0, asm_height, dbg->buffer_size.X / 2 - 1, asm_height + reg_height - 1});
    ui_draw_memory(dbg, (Rect){dbg->buffer_size.X / 2, asm_height, dbg->buffer_size.X - 1, asm_height + reg_height - 1});
    ui_draw_command(dbg, (Rect){0, asm_height + reg_height, dbg->buffer_size.X - 1, dbg->buffer_size.Y - 1});
    
    // Status bar will be drawn by ui_common.c
    
    refresh();
}

void ui_handle_input(Debugger* dbg) {
    WINDOW* cmd_win = (WINDOW*)dbg->windows[PANEL_COMMAND];
    
    int ch = wgetch(cmd_win);
    
    if (ch == 27) { // ESC key
        dbg->active_panel = (PanelId)((dbg->active_panel + 1) % PANEL_COUNT);
        return;
    }
    
    switch (dbg->active_panel) {
        case PANEL_ASSEMBLY:
            if (ch == KEY_UP) dbg->assembly_offset++;
            else if (ch == KEY_DOWN) dbg->assembly_offset--;
            break;
            
            case PANEL_MEMORY:
                if (ch == KEY_UP) dbg->memory_base -= MEMORY_COLS;
                else if (ch == KEY_DOWN) dbg->memory_base += MEMORY_COLS;
                else if (ch == KEY_LEFT) dbg->memory_base -= 8;
                else if (ch == KEY_RIGHT) dbg->memory_base += 8;
                break;
                
            case PANEL_REGISTERS:
                // No specific handling for registers panel
                break;
            
        case PANEL_COMMAND:
            if (ch == KEY_UP) {
                if (dbg->history_index > 0) {
                    dbg->history_index--;
                    strcpy(dbg->command_line, dbg->history[dbg->history_index]);
                    dbg->command_cursor = strlen(dbg->command_line);
                }
            }
            else if (ch == KEY_DOWN) {
                if (dbg->history_index < dbg->history_count) {
                    dbg->history_index++;
                    if (dbg->history_index < dbg->history_count) {
                        strcpy(dbg->command_line, dbg->history[dbg->history_index]);
                    } else {
                        dbg->command_line[0] = '\0';
                    }
                    dbg->command_cursor = strlen(dbg->command_line);
                }
            }
            else if (ch == KEY_LEFT && dbg->command_cursor > 0) {
                dbg->command_cursor--;
            }
            else if (ch == KEY_RIGHT && dbg->command_cursor < (int)strlen(dbg->command_line)) {
                dbg->command_cursor++;
            }
            else if (ch == KEY_BACKSPACE || ch == 127) {
                if (dbg->command_cursor > 0) {
                    memmove(&dbg->command_line[dbg->command_cursor - 1], 
                           &dbg->command_line[dbg->command_cursor],
                           strlen(dbg->command_line) - dbg->command_cursor + 1);
                    dbg->command_cursor--;
                }
            }
            else if (ch == KEY_DC) {
                if (dbg->command_line[dbg->command_cursor]) {
                    memmove(&dbg->command_line[dbg->command_cursor], 
                           &dbg->command_line[dbg->command_cursor + 1],
                           strlen(dbg->command_line) - dbg->command_cursor + 1);
                }
            }
            else if (ch >= 0x20 && ch <= 0x7E && 
                    strlen(dbg->command_line) < sizeof(dbg->command_line) - 1) {
                memmove(&dbg->command_line[dbg->command_cursor + 1], 
                       &dbg->command_line[dbg->command_cursor],
                       strlen(dbg->command_line) - dbg->command_cursor + 1);
                dbg->command_line[dbg->command_cursor] = ch;
                dbg->command_cursor++;
            }
            else if (ch == '\n' || ch == '\r') {
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

void ui_render_to_screen(Debugger* dbg) {
    // ncurses handles this automatically
}

#endif

// Forward declarations for common UI functions
void ui_draw_assembly(Debugger* dbg, Rect area);
void ui_draw_registers(Debugger* dbg, Rect area);
void ui_draw_memory(Debugger* dbg, Rect area);
void ui_draw_command(Debugger* dbg, Rect area);

void ui_draw_panel_border(Debugger* dbg, Rect area, const char* title, bool focused);
void ui_clear_area(Debugger* dbg, Rect area, unsigned short attributes);
void ui_draw_text(Debugger* dbg, int x, int y, const char* text, unsigned short attributes);

#ifndef KEY_ESC
#define KEY_ESC 27
#endif