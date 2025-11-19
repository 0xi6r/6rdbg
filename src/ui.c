#include "ui.h"
#include "debugger.h"
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <stdarg.h>

UIState g_ui = {0};

/* Initialize console for TUI */
void InitializeUI(void) {
    memset(&g_ui, 0, sizeof(UIState));
    
    HANDLE hConsole = GetStdHandle(STD_OUTPUT_HANDLE);
    CONSOLE_SCREEN_BUFFER_INFO csbi;
    GetConsoleScreenBufferInfo(hConsole, &csbi);
    
    // Enable ANSI escape sequences on Windows 10+
    DWORD mode = 0;
    GetConsoleMode(hConsole, &mode);
    mode |= ENABLE_VIRTUAL_TERMINAL_PROCESSING;
    SetConsoleMode(hConsole, mode);
}

/* Set cursor position */
void SetCursorPosition(int x, int y) {
    COORD coord = {(SHORT)x, (SHORT)y};
    SetConsoleCursorPosition(GetStdHandle(STD_OUTPUT_HANDLE), coord);
}

/* Set console color */
void SetConsoleColor(int foreground, int background) {
    HANDLE hConsole = GetStdHandle(STD_OUTPUT_HANDLE);
    SetConsoleTextAttribute(hConsole, (background << 4) | foreground);
}

/* Reset console color to default */
void ResetConsoleColor(void) {
    SetConsoleColor(7, 0);  // White on black
}

/* Draw a box border */
void DrawBox(int x, int y, int width, int height, const char* title) {
    int i, j;
    
    SetCursorPosition(x, y);
    printf("┌");
    for (i = 1; i < width - 1; i++) printf("─");
    printf("┐");
    
    if (title) {
        SetCursorPosition(x + 2, y);
        printf(" %s ", title);
    }
    
    for (j = y + 1; j < y + height - 1; j++) {
        SetCursorPosition(x, j);
        printf("│");
        SetCursorPosition(x + width - 1, j);
        printf("│");
    }
    
    SetCursorPosition(x, y + height - 1);
    printf("└");
    for (i = 1; i < width - 1; i++) printf("─");
    printf("┘");
}

/* Print text at specific position */
void PrintAt(int x, int y, const char* format, ...) {
    va_list args;
    SetCursorPosition(x, y);
    va_start(args, format);
    vprintf(format, args);
    va_end(args);
}

/* Render assembly panel */
void RenderAssemblyPanel(void) {
    int x = 2, y = 2, width = 60, height = 20;
    
    DrawBox(x, y, width, height, "Assembly");
    
    GetThreadContext();
    
    // Display 20 lines of disassembled code
    for (int i = 0; i < 18; i++) {
        DWORD64 address = g_debugger.threadContext.Rip + (i * 4);
        BYTE opcode[16];
        SIZE_T bytesRead;
        
        ReadProcessMemory(g_debugger.hProcess, (LPVOID)address,
                         opcode, 4, &bytesRead);
        
        if (i == 0) {
            SetConsoleColor(15, 1);  // Highlight current instruction
            PrintAt(x + 2, y + 1 + i, ">>> 0x%016llx: %02x %02x %02x %02x",
                   (unsigned long long)address, opcode[0], opcode[1], opcode[2], opcode[3]);
            ResetConsoleColor();
        } else {
            PrintAt(x + 2, y + 1 + i, "    0x%016llx: %02x %02x %02x %02x",
                   (unsigned long long)address, opcode[0], opcode[1], opcode[2], opcode[3]);
        }
    }
}

/* Render register panel */
void RenderRegisterPanel(void) {
    int x = 64, y = 2, width = 40, height = 12;
    
    DrawBox(x, y, width, height, "Registers");
    
    GetThreadContext();
    
    PrintAt(x + 2, y + 1, "RAX: 0x%016llx", (unsigned long long)g_debugger.threadContext.Rax);
    PrintAt(x + 2, y + 2, "RBX: 0x%016llx", (unsigned long long)g_debugger.threadContext.Rbx);
    PrintAt(x + 2, y + 3, "RCX: 0x%016llx", (unsigned long long)g_debugger.threadContext.Rcx);
    PrintAt(x + 2, y + 4, "RDX: 0x%016llx", (unsigned long long)g_debugger.threadContext.Rdx);
    PrintAt(x + 2, y + 5, "RSI: 0x%016llx", (unsigned long long)g_debugger.threadContext.Rsi);
    PrintAt(x + 2, y + 6, "RDI: 0x%016llx", (unsigned long long)g_debugger.threadContext.Rdi);
    PrintAt(x + 2, y + 7, "RBP: 0x%016llx", (unsigned long long)g_debugger.threadContext.Rbp);
    PrintAt(x + 2, y + 8, "RSP: 0x%016llx", (unsigned long long)g_debugger.threadContext.Rsp);
    PrintAt(x + 2, y + 9, "RIP: 0x%016llx", (unsigned long long)g_debugger.threadContext.Rip);
    PrintAt(x + 2, y + 10, "R8:  0x%016llx", (unsigned long long)g_debugger.threadContext.R8);
}

/* Render flags panel */
void RenderFlagsPanel(void) {
    int x = 64, y = 14, width = 40, height = 6;
    
    DrawBox(x, y, width, height, "Flags");
    
    GetThreadContext();
    
    DWORD flags = g_debugger.threadContext.EFlags;
    
    PrintAt(x + 2, y + 1, "ZF:%d CF:%d SF:%d OF:%d",
           (flags >> 6) & 1, flags & 1, (flags >> 7) & 1, (flags >> 11) & 1);
    PrintAt(x + 2, y + 2, "IF:%d DF:%d PF:%d AF:%d",
           (flags >> 9) & 1, (flags >> 10) & 1, (flags >> 2) & 1, (flags >> 4) & 1);
    PrintAt(x + 2, y + 3, "TF:%d", (flags >> 8) & 1);
}

/* Render memory panel */
void RenderMemoryPanel(void) {
    int x = 64, y = 20, width = 40, height = 10;
    
    DrawBox(x, y, width, height, "Memory (RSP)");
    
    GetThreadContext();
    ReadMemoryDump(g_debugger.threadContext.Rsp, 128);
    
    for (int i = 0; i < 8; i++) {
        DWORD64 addr = g_debugger.memoryBase + i * 16;
        PrintAt(x + 2, y + 1 + i, "0x%llx: ", (unsigned long long)addr);
        
        for (int j = 0; j < 16; j++) {
            printf("%02x ", g_debugger.memoryDump[i * 16 + j]);
        }
    }
}

/* Render command prompt */
void RenderCommandPrompt(void) {
    int x = 2, y = 30, width = 102, height = 3;
    
    DrawBox(x, y, width, height, "Command");
    PrintAt(x + 2, y + 1, ">> ");
}

/* Render full UI */
void RenderUI(void) {
    system("cls");
    
    // Draw all panels
    RenderAssemblyPanel();
    RenderRegisterPanel();
    RenderFlagsPanel();
    RenderMemoryPanel();
    RenderCommandPrompt();
    
    // Show active panel indicator and status
    const char* panelNames[] = {"Assembly", "Registers", "Memory", "Command"};
    SetConsoleColor(11, 0);  // Cyan
    PrintAt(2, 0, "Active: %s | State: %s",
           panelNames[g_ui.activePanel],
           g_debugger.state == DBG_RUNNING ? "RUNNING" : "STOPPED");
    ResetConsoleColor();
    
    // Show breakpoints
    if (g_debugger.breakpointCount > 0) {
        PrintAt(60, 0, "Breakpoints: %d", g_debugger.breakpointCount);
    }
}

/* Cycle to next panel */
void CyclePanel(void) {
    g_ui.activePanel = (g_ui.activePanel + 1) % PANEL_COUNT;
}