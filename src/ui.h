#ifndef UI_H
#define UI_H

#include <windows.h>

typedef enum {
    PANEL_ASSEMBLY,
    PANEL_REGISTERS,
    PANEL_MEMORY,
    PANEL_COMMAND,
    PANEL_COUNT
} PanelType;

typedef struct {
    PanelType activePanel;
    int assemblyOffset;
    int memoryOffset;
    int commandHistoryIndex;
    BOOL needsRedraw;
} UIState;

// UI functions
void InitializeUI(void);
void RenderUI(void);
void RenderAssemblyPanel(void);
void RenderRegisterPanel(void);
void RenderFlagsPanel(void);
void RenderMemoryPanel(void);
void RenderCommandPrompt(void);
void CyclePanel(void);
void DrawBox(int x, int y, int width, int height, const char* title);
void PrintAt(int x, int y, const char* format, ...);
void SetConsoleColor(int foreground, int background);
void ResetConsoleColor(void);

extern UIState g_ui;

#endif