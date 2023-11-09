#include <windows.h>
#pragma comment(lib, "user32.lib")

// Declare global variables for window and controls
HWND g_hWnd;
HWND g_hButton;
HWND g_hTextBox;

// Window procedure
LRESULT CALLBACK WindowProc(HWND hWnd, UINT uMsg, WPARAM wParam, LPARAM lParam)
{
    switch (uMsg)
    {
        case WM_CREATE:
        {
            // Create a button control
            g_hButton = CreateWindow("BUTTON", "Click Me", WS_VISIBLE | WS_CHILD, 10, 10, 100, 30, hWnd, NULL, NULL, NULL);

            // Create a text box control
            g_hTextBox = CreateWindow("EDIT", "", WS_VISIBLE | WS_CHILD | WS_BORDER | ES_AUTOHSCROLL, 10, 50, 300, 30, hWnd, NULL, NULL, NULL);

            break;
        }
        case WM_COMMAND:
        {
            if (lParam == (LPARAM)g_hButton)
            {
                // Button clicked, display a message box with the text from the text box
                char text[256];
                GetWindowText(g_hTextBox, text, sizeof(text));
                MessageBox(hWnd, text, "Button Clicked", MB_OK);
            }

            break;
        }
        case WM_DESTROY:
        {
            // Exit the application when the window is closed
            PostQuitMessage(0);
            break;
        }
        default:
            return DefWindowProc(hWnd, uMsg, wParam, lParam);
    }

    return 0;
}

// Entry point of the program
int WINAPI WinMain(HINSTANCE hInstance, HINSTANCE hPrevInstance, LPSTR lpCmdLine, int nCmdShow)
{
    // Register the window class
    const char* CLASS_NAME = "MyWindowClass";

    WNDCLASS wc = { 0 };
    wc.lpfnWndProc = WindowProc;
    wc.hInstance = hInstance;
    wc.lpszClassName = CLASS_NAME;

    RegisterClass(&wc);

    // Create the window
    g_hWnd = CreateWindowEx(0, CLASS_NAME, "Simple Windows Program", WS_OVERLAPPEDWINDOW, CW_USEDEFAULT, CW_USEDEFAULT, 400, 200, NULL, NULL, hInstance, NULL);

    if (g_hWnd == NULL)
        return 0;

    // Show the window
    ShowWindow(g_hWnd, nCmdShow);

    // Main message loop
    MSG msg;
    while (GetMessage(&msg, NULL, 0, 0))
    {
        TranslateMessage(&msg);
        DispatchMessage(&msg);
    }

    return (int)msg.wParam;
}
