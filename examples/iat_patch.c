#include "../TinyHook.h"

static int (WINAPI* g_original_message_box_a)(HWND, LPCSTR, LPCSTR, UINT) = 0;

static int WINAPI my_message_box_a(HWND hWnd, LPCSTR text, LPCSTR caption, UINT type) {
    if (!caption) {
        caption = "TinyHook IAT";
    }
    if (g_original_message_box_a) {
        return g_original_message_box_a(hWnd, text, caption, type);
    }
    return 0;
}

int main(void) {
    void** entry = hook_find_iat_entry(NULL, "USER32.dll", "MessageBoxA");
    if (!entry) {
        return 1;
    }

    if (!hook_iat_patch(entry, (void*)&my_message_box_a, (void**)&g_original_message_box_a)) {
        return 2;
    }

    MessageBoxA(NULL, "IAT patched", "TinyHook", MB_OK);

    // Restore original import entry.
    if (g_original_message_box_a) {
        hook_iat_patch(entry, (void*)g_original_message_box_a, NULL);
    }

    return 0;
}
