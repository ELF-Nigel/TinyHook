#include "../TinyHook.h"

static int (__stdcall* g_original_target)(int) = 0;

static int __stdcall my_detour(int x) {
    if (g_original_target) {
        return g_original_target(x + 1);
    }
    return x;
}

int main(void) {
    tinyhook_t hk = {0};

    void* target = (void*)0x12345678;  // Replace with resolved function address.
    void* detour = (void*)&my_detour;

    th_status_t st = tinyhook_create_ex(
        &hk,
        target,
        detour,
        TH_FLAG_VERIFY_STUB | TH_FLAG_RESOLVE_CHAIN | TH_FLAG_VERIFY_EXEC
    );
    if (st != TH_OK) {
        return 1;
    }

    g_original_target = (int(__stdcall*)(int))hk.trampoline;

    st = tinyhook_enable(&hk);
    if (st != TH_OK) {
        tinyhook_destroy(&hk);
        return 2;
    }

    // Call into target path here while hook is active.

    tinyhook_disable(&hk);
    tinyhook_destroy(&hk);
    return 0;
}
