#include "../TinyHook.h"

struct FakeInterface {
    void** vtable;
};

static long(__stdcall* g_original_present)(void*) = 0;

static long __stdcall my_present(void* self) {
    if (g_original_present) {
        return g_original_present(self);
    }
    return 0;
}

int main(void) {
    FakeInterface obj = {0};
    vmt_hook_t vh = {0};

    // Replace obj.vtable/object with a real interface instance and valid index.
    if (!vmt_hook_create(&vh, &obj, 8, (void*)&my_present)) {
        return 1;
    }

    g_original_present = (long(__stdcall*)(void*))vh.original;

    if (!vmt_hook_enable(&vh)) {
        vmt_hook_destroy(&vh);
        return 2;
    }

    // Render or call path while hook is active.

    vmt_hook_disable(&vh);
    vmt_hook_destroy(&vh);
    return 0;
}
