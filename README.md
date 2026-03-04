# TinyHook

TinyHook is a single-header, Windows x64 hooking toolkit that combines reliable 5-byte detours, VMT hooks, and a large set of advanced helpers (IAT/EAT, code-caves, auto-resolvers, integrity checks, watchdogs, and diagnostics) without external dependencies by default. It is designed for IL2CPP/AOT stubs, game rendering hooks, and custom tooling where fast iteration and a self-contained header are preferred.

Single-header TinyHook + VMT hook utilities for Windows x64.

## Files
- `TinyHook.h` — single header with all features

## Features
- hook priority system
- multi-detour chaining container
- hot-reloadable hooks
- module allow/deny lists
- symbol resolver (GetProcAddress)
- crc32 helpers for integrity checks
- self-healing hooks (reapply if overwritten)
- reentrancy guard helpers
- lazy install helper
- pattern scan helper
- auto-disable on dll detach
- 5-byte rel32 patching with near relay stubs
- IL2CPP/AOT stub chain resolution
- optional thread suspension during patching
- optional executable memory verification
- safe trampoline (wrapper-aware)
- VMT hook + shadow VMT
- DXGI (D3D11) helpers (optional)
- DX12 helpers (optional)
- batch helpers + auto helpers
- logging callbacks for diagnostics

## Build
- Windows x64
- C or C++
- No external dependencies

## Usage
```cpp
#include "TinyHook.h"

// optional logger
hook_set_logger([](const char* tag, const char* msg){
    // log tag/msg
});

// tinyhook example
tinyhook_t hk = {0};
void* target = (void*)0x12345678;
void* detour = (void*)&MyDetour;

th_status_t st = tinyhook_create_ex(&hk, target, detour,
    TH_FLAG_VERIFY_STUB | TH_FLAG_RESOLVE_CHAIN | TH_FLAG_VERIFY_EXEC | TH_FLAG_SUSPEND_THREADS);
if (st == TH_OK) {
    tinyhook_enable(&hk);
}

// vmt example
vmt_hook_t vh = {0};
vmt_hook_create(&vh, swapchain, 8, (void*)&MyPresent);
vmt_hook_enable(&vh);
``

## Tinyhook API (common)
- `tinyhook_create_ex`
- `tinyhook_enable`, `tinyhook_disable`, `tinyhook_destroy`
- `tinyhook_create_safe`
- `tinyhook_auto`, `tinyhook_auto_chain`, `tinyhook_auto_unhook`
- `tinyhook_simple`, `tinyhook_batch`
- `tinyhook_default_flags`, `tinyhook_status_str`

### Tinyhook Flags
- `TH_FLAG_VERIFY_STUB`
- `TH_FLAG_RESOLVE_CHAIN`
- `TH_FLAG_VERIFY_EXEC`
- `TH_FLAG_SUSPEND_THREADS`
- `TH_FLAG_ALLOW_RAW_TRAMP`

## VMT API (common)
- `vmt_hook_create`, `vmt_hook_enable`, `vmt_hook_disable`, `vmt_hook_destroy`
- `vmt_hook_enable_ex`, `vmt_hook_disable_ex`
- `vmt_shadow_create`, `vmt_shadow_enable`, `vmt_shadow_disable`
- `vmt_shadow_create_auto`, `vmt_shadow_auto`
- `vmt_hook_auto`, `vmt_hook_auto_ex`, `vmt_hook_simple`, `vmt_hook_batch`
- `vmt_registry_add`, `vmt_registry_enable_all`, `vmt_registry_disable_all`

## Optional DXGI/DX12 helpers
Define before include:
```cpp
#define VMT_DXGI_HELPERS
#define VMT_DX12_HELPERS
#include "TinyHook.h"
```
Provides helpers to create dummy swapchains and auto-resolve indices.

## Logging
```cpp
hook_set_logger([](const char* tag, const char* msg){
    // your logging here
});

// formatted logging
hook_logf("tinyhook", "status=%s", tinyhook_status_str(st));
```

## Credits
Discord: pb2j
Telegram: ELF_Nigel

## Changelog
- 2026-03-02: added priority system, chaining, hot-reload, allow/deny list, symbol resolver.
- 2026-03-02: initial public release (single header + docs).
- 2026-03-02: improved logging and diagnostics.

## API Reference
### Tinyhook Core
- `tinyhook_create_ex` — create hook with flags
- `tinyhook_enable`, `tinyhook_disable`, `tinyhook_destroy`
- `tinyhook_create_safe` — includes executable verification
- `tinyhook_auto`, `tinyhook_auto_chain`, `tinyhook_auto_unhook`
- `tinyhook_simple`, `tinyhook_batch`
- `tinyhook_default_flags`, `tinyhook_status_str`

### Tinyhook Flags
- `TH_FLAG_VERIFY_STUB`
- `TH_FLAG_RESOLVE_CHAIN`
- `TH_FLAG_VERIFY_EXEC`
- `TH_FLAG_SUSPEND_THREADS`
- `TH_FLAG_ALLOW_RAW_TRAMP`

### VMT Core
- `vmt_hook_create`, `vmt_hook_enable`, `vmt_hook_disable`, `vmt_hook_destroy`
- `vmt_hook_enable_ex`, `vmt_hook_disable_ex`
- `vmt_shadow_create`, `vmt_shadow_enable`, `vmt_shadow_disable`
- `vmt_shadow_create_auto`, `vmt_shadow_auto`
- `vmt_hook_auto`, `vmt_hook_auto_ex`, `vmt_hook_simple`, `vmt_hook_batch`
- `vmt_registry_add`, `vmt_registry_enable_all`, `vmt_registry_disable_all`

### Optional DXGI/DX12
- Enable with `#define VMT_DXGI_HELPERS` / `#define VMT_DX12_HELPERS`
- Dummy swapchain helpers + index resolution + auto hook helpers

## Usage Guides
### Unity IL2CPP (AOT)
- prefer hooking the entry stub with `TH_FLAG_VERIFY_STUB | TH_FLAG_RESOLVE_CHAIN`.
- use `TH_FLAG_SUSPEND_THREADS` if patching at runtime.
- if you need the real implementation, use `tinyhook_auto_chain(..., hook_final=1, ...)`.

Example:
```cpp
void* target = (void*)0x12345678; // il2cpp stub
th_status_t st = tinyhook_create_ex(&hk, target, detour,
    TH_FLAG_VERIFY_STUB | TH_FLAG_RESOLVE_CHAIN | TH_FLAG_VERIFY_EXEC | TH_FLAG_SUSPEND_THREADS);
```

### Unreal (D3D11/D3D12 present)
- prefer vmt hooking for swapchain `Present` and `ResizeBuffers`.
- use the dxgi/dx12 helper to resolve indices safely.

D3D11 example:
```cpp
#define VMT_DXGI_HELPERS
#include "TinyHook.h"
size_t present = 0, resize = 0;
if (vmt_dxgi_resolve_indices_for_swapchain(sc, &present, &resize)) {
    vmt_hook_create(&hp, sc, present, (void*)hkPresent);
    vmt_hook_enable(&hp);
}
```

D3D12 example:
```cpp
#define VMT_DX12_HELPERS
#include "TinyHook.h"
size_t present = 0, resize = 0;
if (vmt_dx12_resolve_indices_for_swapchain(sc3, &present, &resize)) {
    vmt_hook_create(&hp, sc3, present, (void*)hkPresent);
    vmt_hook_enable(&hp);
}
```

### Vulkan
- hook via `vkQueuePresentKHR` and/or swapchain functions.
- prefer detouring export addresses or using a loader layer.
- tinyhook can be used on exported function stubs if a 5-byte patch is safe.

Example (export detour):
```cpp
// resolve vkQueuePresentKHR from vulkan-1.dll and detour with tinyhook
```

### OpenGL
- hook `wglSwapBuffers` or `SwapBuffers` for present.
- tinyhook works well on exported functions (ensure 5-byte patch is safe).

Example:
```cpp
// resolve wglSwapBuffers from opengl32.dll and detour with tinyhook
```

## Injection Flow (Generic)
1. inject your dll (manual map or CreateRemoteThread).
2. wait for render device creation (dxgi/vk/wgl ready).
3. resolve your target functions or swapchain pointers.
4. install hooks (tinyhook/vmt) with thread suspend if needed.
5. verify with logger and sanity checks.
6. uninstall cleanly on detach.

## Integrity Checks
```cpp
uint32_t before = tinyhook_crc32_target5(target);
// install hook
uint32_t after = tinyhook_crc32_target5(target);
```

## Self-Healing
```cpp
// periodically call this
if (!tinyhook_verify_installed(&hk)) {
    tinyhook_reapply_if_needed(&hk);
}
```

## Reentrancy Guard
```cpp
if (!hook_reentry_enter()) return;
// do work
hook_reentry_leave();
```

## Lazy Install
```cpp
static volatile LONG g_guard = 0;
if (tinyhook_lazy_install(&g_guard, &hk, target, detour, tinyhook_default_flags())) {
    // installed once
}
```

## Pattern Scan
```cpp
void* fn = hook_pattern_scan_module(base, size, pattern, mask);
```

## Dll Detach Cleanup
```cpp
// call from dllmain
hook_on_dll_detach();
```

## Auto-Resolvers
### Module export
```cpp
void* fn = hook_resolve_export("kernel32.dll", "CreateFileW", 0);
```

### Pattern scan (auto module bounds)
```cpp
void* fn = hook_pattern_scan_module_auto("game.dll", pattern, mask);
```

### IL2CPP resolver (user-supplied)
```cpp
void* fn = hook_il2cpp_resolve_method(my_resolver, "", "Player", "Update", 0);
```

### Unreal resolver (user-supplied)
```cpp
void* fn = hook_unreal_resolve_function(my_resolver, "Class /Script/Game.MyClass", "Tick");
```

### DXGI swapchain
```cpp
IDXGISwapChain* sc = hook_dxgi_find_swapchain(hwnd);
```

### Module section scan
```cpp
void* fn = hook_pattern_scan_section(base, ".text", pattern, mask);
```

### Export by hash
```cpp
uint32_t crc = tinyhook_crc32("CreateFileW", 11);
void* fn = hook_resolve_export_hash("kernel32.dll", crc);
```

### Wait for module
```cpp
HMODULE h = hook_wait_for_module("game.dll", 100, 50);
```

### Enumerate modules
```cpp
HMODULE mods[256];
size_t count = hook_enum_modules(mods, 256);
```

## Additional Hook Concepts
### IAT Hooking
```cpp
void** entry = hook_find_iat_entry("game.exe", "kernel32.dll", "CreateFileW");
void* orig = NULL;
hook_iat_patch(entry, (void*)MyCreateFileW, &orig);
```

### VEH / Guard Page (stub)
```cpp
void* h = hook_install_veh();
// configure guard pages yourself
hook_remove_veh(h);
```

### Hardware Breakpoint (thread-local)
```cpp
hook_hw_breakpoint_set(GetCurrentThread(), target);
```

## Advanced Checks
```cpp
uint32_t crc = hook_crc_section("game.dll", ".text");
```

## Self Resolution
```cpp
void* fn = hook_rescan_after_module("game.dll", pattern, mask, 200, 50);
```

## Disassembler Support (Optional)
Define one of these before including `TinyHook.h`:
- `HOOK_USE_ZYDIS`
- `HOOK_USE_CAPSTONE`

Then use:
```cpp
size_t len = hook_min_prologue_len_disasm(target, 5);
```

### EAT Hooking
```cpp
void* orig = NULL;
hook_eat_patch("user32.dll", "MessageBoxA", (void*)MyMsgBoxA, &orig);
```

### Watchdog
```cpp
hook_watchdog_start();
// ...
hook_watchdog_stop();
```

### Transactions
```cpp
hook_tx_t tx = {0};
hook_tx_begin(&tx);
// apply multiple hooks
hook_tx_end(&tx);
```

## Code Cave Helpers
```cpp
void* cave = hook_find_codecave_module("game.dll", 64);
if (cave) {
    uint8_t bytes[5] = {0x90,0x90,0x90,0x90,0x90};
    hook_write_codecave(cave, bytes, sizeof(bytes));
}
```

## Hook Manager
```cpp
hook_manager_t mgr;
hook_manager_init(&mgr);
mgr.watchdog_enabled = 1;
mgr.priority_enable = 1;
hook_manager_enable_all(&mgr);
```

## Hook Metadata
```cpp
hook_meta_t meta = {"present", "render", 5, 1000, 0};
hook_manager_bind_meta_tiny(&hk, &meta);
```

## Hook Manager Policies
```cpp
hook_manager_policy_t pol = {"render", NULL, 1000};
hook_manager_tick(&pol);
```

## Hook Dump
```cpp
hook_dump_active();
```

## Resolver Cache
```cpp
void* fn = hook_resolve_symbol_cached("kernel32.dll", "CreateFileW");
```

## Syscall Proxy
```cpp
void* ntOpen = hook_resolve_syscall("NtOpenProcess");
```

## Hook Profiling
```cpp
hook_profile_t p;
hook_profile_begin(&p);
// call detour
hook_profile_end(&p);
```
