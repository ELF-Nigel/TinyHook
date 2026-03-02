# TinyHook

Single-header TinyHook + VMT hook utilities for Windows x64.

## Files
- `TinyHook.h` — single header with all features

## Features
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
Discord: chefendpoint
Telegram: ELF_Nigel
