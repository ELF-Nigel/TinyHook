// tinyhook.h - tinyhook + vmt hook (single header)
// credits: discord: chefendpoint | telegram: elf_nigel

#pragma once

// tinyhook_plus.h - hardened 5-byte rel32 hook for windows x64
// - supports stub patterns: jmp rel32, nop; jmp rel32
// - uses near relay stub (rel32) + absolute jump to detour
// - optional thread suspension during patching
// - optional safe trampoline that jumps to original wrapper target
//
// this is for cases where only a 5-byte patch is allowed.
// credits: discord: chefendpoint | telegram: elf_nigel

#include <windows.h>
#include <stdint.h>
#include <stddef.h>
#include <stdarg.h>
#include <stdio.h>
#include <psapi.h>
#include <string.h>
// optional disassembler support
#ifdef HOOK_USE_ZYDIS
#include <Zydis/Zydis.h>
#endif
#ifdef HOOK_USE_CAPSTONE
#include <capstone/capstone.h>
#endif

#include <tlhelp32.h>

#ifdef __cplusplus
extern "C" {
#endif

typedef enum th_status_t {
    TH_OK = 0,
    TH_ERR_INVALID_ARGS,
    TH_ERR_ALREADY_ENABLED,
    TH_ERR_ALLOC_NEAR,
    TH_ERR_REACHABILITY,
    TH_ERR_PROTECT,
    TH_ERR_STUB_UNSUPPORTED,
    TH_ERR_NOT_EXEC
} th_status_t;

// simple thread-local reentrancy guard
static __declspec(thread) int g_hook_reentry = 0;

static int hook_reentry_enter(void) {
    if (g_hook_reentry) return 0;
    g_hook_reentry = 1;
    return 1;
}

static void hook_reentry_leave(void) {
    g_hook_reentry = 0;
}

// simple detour chain container (user manages call order)
typedef struct hook_chain_t {
    void** detours;
    size_t count;
    size_t cap;
} hook_chain_t;

static int hook_chain_add(hook_chain_t* c, void* detour) {
    if (!c || !detour) return 0;
    if (c->count == c->cap) {
        size_t ncap = c->cap ? c->cap * 2 : 4;
        void** n = (void**)HeapReAlloc(GetProcessHeap(), 0, c->detours, ncap * sizeof(void*));
        if (!n) return 0;
        c->detours = n;
        c->cap = ncap;
    }
    c->detours[c->count++] = detour;
    return 1;
}

static int hook_chain_remove(hook_chain_t* c, void* detour) {
    if (!c || !detour) return 0;
    for (size_t i = 0; i < c->count; ++i) {
        if (c->detours[i] == detour) {
            c->detours[i] = c->detours[c->count - 1];
            c->count--;
            return 1;
        }
    }
    return 0;
}

static void hook_chain_destroy(hook_chain_t* c) {
    if (!c) return;
    if (c->detours) HeapFree(GetProcessHeap(), 0, c->detours);
    c->detours = NULL;
    c->count = 0;
    c->cap = 0;
}

// chain call-next helper (user handles casting)
static void* hook_chain_call_next(hook_chain_t* c, size_t* idx) {
    if (!c || !idx || *idx >= c->count) return NULL;
    return c->detours[(*idx)++];
}

// module allow/deny list
static HMODULE hook_module_allowlist[32];
static size_t hook_module_allowlist_count = 0;
static HMODULE hook_module_denylist[32];
static size_t hook_module_denylist_count = 0;

static int hook_allow_module(HMODULE mod) {
    if (!mod || hook_module_allowlist_count >= 32) return 0;
    hook_module_allowlist[hook_module_allowlist_count++] = mod;
    return 1;
}

static int hook_deny_module(HMODULE mod) {
    if (!mod || hook_module_denylist_count >= 32) return 0;
    hook_module_denylist[hook_module_denylist_count++] = mod;
    return 1;
}

static int hook_is_module_allowed(void* addr) {
    if (!addr) return 0;
    HMODULE mod = NULL;
    if (!GetModuleHandleExA(GET_MODULE_HANDLE_EX_FLAG_FROM_ADDRESS | GET_MODULE_HANDLE_EX_FLAG_UNCHANGED_REFCOUNT,
                            (LPCSTR)addr, &mod)) {
        return 0;
    }
    for (size_t i = 0; i < hook_module_denylist_count; ++i) {
        if (hook_module_denylist[i] == mod) return 0;
    }
    if (hook_module_allowlist_count == 0) return 1;
    for (size_t i = 0; i < hook_module_allowlist_count; ++i) {
        if (hook_module_allowlist[i] == mod) return 1;
    }
    return 0;
}

// il2cpp resolver stub (requires user to provide a resolver function)
typedef void* (*hook_il2cpp_resolver_fn)(const char* namesp, const char* klass, const char* method, int args);

static void* hook_il2cpp_resolve_method(hook_il2cpp_resolver_fn fn, const char* namesp, const char* klass, const char* method, int args) {
    if (!fn) return NULL;
    return fn(namesp, klass, method, args);
}

// unreal resolver stub (user provides resolver)
typedef void* (*hook_unreal_resolver_fn)(const char* object_path, const char* function_name);

static void* hook_unreal_resolve_function(hook_unreal_resolver_fn fn, const char* object_path, const char* function_name) {
    if (!fn) return NULL;
    return fn(object_path, function_name);
}

// iat hook helpers
static void** hook_find_iat_entry(const char* module, const char* import_mod, const char* func) {
    HMODULE h = GetModuleHandleA(module);
    if (!h) return NULL;
    uint8_t* base = (uint8_t*)h;
    IMAGE_DOS_HEADER* dos = (IMAGE_DOS_HEADER*)base;
    if (dos->e_magic != IMAGE_DOS_SIGNATURE) return NULL;
    IMAGE_NT_HEADERS* nt = (IMAGE_NT_HEADERS*)(base + dos->e_lfanew);
    if (nt->Signature != IMAGE_NT_SIGNATURE) return NULL;
    IMAGE_DATA_DIRECTORY dir = nt->OptionalHeader.DataDirectory[IMAGE_DIRECTORY_ENTRY_IMPORT];
    if (!dir.VirtualAddress) return NULL;
    IMAGE_IMPORT_DESCRIPTOR* imp = (IMAGE_IMPORT_DESCRIPTOR*)(base + dir.VirtualAddress);
    for (; imp->Name; ++imp) {
        const char* name = (const char*)(base + imp->Name);
        if (_stricmp(name, import_mod) != 0) continue;
        IMAGE_THUNK_DATA* thunk = (IMAGE_THUNK_DATA*)(base + imp->FirstThunk);
        IMAGE_THUNK_DATA* orig = (IMAGE_THUNK_DATA*)(base + imp->OriginalFirstThunk);
        for (; orig->u1.AddressOfData; ++orig, ++thunk) {
            if (orig->u1.Ordinal & IMAGE_ORDINAL_FLAG) continue;
            IMAGE_IMPORT_BY_NAME* ibn = (IMAGE_IMPORT_BY_NAME*)(base + orig->u1.AddressOfData);
            if (strcmp((char*)ibn->Name, func) == 0) {
                return (void**)&thunk->u1.Function;
            }
        }
    }
    return NULL;
}

static int hook_iat_patch(void** entry, void* detour, void** out_original) {
    if (!entry || !detour) return 0;
    DWORD old;
    if (!VirtualProtect(entry, sizeof(void*), PAGE_READWRITE, &old)) return 0;
    if (out_original) *out_original = *entry;
    *entry = detour;
    VirtualProtect(entry, sizeof(void*), old, &old);
    FlushInstructionCache(GetCurrentProcess(), entry, sizeof(void*));
    return 1;
}

// veh/guard page hook (simplified)
// page guard helpers
static int hook_page_guard_set(void* addr, size_t len, DWORD* old) {
    if (!addr || !len) return 0;
    DWORD prot;
    if (!VirtualProtect(addr, len, PAGE_EXECUTE_READ | PAGE_GUARD, &prot)) return 0;
    if (old) *old = prot;
    return 1;
}

static int hook_page_guard_clear(void* addr, size_t len, DWORD old) {
    if (!addr || !len) return 0;
    DWORD tmp;
    return VirtualProtect(addr, len, old, &tmp) != 0;
}

static LONG CALLBACK hook_veh_guard(EXCEPTION_POINTERS* ep) {
    return EXCEPTION_CONTINUE_SEARCH;
}

static void* hook_install_veh(void) {
    return AddVectoredExceptionHandler(1, hook_veh_guard);
}

static void hook_remove_veh(void* handle) {
    if (handle) RemoveVectoredExceptionHandler(handle);
}

// hardware breakpoint (thread-local)
static int hook_hw_breakpoint_set(HANDLE thread, void* addr) {
    if (!thread || !addr) return 0;
    CONTEXT ctx;
    ZeroMemory(&ctx, sizeof(ctx));
    ctx.ContextFlags = CONTEXT_DEBUG_REGISTERS;
    if (!GetThreadContext(thread, &ctx)) return 0;
    ctx.Dr0 = (DWORD_PTR)addr;
    ctx.Dr7 |= 1;
    return SetThreadContext(thread, &ctx) != 0;
}

static int hook_hw_breakpoint_clear(HANDLE thread) {
    if (!thread) return 0;
    CONTEXT ctx;
    ZeroMemory(&ctx, sizeof(ctx));
    ctx.ContextFlags = CONTEXT_DEBUG_REGISTERS;
    if (!GetThreadContext(thread, &ctx)) return 0;
    ctx.Dr0 = 0;
    ctx.Dr7 &= ~1u;
    return SetThreadContext(thread, &ctx) != 0;
}

typedef void (*hook_log_fn)(const char* tag, const char* msg);

static hook_log_fn g_hook_log = NULL;

static void hook_set_logger(hook_log_fn fn) {
    g_hook_log = fn;
}

static void hook_log(const char* tag, const char* msg) {
    if (g_hook_log) g_hook_log(tag, msg);
}

// forward declarations for early helpers
static uint32_t tinyhook_crc32(const void* data, size_t len);
static int hook_module_bounds(const char* module, void** out_base, size_t* out_size);
static int hook_find_section(void* module_base, const char* name, void** out_base, size_t* out_size);
static void* hook_resolve_symbol(const char* module, const char* symbol);
static void* hook_pattern_scan_module(void* module_base, size_t module_size, const uint8_t* pattern, const char* mask);
static void* hook_pattern_scan_module_auto(const char* module, const uint8_t* pattern, const char* mask);
static int tinyhook_reapply_if_needed(tinyhook_t* h);
static void vmt_registry_destroy_all(void);

// crc32 of a module section
static uint32_t hook_crc_section(const char* module, const char* section) {
    void* base = NULL;
    size_t size = 0;
    if (!hook_module_bounds(module, &base, &size)) return 0;
    void* sec_base = NULL;
    size_t sec_size = 0;
    if (!hook_find_section(base, section, &sec_base, &sec_size)) return 0;
    return tinyhook_crc32(sec_base, sec_size);
}

// safe memory helpers
static int hook_safe_read(void* addr, void* out, size_t len) {
    if (!addr || !out || !len) return 0;
    __try {
        memcpy(out, addr, len);
        return 1;
    } __except (EXCEPTION_EXECUTE_HANDLER) {
        return 0;
    }
}

static int hook_safe_write(void* addr, const void* data, size_t len) {
    if (!addr || !data || !len) return 0;
    DWORD old;
    if (!VirtualProtect(addr, len, PAGE_EXECUTE_READWRITE, &old)) return 0;
    __try {
        memcpy(addr, data, len);
    } __except (EXCEPTION_EXECUTE_HANDLER) {
        VirtualProtect(addr, len, old, &old);
        return 0;
    }
    VirtualProtect(addr, len, old, &old);
    FlushInstructionCache(GetCurrentProcess(), addr, len);
    return 1;
}

static uint32_t tinyhook_crc32(const void* data, size_t len);
static void* hook_pattern_scan_module(void* module_base, size_t module_size, const uint8_t* pattern, const char* mask);

// call this from dllmain to auto-disable hooks on detach
// optional symbol resolver (dbghelp)
// resolve export by name or ordinal
// resolve export by crc32 of name
// export address table hook (name)
static int hook_eat_patch(const char* module, const char* name, void* detour, void** out_original) {
    if (!module || !name || !detour) return 0;
    HMODULE mod = GetModuleHandleA(module);
    if (!mod) return 0;
    uint8_t* base = (uint8_t*)mod;
    IMAGE_DOS_HEADER* dos = (IMAGE_DOS_HEADER*)base;
    if (dos->e_magic != IMAGE_DOS_SIGNATURE) return 0;
    IMAGE_NT_HEADERS* nt = (IMAGE_NT_HEADERS*)(base + dos->e_lfanew);
    if (nt->Signature != IMAGE_NT_SIGNATURE) return 0;
    IMAGE_DATA_DIRECTORY dir = nt->OptionalHeader.DataDirectory[IMAGE_DIRECTORY_ENTRY_EXPORT];
    if (!dir.VirtualAddress) return 0;
    IMAGE_EXPORT_DIRECTORY* exp = (IMAGE_EXPORT_DIRECTORY*)(base + dir.VirtualAddress);
    DWORD* names = (DWORD*)(base + exp->AddressOfNames);
    WORD* ords = (WORD*)(base + exp->AddressOfNameOrdinals);
    DWORD* funcs = (DWORD*)(base + exp->AddressOfFunctions);
    for (DWORD i = 0; i < exp->NumberOfNames; ++i) {
        const char* n = (const char*)(base + names[i]);
        if (strcmp(n, name) == 0) {
            WORD ord = ords[i];
            DWORD old;
            if (!VirtualProtect(&funcs[ord], sizeof(DWORD), PAGE_READWRITE, &old)) return 0;
            if (out_original) *out_original = (void*)(base + funcs[ord]);
            funcs[ord] = (DWORD)((uint8_t*)detour - base);
            VirtualProtect(&funcs[ord], sizeof(DWORD), old, &old);
            return 1;
        }
    }
    return 0;
}

static void* hook_resolve_export_hash(const char* module, uint32_t name_crc32) {
    if (!module) return NULL;
    HMODULE mod = GetModuleHandleA(module);
    if (!mod) return NULL;
    uint8_t* base = (uint8_t*)mod;
    IMAGE_DOS_HEADER* dos = (IMAGE_DOS_HEADER*)base;
    if (dos->e_magic != IMAGE_DOS_SIGNATURE) return NULL;
    IMAGE_NT_HEADERS* nt = (IMAGE_NT_HEADERS*)(base + dos->e_lfanew);
    if (nt->Signature != IMAGE_NT_SIGNATURE) return NULL;
    IMAGE_DATA_DIRECTORY dir = nt->OptionalHeader.DataDirectory[IMAGE_DIRECTORY_ENTRY_EXPORT];
    if (!dir.VirtualAddress) return NULL;
    IMAGE_EXPORT_DIRECTORY* exp = (IMAGE_EXPORT_DIRECTORY*)(base + dir.VirtualAddress);
    DWORD* names = (DWORD*)(base + exp->AddressOfNames);
    WORD* ords = (WORD*)(base + exp->AddressOfNameOrdinals);
    DWORD* funcs = (DWORD*)(base + exp->AddressOfFunctions);
    for (DWORD i = 0; i < exp->NumberOfNames; ++i) {
        const char* n = (const char*)(base + names[i]);
        if (tinyhook_crc32(n, (size_t)strlen(n)) == name_crc32) {
            WORD ord = ords[i];
            return (void*)(base + funcs[ord]);
        }
    }
    return NULL;
}

static void* hook_resolve_export(const char* module, const char* name, uint16_t ordinal) {
    HMODULE mod = GetModuleHandleA(module);
    if (!mod) return NULL;
    if (name) return (void*)GetProcAddress(mod, name);
    if (ordinal) return (void*)GetProcAddress(mod, (LPCSTR)(uintptr_t)ordinal);
    return NULL;
}

// pdb resolver stub (user integrates dbghelp/symsrv)
static void* hook_resolve_symbol_pdb(const char* module, const char* symbol) {
    return hook_resolve_symbol(module, symbol);
}

static void* hook_resolve_symbol(const char* module, const char* symbol) {
    if (!module || !symbol) return NULL;
    HMODULE mod = GetModuleHandleA(module);
    if (!mod) return NULL;
    FARPROC p = GetProcAddress(mod, symbol);
    return (void*)p;
}

static void hook_logf(const char* tag, const char* fmt, ...) {
    if (!g_hook_log || !fmt) return;
    char buf[512];
    va_list ap;
    va_start(ap, fmt);
    vsnprintf(buf, sizeof(buf), fmt, ap);
    va_end(ap);
    g_hook_log(tag, buf);
}

typedef enum th_stub_kind_t {
    TH_STUB_UNKNOWN = 0,
    TH_STUB_JMP_REL32,
    TH_STUB_NOP_JMP_REL32,
    TH_STUB_JMP_REL8,
    TH_STUB_JMP_RIP,
    TH_STUB_MOV_JMP
} th_stub_kind_t;

enum {
    TH_FLAG_VERIFY_STUB      = 1u << 0, // default: only allow jmp rel32 or nop; jmp rel32
    TH_FLAG_SUSPEND_THREADS  = 1u << 1, // suspend other threads while patching
    TH_FLAG_ALLOW_RAW_TRAMP  = 1u << 2, // if stub unsupported, build raw 5-byte trampoline (unsafe)
    TH_FLAG_RESOLVE_CHAIN    = 1u << 3, // resolve wrapper chain for trampoline (il2cpp-style stubs)
    TH_FLAG_VERIFY_EXEC      = 1u << 4  // verify target is in executable memory
};

typedef struct tinyhook_t {
    void* target;        // function entry to hook
    void* detour;        // user detour function
    void* relay;         // relay stub (near target, rel32 reachable)
    void* trampoline;    // safe trampoline (if available)
    uint8_t original[5]; // saved bytes
    uint32_t flags;
    int enabled;
    int priority;
} tinyhook_t;

// forward declarations (tinyhook)
static int th_safe_read_ptr(void* addr, void** out);
static int th_is_executable_ptr(void* p);

// ------------------------------------------------------------
// crc32 (ieee)
static uint32_t tinyhook_crc32(const void* data, size_t len) {
    const uint8_t* p = (const uint8_t*)data;
    uint32_t crc = 0xFFFFFFFFu;
    for (size_t i = 0; i < len; ++i) {
        crc ^= p[i];
        for (int k = 0; k < 8; ++k) {
            uint32_t mask = (uint32_t)(-(int)(crc & 1u));
            crc = (crc >> 1) ^ (0xEDB88320u & mask);
        }
    }
    return ~crc;
}

static uint32_t tinyhook_crc32_target5(void* target) {
    if (!target) return 0;
    return tinyhook_crc32(target, 5);
}

// generic module pattern scan
// module bounds helper
// wait for a module to load (poll)
static HMODULE hook_wait_for_module(const char* module, int tries, int sleep_ms) {
    if (!module) return NULL;
    for (int i = 0; i < tries; ++i) {
        HMODULE h = GetModuleHandleA(module);
        if (h) return h;
        Sleep(sleep_ms);
    }
    return NULL;
}

// enumerate modules in current process (returns count)
static size_t hook_enum_modules(HMODULE* out, size_t cap) {
    if (!out || cap == 0) return 0;
    DWORD needed = 0;
    if (!EnumProcessModules(GetCurrentProcess(), out, (DWORD)(cap * sizeof(HMODULE)), &needed)) return 0;
    return (size_t)(needed / sizeof(HMODULE));
}

static int hook_module_bounds(const char* module, void** out_base, size_t* out_size) {
    if (!module || !out_base || !out_size) return 0;
    HMODULE mod = GetModuleHandleA(module);
    if (!mod) return 0;
    MODULEINFO mi;
    if (!GetModuleInformation(GetCurrentProcess(), mod, &mi, sizeof(mi))) return 0;
    *out_base = mi.lpBaseOfDll;
    *out_size = (size_t)mi.SizeOfImage;
    return 1;
}

// pattern scan with module auto-bounds
// forward declaration
// find a module section by name
static int hook_find_section(void* module_base, const char* name, void** out_base, size_t* out_size) {
    if (!module_base || !name || !out_base || !out_size) return 0;
    uint8_t* base = (uint8_t*)module_base;
    IMAGE_DOS_HEADER* dos = (IMAGE_DOS_HEADER*)base;
    if (dos->e_magic != IMAGE_DOS_SIGNATURE) return 0;
    IMAGE_NT_HEADERS* nt = (IMAGE_NT_HEADERS*)(base + dos->e_lfanew);
    if (nt->Signature != IMAGE_NT_SIGNATURE) return 0;
    IMAGE_SECTION_HEADER* sec = (IMAGE_SECTION_HEADER*)((uint8_t*)&nt->OptionalHeader + nt->FileHeader.SizeOfOptionalHeader);
    for (WORD i = 0; i < nt->FileHeader.NumberOfSections; ++i) {
        char secname[9] = {0};
        memcpy(secname, sec[i].Name, 8);
        if (_stricmp(secname, name) == 0) {
            *out_base = base + sec[i].VirtualAddress;
            *out_size = (size_t)sec[i].Misc.VirtualSize;
            return 1;
        }
    }
    return 0;
}

// pattern scan within a module section
static void* hook_pattern_scan_section(void* module_base, const char* section, const uint8_t* pattern, const char* mask) {
    void* base = NULL;
    size_t size = 0;
    if (!hook_find_section(module_base, section, &base, &size)) return NULL;
    return hook_pattern_scan_module(base, size, pattern, mask);
}

static void* hook_pattern_scan_module(void* module_base, size_t module_size, const uint8_t* pattern, const char* mask);

// pattern scan with module auto-bounds
// rescan a pattern after module reload
static void* hook_rescan_after_module(const char* module, const uint8_t* pattern, const char* mask, int tries, int sleep_ms) {
    HMODULE h = hook_wait_for_module(module, tries, sleep_ms);
    if (!h) return NULL;
    return hook_pattern_scan_module_auto(module, pattern, mask);
}

// code cave helpers
static void* hook_find_codecave(void* base, size_t size, size_t needed) {
    if (!base || !size || !needed) return NULL;
    uint8_t* p = (uint8_t*)base;
    size_t run = 0;
    for (size_t i = 0; i < size; ++i) {
        if (p[i] == 0xCC || p[i] == 0x90) {
            run++;
            if (run >= needed) return p + i - run + 1;
        } else {
            run = 0;
        }
    }
    return NULL;
}

static void* hook_find_codecave_module(const char* module, size_t needed) {
    void* base = NULL;
    size_t size = 0;
    if (!hook_module_bounds(module, &base, &size)) return NULL;
    return hook_find_codecave(base, size, needed);
}

static int hook_write_codecave(void* cave, const void* data, size_t len) {
    return hook_safe_write(cave, data, len);
}

static void* hook_pattern_scan_module_auto(const char* module, const uint8_t* pattern, const char* mask) {
    void* base = NULL;
    size_t size = 0;
    if (!hook_module_bounds(module, &base, &size)) return NULL;
    return hook_pattern_scan_module(base, size, pattern, mask);
}

static void* hook_pattern_scan_module(void* module_base, size_t module_size, const uint8_t* pattern, const char* mask) {
    if (!module_base || !module_size || !pattern || !mask) return NULL;
    size_t pat_len = 0;
    while (mask[pat_len]) pat_len++;
    if (!pat_len || pat_len > module_size) return NULL;

    uint8_t* base = (uint8_t*)module_base;
    size_t limit = module_size - pat_len;
    for (size_t i = 0; i <= limit; ++i) {
        size_t j = 0;
        for (; j < pat_len; ++j) {
            if (mask[j] == 'x' && base[i + j] != pattern[j]) break;
        }
        if (j == pat_len) return base + i;
    }
    return NULL;
}

// helpers
// ------------------------------------------------------------
// minimal prologue length (stub, user may replace with disasm)
static size_t hook_min_prologue_len(void* addr) {
    (void)addr;
    return 5;
}

// disassembler-based prologue length (optional)
static size_t hook_min_prologue_len_disasm(void* addr, size_t min_len) {
    if (!addr) return 0;
#ifdef HOOK_USE_ZYDIS
    ZydisDecoder dec;
    ZydisDecoderInit(&dec, ZYDIS_MACHINE_MODE_LONG_64, ZYDIS_ADDRESS_WIDTH_64);
    size_t off = 0;
    while (off < min_len) {
        ZydisDecodedInstruction ins;
        if (ZYDIS_SUCCESS != ZydisDecoderDecodeBuffer(&dec, (uint8_t*)addr + off, 32, &ins)) break;
        off += ins.length;
    }
    return off ? off : min_len;
#elif defined(HOOK_USE_CAPSTONE)
    csh handle;
    if (cs_open(CS_ARCH_X86, CS_MODE_64, &handle) != CS_ERR_OK) return min_len;
    cs_option(handle, CS_OPT_DETAIL, CS_OPT_OFF);
    size_t off = 0;
    cs_insn* insn = NULL;
    while (off < min_len) {
        size_t count = cs_disasm(handle, (uint8_t*)addr + off, 32, (uint64_t)addr + off, 1, &insn);
        if (count == 0) break;
        off += insn[0].size;
        cs_free(insn, count);
    }
    cs_close(&handle);
    return off ? off : min_len;
#else
    (void)min_len;
    return 5;
#endif
}

static inline int th_rel32_fit(void* src, void* dst) {
    intptr_t delta = (intptr_t)dst - ((intptr_t)src + 5);
    return (delta >= INT32_MIN && delta <= INT32_MAX);
}

static inline void th_write_rel32(void* src, void* dst) {
    uint8_t* p = (uint8_t*)src;
    intptr_t delta = (intptr_t)dst - ((intptr_t)src + 5);
    p[0] = 0xE9; // jmp rel32
    *(int32_t*)(p + 1) = (int32_t)delta;
}

// th_protect_rw helper
static inline int th_protect_rw(void* addr, size_t size, DWORD* old) {
    return VirtualProtect(addr, size, PAGE_EXECUTE_READWRITE, old) != 0;
}

static inline void th_restore_protect(void* addr, size_t size, DWORD old) {
    DWORD tmp;
    VirtualProtect(addr, size, old, &tmp);
}

static inline void th_flush(void* addr, size_t size) {
    FlushInstructionCache(GetCurrentProcess(), addr, size);
}

static inline void th_write_abs_jmp(uint8_t* buf, void* dst) {
    buf[0] = 0x48; buf[1] = 0xB8;               // mov rax, imm64
    *(uint64_t*)(buf + 2) = (uint64_t)dst;
    buf[10] = 0xFF; buf[11] = 0xE0;             // jmp rax
}

// th_is_nop1 helper
static int th_is_nop1(uint8_t* p) {
    return p[0] == 0x90;
}

// th_is_nop2 helper
static int th_is_nop2(uint8_t* p) {
    return p[0] == 0x66 && p[1] == 0x90;
}

// th_is_nop3 helper
static int th_is_nop3(uint8_t* p) {
    return p[0] == 0x0F && p[1] == 0x1F && p[2] == 0x00;
}

// th_is_nop4 helper
static int th_is_nop4(uint8_t* p) {
    return p[0] == 0x0F && p[1] == 0x1F && p[2] == 0x40 && p[3] == 0x00;
}

// th_is_nop5 helper
static int th_is_nop5(uint8_t* p) {
    return p[0] == 0x0F && p[1] == 0x1F && p[2] == 0x44 && p[3] == 0x00 && p[4] == 0x00;
}

static size_t th_skip_nops(uint8_t* p, size_t max_skip) {
    size_t i = 0;
    while (i < max_skip) {
        if (i + 5 <= max_skip && th_is_nop5(p + i)) { i += 5; continue; }
        if (i + 4 <= max_skip && th_is_nop4(p + i)) { i += 4; continue; }
        if (i + 3 <= max_skip && th_is_nop3(p + i)) { i += 3; continue; }
        if (i + 2 <= max_skip && th_is_nop2(p + i)) { i += 2; continue; }
        if (i + 1 <= max_skip && th_is_nop1(p + i)) { i += 1; continue; }
        break;
    }
    return i;
}

// probe a stub and return next target
static int th_probe_stub(uint8_t* entry, th_stub_kind_t* out_kind, uint8_t** out_target) {
    if (!entry) return 0;
    size_t skip = th_skip_nops(entry, 16);
    uint8_t* p = entry + skip;

    if (p[0] == 0xE9) { // jmp rel32
        int32_t disp = *(int32_t*)(p + 1);
        if (out_kind) *out_kind = (skip ? TH_STUB_NOP_JMP_REL32 : TH_STUB_JMP_REL32);
        if (out_target) *out_target = p + 5 + disp;
        return 1;
    }
    if (p[0] == 0xEB) { // jmp rel8
        int8_t disp = *(int8_t*)(p + 1);
        if (out_kind) *out_kind = TH_STUB_JMP_REL8;
        if (out_target) *out_target = p + 2 + disp;
        return 1;
    }
    if (p[0] == 0xFF && p[1] == 0x25) { // jmp [rip+disp32]
        int32_t disp = *(int32_t*)(p + 2);
        uint8_t* slot = p + 6 + disp;
        void* target = NULL;
        if (!th_safe_read_ptr(slot, &target)) return 0;
        if (out_kind) *out_kind = TH_STUB_JMP_RIP;
        if (out_target) *out_target = (uint8_t*)target;
        return 1;
    }
    if (p[0] == 0x48 && p[1] == 0xB8 && p[10] == 0xFF && p[11] == 0xE0) {
        uint64_t target = *(uint64_t*)(p + 2);
        if (out_kind) *out_kind = TH_STUB_MOV_JMP;
        if (out_target) *out_target = (uint8_t*)target;
        return 1;
    }
    if (out_kind) *out_kind = TH_STUB_UNKNOWN;
    if (out_target) *out_target = entry;
    hook_log("tinyhook", "resolve chain failed");
    return 0;
}

// resolve stub/jump chain to a final target.
// supports: jmp rel32, jmp rel8, nop*; jmp rel32, jmp [rip+disp32], mov rax, imm64; jmp rax
static int th_resolve_stub_target(void* entry, int max_depth, void** out_target) {
    if (!entry || !out_target || max_depth <= 0) return 0;
    uint8_t* cur = (uint8_t*)entry;
    for (int depth = 0; depth < max_depth; ++depth) {
        size_t skip = th_skip_nops(cur, 16);
        uint8_t* p = cur + skip;

        if (p[0] == 0xE9) { // jmp rel32
            int32_t disp = *(int32_t*)(p + 1);
            cur = p + 5 + disp;
            continue;
        }
        if (p[0] == 0xEB) { // jmp rel8
            int8_t disp = *(int8_t*)(p + 1);
            cur = p + 2 + disp;
            continue;
        }
        if (p[0] == 0xFF && p[1] == 0x25) { // jmp [rip+disp32]
            int32_t disp = *(int32_t*)(p + 2);
            uint8_t* slot = p + 6 + disp;
            void* target = NULL;
            if (!th_safe_read_ptr(slot, &target)) return 0;
            cur = (uint8_t*)target;
            continue;
        }
        if (p[0] == 0x48 && p[1] == 0xB8 && p[10] == 0xFF && p[11] == 0xE0) {
            uint64_t target = *(uint64_t*)(p + 2);
            cur = (uint8_t*)target;
            continue;
        }

        hook_log("tinyhook", "resolve chain hit final target");
        *out_target = cur;
        return 1;
    }
    return 0;
}

static void* th_alloc_near(void* target, size_t size) {
    SYSTEM_INFO si;
    GetSystemInfo(&si);

    const uintptr_t gran = (uintptr_t)si.dwAllocationGranularity;
    const uintptr_t min_addr = (uintptr_t)si.lpMinimumApplicationAddress;
    const uintptr_t max_addr = (uintptr_t)si.lpMaximumApplicationAddress;

    uintptr_t start = (uintptr_t)target > (1ULL << 31) ? (uintptr_t)target - (1ULL << 31) : min_addr;
    uintptr_t end   = (uintptr_t)target + (1ULL << 31) < max_addr ? (uintptr_t)target + (1ULL << 31) : max_addr;

    uintptr_t addr = start;
    while (addr < end) {
        MEMORY_BASIC_INFORMATION mbi;
        if (!VirtualQuery((void*)addr, &mbi, sizeof(mbi))) break;

        if (mbi.State == MEM_FREE) {
            uintptr_t aligned = (addr + gran - 1) & ~(gran - 1);
            if (aligned + size < end) {
                void* p = VirtualAlloc((void*)aligned, size, MEM_RESERVE | MEM_COMMIT, PAGE_EXECUTE_READWRITE);
                if (p) return p;
            }
        }
        addr = (uintptr_t)mbi.BaseAddress + mbi.RegionSize;
    }
    return NULL;
}

// check if a pointer is in executable memory
static int th_is_executable_ptr(void* p) {
    if (!p) return 0;
    MEMORY_BASIC_INFORMATION mbi;
    if (!VirtualQuery(p, &mbi, sizeof(mbi))) return 0;
    if (mbi.State != MEM_COMMIT) return 0;
    DWORD prot = mbi.Protect & 0xFF;
    return prot == PAGE_EXECUTE ||
           prot == PAGE_EXECUTE_READ ||
           prot == PAGE_EXECUTE_READWRITE ||
           prot == PAGE_EXECUTE_WRITECOPY;
}

// safe read for a pointer-sized value
static int th_safe_read_ptr(void* addr, void** out) {
    if (!addr || !out) return 0;
    __try {
        *out = *(void**)addr;
        return 1;
    } __except (EXCEPTION_EXECUTE_HANDLER) {
        return 0;
    }
}

typedef struct th_threads_t {
    HANDLE* handles;
    size_t count;
} th_threads_t;

static th_threads_t th_suspend_other_threads(void) {
    th_threads_t out = {0};
    DWORD self_tid = GetCurrentThreadId();
    HANDLE snap = CreateToolhelp32Snapshot(TH32CS_SNAPTHREAD, 0);
    if (snap == INVALID_HANDLE_VALUE) return out;

    THREADENTRY32 te;
    te.dwSize = sizeof(te);
    if (Thread32First(snap, &te)) {
        do {
            if (te.th32OwnerProcessID == GetCurrentProcessId() && te.th32ThreadID != self_tid) {
                HANDLE h = OpenThread(THREAD_SUSPEND_RESUME, FALSE, te.th32ThreadID);
                if (h) {
                    if (SuspendThread(h) != (DWORD)-1) {
                        HANDLE* new_arr = (HANDLE*)HeapReAlloc(GetProcessHeap(), 0, out.handles, (out.count + 1) * sizeof(HANDLE));
                        if (new_arr) {
                            out.handles = new_arr;
                            out.handles[out.count++] = h;
                        } else {
                            ResumeThread(h);
                            CloseHandle(h);
                        }
                    } else {
                        CloseHandle(h);
                    }
                }
            }
        } while (Thread32Next(snap, &te));
    }
    CloseHandle(snap);
    return out;
}

static void th_resume_threads(th_threads_t* t) {
    if (!t || !t->handles) return;
    for (size_t i = 0; i < t->count; ++i) {
        ResumeThread(t->handles[i]);
        CloseHandle(t->handles[i]);
    }
    HeapFree(GetProcessHeap(), 0, t->handles);
    t->handles = NULL;
    t->count = 0;
}

// ------------------------------------------------------------
// api
// ------------------------------------------------------------
static th_status_t tinyhook_create_ex(tinyhook_t* h, void* target, void* detour, uint32_t flags) {
    if (!h || !target || !detour) { hook_log("tinyhook", "invalid args"); return TH_ERR_INVALID_ARGS; }
    if (h->enabled) { hook_log("tinyhook", "already enabled"); return TH_ERR_ALREADY_ENABLED; }

    h->target = target;
    h->detour = detour;
    h->relay = NULL;
    h->trampoline = NULL;
    h->flags = flags;

    // save original 5 bytes
    if ((flags & TH_FLAG_VERIFY_EXEC) && !th_is_executable_ptr(target)) return TH_ERR_NOT_EXEC;

    memcpy(h->original, target, 5);

    // allocate block near target: relay (12) + trampoline (12)
    const size_t relay_size = 12;
    const size_t tramp_size = 12;
    const size_t block_size = relay_size + tramp_size;
    uint8_t* block = (uint8_t*)th_alloc_near(target, block_size);
    if (!block) { hook_log("tinyhook", "alloc near failed"); return TH_ERR_ALLOC_NEAR; }

    uint8_t* relay = block;
    uint8_t* tramp = block + relay_size;

    // build relay: absolute jump to detour
    th_write_abs_jmp(relay, detour);

    // build trampoline:
    // - resolve wrapper chain if requested (il2cpp-style stubs).
    // - otherwise, handle jmp rel32 or nop; jmp rel32 directly.
    // - otherwise, optionally build a raw 5-byte copy + jump back (unsafe).
    uint8_t* t = (uint8_t*)target;
    if (flags & TH_FLAG_RESOLVE_CHAIN) {
        void* resolved = NULL;
        if (th_resolve_stub_target(t, 8, &resolved)) {
            hook_log("tinyhook", "chain resolved for trampoline");
            th_write_abs_jmp(tramp, resolved);
        } else {
            if ((flags & TH_FLAG_VERIFY_STUB) && !(flags & TH_FLAG_ALLOW_RAW_TRAMP)) {
                VirtualFree(block, 0, MEM_RELEASE);
                h->relay = NULL;
                h->trampoline = NULL;
                hook_log("tinyhook", "stub unsupported"); return TH_ERR_STUB_UNSUPPORTED;
            }
            hook_log("tinyhook", "using raw trampoline");
            memcpy(tramp, t, 5);
            th_write_abs_jmp(tramp + 5, t + 5);
        }
    } else if (t[0] == 0xE9) {
        int32_t disp = *(int32_t*)(t + 1);
        uint8_t* jmp_target = t + 5 + disp;
        th_write_abs_jmp(tramp, jmp_target);
    } else if (t[0] == 0x90 && t[1] == 0xE9) {
        int32_t disp = *(int32_t*)(t + 2);
        uint8_t* jmp_target = t + 6 + disp;
        th_write_abs_jmp(tramp, jmp_target);
    } else {
        if ((flags & TH_FLAG_VERIFY_STUB) && !(flags & TH_FLAG_ALLOW_RAW_TRAMP)) {
            VirtualFree(block, 0, MEM_RELEASE);
            h->relay = NULL;
            h->trampoline = NULL;
            hook_log("tinyhook", "stub unsupported"); return TH_ERR_STUB_UNSUPPORTED;
        }
        // unsafe raw trampoline: copy 5 bytes and jump back to +5
        memcpy(tramp, t, 5);
        th_write_abs_jmp(tramp + 5, t + 5);
    }

    h->relay = relay;
    h->trampoline = tramp;

    hook_log("tinyhook", "relay/trampoline built");

    if (!th_rel32_fit(target, relay)) {
        VirtualFree(block, 0, MEM_RELEASE);
        h->relay = NULL;
        h->trampoline = NULL;
        hook_log("tinyhook", "rel32 not reachable"); return TH_ERR_REACHABILITY;
    }
    return TH_OK;
}

// default flags for typical il2cpp/aot stubs
static uint32_t tinyhook_default_flags(void) {
    return TH_FLAG_VERIFY_STUB | TH_FLAG_RESOLVE_CHAIN | TH_FLAG_VERIFY_EXEC;
}

// status to string
static const char* tinyhook_status_str(th_status_t st) {
    switch (st) {
        case TH_OK: return "ok";
        case TH_ERR_INVALID_ARGS: return "invalid_args";
        case TH_ERR_ALREADY_ENABLED: return "already_enabled";
        case TH_ERR_ALLOC_NEAR: return "alloc_near_failed";
        case TH_ERR_REACHABILITY: return "rel32_not_reachable";
        case TH_ERR_PROTECT: return "protect_failed";
        case TH_ERR_STUB_UNSUPPORTED: return "stub_unsupported";
        case TH_ERR_NOT_EXEC: return "not_executable";
        default: return "unknown";
    }
}

// tinyhook_is_enabled helper
static int tinyhook_is_enabled(tinyhook_t* h) {
    return h && h->enabled;
}

// tinyhook_is_installed helper
static int tinyhook_is_installed(tinyhook_t* h) {
    if (!h || !h->target || !h->relay) return 0;
    uint8_t* p = (uint8_t*)h->target;
    if (p[0] != 0xE9) return 0;
    int32_t disp = *(int32_t*)(p + 1);
    return (p + 5 + disp) == (uint8_t*)h->relay;
}

static th_status_t tinyhook_create(tinyhook_t* h, void* target, void* detour) {
    return tinyhook_create_ex(h, target, detour, TH_FLAG_VERIFY_STUB | TH_FLAG_RESOLVE_CHAIN);
}

// safe create with exec verification
// resolve chain with explicit depth
static int tinyhook_resolve_chain_ex(void* entry, int max_depth, void** out_target) {
    return th_resolve_stub_target(entry, max_depth, out_target);
}

static th_status_t tinyhook_create_safe(tinyhook_t* h, void* target, void* detour) {
    return tinyhook_create_ex(h, target, detour, TH_FLAG_VERIFY_STUB | TH_FLAG_RESOLVE_CHAIN | TH_FLAG_VERIFY_EXEC);
}

static th_status_t tinyhook_enable(tinyhook_t* h) {
    if (!h || !h->target || !h->relay) { hook_log("tinyhook", "enable invalid args"); return TH_ERR_INVALID_ARGS; }
    if (h->enabled) return TH_OK;

    th_threads_t threads = {0};
    if (h->flags & TH_FLAG_SUSPEND_THREADS) {
        hook_log("tinyhook", "suspending threads");
        threads = th_suspend_other_threads();
    }

    DWORD old;
    if (!th_protect_rw(h->target, 5, &old)) {
        hook_log("tinyhook", "protect failed on disable");
        hook_log("tinyhook", "protect failed on enable");
        if (threads.handles) { hook_log("tinyhook", "resuming threads"); th_resume_threads(&threads); }
        return TH_ERR_PROTECT;
    }

    th_write_rel32(h->target, h->relay);

    th_restore_protect(h->target, 5, old);
    th_flush(h->target, 5);

    if (threads.handles) { hook_log("tinyhook", "resuming threads"); th_resume_threads(&threads); }

    h->enabled = 1;
    return TH_OK;
}

static th_status_t tinyhook_disable(tinyhook_t* h) {
    if (!h || !h->target) { hook_log("tinyhook", "disable invalid args"); return TH_ERR_INVALID_ARGS; }
    if (!h->enabled) return TH_OK;

    th_threads_t threads = {0};
    if (h->flags & TH_FLAG_SUSPEND_THREADS) {
        hook_log("tinyhook", "suspending threads");
        threads = th_suspend_other_threads();
    }

    DWORD old;
    if (!th_protect_rw(h->target, 5, &old)) {
        hook_log("tinyhook", "protect failed on disable");
        hook_log("tinyhook", "protect failed on enable");
        if (threads.handles) { hook_log("tinyhook", "resuming threads"); th_resume_threads(&threads); }
        return TH_ERR_PROTECT;
    }

    memcpy(h->target, h->original, 5);

    th_restore_protect(h->target, 5, old);
    th_flush(h->target, 5);

    if (threads.handles) { hook_log("tinyhook", "resuming threads"); th_resume_threads(&threads); }

    h->enabled = 0;
    return TH_OK;
}

static void tinyhook_destroy(tinyhook_t* h) {
    if (!h) return;
    if (h->enabled) tinyhook_disable(h);
    if (h->relay) VirtualFree(h->relay, 0, MEM_RELEASE);
    h->relay = NULL;
    h->trampoline = NULL;
    h->target = NULL;
    h->detour = NULL;
}

#ifndef TH_REGISTRY_MAX
#define TH_REGISTRY_MAX 128
#endif

typedef struct tinyhook_registry_t {
    tinyhook_t* hooks[TH_REGISTRY_MAX];
    size_t count;
    SRWLOCK lock;
} tinyhook_registry_t;

static tinyhook_registry_t* tinyhook_registry_instance(void) {
    static tinyhook_registry_t reg;
    static int inited = 0;
    if (!inited) {
        InitializeSRWLock(&reg.lock);
        reg.count = 0;
        inited = 1;
    }
    return &reg;
}

// tinyhook_registry_add helper
static int tinyhook_registry_add(tinyhook_t* h) {
    if (!h) return 0;
    tinyhook_registry_t* r = tinyhook_registry_instance();
    AcquireSRWLockExclusive(&r->lock);
    if (r->count >= TH_REGISTRY_MAX) {
        ReleaseSRWLockExclusive(&r->lock);
        return 0;
    }
    r->hooks[r->count++] = h;
    ReleaseSRWLockExclusive(&r->lock);
    hook_log("tinyhook", "registry add");
    return 1;
}

// tinyhook_registry_remove helper
static int tinyhook_registry_remove(tinyhook_t* h) {
    if (!h) return 0;
    tinyhook_registry_t* r = tinyhook_registry_instance();
    AcquireSRWLockExclusive(&r->lock);
    for (size_t i = 0; i < r->count; ++i) {
        if (r->hooks[i] == h) {
            r->hooks[i] = r->hooks[r->count - 1];
            r->hooks[r->count - 1] = NULL;
            r->count--;
            ReleaseSRWLockExclusive(&r->lock);
            hook_log("tinyhook", "registry remove");
            return 1;
        }
    }
    ReleaseSRWLockExclusive(&r->lock);
    return 0;
}

// enable hooks by priority (low to high)
static void tinyhook_registry_enable_all_priority(void) {
    tinyhook_registry_t* r = tinyhook_registry_instance();
    AcquireSRWLockShared(&r->lock);
    // simple selection sort by priority
    for (size_t i = 0; i < r->count; ++i) {
        size_t best = i;
        for (size_t j = i + 1; j < r->count; ++j) {
            if (r->hooks[j]->priority < r->hooks[best]->priority) best = j;
        }
        tinyhook_enable(r->hooks[best]);
    }
    ReleaseSRWLockShared(&r->lock);
}

static void tinyhook_registry_enable_all(void) {
    tinyhook_registry_t* r = tinyhook_registry_instance();
    AcquireSRWLockShared(&r->lock);
    for (size_t i = 0; i < r->count; ++i) {
        tinyhook_enable(r->hooks[i]);
    }
    ReleaseSRWLockShared(&r->lock);
}

static void tinyhook_registry_disable_all(void) {
    tinyhook_registry_t* r = tinyhook_registry_instance();
    AcquireSRWLockShared(&r->lock);
    for (size_t i = 0; i < r->count; ++i) {
        tinyhook_disable(r->hooks[i]);
    }
    ReleaseSRWLockShared(&r->lock);
}

static void tinyhook_registry_destroy_all(void) {
    tinyhook_registry_t* r = tinyhook_registry_instance();
    AcquireSRWLockShared(&r->lock);
    for (size_t i = 0; i < r->count; ++i) {
        tinyhook_destroy(r->hooks[i]);
    }
    ReleaseSRWLockShared(&r->lock);
}

// auto hook: create + enable + optional registry add
static th_status_t tinyhook_auto(tinyhook_t* h, void* target, void* detour, uint32_t flags, int add_to_registry) {
    if (!h) return TH_ERR_INVALID_ARGS;
    th_status_t st = tinyhook_create_ex(h, target, detour, flags);
    if (st != TH_OK) return st;
    st = tinyhook_enable(h);
    if (st != TH_OK) return st;
    if (add_to_registry) tinyhook_registry_add(h);
    return TH_OK;
}

// auto hook with optional chain resolve:
// - if hook_final is nonzero, resolve stub chain and hook the final target
// - otherwise, hook the entry stub
static th_status_t tinyhook_auto_chain(tinyhook_t* h, void* target, void* detour, uint32_t flags, int hook_final, int add_to_registry) {
    if (!h || !target || !detour) { hook_log("tinyhook", "invalid args"); return TH_ERR_INVALID_ARGS; }
    void* hook_target = target;
    if (hook_final) {
        void* resolved = NULL;
        if (!th_resolve_stub_target(target, 8, &resolved)) hook_log("tinyhook", "stub unsupported"); return TH_ERR_STUB_UNSUPPORTED;
        hook_target = resolved;
    }
    return tinyhook_auto(h, hook_target, detour, flags, add_to_registry);
}

// auto unhook: disable + destroy + optional registry remove
// simple one-shot hook that returns original trampoline
static void* tinyhook_simple(void* target, void* detour, uint32_t flags) {
    static tinyhook_t h;
    static int used = 0;
    if (used) return NULL;
    used = 1;
    if (tinyhook_auto(&h, target, detour, flags, 0) != TH_OK) return NULL;
    return h.trampoline;
}

// batch create+enable for an array of hooks; returns count enabled
static size_t tinyhook_batch(tinyhook_t* hooks, void** targets, void** detours, size_t count, uint32_t flags, int add_to_registry) {
    size_t ok = 0;
    for (size_t i = 0; i < count; ++i) {
        if (!hooks || !targets || !detours) break;
        if (tinyhook_auto(&hooks[i], targets[i], detours[i], flags, add_to_registry) == TH_OK) {
            ok++;
        }
    }
    return ok;
}

// hot-reload tinyhook (detour change)
static int tinyhook_hot_reload(tinyhook_t* h, void* new_detour, uint32_t flags) {
    if (!h || !h->target || !new_detour) return 0;
    tinyhook_disable(h);
    tinyhook_destroy(h);
    return tinyhook_auto(h, h->target, new_detour, flags, 0) == TH_OK;
}

static void tinyhook_auto_unhook(tinyhook_t* h, int remove_from_registry) {
    if (!h) return;
    if (remove_from_registry) tinyhook_registry_remove(h);
    tinyhook_destroy(h);
}

#ifdef __cplusplus
}
#endif

// vmt_hook.h - minimal vmt hook helper for windows x64
// - safe swap/restore of vtable entries
// - optional rtti guard (best-effort, msvc)
// - works for c or c++
// credits: discord: chefendpoint | telegram: elf_nigel

#include <windows.h>
#include <stdint.h>
#include <stddef.h>
#include <stdarg.h>
#include <stdio.h>
#include <psapi.h>

#ifdef __cplusplus
extern "C" {
#endif

typedef struct vmt_hook_t {
    void*** obj;      // pointer to object pointer (this)
    void**  vtable;   // original vtable
    size_t  index;    // method index
    void*   original; // original function pointer
    void*   detour;   // replacement function pointer
    int     enabled;
    int     priority;
} vmt_hook_t;

typedef struct vmt_shadow_t {
    void*** obj;      // pointer to object pointer (this)
    void**  original; // original vtable
    void**  shadow;   // cloned vtable
    size_t  count;    // entries cloned
    int     enabled;
} vmt_shadow_t;

typedef struct vmt_threads_t {
    HANDLE* handles;
    size_t count;
} vmt_threads_t;

typedef struct vmt_registry_t {
    vmt_hook_t* hooks[128];
    size_t count;
    SRWLOCK lock;
} vmt_registry_t;

// forward declarations (vmt)
static int vmt_is_executable_ptr(void* p);
static int vmt_shadow_hook(vmt_shadow_t* s, size_t index, void* detour, void** out_original);
static int vmt_shadow_enable_ex(vmt_shadow_t* s, int suspend_threads);
static int vmt_hook_create(vmt_hook_t* h, void* obj, size_t index, void* detour);
static int vmt_hook_enable_ex(vmt_hook_t* h, int suspend_threads);
static int vmt_hook_enable(vmt_hook_t* h);
static int vmt_hook_disable(vmt_hook_t* h);
static void vmt_hook_destroy(vmt_hook_t* h);
static int vmt_registry_add(vmt_hook_t* h);

// suspend other threads in the current process
static vmt_threads_t vmt_suspend_other_threads(void) {
    vmt_threads_t out = {0};
    DWORD self_tid = GetCurrentThreadId();
    HANDLE snap = CreateToolhelp32Snapshot(TH32CS_SNAPTHREAD, 0);
    if (snap == INVALID_HANDLE_VALUE) return out;

    THREADENTRY32 te;
    te.dwSize = sizeof(te);
    if (Thread32First(snap, &te)) {
        do {
            if (te.th32OwnerProcessID == GetCurrentProcessId() && te.th32ThreadID != self_tid) {
                HANDLE h = OpenThread(THREAD_SUSPEND_RESUME, FALSE, te.th32ThreadID);
                if (h) {
                    if (SuspendThread(h) != (DWORD)-1) {
                        HANDLE* new_arr = (HANDLE*)HeapReAlloc(GetProcessHeap(), 0, out.handles, (out.count + 1) * sizeof(HANDLE));
                        if (new_arr) {
                            out.handles = new_arr;
                            out.handles[out.count++] = h;
                        } else {
                            ResumeThread(h);
                            CloseHandle(h);
                        }
                    } else {
                        CloseHandle(h);
                    }
                }
            }
        } while (Thread32Next(snap, &te));
    }
    CloseHandle(snap);
    return out;
}

// resume previously suspended threads
static void vmt_resume_threads(vmt_threads_t* t) {
    if (!t || !t->handles) return;
    for (size_t i = 0; i < t->count; ++i) {
        ResumeThread(t->handles[i]);
        CloseHandle(t->handles[i]);
    }
    HeapFree(GetProcessHeap(), 0, t->handles);
    t->handles = NULL;
    t->count = 0;
}

// best-effort rtti guard (msvc abi). returns 1 if seems plausible.
static int vmt_rtti_guard(void** vtable) {
    if (!vtable) return 0;
    void* col = vtable[-1]; // complete object locator
    if (!col) return 0;
    __try {
        volatile uint32_t sig = *(uint32_t*)col;
        (void)sig;
    } __except (EXCEPTION_EXECUTE_HANDLER) {
        return 0;
    }
    return 1;
}

// safe read for a pointer-sized value
static int vmt_safe_read_ptr(void* addr, void** out) {
    if (!addr || !out) return 0;
    __try {
        *out = *(void**)addr;
        return 1;
    } __except (EXCEPTION_EXECUTE_HANDLER) {
        return 0;
    }
}

// basic vtable plausibility check
static int vmt_is_vtable_ptr(void** vt) {
    if (!vt) return 0;
    if (!vmt_is_executable_ptr(vt[0])) return 0;
    return vmt_rtti_guard(vt);
}

// get vtable pointer from object
static void** vmt_get_vtable(void* obj) {
    if (!obj) return NULL;
    return *(void***)obj;
}

// get method pointer by index
static void* vmt_get_method(void* obj, size_t index) {
    void** vt = vmt_get_vtable(obj);
    if (!vt) return NULL;
    return vt[index];
}

// validate object and vtable pointer
static int vmt_validate_object(void* obj) {
    void** vt = vmt_get_vtable(obj);
    if (!vt) return 0;
    return vmt_is_vtable_ptr(vt);
}

// simple masked pattern scan inside a module
// mask uses 'x' for match and '?' for wildcard
static void* vmt_pattern_scan_module(void* module_base, size_t module_size, const uint8_t* pattern, const char* mask) {
    if (!module_base || !module_size || !pattern || !mask) return NULL;
    size_t pat_len = 0;
    while (mask[pat_len]) pat_len++;
    if (!pat_len || pat_len > module_size) return NULL;

    uint8_t* base = (uint8_t*)module_base;
    size_t limit = module_size - pat_len;
    for (size_t i = 0; i <= limit; ++i) {
        size_t j = 0;
        for (; j < pat_len; ++j) {
            if (mask[j] == 'x' && base[i + j] != pattern[j]) break;
        }
        if (j == pat_len) return base + i;
    }
    return NULL;
}

// try to get module bounds for a code pointer.
static int vmt_get_module_bounds_from_ptr(void* p, void** out_base, size_t* out_size) {
    if (!p || !out_base || !out_size) return 0;
    HMODULE mod = NULL;
    if (!GetModuleHandleExA(GET_MODULE_HANDLE_EX_FLAG_FROM_ADDRESS | GET_MODULE_HANDLE_EX_FLAG_UNCHANGED_REFCOUNT,
                            (LPCSTR)p, &mod)) {
        return 0;
    }
    MODULEINFO mi;
    if (!GetModuleInformation(GetCurrentProcess(), mod, &mi, sizeof(mi))) return 0;
    *out_base = mi.lpBaseOfDll;
    *out_size = (size_t)mi.SizeOfImage;
    return 1;
}

// find index of a function pointer in a vtable.
// max_scan is a safety cap; pass 0 to use default (256).
static size_t vmt_find_index_by_ptr(void* obj, void* fn, size_t max_scan) {
    if (!obj || !fn) return (size_t)-1;
    void** vt = *(void***)obj;
    if (!vt) return (size_t)-1;

    size_t cap = max_scan ? max_scan : 256;
    for (size_t i = 0; i < cap; ++i) {
        if (vt[i] == fn) return i;
    }
    return (size_t)-1;
}

// find index of a method by comparing a known function pointer from another instance.
// useful if you can capture the original pointer from a clean object.
static size_t vmt_find_index_by_ptr_ref(void* obj, void* ref_obj, size_t max_scan) {
    if (!obj || !ref_obj) return (size_t)-1;
    void** vt = *(void***)obj;
    void** vt_ref = *(void***)ref_obj;
    if (!vt || !vt_ref) return (size_t)-1;

    size_t cap = max_scan ? max_scan : 256;
    for (size_t i = 0; i < cap; ++i) {
        if (vt[i] && vt[i] == vt_ref[i]) return i;
    }
    return (size_t)-1;
}

// find index of the first method pointer within a module range.
// you can pass module bounds from vmt_get_module_bounds_from_ptr.
static size_t vmt_find_index_in_module(void* obj, void* module_base, size_t module_size, size_t max_scan) {
    if (!obj || !module_base || !module_size) return (size_t)-1;
    void** vt = *(void***)obj;
    if (!vt) return (size_t)-1;

    uintptr_t base = (uintptr_t)module_base;
    uintptr_t end = base + module_size;
    size_t cap = max_scan ? max_scan : 256;
    for (size_t i = 0; i < cap; ++i) {
        uintptr_t fp = (uintptr_t)vt[i];
        if (fp >= base && fp < end) return i;
    }
    return (size_t)-1;
}

// check if a pointer is in executable memory.
static int vmt_is_executable_ptr(void* p) {
    if (!p) return 0;
    MEMORY_BASIC_INFORMATION mbi;
    if (!VirtualQuery(p, &mbi, sizeof(mbi))) return 0;
    if (mbi.State != MEM_COMMIT) return 0;
    DWORD prot = mbi.Protect & 0xFF;
    return prot == PAGE_EXECUTE ||
           prot == PAGE_EXECUTE_READ ||
           prot == PAGE_EXECUTE_READWRITE ||
           prot == PAGE_EXECUTE_WRITECOPY;
}

// check if a pointer falls inside a module.
static int vmt_ptr_in_module(void* p, void* module_base, size_t module_size) {
    if (!p || !module_base || !module_size) return 0;
    uintptr_t addr = (uintptr_t)p;
    uintptr_t base = (uintptr_t)module_base;
    return addr >= base && addr < (base + module_size);
}

// scan vtable until a non-executable pointer is found.
// returns max entries scanned; use as a safe cap for other searches.
static size_t vmt_scan_exec_bound(void* obj, size_t max_limit) {
    if (!obj) return 0;
    void** vt = *(void***)obj;
    if (!vt) return 0;

    size_t cap = max_limit ? max_limit : 512;
    size_t i = 0;
    for (; i < cap; ++i) {
        if (!vmt_is_executable_ptr(vt[i])) break;
    }
    return i;
}

// scan vtable until read fails or non-exec encountered
static size_t vmt_scan_safe_bound(void* obj, size_t max_limit) {
    if (!obj) return 0;
    void** vt = *(void***)obj;
    if (!vt) return 0;

    size_t cap = max_limit ? max_limit : 512;
    size_t i = 0;
    for (; i < cap; ++i) {
        void* fp = NULL;
        if (!vmt_safe_read_ptr(&vt[i], &fp)) break;
        if (!vmt_is_executable_ptr(fp)) break;
    }
    return i;
}

// scan vtable until entry leaves the module or becomes non-executable.
// if module bounds can't be resolved, falls back to exec-only scan.
static size_t vmt_scan_module_exec_bound(void* obj, size_t max_limit) {
    if (!obj) return 0;
    void** vt = *(void***)obj;
    if (!vt) return 0;

    void* base = NULL;
    size_t size = 0;
    if (!vmt_get_module_bounds_from_ptr(vt[0], &base, &size)) {
        return vmt_scan_exec_bound(obj, max_limit);
    }

    size_t cap = max_limit ? max_limit : 512;
    size_t i = 0;
    for (; i < cap; ++i) {
        if (!vmt_is_executable_ptr(vt[i])) break;
        if (!vmt_ptr_in_module(vt[i], base, size)) break;
    }
    return i;
}

// clone vtable into a shadow table.
// count: number of entries to copy (use vmt_scan_exec_bound for a safe guess)
static int vmt_shadow_create(vmt_shadow_t* s, void* obj, size_t count) {
    if (!s || !obj || !count) return 0;
    s->obj = (void***)obj;
    s->original = *(void***)obj;
    s->count = count;
    s->enabled = 0;
    if (!s->original) return 0;

    s->shadow = (void**)HeapAlloc(GetProcessHeap(), 0, count * sizeof(void*));
    if (!s->shadow) return 0;
    memcpy(s->shadow, s->original, count * sizeof(void*));
    return 1;
}

// clone vtable with an automatic count based on module+exec scan.
static int vmt_shadow_create_auto(vmt_shadow_t* s, void* obj, size_t max_limit) {
    size_t count = vmt_scan_module_exec_bound(obj, max_limit ? max_limit : 512);
    if (!count) return 0;
    return vmt_shadow_create(s, obj, count);
}

// auto shadow hook: create, patch, enable
static int vmt_shadow_auto(vmt_shadow_t* s, void* obj, size_t max_limit,
                           size_t index, void* detour, void** out_original, int suspend_threads) {
    if (!vmt_shadow_create_auto(s, obj, max_limit)) return 0;
    if (!vmt_shadow_hook(s, index, detour, out_original)) return 0;
    return vmt_shadow_enable_ex(s, suspend_threads);
}

// create a hook by searching for a function pointer in the vtable
static int vmt_hook_create_by_ptr(vmt_hook_t* h, void* obj, void* fn, size_t max_scan, void* detour) {
    if (!h || !obj || !fn || !detour) return 0;
    size_t idx = vmt_find_index_by_ptr(obj, fn, max_scan);
    if (idx == (size_t)-1) return 0;
    return vmt_hook_create(h, obj, idx, detour);
}

// create a hook by matching a reference object's vtable
static int vmt_hook_create_by_ref(vmt_hook_t* h, void* obj, void* ref_obj, size_t max_scan, size_t ref_index, void* detour) {
    if (!h || !obj || !ref_obj || !detour) return 0;
    void** vt_ref = *(void***)ref_obj;
    if (!vt_ref) return 0;
    void* fn = vt_ref[ref_index];
    return vmt_hook_create_by_ptr(h, obj, fn, max_scan, detour);
}

// create hook after validating object and index
static int vmt_hook_create_checked(vmt_hook_t* h, void* obj, size_t index, void* detour) {
    if (!vmt_validate_object(obj)) return 0;
    return vmt_hook_create(h, obj, index, detour);
}

// guarded enable with optional thread suspension
static int vmt_hook_enable_guarded_ex(vmt_hook_t* h, void* expected_original, int suspend_threads) {
    if (!h || !h->vtable) { hook_log("vmt", "hook invalid args"); return 0; }
    if (h->enabled) return 1;
    if (h->vtable[h->index] != expected_original) return 0;
    return vmt_hook_enable_ex(h, suspend_threads);
}

// auto hook with optional thread suspension
// simple vmt hook; returns original function pointer
static void* vmt_hook_simple(void* obj, size_t index, void* detour, int suspend_threads) {
    static vmt_hook_t h;
    static int used = 0;
    if (used) return NULL;
    used = 1;
    if (!vmt_hook_create(&h, obj, index, detour)) return NULL;
    if (!vmt_hook_enable_ex(&h, suspend_threads)) return NULL;
    return h.original;
}

// batch hook by indices; returns count enabled
static size_t vmt_hook_batch(void* obj, const size_t* indices, void** detours, void** out_originals, size_t count, int suspend_threads) {
    if (!obj || !indices || !detours) return 0;
    size_t ok = 0;
    for (size_t i = 0; i < count; ++i) {
        vmt_hook_t* h = (vmt_hook_t*)HeapAlloc(GetProcessHeap(), HEAP_ZERO_MEMORY, sizeof(vmt_hook_t));
        if (!h) break;
        if (!vmt_hook_create(h, obj, indices[i], detours[i])) {
            HeapFree(GetProcessHeap(), 0, h);
            continue;
        }
        if (!vmt_hook_enable_ex(h, suspend_threads)) {
            HeapFree(GetProcessHeap(), 0, h);
            continue;
        }
        if (out_originals) out_originals[i] = h->original;
        vmt_registry_add(h);
        ok++;
    }
    return ok;
}

// vmt_hook_auto_ex helper
// verify vmt entry still matches expected pointer
static int vmt_verify_entry(vmt_hook_t* h, void* expected) {
    if (!h || !h->vtable) return 0;
    return h->vtable[h->index] == expected;
}

// forward decl for hot reload
static int vmt_hook_disable_ex(vmt_hook_t* h, int suspend_threads);

// hot-reload vmt hook (detour change)
static int vmt_hook_hot_reload(vmt_hook_t* h, void* new_detour, int suspend_threads) {
    if (!h || !h->obj || !new_detour) return 0;
    vmt_hook_disable_ex(h, suspend_threads);
    h->detour = new_detour;
    return vmt_hook_enable_ex(h, suspend_threads);
}

static int vmt_hook_auto_ex(vmt_hook_t* h, void* obj, void* fn, size_t max_scan, void* detour, int add_to_registry, int suspend_threads) {
    if (!vmt_hook_create_by_ptr(h, obj, fn, max_scan, detour)) return 0;
    if (!vmt_hook_enable_guarded_ex(h, h->original, suspend_threads)) return 0;
    if (add_to_registry) vmt_registry_add(h);
    return 1;
}

// enable hook only if current vtable entry matches expected pointer
static int vmt_hook_enable_guarded(vmt_hook_t* h, void* expected_original) {
    if (!h || !h->vtable) { hook_log("vmt", "hook invalid args"); return 0; }
    if (h->enabled) return 1;
    if (h->vtable[h->index] != expected_original) return 0;
    return vmt_hook_enable(h);
}

// auto hook by function pointer with guard and registry add
static int vmt_hook_auto(vmt_hook_t* h, void* obj, void* fn, size_t max_scan, void* detour, int add_to_registry) {
    if (!vmt_hook_create_by_ptr(h, obj, fn, max_scan, detour)) return 0;
    if (!vmt_hook_enable_guarded(h, h->original)) return 0;
    if (add_to_registry) vmt_registry_add(h);
    return 1;
}

// auto hook by reference object and index
static int vmt_hook_auto_ref(vmt_hook_t* h, void* obj, void* ref_obj, size_t ref_index, size_t max_scan, void* detour, int add_to_registry) {
    if (!vmt_hook_create_by_ref(h, obj, ref_obj, max_scan, ref_index, detour)) return 0;
    if (!vmt_hook_enable_guarded(h, h->original)) return 0;
    if (add_to_registry) vmt_registry_add(h);
    return 1;
}

// find a vtable index by a pattern scan on a module; expects the vtable to point into the module
static size_t vmt_find_index_by_pattern(void* obj, void* module_base, size_t module_size,
                                        const uint8_t* pattern, const char* mask, size_t max_scan) {
    void* match = vmt_pattern_scan_module(module_base, module_size, pattern, mask);
    if (!match) return (size_t)-1;
    return vmt_find_index_by_ptr(obj, match, max_scan);
}

// patch a shadow vtable entry.
static int vmt_shadow_hook(vmt_shadow_t* s, size_t index, void* detour, void** out_original) {
    if (!s || !s->shadow || !detour || index >= s->count) return 0;
    if (out_original) *out_original = s->shadow[index];
    s->shadow[index] = detour;
    return 1;
}

// swap object's vtable to shadow.
// swap object's vtable to shadow with optional thread suspension
static int vmt_shadow_enable_ex(vmt_shadow_t* s, int suspend_threads) {
    if (!s || !s->obj || !s->shadow) { hook_log("vmt", "shadow invalid args"); return 0; }
    if (s->enabled) return 1;

    vmt_threads_t threads = {0};
    if (suspend_threads) { hook_log("vmt", "suspending threads"); threads = vmt_suspend_other_threads(); }

    DWORD old;
    if (!VirtualProtect(s->obj, sizeof(void*), PAGE_READWRITE, &old)) {
        if (threads.handles) { hook_log("vmt", "resuming threads"); vmt_resume_threads(&threads); }
        return 0;
    }
    *s->obj = s->shadow;
    VirtualProtect(s->obj, sizeof(void*), old, &old);
    FlushInstructionCache(GetCurrentProcess(), s->obj, sizeof(void*));
    if (threads.handles) { hook_log("vmt", "resuming threads"); vmt_resume_threads(&threads); }
    s->enabled = 1;
    hook_log("vmt", "shadow enabled");
    return 1;
}

// restore object's original vtable with optional thread suspension
static int vmt_shadow_disable_ex(vmt_shadow_t* s, int suspend_threads) {
    if (!s || !s->obj || !s->original) { hook_log("vmt", "shadow invalid args"); return 0; }
    if (!s->enabled) return 1;

    vmt_threads_t threads = {0};
    if (suspend_threads) { hook_log("vmt", "suspending threads"); threads = vmt_suspend_other_threads(); }

    DWORD old;
    if (!VirtualProtect(s->obj, sizeof(void*), PAGE_READWRITE, &old)) {
        if (threads.handles) { hook_log("vmt", "resuming threads"); vmt_resume_threads(&threads); }
        return 0;
    }
    *s->obj = s->original;
    VirtualProtect(s->obj, sizeof(void*), old, &old);
    FlushInstructionCache(GetCurrentProcess(), s->obj, sizeof(void*));
    if (threads.handles) { hook_log("vmt", "resuming threads"); vmt_resume_threads(&threads); }
    s->enabled = 0;
    hook_log("vmt", "shadow disabled");
    return 1;
}

// vmt_shadow_enable helper
static int vmt_shadow_enable(vmt_shadow_t* s) {
    if (!s || !s->obj || !s->shadow) { hook_log("vmt", "shadow invalid args"); return 0; }
    if (s->enabled) return 1;

    DWORD old;
    if (!VirtualProtect(s->obj, sizeof(void*), PAGE_READWRITE, &old)) {
        return 0;
    }
    *s->obj = s->shadow;
    VirtualProtect(s->obj, sizeof(void*), old, &old);
    FlushInstructionCache(GetCurrentProcess(), s->obj, sizeof(void*));
    s->enabled = 1;
    hook_log("vmt", "shadow enabled");
    return 1;
}

// restore object's original vtable.
static int vmt_shadow_disable(vmt_shadow_t* s) {
    if (!s || !s->obj || !s->original) { hook_log("vmt", "shadow invalid args"); return 0; }
    if (!s->enabled) return 1;

    DWORD old;
    if (!VirtualProtect(s->obj, sizeof(void*), PAGE_READWRITE, &old)) {
        return 0;
    }
    *s->obj = s->original;
    VirtualProtect(s->obj, sizeof(void*), old, &old);
    FlushInstructionCache(GetCurrentProcess(), s->obj, sizeof(void*));
    s->enabled = 0;
    hook_log("vmt", "shadow disabled");
    return 1;
}

static void vmt_shadow_destroy(vmt_shadow_t* s) {
    if (!s) return;
    if (s->enabled) vmt_shadow_disable(s);
    if (s->shadow) HeapFree(GetProcessHeap(), 0, s->shadow);
    s->shadow = NULL;
    s->original = NULL;
    s->obj = NULL;
    s->count = 0;
    s->enabled = 0;
}

static vmt_registry_t* vmt_registry_instance(void) {
    static vmt_registry_t reg;
    static int inited = 0;
    if (!inited) {
        InitializeSRWLock(&reg.lock);
        reg.count = 0;
        inited = 1;
    }
    return &reg;
}

// vmt_registry_add helper
static int vmt_registry_add(vmt_hook_t* h) {
    if (!h) return 0;
    vmt_registry_t* r = vmt_registry_instance();
    AcquireSRWLockExclusive(&r->lock);
    if (r->count >= 128) {
        ReleaseSRWLockExclusive(&r->lock);
        return 0;
    }
    r->hooks[r->count++] = h;
    ReleaseSRWLockExclusive(&r->lock);
    hook_log("tinyhook", "registry add");
    return 1;
}

// vmt_registry_remove helper
static int vmt_registry_remove(vmt_hook_t* h) {
    if (!h) return 0;
    vmt_registry_t* r = vmt_registry_instance();
    AcquireSRWLockExclusive(&r->lock);
    for (size_t i = 0; i < r->count; ++i) {
        if (r->hooks[i] == h) {
            r->hooks[i] = r->hooks[r->count - 1];
            r->hooks[r->count - 1] = NULL;
            r->count--;
            ReleaseSRWLockExclusive(&r->lock);
            return 1;
        }
    }
    ReleaseSRWLockExclusive(&r->lock);
    return 0;
}

// enable vmt hooks by priority (low to high)
static void vmt_registry_enable_all_priority(void) {
    vmt_registry_t* r = vmt_registry_instance();
    AcquireSRWLockShared(&r->lock);
    for (size_t i = 0; i < r->count; ++i) {
        size_t best = i;
        for (size_t j = i + 1; j < r->count; ++j) {
            if (r->hooks[j]->priority < r->hooks[best]->priority) best = j;
        }
        vmt_hook_enable(r->hooks[best]);
    }
    ReleaseSRWLockShared(&r->lock);
}

static void vmt_registry_enable_all(void) {
    vmt_registry_t* r = vmt_registry_instance();
    AcquireSRWLockShared(&r->lock);
    for (size_t i = 0; i < r->count; ++i) vmt_hook_enable(r->hooks[i]);
    ReleaseSRWLockShared(&r->lock);
}

static void vmt_registry_disable_all(void) {
    vmt_registry_t* r = vmt_registry_instance();
    AcquireSRWLockShared(&r->lock);
    for (size_t i = 0; i < r->count; ++i) vmt_hook_disable(r->hooks[i]);
    ReleaseSRWLockShared(&r->lock);
}

// hook watchdog (periodic reapply)
static HANDLE g_hook_watchdog = NULL;
static volatile LONG g_hook_watchdog_run = 0;

static DWORD WINAPI hook_watchdog_thread(LPVOID param) {
    (void)param;
    while (InterlockedCompareExchange(&g_hook_watchdog_run, 1, 1)) {
        tinyhook_registry_t* r = tinyhook_registry_instance();
        AcquireSRWLockShared(&r->lock);
        for (size_t i = 0; i < r->count; ++i) {
            tinyhook_reapply_if_needed(r->hooks[i]);
        }
        ReleaseSRWLockShared(&r->lock);
        Sleep(1000);
    }
    return 0;
}

static int hook_watchdog_start(void) {
    if (g_hook_watchdog) return 1;
    InterlockedExchange(&g_hook_watchdog_run, 1);
    g_hook_watchdog = CreateThread(NULL, 0, hook_watchdog_thread, NULL, 0, NULL);
    return g_hook_watchdog != NULL;
}

static void hook_watchdog_stop(void) {
    if (!g_hook_watchdog) return;
    InterlockedExchange(&g_hook_watchdog_run, 0);
    WaitForSingleObject(g_hook_watchdog, 2000);
    CloseHandle(g_hook_watchdog);
    g_hook_watchdog = NULL;
}

// hook manager (central control)
// hook metadata
typedef struct hook_meta_t {
    const char* name;
    const char* category;
    int priority;
    int cooldown_ms;
    uint64_t last_tick;
} hook_meta_t;

static uint64_t hook_get_tick_ms(void) {
    return GetTickCount64();
}

static int hook_meta_can_run(hook_meta_t* m) {
    if (!m) return 1;
    if (m->cooldown_ms <= 0) return 1;
    uint64_t now = hook_get_tick_ms();
    if (now - m->last_tick < (uint64_t)m->cooldown_ms) return 0;
    m->last_tick = now;
    return 1;
}

typedef struct hook_manager_t {
    int watchdog_enabled;
    int suspend_threads;
    int priority_enable;
} hook_manager_t;

// bind metadata to hooks (optional)
static void hook_manager_bind_meta_tiny(tinyhook_t* h, hook_meta_t* meta) {
    if (!h || !meta) return;
    h->priority = meta->priority;
}

static void hook_manager_bind_meta_vmt(vmt_hook_t* h, hook_meta_t* meta) {
    if (!h || !meta) return;
    h->priority = meta->priority;
}

static void hook_manager_init(hook_manager_t* m) {
    if (!m) return;
    m->watchdog_enabled = 0;
    m->suspend_threads = 0;
    m->priority_enable = 0;
}

static void hook_manager_enable_all(hook_manager_t* m) {
    if (!m) return;
    if (m->priority_enable) {
        tinyhook_registry_enable_all_priority();
        vmt_registry_enable_all_priority();
    } else {
        tinyhook_registry_enable_all();
        vmt_registry_enable_all();
    }
    if (m->watchdog_enabled) hook_watchdog_start();
}

static void hook_manager_disable_all(hook_manager_t* m) {
    (void)m;
    hook_watchdog_stop();
    tinyhook_registry_disable_all();
    vmt_registry_disable_all();
}

static void hook_manager_destroy_all(hook_manager_t* m) {
    (void)m;
    hook_watchdog_stop();
    tinyhook_registry_destroy_all();
    vmt_registry_destroy_all();
}

static void hook_on_dll_detach(void) {
    tinyhook_registry_disable_all();
    vmt_registry_disable_all();
}

static void vmt_registry_destroy_all(void) {
    vmt_registry_t* r = vmt_registry_instance();
    AcquireSRWLockShared(&r->lock);
    for (size_t i = 0; i < r->count; ++i) vmt_hook_destroy(r->hooks[i]);
    ReleaseSRWLockShared(&r->lock);
}

#ifdef VMT_DXGI_HELPERS
#ifdef __cplusplus
} // extern "c"
#endif
#include <dxgi.h>
#include <d3d11.h>
#ifdef __cplusplus
extern "C" {
#endif

typedef struct vmt_dxgi_dummy_t {
    HWND hwnd;
    IDXGISwapChain* swapchain;
    ID3D11Device* device;
    ID3D11DeviceContext* context;
} vmt_dxgi_dummy_t;

static LRESULT CALLBACK vmt_dxgi_dummy_wndproc(HWND h, UINT m, WPARAM w, LPARAM l) {
    return DefWindowProcA(h, m, w, l);
}

// vmt_dxgi_create_dummy_swapchain helper
// create a dummy dxgi swapchain for a hwnd and return it
static IDXGISwapChain* hook_dxgi_find_swapchain(HWND hwnd) {
    if (!hwnd) return NULL;
    DXGI_SWAP_CHAIN_DESC sd;
    ZeroMemory(&sd, sizeof(sd));
    sd.BufferCount = 2;
    sd.BufferDesc.Format = DXGI_FORMAT_R8G8B8A8_UNORM;
    sd.BufferUsage = DXGI_USAGE_RENDER_TARGET_OUTPUT;
    sd.OutputWindow = hwnd;
    sd.SampleDesc.Count = 1;
    sd.Windowed = TRUE;
    sd.SwapEffect = DXGI_SWAP_EFFECT_DISCARD;

    ID3D11Device* dev = NULL;
    ID3D11DeviceContext* ctx = NULL;
    IDXGISwapChain* sc = NULL;
    D3D_FEATURE_LEVEL fl;
    HRESULT hr = D3D11CreateDeviceAndSwapChain(NULL, D3D_DRIVER_TYPE_HARDWARE, NULL, 0,
        NULL, 0, D3D11_SDK_VERSION, &sd, &sc, &dev, &fl, &ctx);
    if (FAILED(hr)) return NULL;
    if (ctx) ctx->Release();
    if (dev) dev->Release();
    return sc;
}

static int vmt_dxgi_create_dummy_swapchain(vmt_dxgi_dummy_t* out) {
    if (!out) return 0;
    ZeroMemory(out, sizeof(*out));

    WNDCLASSEXA wc;
    ZeroMemory(&wc, sizeof(wc));
    wc.cbSize = sizeof(wc);
    wc.lpfnWndProc = vmt_dxgi_dummy_wndproc;
    wc.hInstance = GetModuleHandleA(NULL);
    wc.lpszClassName = "VMT_DXGI_DUMMY";
    RegisterClassExA(&wc);

    HWND hwnd = CreateWindowExA(0, wc.lpszClassName, "VMT_DXGI_DUMMY",
                                WS_OVERLAPPEDWINDOW, 0, 0, 100, 100,
                                NULL, NULL, wc.hInstance, NULL);
    if (!hwnd) { hook_log("dxgi", "create window failed"); return 0; }

    DXGI_SWAP_CHAIN_DESC sd;
    ZeroMemory(&sd, sizeof(sd));
    sd.BufferCount = 2;
    sd.BufferDesc.Format = DXGI_FORMAT_R8G8B8A8_UNORM;
    sd.BufferUsage = DXGI_USAGE_RENDER_TARGET_OUTPUT;
    sd.OutputWindow = hwnd;
    sd.SampleDesc.Count = 1;
    sd.Windowed = TRUE;
    sd.SwapEffect = DXGI_SWAP_EFFECT_DISCARD;

    D3D_FEATURE_LEVEL fl;
    ID3D11Device* dev = NULL;
    ID3D11DeviceContext* ctx = NULL;
    IDXGISwapChain* sc = NULL;
    HRESULT hr = D3D11CreateDeviceAndSwapChain(
        NULL, D3D_DRIVER_TYPE_HARDWARE, NULL, 0,
        NULL, 0, D3D11_SDK_VERSION, &sd, &sc, &dev, &fl, &ctx);

    if (FAILED(hr) || !sc) {
        hook_log("dxgi", "create swapchain failed");
        DestroyWindow(hwnd);
        return 0;
    }

    out->hwnd = hwnd;
    out->swapchain = sc;
    out->device = dev;
    out->context = ctx;
    return 1;
}

static void vmt_dxgi_release_dummy_swapchain(vmt_dxgi_dummy_t* d) {
    if (!d) return;
    if (d->swapchain) d->swapchain->Release();
    if (d->context) d->context->Release();
    if (d->device) d->device->Release();
    if (d->hwnd) DestroyWindow(d->hwnd);
    ZeroMemory(d, sizeof(*d));
}

// validate typical idxgiswapchain indices.
// returns 1 if present and resizebuffers appear executable and within vtable bound.
static int vmt_dxgi_validate_swapchain_indices(IDXGISwapChain* sc, size_t* out_present, size_t* out_resize) {
    if (!sc) return 0;
    size_t bound = vmt_scan_exec_bound(sc, 512);
    size_t present = 8;
    size_t resize = 13;
    if (present >= bound || resize >= bound) return 0;
    void** vt = *(void***)sc;
    if (!vmt_is_executable_ptr(vt[present]) || !vmt_is_executable_ptr(vt[resize])) return 0;
    if (out_present) *out_present = present;
    if (out_resize) *out_resize = resize;
    return 1;
}

// one-shot helper to fetch present/resizebuffers indices using a dummy swapchain.
static int vmt_dxgi_get_swapchain_indices(size_t* out_present, size_t* out_resize) {
    vmt_dxgi_dummy_t d;
    if (!vmt_dxgi_create_dummy_swapchain(&d)) return 0;
    int ok = vmt_dxgi_validate_swapchain_indices(d.swapchain, out_present, out_resize);
    vmt_dxgi_release_dummy_swapchain(&d);
    return ok;
}

// resolve present/resize indices for a real swapchain by matching to a dummy vtable.
static int vmt_dxgi_resolve_indices_for_swapchain(IDXGISwapChain* sc, size_t* out_present, size_t* out_resize) {
    if (!sc) return 0;
    vmt_dxgi_dummy_t d;
    if (!vmt_dxgi_create_dummy_swapchain(&d)) return 0;

    void** vt_dummy = *(void***)d.swapchain;
    void* present_ptr = vt_dummy[8];
    void* resize_ptr = vt_dummy[13];

    size_t bound = vmt_scan_exec_bound(sc, 512);
    size_t present = vmt_find_index_by_ptr(sc, present_ptr, bound);
    size_t resize = vmt_find_index_by_ptr(sc, resize_ptr, bound);

    vmt_dxgi_release_dummy_swapchain(&d);

    if (present == (size_t)-1 || resize == (size_t)-1) {
        return 0;
    }
    if (out_present) *out_present = present;
    if (out_resize) *out_resize = resize;
    return 1;
}

// auto hook present/resize for a real swapchain (direct vmt patch)
static int vmt_dxgi_hook_swapchain(IDXGISwapChain* sc,
                                   vmt_hook_t* out_present_hook, void* present_detour, void** out_present_orig,
                                   vmt_hook_t* out_resize_hook, void* resize_detour, void** out_resize_orig,
                                   int add_to_registry) {
    if (!sc) return 0;
    size_t present = 0, resize = 0;
    if (!vmt_dxgi_resolve_indices_for_swapchain(sc, &present, &resize)) return 0;

    int ok = 1;
    if (out_present_hook && present_detour) {
        if (!vmt_hook_create(out_present_hook, sc, present, present_detour)) ok = 0;
        else if (!vmt_hook_enable_guarded(out_present_hook, out_present_hook->original)) ok = 0;
        if (out_present_orig) *out_present_orig = out_present_hook->original;
        if (add_to_registry && ok) vmt_registry_add(out_present_hook);
    }
    if (out_resize_hook && resize_detour) {
        if (!vmt_hook_create(out_resize_hook, sc, resize, resize_detour)) ok = 0;
        else if (!vmt_hook_enable_guarded(out_resize_hook, out_resize_hook->original)) ok = 0;
        if (out_resize_orig) *out_resize_orig = out_resize_hook->original;
        if (add_to_registry && ok) vmt_registry_add(out_resize_hook);
    }
    return ok;
}

// auto hook present/resize for a real swapchain using a shadow vmt
static int vmt_dxgi_hook_swapchain_shadow(IDXGISwapChain* sc,
                                          vmt_shadow_t* shadow,
                                          void* present_detour, void** out_present_orig,
                                          void* resize_detour, void** out_resize_orig) {
    if (!sc || !shadow) return 0;
    size_t present = 0, resize = 0;
    if (!vmt_dxgi_resolve_indices_for_swapchain(sc, &present, &resize)) return 0;
    if (!vmt_shadow_create_auto(shadow, sc, 512)) { hook_log("vmt", "shadow create failed"); return 0; }
    if (present_detour) vmt_shadow_hook(shadow, present, present_detour, out_present_orig);
    if (resize_detour) vmt_shadow_hook(shadow, resize, resize_detour, out_resize_orig);
    return vmt_shadow_enable(shadow);
}


#endif

#ifdef VMT_DX12_HELPERS
#ifdef __cplusplus
} // extern "c"
#endif
#include <d3d12.h>
#include <dxgi1_4.h>
#ifdef __cplusplus
extern "C" {
#endif

typedef struct vmt_dx12_dummy_t {
    HWND hwnd;
    IDXGISwapChain3* swapchain;
    ID3D12Device* device;
    ID3D12CommandQueue* queue;
} vmt_dx12_dummy_t;

// vmt_dx12_create_dummy_swapchain helper
static int vmt_dx12_create_dummy_swapchain(vmt_dx12_dummy_t* out) {
    if (!out) return 0;
    ZeroMemory(out, sizeof(*out));

    WNDCLASSEXA wc;
    ZeroMemory(&wc, sizeof(wc));
    wc.cbSize = sizeof(wc);
    wc.lpfnWndProc = DefWindowProcA;
    wc.hInstance = GetModuleHandleA(NULL);
    wc.lpszClassName = "VMT_DX12_DUMMY";
    RegisterClassExA(&wc);

    HWND hwnd = CreateWindowExA(0, wc.lpszClassName, "VMT_DX12_DUMMY",
                                WS_OVERLAPPEDWINDOW, 0, 0, 100, 100,
                                NULL, NULL, wc.hInstance, NULL);
    if (!hwnd) { hook_log("dxgi", "create window failed"); return 0; }

    IDXGIFactory4* factory = NULL;
    if (FAILED(CreateDXGIFactory1(IID_PPV_ARGS(&factory)))) {
        hook_log("dx12", "create factory failed");
        DestroyWindow(hwnd);
        return 0;
    }

    ID3D12Device* dev = NULL;
    if (FAILED(D3D12CreateDevice(NULL, D3D_FEATURE_LEVEL_11_0, IID_PPV_ARGS(&dev)))) {
        hook_log("dx12", "create device failed");
        factory->Release();
        DestroyWindow(hwnd);
        return 0;
    }

    D3D12_COMMAND_QUEUE_DESC qd;
    ZeroMemory(&qd, sizeof(qd));
    qd.Type = D3D12_COMMAND_LIST_TYPE_DIRECT;
    ID3D12CommandQueue* queue = NULL;
    if (FAILED(dev->CreateCommandQueue(&qd, IID_PPV_ARGS(&queue)))) {
        hook_log("dx12", "create queue failed");
        dev->Release();
        factory->Release();
        DestroyWindow(hwnd);
        return 0;
    }

    DXGI_SWAP_CHAIN_DESC1 sd;
    ZeroMemory(&sd, sizeof(sd));
    sd.BufferCount = 2;
    sd.Format = DXGI_FORMAT_R8G8B8A8_UNORM;
    sd.BufferUsage = DXGI_USAGE_RENDER_TARGET_OUTPUT;
    sd.SwapEffect = DXGI_SWAP_EFFECT_FLIP_DISCARD;
    sd.SampleDesc.Count = 1;

    IDXGISwapChain1* sc1 = NULL;
    HRESULT hr = factory->CreateSwapChainForHwnd(queue, hwnd, &sd, NULL, NULL, &sc1);
    if (FAILED(hr) || !sc1) {
        queue->Release();
        dev->Release();
        factory->Release();
        DestroyWindow(hwnd);
        return 0;
    }

    IDXGISwapChain3* sc3 = NULL;
    sc1->QueryInterface(IID_PPV_ARGS(&sc3));
    sc1->Release();
    factory->Release();
    if (!sc3) {
        queue->Release();
        dev->Release();
        DestroyWindow(hwnd);
        return 0;
    }

    out->hwnd = hwnd;
    out->swapchain = sc3;
    out->device = dev;
    out->queue = queue;
    return 1;
}

static void vmt_dx12_release_dummy_swapchain(vmt_dx12_dummy_t* d) {
    if (!d) return;
    if (d->swapchain) d->swapchain->Release();
    if (d->queue) d->queue->Release();
    if (d->device) d->device->Release();
    if (d->hwnd) DestroyWindow(d->hwnd);
    ZeroMemory(d, sizeof(*d));
}

// validate typical swapchain indices for dx12 (present=8, resizebuffers=13)
static int vmt_dx12_validate_swapchain_indices(IDXGISwapChain3* sc, size_t* out_present, size_t* out_resize) {
    if (!sc) return 0;
    size_t bound = vmt_scan_exec_bound(sc, 512);
    size_t present = 8;
    size_t resize = 13;
    if (present >= bound || resize >= bound) return 0;
    void** vt = *(void***)sc;
    if (!vmt_is_executable_ptr(vt[present]) || !vmt_is_executable_ptr(vt[resize])) return 0;
    if (out_present) *out_present = present;
    if (out_resize) *out_resize = resize;
    return 1;
}

// vmt_dx12_get_swapchain_indices helper
static int vmt_dx12_get_swapchain_indices(size_t* out_present, size_t* out_resize) {
    vmt_dx12_dummy_t d;
    if (!vmt_dx12_create_dummy_swapchain(&d)) return 0;
    int ok = vmt_dx12_validate_swapchain_indices(d.swapchain, out_present, out_resize);
    vmt_dx12_release_dummy_swapchain(&d);
    return ok;
}

// resolve present/resize indices for a real swapchain by matching to a dummy vtable.
static int vmt_dx12_resolve_indices_for_swapchain(IDXGISwapChain3* sc, size_t* out_present, size_t* out_resize) {
    if (!sc) return 0;
    vmt_dx12_dummy_t d;
    if (!vmt_dx12_create_dummy_swapchain(&d)) return 0;

    void** vt_dummy = *(void***)d.swapchain;
    void* present_ptr = vt_dummy[8];
    void* resize_ptr = vt_dummy[13];

    size_t bound = vmt_scan_exec_bound(sc, 512);
    size_t present = vmt_find_index_by_ptr(sc, present_ptr, bound);
    size_t resize = vmt_find_index_by_ptr(sc, resize_ptr, bound);

    vmt_dx12_release_dummy_swapchain(&d);

    if (present == (size_t)-1 || resize == (size_t)-1) {
        return 0;
    }
    if (out_present) *out_present = present;
    if (out_resize) *out_resize = resize;
    return 1;
}

// auto hook present/resize for a real dx12 swapchain (direct vmt patch)
static int vmt_dx12_hook_swapchain(IDXGISwapChain3* sc,
                                   vmt_hook_t* out_present_hook, void* present_detour, void** out_present_orig,
                                   vmt_hook_t* out_resize_hook, void* resize_detour, void** out_resize_orig,
                                   int add_to_registry) {
    if (!sc) return 0;
    size_t present = 0, resize = 0;
    if (!vmt_dx12_resolve_indices_for_swapchain(sc, &present, &resize)) return 0;

    int ok = 1;
    if (out_present_hook && present_detour) {
        if (!vmt_hook_create(out_present_hook, sc, present, present_detour)) ok = 0;
        else if (!vmt_hook_enable_guarded(out_present_hook, out_present_hook->original)) ok = 0;
        if (out_present_orig) *out_present_orig = out_present_hook->original;
        if (add_to_registry && ok) vmt_registry_add(out_present_hook);
    }
    if (out_resize_hook && resize_detour) {
        if (!vmt_hook_create(out_resize_hook, sc, resize, resize_detour)) ok = 0;
        else if (!vmt_hook_enable_guarded(out_resize_hook, out_resize_hook->original)) ok = 0;
        if (out_resize_orig) *out_resize_orig = out_resize_hook->original;
        if (add_to_registry && ok) vmt_registry_add(out_resize_hook);
    }
    return ok;
}

// auto hook present/resize for a real dx12 swapchain using a shadow vmt
static int vmt_dx12_hook_swapchain_shadow(IDXGISwapChain3* sc,
                                          vmt_shadow_t* shadow,
                                          void* present_detour, void** out_present_orig,
                                          void* resize_detour, void** out_resize_orig) {
    if (!sc || !shadow) return 0;
    size_t present = 0, resize = 0;
    if (!vmt_dx12_resolve_indices_for_swapchain(sc, &present, &resize)) return 0;
    if (!vmt_shadow_create_auto(shadow, sc, 512)) { hook_log("vmt", "shadow create failed"); return 0; }
    if (present_detour) vmt_shadow_hook(shadow, present, present_detour, out_present_orig);
    if (resize_detour) vmt_shadow_hook(shadow, resize, resize_detour, out_resize_orig);
    return vmt_shadow_enable(shadow);
}
#endif

// vmt_hook_create helper
static int vmt_hook_create(vmt_hook_t* h, void* obj, size_t index, void* detour) {
    if (!h || !obj || !detour) { hook_log("vmt", "create invalid args"); return 0; }
    h->obj = (void***)obj;
    h->vtable = *(void***)obj;
    h->index = index;
    h->detour = detour;
    h->original = h->vtable[index];
    h->enabled = 0;
    hook_log("vmt", "hook created");
    return 1;
}

// enable hook with optional thread suspension
static int vmt_hook_enable_ex(vmt_hook_t* h, int suspend_threads) {
    if (!h || !h->vtable) { hook_log("vmt", "hook invalid args"); return 0; }
    if (h->enabled) return 1;

    vmt_threads_t threads = {0};
    if (suspend_threads) { hook_log("vmt", "suspending threads"); threads = vmt_suspend_other_threads(); }

    DWORD old;
    if (!VirtualProtect(&h->vtable[h->index], sizeof(void*), PAGE_EXECUTE_READWRITE, &old)) {
        hook_log("vmt", "protect failed");
        if (threads.handles) { hook_log("vmt", "resuming threads"); vmt_resume_threads(&threads); }
        return 0;
    }
    h->vtable[h->index] = h->detour;
    VirtualProtect(&h->vtable[h->index], sizeof(void*), old, &old);
    FlushInstructionCache(GetCurrentProcess(), &h->vtable[h->index], sizeof(void*));
    if (threads.handles) { hook_log("vmt", "resuming threads"); vmt_resume_threads(&threads); }
    h->enabled = 1;
    hook_log("vmt", "hook enabled");
    return 1;
}

// disable hook with optional thread suspension
static int vmt_hook_disable_ex(vmt_hook_t* h, int suspend_threads) {
    if (!h || !h->vtable) { hook_log("vmt", "hook invalid args"); return 0; }
    if (!h->enabled) return 1;

    vmt_threads_t threads = {0};
    if (suspend_threads) { hook_log("vmt", "suspending threads"); threads = vmt_suspend_other_threads(); }

    DWORD old;
    if (!VirtualProtect(&h->vtable[h->index], sizeof(void*), PAGE_EXECUTE_READWRITE, &old)) {
        hook_log("vmt", "protect failed");
        if (threads.handles) { hook_log("vmt", "resuming threads"); vmt_resume_threads(&threads); }
        return 0;
    }
    h->vtable[h->index] = h->original;
    VirtualProtect(&h->vtable[h->index], sizeof(void*), old, &old);
    FlushInstructionCache(GetCurrentProcess(), &h->vtable[h->index], sizeof(void*));
    if (threads.handles) { hook_log("vmt", "resuming threads"); vmt_resume_threads(&threads); }
    h->enabled = 0;
    hook_log("vmt", "hook disabled");
    return 1;
}

// vmt_hook_enable helper
static int vmt_hook_enable(vmt_hook_t* h) {
    if (!h || !h->vtable) { hook_log("vmt", "hook invalid args"); return 0; }
    if (h->enabled) return 1;

    DWORD old;
    if (!VirtualProtect(&h->vtable[h->index], sizeof(void*), PAGE_EXECUTE_READWRITE, &old)) {
        hook_log("vmt", "protect failed");
        return 0;
    }
    h->vtable[h->index] = h->detour;
    VirtualProtect(&h->vtable[h->index], sizeof(void*), old, &old);
    FlushInstructionCache(GetCurrentProcess(), &h->vtable[h->index], sizeof(void*));
    h->enabled = 1;
    hook_log("vmt", "hook enabled");
    return 1;
}

// vmt_hook_disable helper
static int vmt_hook_disable(vmt_hook_t* h) {
    if (!h || !h->vtable) { hook_log("vmt", "hook invalid args"); return 0; }
    if (!h->enabled) return 1;

    DWORD old;
    if (!VirtualProtect(&h->vtable[h->index], sizeof(void*), PAGE_EXECUTE_READWRITE, &old)) {
        hook_log("vmt", "protect failed");
        return 0;
    }
    h->vtable[h->index] = h->original;
    VirtualProtect(&h->vtable[h->index], sizeof(void*), old, &old);
    FlushInstructionCache(GetCurrentProcess(), &h->vtable[h->index], sizeof(void*));
    h->enabled = 0;
    hook_log("vmt", "hook disabled");
    return 1;
}

static void vmt_hook_destroy(vmt_hook_t* h) {
    if (!h) return;
    if (h->enabled) vmt_hook_disable(h);
    h->obj = NULL;
    h->vtable = NULL;
    h->index = 0;
    h->original = NULL;
    h->detour = NULL;
}

#ifdef __cplusplus
}
#endif


// hook_all_example
// this is a minimal example; remove in production
#ifdef HOOK_ALL_EXAMPLE

typedef int(__fastcall* fn_example)(int);
static fn_example g_example_orig = NULL;

static int __fastcall hk_example(int x) {
    return g_example_orig ? g_example_orig(x) : x;
}

static void hook_all_example(void) {
    void* target = (void*)0x12345678;
    tinyhook_t hk = {0};
    if (tinyhook_auto_chain(&hk, target, (void*)&hk_example, tinyhook_default_flags(), 0, 0) == TH_OK) {
        g_example_orig = (fn_example)hk.trampoline;
    }
}

#endif
