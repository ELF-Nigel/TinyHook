# TinyHook Examples

These examples are additive templates for integrating `TinyHook.h` into your own project.
They are intentionally minimal and are not wired into CI linking steps.

## Files
- `minimal_detour.cpp` - basic tinyhook create/enable/disable flow
- `vmt_basic.cpp` - basic VMT hook flow (no graphics API dependencies)
- `iat_patch.c` - IAT patch helper usage in C

## Notes
- Replace placeholder function addresses with real targets discovered at runtime.
- Use `TH_FLAG_VERIFY_STUB | TH_FLAG_RESOLVE_CHAIN | TH_FLAG_VERIFY_EXEC` for safer detours.
- For runtime patching in active processes, add `TH_FLAG_SUSPEND_THREADS`.
