# Unreal Engine Signatures Reference

## Overview

These are known AOB (Array of Bytes) signatures for locating Unreal Engine 4 and Unreal Engine 5 global pointers in a running game process. They are designed to be used with the `signature_resolve` MCP tool, which combines AOB scanning with RIP-relative operand resolution in a single step.

The three critical globals are:
- **GNames (FNamePool)** -- the global name table that maps name indices to strings
- **GObjects (FUObjectArray)** -- the global object array containing all UObject instances
- **GWorld** -- pointer to the current UWorld instance

## How to Use

1. Use `module_list` to identify the game's main executable module name.
2. Call `signature_resolve` with the AOB pattern and the module set to the game exe. The tool performs the AOB scan and RIP-relative address resolution in one step, returning the resolved global pointer address.
3. Verify the resolved address by reading memory at it and checking for expected data structures.
4. Feed the resolved addresses into `ue_dump_names`, `ue_dump_objects`, or `ue_dump_sdk` for full SDK generation.

Example call:
```
signature_resolve(
    pid=<pid>,
    pattern="48 8D 05 ?? ?? ?? ?? EB 27",
    module="GameExecutable.exe"
)
```

The default parameters (`op_offset=3`, `op_length=4`, `instruction_length=7`, `rip_relative=true`) work for standard `lea reg, [rip+disp32]` and `mov reg, [rip+disp32]` instructions.

---

## UE5 Signatures

### GNames (FNamePool)

| Pattern | Instruction | Notes |
|---|---|---|
| `48 8D 05 ?? ?? ?? ?? EB 27` | `lea rax, [rip+FNamePool]` | Common in FName::GetDisplayNameEntry |
| `48 8D 0D ?? ?? ?? ?? E8 ?? ?? ?? ?? C6 05` | `lea rcx, [rip+GNameBlocksDebug]` | Alternative entry point |
| `4C 8D 05 ?? ?? ?? ?? EB 24` | `lea r8, [rip+FNamePool]` | Variant using r8 register |

Default parameters work: `op_offset=3`, `op_length=4`, `instruction_length=7`.

### GObjects (FUObjectArray)

| Pattern | Instruction | Notes |
|---|---|---|
| `48 8B 05 ?? ?? ?? ?? 48 8B 0C C8 48 8D 04 D1` | `mov rax,[rip+GUObjectArray]; mov rcx,[rax+rcx*8]; lea rax,[rcx+rdx*8]` | Object array traversal sequence |
| `48 8D 0D ?? ?? ?? ?? E8 ?? ?? ?? ?? 48 8B D6 48 8D 0D` | `lea rcx,[rip+GUObjectArray]` | Before function call |
| `89 0D ?? ?? ?? ?? 48 8B DF` | `mov [rip+ObjObjects.NumElements], ecx` | NumElements field; use `op_offset=2`, `instruction_length=6` |

### GWorld

| Pattern | Instruction | Notes |
|---|---|---|
| `48 8B 05 ?? ?? ?? ?? 48 3B C8 75` | `mov rax,[rip+GWorld]; cmp rcx,rax` | Comparison against GWorld |
| `48 8D 0D ?? ?? ?? ?? E8 ?? ?? ?? ?? 48 8B 4B` | `lea rcx,[rip+GWorld]` | Before function call |
| `48 89 05 ?? ?? ?? ?? 48 85 C0 75` | `mov [rip+GWorld], rax` | GWorld assignment |

---

## UE4 Signatures

### GNames

| Pattern | Instruction | Notes |
|---|---|---|
| `48 8D 05 ?? ?? ?? ?? EB 27` | `lea rax, [rip+GNames]` | Same pattern as UE5 |
| `48 8D 35 ?? ?? ?? ?? EB 27` | `lea rsi, [rip+GNames]` | Variant using rsi register |
| `E8 ?? ?? ?? ?? 48 8D 0D ?? ?? ?? ?? 48 89 44 24` | Call then `lea rcx,[rip+GNames]` | GNames is second operand; extract the `48 8D 0D` sub-pattern separately |

For the combined pattern where GNames is the second operand, isolate and scan for just the `48 8D 0D` lea instruction rather than trying to adjust offsets across the call.

### GObjects

| Pattern | Instruction | Notes |
|---|---|---|
| `48 8B 05 ?? ?? ?? ?? 48 8B 0C C8 48 8D 04 D1` | `mov rax,[rip+GUObjectArray]; mov rcx,[rax+rcx*8]; lea rax,[rcx+rdx*8]` | Same as UE5 |
| `48 8D 0D ?? ?? ?? ?? C6 05 ?? ?? ?? ?? 01 E8` | `lea rcx,[rip+GUObjectArray]` | Before flag set and call |

### GWorld

| Pattern | Instruction | Notes |
|---|---|---|
| `48 8B 1D ?? ?? ?? ?? 48 85 DB 74` | `mov rbx,[rip+GWorld]` | GWorld load into rbx with null check |
| `48 89 05 ?? ?? ?? ?? 48 85 C0 75` | `mov [rip+GWorld], rax` | GWorld assignment (same as UE5) |

---

## ProcessEvent

These are **function signatures**, not RIP-relative pointer references. Use `aob_scan` directly instead of `signature_resolve`.

| Pattern | Engine | Notes |
|---|---|---|
| `40 55 56 57 41 54 41 55 41 56 41 57 48 81 EC ?? ?? ?? ?? 48 8D 6C 24` | UE4 | ProcessEvent function prologue |
| `40 55 56 57 41 54 41 55 41 56 41 57 48 8D AC 24` | UE5 | ProcessEvent function prologue |

The address returned by `aob_scan` is the function entry point itself.

---

## Tips

- These signatures may vary between game builds, engine versions, and compiler optimizations. They are starting points, not guarantees.
- Always verify the resolved address by reading memory at it and checking for expected structure:
  - **GNames**: the resolved address should point to FNamePool. Read the first few name entries and confirm they contain readable ASCII strings (e.g., "None", "ByteProperty", "IntProperty").
  - **GObjects**: the resolved address should point to FUObjectArray. The first pointer in the array should be non-null and point to a valid UObject.
  - **GWorld**: should contain a pointer to the current UWorld instance. Dereference it and check that the object's name index resolves to something sensible via GNames.
- If a signature does not match, try dumping the `.text` section bytes around known function calls with `module_dump` and craft a new signature from the surrounding context.
- Use `module_list` to find the game's main executable name before scanning.
- Some games ship with multiple executables or use a shipping client binary with a different name than the development build. Confirm the correct module.
- Stripped/obfuscated builds (e.g., EAC, BattlEye protected) may inline or shuffle code enough to break these patterns. In that case, search for string cross-references (e.g., scan for the UTF-8 string `"None"` and trace back to the name pool).

---

## Parameter Reference for signature_resolve

| Parameter | Default | Description |
|---|---|---|
| `pattern` | *required* | AOB pattern with `??` wildcards for unknown bytes |
| `module` | *recommended* | Module name to restrict the scan (e.g., the game exe) |
| `op_offset` | `3` | Byte offset from pattern start to the displacement operand |
| `op_length` | `4` | Size of the displacement in bytes (always 4 for x64 RIP-relative) |
| `rip_relative` | `true` | Whether to apply RIP-relative address resolution |
| `instruction_length` | `op_offset + op_length` | Full instruction length used for RIP calculation (rip = match_addr + instruction_length) |

For a standard 3-byte opcode + 4-byte displacement instruction (e.g., `48 8B 05 xx xx xx xx`), the defaults are correct. Adjust `op_offset` and `instruction_length` when the displacement appears at a different position in the pattern.
