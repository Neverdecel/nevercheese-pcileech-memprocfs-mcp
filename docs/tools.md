# Tool Reference

Complete reference for all 28 MCP tools.

---

## Core Memory

### memory_read

Read memory from a physical or virtual address.

| Parameter | Type | Required | Description |
|---|---|---|---|
| `address` | string | yes | Hex address (e.g. `"0x1000"`) |
| `length` | integer | yes | Bytes to read (1 - 1048576) |
| `pid` | integer | no | Process ID for virtual address mode |
| `process_name` | string | no | Process name for virtual address mode |

`pid` and `process_name` are mutually exclusive. If neither is set, the address is treated as physical.

**Returns:** hex data, byte count, timestamp.

---

### memory_write

Write data to a physical or virtual address.

| Parameter | Type | Required | Description |
|---|---|---|---|
| `address` | string | yes | Hex address |
| `data` | string | yes | Hex string to write (e.g. `"90909090"`) |
| `pid` | integer | no | Process ID for virtual address mode |
| `process_name` | string | no | Process name for virtual address mode |

**Returns:** bytes written, confirmation.

---

### memory_format

Read memory and display in multiple formatted views.

| Parameter | Type | Required | Description |
|---|---|---|---|
| `address` | string | yes | Hex address |
| `length` | integer | yes | Bytes to read (1 - 4096) |
| `formats` | array | no | Subset of `["hexdump", "ascii", "bytes", "dwords", "raw"]` (default: all) |
| `pid` | integer | no | Process ID |
| `process_name` | string | no | Process name |

**Returns:** formatted output with selected views.

---

## System

### system_info

Get target system and device information.

| Parameter | Type | Required | Description |
|---|---|---|---|
| `verbose` | boolean | no | Include FPGA hardware details (default: false) |

**Returns:** device type, OS version, kernel build, FPGA info (if verbose).

---

### memory_probe

Find readable memory regions on the target.

| Parameter | Type | Required | Description |
|---|---|---|---|
| `min_address` | string | no | Start address (default: `"0x0"`) |
| `max_address` | string | no | End address (default: auto) |

**Returns:** list of memory regions with start, end, size.

---

### memory_dump

Dump a memory range to a file.

| Parameter | Type | Required | Description |
|---|---|---|---|
| `min_address` | string | yes | Start address |
| `max_address` | string | yes | End address |
| `output_file` | string | no | File path (auto-generated if omitted) |
| `force` | boolean | no | Zero-pad on read failure (default: false) |

Max dump size: 256MB.

**Returns:** file path, size, success status.

---

### memory_search

Search physical memory for a hex byte pattern.

| Parameter | Type | Required | Description |
|---|---|---|---|
| `pattern` | string | yes | Hex pattern (e.g. `"4D5A9000"`) |
| `min_address` | string | no | Start address |
| `max_address` | string | no | End address (default: `0x100000000`) |
| `find_all` | boolean | no | Find all matches vs. first only (default: false) |

**Returns:** list of matching addresses with surrounding context.

---

### memory_patch

Search and patch memory using a signature file.

> **Note:** Not yet implemented in the native Linux version. Signature `.sig` files are a pcileech CLI feature. Use `memory_search` + `memory_write` for manual patching.

---

### process_list

List processes on the target system.

No parameters.

**Returns:** table of PID, PPID, state, name for each process.

---

## Address Translation

### translate_virt2phys

Translate a virtual address to physical using a CR3 page table base.

| Parameter | Type | Required | Description |
|---|---|---|---|
| `virtual_address` | string | yes | Virtual address in hex |
| `cr3` | string | yes | Page table base (CR3 register) in hex |

> **Note:** CR3-based translation is limited. Prefer `process_virt2phys` with a PID.

---

### process_virt2phys

Translate a process virtual address to physical.

| Parameter | Type | Required | Description |
|---|---|---|---|
| `pid` | integer | yes | Process ID |
| `virtual_address` | string | yes | Virtual address in hex |

**Returns:** physical address, DTB, success status.

---

## Modules

### module_list

List loaded modules/DLLs for a process.

| Parameter | Type | Required | Description |
|---|---|---|---|
| `pid` | integer | no | Process ID |
| `process_name` | string | no | Process name (alternative to pid) |

One of `pid` or `process_name` is required.

**Returns:** table of module name, base address, size.

---

## Advanced / FPGA

### benchmark

Run a DMA read/write performance benchmark.

| Parameter | Type | Required | Description |
|---|---|---|---|
| `test_type` | string | no | `"read"`, `"readwrite"`, or `"full"` (default: `"read"`) |
| `address` | string | no | Test address (default: `"0x1000"`) |

Runs 1000 iterations of 4KB reads (and writes if selected).

**Returns:** MB/s throughput.

---

### tlp_send

Send and/or receive raw PCIe TLP packets. FPGA only.

| Parameter | Type | Required | Description |
|---|---|---|---|
| `tlp_data` | string | no | TLP packet data in hex (omit to just listen) |
| `wait_seconds` | number | no | Listen duration (0.1 - 60, default: 0.5) |
| `verbose` | boolean | no | Include TLP decode info (default: true) |

**Returns:** sent confirmation, received TLP list.

---

### fpga_config

Read or write FPGA PCIe configuration space. FPGA only.

| Parameter | Type | Required | Description |
|---|---|---|---|
| `action` | string | no | `"read"` or `"write"` (default: `"read"`) |
| `address` | string | no | Config register offset in hex (required for write) |
| `data` | string | no | Data in hex (required for write) |
| `output_file` | string | no | Save config space to file |

**Returns:** config space hex dump (read) or write confirmation.

---

## Advanced RE Tools

### scatter_read

Batch-read multiple disjoint memory regions in a single DMA operation (~10x faster).

| Parameter | Type | Required | Description |
|---|---|---|---|
| `reads` | array | yes | List of `{address, size}` objects (max 1024) |
| `pid` | integer | no | Process ID for virtual address mode |
| `process_name` | string | no | Process name for virtual address mode |

**Returns:** list of read results with address, size, and hex data.

---

### pe_sections

Enumerate PE sections (.text, .rdata, .data, etc.) of a loaded module.

| Parameter | Type | Required | Description |
|---|---|---|---|
| `module_name` | string | yes | Module to enumerate (e.g. `"game.exe"`) |
| `pid` | integer | no | Process ID |
| `process_name` | string | no | Process name |

**Returns:** section name, virtual address, sizes, characteristics flags.

---

### signature_resolve

Find a byte pattern and resolve the operand to a target address in one step.

| Parameter | Type | Required | Description |
|---|---|---|---|
| `pattern` | string | yes | AOB pattern with `??` wildcards |
| `pid` | integer | no | Process ID |
| `process_name` | string | no | Process name |
| `module` | string | no | Module to scan (recommended) |
| `op_offset` | integer | no | Operand offset within match (default: 3) |
| `op_length` | integer | no | Operand size: 1, 2, 4, or 8 (default: 4) |
| `rip_relative` | boolean | no | Resolve as RIP-relative (default: true) |
| `instruction_length` | integer | no | Instruction length (default: op_offset + op_length) |

**Returns:** match address, operand value, resolved target address.

---

### rtti_scan

Scan a module for MSVC C++ RTTI structures to discover classes, vtables, and inheritance.

| Parameter | Type | Required | Description |
|---|---|---|---|
| `module` | string | yes | Module to scan (e.g. `"game.exe"`) |
| `pid` | integer | no | Process ID |
| `process_name` | string | no | Process name |
| `max_classes` | integer | no | Maximum classes to return (default: 500) |

**Returns:** class name, mangled name, TypeDescriptor address, vtable address, base classes.

---

### struct_analyze

Heuristically analyze a memory region to identify data types at each offset.

| Parameter | Type | Required | Description |
|---|---|---|---|
| `address` | string | yes | Start address in hex |
| `size` | integer | no | Bytes to analyze (8-4096, default: 256) |
| `pid` | integer | no | Process ID |
| `process_name` | string | no | Process name |

**Returns:** list of fields with offset, type (pointer/vtable_ptr/float/vec3/int32/null/unknown), and value.

---

### string_scan

Scan process memory for ASCII and/or UTF-16LE strings.

| Parameter | Type | Required | Description |
|---|---|---|---|
| `pid` | integer | no | Process ID |
| `process_name` | string | no | Process name |
| `module` | string | no | Module to scan (recommended for speed) |
| `min_length` | integer | no | Minimum string length (default: 4) |
| `encoding` | string | no | `"ascii"`, `"unicode"`, or `"both"` (default: `"both"`) |
| `pattern` | string | no | Regex filter (e.g. `"Player\|Health"`) |
| `max_results` | integer | no | Maximum results (default: 500) |

**Returns:** list of strings with address, encoding, length, and content.

---

### memory_diff

Snapshot and diff a memory region to detect changes (replaces CE scan workflow).

| Parameter | Type | Required | Description |
|---|---|---|---|
| `address` | string | yes | Start address in hex |
| `size` | integer | yes | Region size in bytes (1-1MB) |
| `label` | string | no | Snapshot label (default: `"default"`) |
| `pid` | integer | no | Process ID |
| `process_name` | string | no | Process name |

First call takes a snapshot. Subsequent calls diff against the previous snapshot and report changes with type interpretations (int32, float, etc.).

**Returns:** snapshot confirmation or diff results with changed bytes and interpretations.
