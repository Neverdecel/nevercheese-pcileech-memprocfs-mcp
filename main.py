#!/usr/bin/env python3
"""
Linux-native MCP Server for PCILeech / MemProcFS.

Uses memprocfs and leechcorepyc Python packages directly instead of
wrapping the pcileech CLI. Provides 19+ MCP tools for DMA-based
memory operations via the Model Context Protocol.
"""

import asyncio
import logging
from datetime import datetime
from typing import Any

from mcp.server import Server
from mcp.types import Tool, TextContent

from vmm_wrapper import (
    VmmWrapper, PCILeechError, DeviceNotFoundError,
    MemoryAccessError, SignatureNotFoundError, ProbeNotSupportedError,
    KMDError, parse_hex_address, format_hex_dump,
)

logging.basicConfig(level=logging.INFO)
logger = logging.getLogger("nevercheese-pcileech-memprocfs-mcp")

wrapper: VmmWrapper | None = None
server = Server("nevercheese-pcileech-memprocfs-mcp")


def get_wrapper() -> VmmWrapper:
    global wrapper
    if wrapper is None:
        try:
            wrapper = VmmWrapper()
        except Exception as e:
            logger.error(f"Failed to initialize wrapper: {e}")
            raise
    return wrapper


def validate_mutually_exclusive(args: dict, *param_names: str) -> str | None:
    provided = [name for name in param_names if args.get(name) is not None]
    if len(provided) > 1:
        return f"Parameters {', '.join(provided)} are mutually exclusive - only one can be specified"
    return None


def format_byte_array(data: bytes) -> str:
    return str(list(data))


def format_dword_array(data: bytes) -> str:
    dwords = []
    for i in range(0, len(data), 4):
        if i + 4 <= len(data):
            dword = int.from_bytes(data[i:i+4], byteorder='little', signed=False)
            dwords.append(f"0x{dword:08x}")
    return str(dwords)


def format_ascii_view(data: bytes) -> str:
    return ''.join(chr(b) if 32 <= b < 127 else '.' for b in data)


def mode_string(pid, process_name) -> str:
    if pid is not None:
        return f"virtual (PID: {pid})"
    if process_name is not None:
        return f"virtual (Process: {process_name})"
    return "physical"


# ==================== Tool Definitions ====================

@server.list_tools()
async def list_tools() -> list[Tool]:
    return [
        # ==================== Core Memory ====================
        Tool(
            name="memory_read",
            description=(
                "Read raw bytes from the target system's memory via DMA. Returns hex-encoded data. "
                "Use this for programmatic access when you need the raw bytes (e.g. to parse structures, "
                "compare values, or feed into further processing). "
                "For human-readable inspection, prefer memory_format instead. "
                "Reads PHYSICAL memory by default. To read a process's VIRTUAL memory, provide either "
                "pid or process_name (use process_list first to find these)."
            ),
            inputSchema={
                "type": "object",
                "properties": {
                    "address": {
                        "type": "string",
                        "description": "Memory address in hex format. Examples: '0x1000', '0x7ff6a000'. Physical address unless pid/process_name is set.",
                    },
                    "length": {
                        "type": "integer",
                        "description": "Number of bytes to read (1 to 1048576 / 1MB)",
                        "minimum": 1,
                        "maximum": 1048576,
                    },
                    "pid": {
                        "type": "integer",
                        "description": "Target process ID — switches to virtual address mode. Mutually exclusive with process_name. Use process_list to find PIDs.",
                    },
                    "process_name": {
                        "type": "string",
                        "description": "Target process name (e.g. 'explorer.exe') — switches to virtual address mode. Mutually exclusive with pid.",
                    },
                },
                "required": ["address", "length"],
            },
        ),
        Tool(
            name="memory_write",
            description=(
                "Write bytes to the target system's memory via DMA. Use this to patch memory, "
                "modify game values, overwrite instructions (e.g. NOP out checks with 0x90), etc. "
                "Writes to PHYSICAL memory by default. To write to a process's VIRTUAL memory, "
                "provide either pid or process_name. "
                "CAUTION: Writing to wrong addresses can crash the target system."
            ),
            inputSchema={
                "type": "object",
                "properties": {
                    "address": {
                        "type": "string",
                        "description": "Target memory address in hex. Physical address unless pid/process_name is set.",
                    },
                    "data": {
                        "type": "string",
                        "description": "Data to write as a hex string (2 chars per byte). Examples: '90909090' (4 NOP bytes), '48656c6c6f' ('Hello')",
                        "maxLength": 2097152,
                    },
                    "pid": {
                        "type": "integer",
                        "description": "Target process ID for virtual address writes. Mutually exclusive with process_name.",
                    },
                    "process_name": {
                        "type": "string",
                        "description": "Target process name for virtual address writes. Mutually exclusive with pid.",
                    },
                },
                "required": ["address", "data"],
            },
        ),
        Tool(
            name="memory_format",
            description=(
                "Read memory and display it in human-readable formatted views: hex dump with ASCII sidebar, "
                "plain ASCII text, byte arrays, DWORD arrays, or raw hex. "
                "Use this when you want to INSPECT or ANALYZE memory contents visually — it's the best tool "
                "for understanding what's at an address. For raw data to process programmatically, use memory_read instead. "
                "Max 4KB per call. Supports physical and virtual addresses (via pid/process_name)."
            ),
            inputSchema={
                "type": "object",
                "properties": {
                    "address": {
                        "type": "string",
                        "description": "Memory address in hex. Physical unless pid/process_name is set.",
                    },
                    "length": {
                        "type": "integer",
                        "description": "Number of bytes to read and format (1 to 4096)",
                        "minimum": 1,
                        "maximum": 4096,
                    },
                    "formats": {
                        "type": "array",
                        "items": {"type": "string", "enum": ["hexdump", "ascii", "bytes", "dwords", "raw"]},
                        "description": "Which views to include. 'hexdump' = hex + ASCII sidebar, 'ascii' = printable text only, 'bytes' = decimal array, 'dwords' = 32-bit LE integers, 'raw' = continuous hex string. Default: all.",
                    },
                    "pid": {
                        "type": "integer",
                        "description": "Process ID for virtual address mode. Mutually exclusive with process_name.",
                    },
                    "process_name": {
                        "type": "string",
                        "description": "Process name for virtual address mode. Mutually exclusive with pid.",
                    },
                },
                "required": ["address", "length"],
            },
        ),
        # ==================== System / Discovery ====================
        Tool(
            name="system_info",
            description=(
                "Get information about the DMA connection, target system, and FPGA device. "
                "Call this FIRST to verify the DMA device is connected and working, identify "
                "the target OS version, and check hardware capabilities. "
                "Set verbose=true to include FPGA hardware details (firmware version, device ID)."
            ),
            inputSchema={
                "type": "object",
                "properties": {
                    "verbose": {
                        "type": "boolean",
                        "description": "Include FPGA firmware version, device ID, and hardware details. Default: false.",
                        "default": False,
                    },
                },
                "required": [],
            },
        ),
        Tool(
            name="memory_probe",
            description=(
                "Discover which physical memory ranges are readable on the target system. "
                "Use this to understand the target's memory layout before reading — shows RAM regions, "
                "MMIO gaps, and reserved areas. Useful when you don't know what addresses are valid."
            ),
            inputSchema={
                "type": "object",
                "properties": {
                    "min_address": {
                        "type": "string",
                        "description": "Start of range to probe in hex. Default: '0x0'.",
                        "default": "0x0",
                    },
                    "max_address": {
                        "type": "string",
                        "description": "End of range to probe in hex. Default: auto-detect from memory map.",
                    },
                },
                "required": [],
            },
        ),
        Tool(
            name="memory_dump",
            description=(
                "Dump a range of physical memory to a file on disk. Use this for large reads that "
                "need to be saved for offline analysis (e.g. dumping a full module, forensic capture). "
                "For small reads you want to inspect inline, use memory_read or memory_format instead. "
                "Max 256MB per dump."
            ),
            inputSchema={
                "type": "object",
                "properties": {
                    "min_address": {"type": "string", "description": "Start address of dump range in hex"},
                    "max_address": {"type": "string", "description": "End address of dump range in hex"},
                    "output_file": {
                        "type": "string",
                        "description": "File path to save the dump. Auto-generated as dump_<min>-<max>.raw if omitted.",
                    },
                    "force": {
                        "type": "boolean",
                        "description": "If true, zero-pads unreadable regions instead of failing. Useful for dumping ranges that include MMIO holes.",
                        "default": False,
                    },
                },
                "required": ["min_address", "max_address"],
            },
        ),
        Tool(
            name="memory_search",
            description=(
                "Search physical memory for a hex byte pattern. Scans memory in 1MB chunks. "
                "Use this to find signatures, strings, or known byte sequences in the target's memory. "
                "Examples: search for PE headers ('4D5A'), strings (convert ASCII to hex first), "
                "or specific instruction patterns. "
                "To patch what you find, note the address and use memory_write."
            ),
            inputSchema={
                "type": "object",
                "properties": {
                    "pattern": {
                        "type": "string",
                        "description": "Hex byte pattern to search for. No spaces, even length. Examples: '4D5A9000' (MZ header), '48656C6C6F' ('Hello')",
                    },
                    "min_address": {
                        "type": "string",
                        "description": "Start of search range in hex. Default: 0x0.",
                    },
                    "max_address": {
                        "type": "string",
                        "description": "End of search range in hex. Default: 0x100000000 (4GB). Reduce for faster searches.",
                    },
                    "find_all": {
                        "type": "boolean",
                        "description": "If true, find ALL matches. If false (default), stop at first match.",
                        "default": False,
                    },
                },
                "required": ["pattern"],
            },
        ),
        Tool(
            name="memory_patch",
            description=(
                "NOT YET IMPLEMENTED. Signature-based patching (.sig files) is a pcileech CLI feature "
                "not available through the native API. "
                "INSTEAD: Use memory_search to find the target bytes, then memory_write to overwrite them."
            ),
            inputSchema={
                "type": "object",
                "properties": {
                    "signature": {"type": "string", "description": "Signature file name (NOT SUPPORTED — use memory_search + memory_write instead)"},
                    "min_address": {"type": "string"},
                    "max_address": {"type": "string"},
                    "patch_all": {"type": "boolean", "default": False},
                },
                "required": ["signature"],
            },
        ),
        Tool(
            name="process_list",
            description=(
                "List all running processes on the TARGET system (the machine connected via DMA, not the local machine). "
                "Returns PID, parent PID, name, and state for each process. "
                "Use this to find a process before reading its virtual memory — you'll need the PID or "
                "process name for memory_read, memory_write, memory_format, and module_list. "
                "Requires the target to be running Windows (MemProcFS performs OS-level analysis)."
            ),
            inputSchema={"type": "object", "properties": {}, "required": []},
        ),
        # ==================== Address Translation ====================
        Tool(
            name="translate_virt2phys",
            description=(
                "Translate a virtual address to a physical address using a raw CR3 page table base. "
                "This is a LOW-LEVEL tool — you need to already know the CR3 value. "
                "In most cases, use process_virt2phys instead (it looks up CR3 automatically from the PID)."
            ),
            inputSchema={
                "type": "object",
                "properties": {
                    "virtual_address": {
                        "type": "string",
                        "description": "Virtual address to translate, in hex",
                    },
                    "cr3": {
                        "type": "string",
                        "description": "Page table base register (CR3/DTB) value in hex. Get this from process_list DTB field.",
                    },
                },
                "required": ["virtual_address", "cr3"],
            },
        ),
        Tool(
            name="process_virt2phys",
            description=(
                "Translate a process's virtual address to the corresponding physical address. "
                "Use this when you have a virtual address from a module or disassembly and need the "
                "physical address for direct physical memory access. "
                "Automatically resolves the process page tables — just provide PID and virtual address."
            ),
            inputSchema={
                "type": "object",
                "properties": {
                    "pid": {
                        "type": "integer",
                        "description": "Process ID. Use process_list to find this.",
                    },
                    "virtual_address": {
                        "type": "string",
                        "description": "Virtual address within the process to translate, in hex",
                    },
                },
                "required": ["pid", "virtual_address"],
            },
        ),
        # ==================== Module Enumeration ====================
        Tool(
            name="module_list",
            description=(
                "List all loaded modules (DLLs/EXEs) for a specific process on the target system. "
                "Shows module name, base address, and size. Use this to find where a module is loaded "
                "in memory before reading or patching it. "
                "Requires pid or process_name — use process_list first to find these."
            ),
            inputSchema={
                "type": "object",
                "properties": {
                    "pid": {
                        "type": "integer",
                        "description": "Process ID to list modules for. Mutually exclusive with process_name.",
                    },
                    "process_name": {
                        "type": "string",
                        "description": "Process name to list modules for (e.g. 'explorer.exe'). Mutually exclusive with pid.",
                    },
                },
                "required": [],
            },
        ),
        # ==================== Advanced / FPGA ====================
        Tool(
            name="benchmark",
            description=(
                "Measure DMA read/write throughput in MB/s. Use this to verify the FPGA device "
                "performance and diagnose speed issues. Runs 1000 iterations of 4KB transfers."
            ),
            inputSchema={
                "type": "object",
                "properties": {
                    "test_type": {
                        "type": "string",
                        "enum": ["read", "readwrite", "full"],
                        "description": "'read' = read-only benchmark, 'readwrite' or 'full' = read + write benchmark. Default: 'read'.",
                        "default": "read",
                    },
                    "address": {
                        "type": "string",
                        "description": "Physical address to benchmark against in hex. Default: '0x1000'.",
                        "default": "0x1000",
                    },
                },
                "required": [],
            },
        ),
        Tool(
            name="tlp_send",
            description=(
                "Send and/or receive raw PCIe Transaction Layer Packets (TLPs). FPGA devices only. "
                "This is an ADVANCED low-level tool for PCIe protocol analysis, device enumeration, "
                "or custom packet crafting. Most users won't need this — use memory_read/write instead. "
                "Omit tlp_data to passively listen for TLPs."
            ),
            inputSchema={
                "type": "object",
                "properties": {
                    "tlp_data": {
                        "type": "string",
                        "description": "Raw TLP packet bytes in hex. Omit to just listen for incoming TLPs without sending.",
                    },
                    "wait_seconds": {
                        "type": "number",
                        "description": "How long to listen for TLP responses in seconds (0.1 to 60). Default: 0.5.",
                        "default": 0.5,
                        "minimum": 0.1,
                        "maximum": 60,
                    },
                    "verbose": {
                        "type": "boolean",
                        "description": "Include decoded TLP header info alongside raw hex. Default: true.",
                        "default": True,
                    },
                },
                "required": [],
            },
        ),
        Tool(
            name="fpga_config",
            description=(
                "Read or write the FPGA's PCIe configuration space registers. FPGA devices only. "
                "Use 'read' to dump the full 4KB PCIe config space (vendor ID, device ID, BARs, capabilities). "
                "Use 'write' to modify specific config registers (e.g. change device ID for spoofing). "
                "This configures the FPGA itself, NOT the target system's memory."
            ),
            inputSchema={
                "type": "object",
                "properties": {
                    "action": {
                        "type": "string",
                        "enum": ["read", "write"],
                        "description": "'read' dumps the full PCIe config space. 'write' modifies a specific register. Default: 'read'.",
                        "default": "read",
                    },
                    "address": {
                        "type": "string",
                        "description": "Config register offset in hex (required for 'write'). E.g. '0x00' = Device/Vendor ID.",
                    },
                    "data": {
                        "type": "string",
                        "description": "Data to write in hex (required for 'write').",
                    },
                    "output_file": {
                        "type": "string",
                        "description": "Save config space to this file path (for 'read' action).",
                    },
                },
                "required": [],
            },
        ),
    ]


# ==================== Tool Handlers ====================

@server.call_tool()
async def call_tool(name: str, arguments: Any) -> list[TextContent]:
    try:
        handlers = {
            "memory_read": handle_memory_read,
            "memory_write": handle_memory_write,
            "memory_format": handle_memory_format,
            "system_info": handle_system_info,
            "memory_probe": handle_memory_probe,
            "memory_dump": handle_memory_dump,
            "memory_search": handle_memory_search,
            "memory_patch": handle_memory_patch,
            "process_list": handle_process_list,
            "translate_virt2phys": handle_translate_virt2phys,
            "process_virt2phys": handle_process_virt2phys,
            "module_list": handle_module_list,
            "benchmark": handle_benchmark,
            "tlp_send": handle_tlp_send,
            "fpga_config": handle_fpga_config,
        }
        handler = handlers.get(name)
        if handler is None:
            return [TextContent(type="text", text=f"Unknown tool: {name}")]
        return await handler(arguments or {})
    except PCILeechError as e:
        logger.error(f"PCILeech error in {name}: {e}")
        return [TextContent(type="text", text=f"PCILeech error: {e}")]
    except Exception as e:
        logger.error(f"Unexpected error in {name}: {e}", exc_info=True)
        return [TextContent(type="text", text=f"Internal error: {e}")]


async def handle_memory_read(args: dict) -> list[TextContent]:
    address = args["address"]
    length = args["length"]
    pid = args.get("pid")
    process_name = args.get("process_name")

    error = validate_mutually_exclusive(args, "pid", "process_name")
    if error:
        return [TextContent(type="text", text=f"Parameter error: {error}")]

    mode = mode_string(pid, process_name)
    w = get_wrapper()
    data = await asyncio.to_thread(w.read_memory, address, length, pid=pid, process_name=process_name)

    return [TextContent(
        type="text",
        text=(
            f"Read {len(data)} bytes from {address} ({mode})\n\n"
            f"Hex: {data.hex()}\n\n"
            f"Bytes read: {len(data)}\n"
            f"Timestamp: {datetime.now().isoformat()}"
        ),
    )]


async def handle_memory_write(args: dict) -> list[TextContent]:
    address = args["address"]
    data_hex = args["data"]
    pid = args.get("pid")
    process_name = args.get("process_name")

    error = validate_mutually_exclusive(args, "pid", "process_name")
    if error:
        return [TextContent(type="text", text=f"Parameter error: {error}")]

    try:
        data = bytes.fromhex(data_hex)
    except ValueError as e:
        return [TextContent(type="text", text=f"Invalid hex data: {e}")]

    mode = mode_string(pid, process_name)
    w = get_wrapper()
    await asyncio.to_thread(w.write_memory, address, data, pid=pid, process_name=process_name)

    return [TextContent(
        type="text",
        text=(
            f"Wrote {len(data)} bytes to {address} ({mode})\n\n"
            f"Data: {data_hex}\n"
            f"Timestamp: {datetime.now().isoformat()}"
        ),
    )]


async def handle_memory_format(args: dict) -> list[TextContent]:
    address = args["address"]
    length = args["length"]
    formats = args.get("formats", ["hexdump", "ascii", "bytes", "dwords", "raw"])
    pid = args.get("pid")
    process_name = args.get("process_name")

    error = validate_mutually_exclusive(args, "pid", "process_name")
    if error:
        return [TextContent(type="text", text=f"Parameter error: {error}")]

    w = get_wrapper()
    data = await asyncio.to_thread(w.read_memory, address, length, pid=pid, process_name=process_name)
    addr_int = parse_hex_address(address)

    parts = [f"Memory at {address} ({length} bytes)", "=" * 80, ""]

    if "hexdump" in formats:
        parts += ["## Hex Dump:", format_hex_dump(data, addr_int), ""]
    if "ascii" in formats:
        parts += ["## ASCII:", format_ascii_view(data), ""]
    if "bytes" in formats:
        parts += ["## Byte Array:", format_byte_array(data), ""]
    if "dwords" in formats:
        parts += ["## DWORD Array (LE):", format_dword_array(data), ""]
    if "raw" in formats:
        parts += ["## Raw Hex:", data.hex(), ""]

    return [TextContent(type="text", text="\n".join(parts))]


async def handle_system_info(args: dict) -> list[TextContent]:
    verbose = args.get("verbose", False)
    w = get_wrapper()
    info = await asyncio.to_thread(w.get_system_info, verbose)

    parts = ["## System Information", "=" * 50, ""]
    for k, v in info.items():
        if k == 'memmap':
            parts.append(f"**Memory Regions:** {len(v)}")
        else:
            parts.append(f"**{k}:** {v}")

    return [TextContent(type="text", text="\n".join(parts))]


async def handle_memory_probe(args: dict) -> list[TextContent]:
    min_addr = args.get("min_address", "0x0")
    max_addr = args.get("max_address")

    w = get_wrapper()
    regions = await asyncio.to_thread(w.probe_memory, min_addr, max_addr)

    parts = ["## Memory Probe Results", "=" * 50, ""]
    if not regions:
        parts.append("No readable memory regions found.")
    else:
        parts.append(f"Found {len(regions)} region(s):\n")
        for i, r in enumerate(regions, 1):
            parts.append(f"{i}. **{r['start']}** - **{r['end']}** ({r['size_mb']:.2f} MB)")

    return [TextContent(type="text", text="\n".join(parts))]


async def handle_memory_dump(args: dict) -> list[TextContent]:
    w = get_wrapper()
    result = await asyncio.to_thread(
        w.dump_memory,
        args["min_address"],
        args["max_address"],
        args.get("output_file"),
        args.get("force", False),
    )

    parts = [
        "## Memory Dump Result", "=" * 50, "",
        f"**Range:** {result['min_address']} - {result['max_address']}",
        f"**Size:** {result['size']} bytes",
        f"**File:** {result.get('file', 'N/A')}",
        f"**Success:** {result['success']}",
    ]
    return [TextContent(type="text", text="\n".join(parts))]


async def handle_memory_search(args: dict) -> list[TextContent]:
    w = get_wrapper()
    matches = await asyncio.to_thread(
        w.search_memory,
        args.get("pattern"),
        args.get("min_address"),
        args.get("max_address"),
        args.get("find_all", False),
    )

    parts = ["## Memory Search Results", "=" * 50, "", f"**Pattern:** {args.get('pattern')}", ""]
    if not matches:
        parts.append("No matches found.")
    else:
        parts.append(f"Found {len(matches)} match(es):\n")
        for i, m in enumerate(matches, 1):
            parts.append(f"{i}. **{m['address']}**  context: {m.get('line', '')}")

    return [TextContent(type="text", text="\n".join(parts))]


async def handle_memory_patch(args: dict) -> list[TextContent]:
    w = get_wrapper()
    result = await asyncio.to_thread(
        w.patch_memory,
        args["signature"],
        args.get("min_address"),
        args.get("max_address"),
        args.get("patch_all", False),
    )
    return [TextContent(type="text", text=str(result))]


async def handle_process_list(args: dict) -> list[TextContent]:
    w = get_wrapper()
    processes = await asyncio.to_thread(w.list_processes)

    parts = ["## Process List", "=" * 50, "", f"Found {len(processes)} process(es):\n"]
    parts.append(f"{'PID':>8}  {'PPID':>8}  {'State':>5}  {'Name'}")
    parts.append("-" * 50)
    for p in processes:
        parts.append(f"{p['pid']:>8}  {p['ppid']:>8}  {p['state']:>5}  {p['name']}")

    return [TextContent(type="text", text="\n".join(parts))]


async def handle_translate_virt2phys(args: dict) -> list[TextContent]:
    w = get_wrapper()
    result = await asyncio.to_thread(
        w.translate_virt2phys,
        args["virtual_address"],
        args.get("cr3"),
    )

    parts = ["## Address Translation (Virt -> Phys)", "=" * 50, ""]
    for k, v in result.items():
        if v is not None:
            parts.append(f"**{k}:** {v}")

    return [TextContent(type="text", text="\n".join(parts))]


async def handle_process_virt2phys(args: dict) -> list[TextContent]:
    w = get_wrapper()
    result = await asyncio.to_thread(
        w.process_virt2phys,
        args["pid"],
        args["virtual_address"],
    )

    parts = ["## Process Address Translation", "=" * 50, ""]
    for k, v in result.items():
        if v is not None:
            parts.append(f"**{k}:** {v}")

    return [TextContent(type="text", text="\n".join(parts))]


async def handle_module_list(args: dict) -> list[TextContent]:
    pid = args.get("pid")
    process_name = args.get("process_name")

    error = validate_mutually_exclusive(args, "pid", "process_name")
    if error:
        return [TextContent(type="text", text=f"Parameter error: {error}")]

    if pid is None and process_name is None:
        return [TextContent(type="text", text="Error: pid or process_name is required")]

    w = get_wrapper()
    modules = await asyncio.to_thread(w.list_modules, pid=pid, process_name=process_name)

    target = f"PID {pid}" if pid else process_name
    parts = [f"## Modules for {target}", "=" * 50, "", f"Found {len(modules)} module(s):\n"]
    parts.append(f"{'Base':>18}  {'Size':>12}  {'Name'}")
    parts.append("-" * 60)
    for m in modules:
        parts.append(f"{m['base']:>18}  {m['size']:>12}  {m['name']}")

    return [TextContent(type="text", text="\n".join(parts))]


async def handle_benchmark(args: dict) -> list[TextContent]:
    w = get_wrapper()
    result = await asyncio.to_thread(
        w.benchmark,
        args.get("test_type", "read"),
        args.get("address", "0x1000"),
    )

    parts = ["## Benchmark Results", "=" * 50, ""]
    parts.append(f"**Read:** {result['read_mbps']} MB/s ({result['read_iterations']} iterations, {result['read_elapsed_s']}s)")
    if 'write_mbps' in result:
        parts.append(f"**Write:** {result['write_mbps']} MB/s ({result['write_iterations']} iterations, {result['write_elapsed_s']}s)")

    return [TextContent(type="text", text="\n".join(parts))]


async def handle_tlp_send(args: dict) -> list[TextContent]:
    w = get_wrapper()
    result = await asyncio.to_thread(
        w.tlp_send,
        args.get("tlp_data"),
        args.get("wait_seconds", 0.5),
        args.get("verbose", True),
    )

    parts = ["## TLP Results", "=" * 50, ""]
    if result['sent']:
        parts.append(f"**Sent:** {result['sent_bytes']} bytes")
        if 'sent_info' in result:
            parts.append(f"```\n{result['sent_info']}\n```")

    parts.append(f"\n**Received TLPs:** {len(result['received_tlps'])}")
    for i, tlp in enumerate(result['received_tlps'], 1):
        parts.append(f"\n### TLP {i}")
        parts.append(f"Data: {tlp['data']}")
        if 'info' in tlp:
            parts.append(f"```\n{tlp['info']}\n```")

    return [TextContent(type="text", text="\n".join(parts))]


async def handle_fpga_config(args: dict) -> list[TextContent]:
    w = get_wrapper()
    result = await asyncio.to_thread(
        w.fpga_config,
        args.get("action", "read"),
        args.get("address"),
        args.get("data"),
        args.get("output_file"),
    )

    parts = ["## FPGA Config Result", "=" * 50, ""]
    parts.append(f"**Action:** {result['action']}")
    parts.append(f"**Success:** {result['success']}")

    if result['action'] == 'read':
        parts.append(f"**Size:** {result['size']} bytes")
        # Show first 256 bytes as hex dump
        raw = bytes.fromhex(result['data_hex'])
        preview = raw[:256]
        parts.append(f"\n### Config Space (first {len(preview)} bytes):")
        parts.append(f"```\n{format_hex_dump(preview, 0)}\n```")
        if result.get('file'):
            parts.append(f"**Saved to:** {result['file']}")
    else:
        parts.append(f"**Address:** {result.get('address')}")
        parts.append(f"**Bytes written:** {result.get('bytes_written')}")

    return [TextContent(type="text", text="\n".join(parts))]


# ==================== Entry Point ====================

async def main():
    from mcp.server.stdio import stdio_server

    async with stdio_server() as (read_stream, write_stream):
        logger.info("nevercheese-pcileech-memprocfs-mcp starting...")
        await server.run(
            read_stream,
            write_stream,
            server.create_initialization_options(),
        )


if __name__ == "__main__":
    asyncio.run(main())
