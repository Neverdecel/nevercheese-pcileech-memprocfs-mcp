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
        # Core Memory
        Tool(
            name="memory_read",
            description="Read memory from specified address using DMA. Supports physical and process virtual addresses.",
            inputSchema={
                "type": "object",
                "properties": {
                    "address": {"type": "string", "description": "Memory address in hex (e.g. '0x1000')"},
                    "length": {"type": "integer", "description": "Bytes to read", "minimum": 1, "maximum": 1048576},
                    "pid": {"type": "integer", "description": "Process ID for virtual address mode"},
                    "process_name": {"type": "string", "description": "Process name for virtual address mode (alternative to pid)"},
                },
                "required": ["address", "length"],
            },
        ),
        Tool(
            name="memory_write",
            description="Write data to memory at specified address using DMA. Supports physical and process virtual addresses.",
            inputSchema={
                "type": "object",
                "properties": {
                    "address": {"type": "string", "description": "Memory address in hex"},
                    "data": {"type": "string", "description": "Hex string of data to write (e.g. '48656c6c6f')", "maxLength": 2097152},
                    "pid": {"type": "integer", "description": "Process ID for virtual address mode"},
                    "process_name": {"type": "string", "description": "Process name for virtual address mode"},
                },
                "required": ["address", "data"],
            },
        ),
        Tool(
            name="memory_format",
            description="Read memory and format in multiple views (hexdump, ASCII, byte/DWORD arrays) for analysis.",
            inputSchema={
                "type": "object",
                "properties": {
                    "address": {"type": "string", "description": "Memory address in hex"},
                    "length": {"type": "integer", "description": "Bytes to read", "minimum": 1, "maximum": 4096},
                    "formats": {
                        "type": "array",
                        "items": {"type": "string", "enum": ["hexdump", "ascii", "bytes", "dwords", "raw"]},
                        "description": "Output formats (default: all)",
                    },
                    "pid": {"type": "integer", "description": "Process ID for virtual address mode"},
                    "process_name": {"type": "string", "description": "Process name for virtual address mode"},
                },
                "required": ["address", "length"],
            },
        ),
        # System
        Tool(
            name="system_info",
            description="Get target system and device information",
            inputSchema={
                "type": "object",
                "properties": {
                    "verbose": {"type": "boolean", "description": "Include FPGA details", "default": False},
                },
                "required": [],
            },
        ),
        Tool(
            name="memory_probe",
            description="Probe target memory to find readable regions",
            inputSchema={
                "type": "object",
                "properties": {
                    "min_address": {"type": "string", "description": "Start address in hex", "default": "0x0"},
                    "max_address": {"type": "string", "description": "End address in hex"},
                },
                "required": [],
            },
        ),
        Tool(
            name="memory_dump",
            description="Dump memory range to file for offline analysis",
            inputSchema={
                "type": "object",
                "properties": {
                    "min_address": {"type": "string", "description": "Start address in hex"},
                    "max_address": {"type": "string", "description": "End address in hex"},
                    "output_file": {"type": "string", "description": "Output file path"},
                    "force": {"type": "boolean", "description": "Zero-pad on read failure", "default": False},
                },
                "required": ["min_address", "max_address"],
            },
        ),
        Tool(
            name="memory_search",
            description="Search physical memory for a hex byte pattern",
            inputSchema={
                "type": "object",
                "properties": {
                    "pattern": {"type": "string", "description": "Hex pattern to search (e.g. '4D5A9000')"},
                    "min_address": {"type": "string", "description": "Start address in hex"},
                    "max_address": {"type": "string", "description": "End address in hex"},
                    "find_all": {"type": "boolean", "description": "Find all matches", "default": False},
                },
                "required": ["pattern"],
            },
        ),
        Tool(
            name="memory_patch",
            description="Search and patch memory using signature (not yet supported natively — use memory_search + memory_write)",
            inputSchema={
                "type": "object",
                "properties": {
                    "signature": {"type": "string", "description": "Signature file name"},
                    "min_address": {"type": "string"},
                    "max_address": {"type": "string"},
                    "patch_all": {"type": "boolean", "default": False},
                },
                "required": ["signature"],
            },
        ),
        Tool(
            name="process_list",
            description="List processes on the target system (requires OS-level analysis via MemProcFS)",
            inputSchema={"type": "object", "properties": {}, "required": []},
        ),
        # Address Translation
        Tool(
            name="translate_virt2phys",
            description="Translate virtual address to physical address using page table (CR3)",
            inputSchema={
                "type": "object",
                "properties": {
                    "virtual_address": {"type": "string", "description": "Virtual address in hex"},
                    "cr3": {"type": "string", "description": "Page table base (CR3) in hex"},
                },
                "required": ["virtual_address", "cr3"],
            },
        ),
        Tool(
            name="process_virt2phys",
            description="Translate a process's virtual address to physical address",
            inputSchema={
                "type": "object",
                "properties": {
                    "pid": {"type": "integer", "description": "Process ID"},
                    "virtual_address": {"type": "string", "description": "Virtual address in hex"},
                },
                "required": ["pid", "virtual_address"],
            },
        ),
        # Module enumeration (new — not in original)
        Tool(
            name="module_list",
            description="List loaded modules/DLLs for a process on the target system",
            inputSchema={
                "type": "object",
                "properties": {
                    "pid": {"type": "integer", "description": "Process ID"},
                    "process_name": {"type": "string", "description": "Process name (alternative to pid)"},
                },
                "required": [],
            },
        ),
        # Advanced / FPGA
        Tool(
            name="benchmark",
            description="Run DMA memory read/write performance benchmark",
            inputSchema={
                "type": "object",
                "properties": {
                    "test_type": {"type": "string", "enum": ["read", "readwrite", "full"], "default": "read"},
                    "address": {"type": "string", "description": "Test address in hex", "default": "0x1000"},
                },
                "required": [],
            },
        ),
        Tool(
            name="tlp_send",
            description="Send/receive PCIe TLP packets (FPGA only)",
            inputSchema={
                "type": "object",
                "properties": {
                    "tlp_data": {"type": "string", "description": "TLP packet data in hex"},
                    "wait_seconds": {"type": "number", "description": "Time to wait for responses", "default": 0.5, "minimum": 0.1, "maximum": 60},
                    "verbose": {"type": "boolean", "default": True},
                },
                "required": [],
            },
        ),
        Tool(
            name="fpga_config",
            description="Read/write FPGA PCIe configuration space",
            inputSchema={
                "type": "object",
                "properties": {
                    "action": {"type": "string", "enum": ["read", "write"], "default": "read"},
                    "address": {"type": "string", "description": "Config space address in hex (for write)"},
                    "data": {"type": "string", "description": "Data in hex (for write)"},
                    "output_file": {"type": "string", "description": "Output file path"},
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
