#!/usr/bin/env python3
"""
Test suite for MCP Server for PCILeech (Linux native).

Tests are split into:
1. Unit tests - no hardware needed (helpers, MCP layer, mock wrapper)
2. Integration test hints - require DMA hardware or valid memory dump
"""

import json
import os
import sys
import struct
import asyncio
from unittest.mock import MagicMock, patch

sys.path.insert(0, os.path.dirname(__file__))

PASS = 0
FAIL = 0


def check(name: str, condition: bool):
    global PASS, FAIL
    if condition:
        PASS += 1
        print(f"  [PASS] {name}")
    else:
        FAIL += 1
        print(f"  [FAIL] {name}")


# ==================== Unit Tests ====================

def test_helpers():
    print("\n--- Helper Functions ---")
    from vmm_wrapper import parse_hex_address, validate_process_name, format_hex_dump, PCILeechError

    check("parse 0x1000", parse_hex_address("0x1000") == 0x1000)
    check("parse 1000", parse_hex_address("1000") == 0x1000)
    check("parse 0xDEADBEEF", parse_hex_address("0xDEADBEEF") == 0xDEADBEEF)
    check("parse 0x0", parse_hex_address("0x0") == 0)
    check("parse uppercase", parse_hex_address("0xABCD") == 0xABCD)

    # Invalid addresses
    for bad in ["-1", "0xZZZZ", "", "not_hex"]:
        try:
            parse_hex_address(bad)
            check(f"reject '{bad}'", False)
        except PCILeechError:
            check(f"reject '{bad}'", True)

    # Process name validation
    check("valid process name", validate_process_name("explorer.exe") == "explorer.exe")
    check("valid hyphen name", validate_process_name("my-app") == "my-app")
    for bad in ["", "../../../etc/passwd", "a" * 300]:
        try:
            validate_process_name(bad)
            check(f"reject process name '{bad[:20]}'", False)
        except PCILeechError:
            check(f"reject process name '{bad[:20]}'", True)

    # Hex dump formatting
    data = bytes(range(32))
    dump = format_hex_dump(data, 0x1000)
    check("hex dump has address", "0x0000000000001000" in dump)
    check("hex dump has hex bytes", "00 01 02 03" in dump)
    check("hex dump has ASCII", "|" in dump)
    check("hex dump two lines", dump.count("\n") == 1)  # 32 bytes = 2 lines, 1 newline


def test_mcp_tools():
    print("\n--- MCP Tool Registration ---")
    from main import server, list_tools

    tools = asyncio.run(list_tools())
    check(f"tool count is 15", len(tools) == 15)

    expected_names = {
        "memory_read", "memory_write", "memory_format",
        "system_info", "memory_probe", "memory_dump",
        "memory_search", "memory_patch", "process_list",
        "translate_virt2phys", "process_virt2phys",
        "module_list", "benchmark", "tlp_send", "fpga_config",
    }
    actual_names = {t.name for t in tools}
    check("all expected tools present", actual_names == expected_names)

    for t in tools:
        check(f"  {t.name} has valid schema", t.inputSchema.get("type") == "object")


def test_format_helpers():
    print("\n--- Output Formatters ---")
    from main import format_byte_array, format_dword_array, format_ascii_view

    data = b'\x48\x65\x6c\x6c\x6f\x00\x01\x02'

    ba = format_byte_array(data)
    check("byte array contains values", "72" in ba and "101" in ba)

    da = format_dword_array(data)
    check("dword array format", "0x" in da)

    av = format_ascii_view(data)
    check("ascii view", av.startswith("Hello"))
    check("ascii non-printable", "." in av)


def test_mutual_exclusion():
    print("\n--- Mutual Exclusion Validation ---")
    from main import validate_mutually_exclusive

    check("both set", validate_mutually_exclusive(
        {"pid": 1, "process_name": "test"}, "pid", "process_name") is not None)
    check("only pid", validate_mutually_exclusive(
        {"pid": 1}, "pid", "process_name") is None)
    check("only name", validate_mutually_exclusive(
        {"process_name": "test"}, "pid", "process_name") is None)
    check("neither set", validate_mutually_exclusive(
        {}, "pid", "process_name") is None)


def test_mock_memory_read():
    print("\n--- Mock Memory Read Handler ---")
    from main import handle_memory_read

    mock_wrapper = MagicMock()
    mock_wrapper.read_memory.return_value = b'\x4d\x5a\x90\x00'

    with patch('main.get_wrapper', return_value=mock_wrapper):
        result = asyncio.run(handle_memory_read({
            "address": "0x1000",
            "length": 4,
        }))

    check("returns TextContent", len(result) == 1)
    check("contains hex data", "4d5a9000" in result[0].text)
    check("contains address", "0x1000" in result[0].text)
    check("mode is physical", "physical" in result[0].text)
    mock_wrapper.read_memory.assert_called_once_with(
        "0x1000", 4, pid=None, process_name=None)


def test_mock_memory_read_virtual():
    print("\n--- Mock Virtual Memory Read ---")
    from main import handle_memory_read

    mock_wrapper = MagicMock()
    mock_wrapper.read_memory.return_value = b'\xCC' * 8

    with patch('main.get_wrapper', return_value=mock_wrapper):
        result = asyncio.run(handle_memory_read({
            "address": "0x7ff7f3a90000",
            "length": 8,
            "pid": 1234,
        }))

    check("contains PID mode", "PID: 1234" in result[0].text)
    mock_wrapper.read_memory.assert_called_once_with(
        "0x7ff7f3a90000", 8, pid=1234, process_name=None)


def test_mock_memory_write():
    print("\n--- Mock Memory Write Handler ---")
    from main import handle_memory_write

    mock_wrapper = MagicMock()
    mock_wrapper.write_memory.return_value = True

    with patch('main.get_wrapper', return_value=mock_wrapper):
        result = asyncio.run(handle_memory_write({
            "address": "0x2000",
            "data": "48656c6c6f",
        }))

    check("write success", "Wrote 5 bytes" in result[0].text)
    mock_wrapper.write_memory.assert_called_once()
    call_args = mock_wrapper.write_memory.call_args
    check("correct data", call_args[0][1] == b'Hello')


def test_mock_memory_format():
    print("\n--- Mock Memory Format Handler ---")
    from main import handle_memory_format

    mock_wrapper = MagicMock()
    mock_wrapper.read_memory.return_value = bytes(range(32))

    with patch('main.get_wrapper', return_value=mock_wrapper):
        result = asyncio.run(handle_memory_format({
            "address": "0x3000",
            "length": 32,
            "formats": ["hexdump", "ascii", "raw"],
        }))

    text = result[0].text
    check("has hexdump section", "## Hex Dump" in text)
    check("has ascii section", "## ASCII" in text)
    check("has raw section", "## Raw Hex" in text)
    check("no bytes section", "## Byte Array" not in text)


def test_mock_process_list():
    print("\n--- Mock Process List ---")
    from main import handle_process_list

    mock_wrapper = MagicMock()
    mock_wrapper.list_processes.return_value = [
        {'pid': 4, 'ppid': 0, 'name': 'System', 'state': 0, 'dtb': '0x1aa000', 'is_usermode': False},
        {'pid': 1234, 'ppid': 4, 'name': 'explorer.exe', 'state': 0, 'dtb': '0x3e1000', 'is_usermode': True},
    ]

    with patch('main.get_wrapper', return_value=mock_wrapper):
        result = asyncio.run(handle_process_list({}))

    text = result[0].text
    check("shows count", "2 process" in text)
    check("shows System", "System" in text)
    check("shows explorer", "explorer.exe" in text)


def test_mock_system_info():
    print("\n--- Mock System Info ---")
    from main import handle_system_info

    mock_wrapper = MagicMock()
    mock_wrapper.get_system_info.return_value = {
        'device': 'fpga',
        'kernel_build': 19041,
        'version_major': 10,
    }

    with patch('main.get_wrapper', return_value=mock_wrapper):
        result = asyncio.run(handle_system_info({"verbose": False}))

    text = result[0].text
    check("shows device", "fpga" in text)
    check("shows kernel build", "19041" in text)


def test_mock_benchmark():
    print("\n--- Mock Benchmark ---")
    from main import handle_benchmark

    mock_wrapper = MagicMock()
    mock_wrapper.benchmark.return_value = {
        'test_type': 'read',
        'address': '0x1000',
        'read_iterations': 1000,
        'read_chunk_size': 4096,
        'read_elapsed_s': 0.5,
        'read_mbps': 7.81,
    }

    with patch('main.get_wrapper', return_value=mock_wrapper):
        result = asyncio.run(handle_benchmark({"test_type": "read"}))

    text = result[0].text
    check("shows MB/s", "7.81 MB/s" in text)


def test_mock_module_list():
    print("\n--- Mock Module List ---")
    from main import handle_module_list

    mock_wrapper = MagicMock()
    mock_wrapper.list_modules.return_value = [
        {'name': 'kernel32.dll', 'base': '0x7ff8a0000', 'size': '0x1a0000',
         'image_size': 0x1a0000, 'fullname': 'kernel32.dll', 'is_wow64': False},
    ]

    with patch('main.get_wrapper', return_value=mock_wrapper):
        result = asyncio.run(handle_module_list({"pid": 1234}))

    text = result[0].text
    check("shows module", "kernel32.dll" in text)
    check("shows PID in header", "PID 1234" in text)


def test_error_handling():
    print("\n--- Error Handling ---")
    from main import call_tool, handle_memory_write
    from vmm_wrapper import MemoryAccessError

    # Test PCILeechError propagation through call_tool
    mock_wrapper = MagicMock()
    mock_wrapper.read_memory.side_effect = MemoryAccessError("Access denied at 0x1000")

    with patch('main.get_wrapper', return_value=mock_wrapper):
        result = asyncio.run(call_tool("memory_read", {
            "address": "0x1000", "length": 16
        }))

    check("error in response", "Access denied" in result[0].text)

    # Invalid hex data (caught before wrapper call)
    mock_wrapper2 = MagicMock()
    with patch('main.get_wrapper', return_value=mock_wrapper2):
        result = asyncio.run(call_tool("memory_write", {
            "address": "0x1000", "data": "ZZZZ"
        }))
    check("invalid hex rejected", "Invalid hex" in result[0].text)

    # Mutual exclusion (caught before wrapper call)
    mock_wrapper3 = MagicMock()
    with patch('main.get_wrapper', return_value=mock_wrapper3):
        result = asyncio.run(call_tool("memory_read", {
            "address": "0x1000", "length": 4,
            "pid": 1, "process_name": "test"
        }))
    check("mutual exclusion error", "mutually exclusive" in result[0].text)

    # Unknown tool
    result = asyncio.run(call_tool("nonexistent_tool", {}))
    check("unknown tool error", "Unknown tool" in result[0].text)


# ==================== Run All ====================

if __name__ == "__main__":
    print("MCP Server for PCILeech (Linux) - Test Suite")
    print("=" * 60)

    test_helpers()
    test_mcp_tools()
    test_format_helpers()
    test_mutual_exclusion()
    test_mock_memory_read()
    test_mock_memory_read_virtual()
    test_mock_memory_write()
    test_mock_memory_format()
    test_mock_process_list()
    test_mock_system_info()
    test_mock_benchmark()
    test_mock_module_list()
    test_error_handling()

    print("\n" + "=" * 60)
    print(f"RESULTS: {PASS} passed, {FAIL} failed")
    print("=" * 60)

    if FAIL > 0:
        print("\nNote: These are unit tests using mocks. For hardware integration")
        print("tests, connect your DMA device and update config.json.")
        sys.exit(1)
    else:
        print("\nAll unit tests passed! For hardware testing:")
        print("  1. Connect your DMA/FPGA device")
        print("  2. Update config.json with device type (e.g. 'fpga')")
        print("  3. Run: .venv/bin/python main.py")
        sys.exit(0)
