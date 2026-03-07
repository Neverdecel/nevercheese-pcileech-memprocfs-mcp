# nevercheese-pcileech-memprocfs-mcp

A Linux-native [Model Context Protocol](https://modelcontextprotocol.io/) (MCP) server for [PCILeech](https://github.com/ufrisk/pcileech) / [MemProcFS](https://github.com/ufrisk/MemProcFS) DMA memory operations.

Built for use with [Claude Code](https://docs.anthropic.com/en/docs/claude-code) and other MCP-compatible clients.

## What is this?

This MCP server lets an AI assistant perform DMA-based memory operations on a target system through a PCILeech-compatible FPGA device. Instead of wrapping the `pcileech.exe` CLI (like [evan7198/mcp_server_pcileech](https://github.com/evan7198/mcp_server_pcileech)), this project uses the native Python bindings directly — no subprocess calls, no text parsing, no Windows dependency.

**Key differences from the original:**

| | Original (evan7198) | This project |
|---|---|---|
| **Platform** | Windows only | Linux native |
| **Backend** | Subprocess calls to `pcileech.exe` | Native `memprocfs` + `leechcorepyc` Python packages |
| **Memory reads** | 256-byte chunks, parsed from text output | Arbitrary size (up to 1MB), direct API calls |
| **Connection** | New subprocess per operation | Persistent device handle |
| **Process support** | CLI flag passthrough | Native process/module enumeration via MemProcFS |

## Tools

21 MCP tools organized by capability:

| Category | Tools |
|---|---|
| **Core Memory** | `memory_read`, `memory_write`, `memory_format` |
| **System** | `system_info`, `memory_probe`, `memory_dump`, `memory_search`, `memory_patch`\*, `process_list` |
| **Address Translation** | `translate_virt2phys`, `process_virt2phys` |
| **Modules** | `module_list`, `module_dump`, `module_exports`, `module_imports` |
| **Game / RE** | `aob_scan`, `pointer_read`, `process_regions` |
| **Advanced / FPGA** | `benchmark`, `tlp_send`, `fpga_config` |

\* `memory_patch` is stubbed — `.sig` files are a CLI-only feature. Use `memory_search` + `memory_write` instead.

## Requirements

- **Linux** (x86_64)
- **Python 3.10+**
- **PCILeech-compatible FPGA hardware** (e.g. Screamer, ZDMA, etc.)
- USB drivers configured (see [MemProcFS Linux setup](https://github.com/ufrisk/MemProcFS/wiki/_Linux))

## Installation

```bash
git clone https://github.com/Neverdecel/nevercheese-pcileech-memprocfs-mcp.git
cd nevercheese-pcileech-memprocfs-mcp

python3 -m venv .venv
source .venv/bin/activate
pip install -r requirements.txt
```

### System dependencies (if needed)

```bash
sudo apt install libusb-1.0-0-dev libfuse-dev openssl libssl-dev liblz4-dev
```

## Configuration

Edit `config.json` to match your setup:

```json
{
  "device": {
    "type": "fpga",
    "remote": "",
    "extra_args": []
  }
}
```

| Field | Description | Examples |
|---|---|---|
| `type` | Device type | `"fpga"`, `"file:///path/to/dump.raw"` |
| `remote` | Remote LeechAgent connection | `""`, `"rpc://user@host"` |
| `extra_args` | Extra args passed to `memprocfs.Vmm()` | `["-v", "-printf"]` |

## Adding to Claude Code

```bash
claude mcp add -s user nevercheese-pcileech-memprocfs-mcp -- \
  /path/to/nevercheese-pcileech-memprocfs-mcp/.venv/bin/python \
  /path/to/nevercheese-pcileech-memprocfs-mcp/main.py
```

Or manually add to your MCP config:

```json
{
  "mcpServers": {
    "nevercheese-pcileech-memprocfs-mcp": {
      "command": "/path/to/.venv/bin/python",
      "args": ["/path/to/main.py"]
    }
  }
}
```

Restart Claude Code after adding.

## Usage

Once connected, you can ask Claude to perform memory operations in natural language:

```
Read 256 bytes from physical address 0x1000
```

```
List all processes on the target system
```

```
Show me the modules loaded by explorer.exe
```

```
Search for the MZ header (4D5A) in the first 16MB of memory
```

```
Write 90909090 (NOPs) to address 0x7ff7f3a90000 in process with PID 1234
```

```
Run a DMA read benchmark
```

```
Scan for the AOB pattern "48 8B 05 ?? ?? ?? ?? 48 85 C0" in game.exe
```

```
Dump the client.dll module from the game process to disk
```

```
Show me the exports of engine2.dll in process cs2.exe
```

```
Follow the pointer chain [[game.exe+0x1A8B230]+0x50]+0x100 in PID 5678 and read 4 bytes
```

## Testing

Run the test suite (no hardware needed):

```bash
source .venv/bin/activate
python test_server.py
```

All 86 tests use mocks and validate the full MCP pipeline without requiring a DMA device.

## Architecture

```
Claude Code
    |
    | (MCP stdio transport)
    |
main.py              ← MCP server: tool schemas, handlers, formatting
    |
vmm_wrapper.py       ← Native wrapper: device init, memory ops, process enum
    |
    ├── memprocfs     ← High-level: processes, virtual memory, modules
    |     └── vmmpyc.so → libvmm.so → libleechcore.so
    |
    └── leechcorepyc  ← Low-level: physical memory, FPGA config, TLP
          └── leechcore.so
```

## Credits

- **PCILeech / MemProcFS / LeechCore:** [Ulf Frisk](https://github.com/ufrisk)
- **Original MCP concept:** [evan7198/mcp_server_pcileech](https://github.com/evan7198/mcp_server_pcileech)
- **Model Context Protocol:** [Anthropic](https://modelcontextprotocol.io/)

## License

This project wraps PCILeech/MemProcFS which are licensed under AGPL-3.0 / GPL-3.0. See [MemProcFS License](https://github.com/ufrisk/MemProcFS/blob/master/LICENSE) and [LeechCore License](https://github.com/ufrisk/LeechCore/blob/master/LICENSE).

## Disclaimer

This tool is intended for authorized security research, debugging, and educational purposes only. Do not use it for unauthorized access. You are responsible for complying with all applicable laws.
