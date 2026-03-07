"""
Native Linux wrapper for MemProcFS / LeechCore.

Uses the memprocfs and leechcorepyc Python packages directly
instead of shelling out to pcileech.exe.
"""

import json
import os
import re
import time
import struct
from pathlib import Path
from typing import Optional


# ==================== Constants ====================
_U64_MAX = 0xFFFFFFFFFFFFFFFF
_HEX_PATTERN = re.compile(r"^[0-9a-fA-F]+$")
_PROCESS_NAME_PATTERN = re.compile(r"^[\w.\-\s]+$")


# ==================== Exceptions ====================

class PCILeechError(Exception):
    """Base exception for PCILeech operations."""
    pass

class DeviceNotFoundError(PCILeechError):
    """Raised when PCILeech hardware device is not found."""
    pass

class MemoryAccessError(PCILeechError):
    """Raised when memory access fails."""
    pass

class SignatureNotFoundError(PCILeechError):
    """Raised when signature file is not found."""
    pass

class ProbeNotSupportedError(PCILeechError):
    """Raised when probe is not supported (non-FPGA device)."""
    pass

class KMDError(PCILeechError):
    """Raised when kernel module operation fails."""
    pass


# ==================== Helpers ====================

def parse_hex_address(value: str, name: str = "address") -> int:
    if not isinstance(value, str):
        raise PCILeechError(f"{name} must be a hex string, got {type(value).__name__}")
    s = value.strip().lower()
    if s.startswith("0x"):
        s = s[2:]
    if s.startswith("-"):
        raise PCILeechError(f"{name} cannot be negative: {value}")
    if not s or not _HEX_PATTERN.fullmatch(s):
        raise PCILeechError(f"Invalid {name} format '{value}' (expected hex like 0x1000)")
    try:
        n = int(s, 16)
    except ValueError as e:
        raise PCILeechError(f"Invalid {name} format '{value}': {e}")
    if n > _U64_MAX:
        raise PCILeechError(f"{name} exceeds 64-bit range: {value}")
    return n


def validate_process_name(name: str) -> str:
    if not name or not name.strip():
        raise PCILeechError("process_name cannot be empty")
    name = name.strip()
    if len(name) > 260:
        raise PCILeechError(f"process_name too long: {len(name)} chars (max 260)")
    if not _PROCESS_NAME_PATTERN.fullmatch(name):
        raise PCILeechError(
            f"process_name contains invalid characters: '{name}'. "
            f"Only alphanumeric, dot, underscore, hyphen, and space allowed"
        )
    return name


def format_hex_dump(data: bytes, base_addr: int) -> str:
    lines = []
    for i in range(0, len(data), 16):
        chunk = data[i:i + 16]
        addr = f"0x{base_addr + i:016x}"
        hex_part = ' '.join(f"{b:02x}" for b in chunk).ljust(47)
        ascii_part = ''.join(chr(b) if 32 <= b < 127 else '.' for b in chunk)
        lines.append(f"{addr}: {hex_part}  |{ascii_part}|")
    return '\n'.join(lines)


# ==================== Wrapper ====================

class VmmWrapper:
    """Native wrapper around memprocfs and leechcorepyc."""

    def __init__(self, config_path: str | None = None):
        if config_path is None:
            config_path = str(Path(__file__).parent / "config.json")

        try:
            with open(config_path, 'r', encoding='utf-8') as f:
                config = json.load(f)
        except FileNotFoundError:
            raise PCILeechError(f"Configuration file not found: {config_path}")
        except json.JSONDecodeError as e:
            raise PCILeechError(f"Invalid JSON in configuration file: {e}")

        self._device_type = config.get("device", {}).get("type", "fpga")
        self._remote = config.get("device", {}).get("remote", "")
        self._extra_args = config.get("device", {}).get("extra_args", [])

        self._vmm = None
        self._lc = None

    def _get_vmm(self):
        """Lazily initialize the memprocfs Vmm instance."""
        if self._vmm is None:
            try:
                import memprocfs
            except ImportError:
                raise PCILeechError(
                    "memprocfs package not installed. Run: pip install memprocfs"
                )
            args = ['-device', self._device_type]
            if self._remote:
                args.extend(['-remote', self._remote])
            args.extend(self._extra_args)
            try:
                self._vmm = memprocfs.Vmm(args)
            except Exception as e:
                raise DeviceNotFoundError(f"Failed to initialize MemProcFS: {e}")
        return self._vmm

    def _get_lc(self):
        """Lazily initialize the leechcorepyc LeechCore instance."""
        if self._lc is None:
            try:
                import leechcorepyc
            except ImportError:
                raise PCILeechError(
                    "leechcorepyc package not installed. Run: pip install leechcorepyc"
                )
            try:
                self._lc = leechcorepyc.LeechCore(self._device_type, self._remote)
            except Exception as e:
                raise DeviceNotFoundError(f"Failed to initialize LeechCore: {e}")
        return self._lc

    def _resolve_process(self, pid: int | None, process_name: str | None):
        """Resolve a process by PID or name. Returns VmmProcess."""
        if pid is not None and process_name is not None:
            raise PCILeechError("pid and process_name are mutually exclusive")
        vmm = self._get_vmm()
        if pid is not None:
            if pid <= 0:
                raise PCILeechError(f"pid must be positive, got {pid}")
            try:
                return vmm.process(pid)
            except Exception as e:
                raise PCILeechError(f"Process with PID {pid} not found: {e}")
        if process_name is not None:
            process_name = validate_process_name(process_name)
            try:
                return vmm.process(process_name)
            except Exception as e:
                raise PCILeechError(f"Process '{process_name}' not found: {e}")
        return None

    def close(self):
        if self._vmm is not None:
            try:
                self._vmm.close()
            except Exception:
                pass
            self._vmm = None
        if self._lc is not None:
            try:
                self._lc.close()
            except Exception:
                pass
            self._lc = None

    # ==================== Core Memory ====================

    def read_memory(self, address: str, length: int,
                    pid: int | None = None,
                    process_name: str | None = None) -> bytes:
        addr_int = parse_hex_address(address)
        if length < 1:
            raise PCILeechError("length must be >= 1")
        if length > 1048576:
            raise PCILeechError("length must be <= 1MB (1048576)")

        proc = self._resolve_process(pid, process_name)
        try:
            if proc is not None:
                import memprocfs
                data = proc.memory.read(addr_int, length,
                                        memprocfs.FLAG_ZEROPAD_ON_FAIL)
            else:
                vmm = self._get_vmm()
                import memprocfs
                data = vmm.memory.read(addr_int, length,
                                       memprocfs.FLAG_ZEROPAD_ON_FAIL)
        except Exception as e:
            raise MemoryAccessError(f"Memory read failed at 0x{addr_int:x}: {e}")

        return data

    def write_memory(self, address: str, data: bytes,
                     pid: int | None = None,
                     process_name: str | None = None) -> bool:
        addr_int = parse_hex_address(address)
        if not data:
            raise PCILeechError("data cannot be empty")

        proc = self._resolve_process(pid, process_name)
        try:
            if proc is not None:
                proc.memory.write(addr_int, data)
            else:
                vmm = self._get_vmm()
                vmm.memory.write(addr_int, data)
        except Exception as e:
            raise MemoryAccessError(f"Memory write failed at 0x{addr_int:x}: {e}")

        return True

    # ==================== System ====================

    def get_system_info(self, verbose: bool = False) -> dict:
        vmm = self._get_vmm()
        info = {
            'device': self._device_type,
        }

        try:
            import memprocfs
            info['version_major'] = vmm.get_config(memprocfs.OPT_WIN_VERSION_MAJOR)
            info['version_minor'] = vmm.get_config(memprocfs.OPT_WIN_VERSION_MINOR)
            info['version_build'] = vmm.get_config(memprocfs.OPT_WIN_VERSION_BUILD)
        except Exception:
            pass

        try:
            info['kernel_build'] = vmm.kernel.build
        except Exception:
            pass

        try:
            info['memmap'] = vmm.maps.memmap()
        except Exception:
            pass

        if verbose:
            try:
                lc = self._get_lc()
                import leechcorepyc
                info['fpga_id'] = lc.get_option(leechcorepyc.LC_OPT_FPGA_FPGA_ID)
                info['fpga_version_major'] = lc.get_option(
                    leechcorepyc.LC_OPT_FPGA_VERSION_MAJOR)
                info['fpga_version_minor'] = lc.get_option(
                    leechcorepyc.LC_OPT_FPGA_VERSION_MINOR)
                info['fpga_device_id'] = lc.get_option(
                    leechcorepyc.LC_OPT_FPGA_DEVICE_ID)
                info['is_fpga'] = True
            except Exception:
                info['is_fpga'] = False

        return info

    def probe_memory(self, min_addr: str = "0x0",
                     max_addr: str | None = None) -> list[dict]:
        vmm = self._get_vmm()
        try:
            memmap = vmm.maps.memmap()
        except Exception as e:
            raise ProbeNotSupportedError(f"Memory probe failed: {e}")

        regions = []
        min_int = parse_hex_address(min_addr, "min_address")
        max_int = parse_hex_address(max_addr, "max_address") if max_addr else _U64_MAX

        for entry in memmap:
            start = entry.get('pa', entry.get('address', 0))
            size = entry.get('cb', entry.get('size', 0))
            end = start + size - 1

            if end < min_int or start > max_int:
                continue

            regions.append({
                'start': f'0x{start:x}',
                'end': f'0x{end:x}',
                'size_mb': size / (1024 * 1024),
                'status': 'readable'
            })

        return regions

    def dump_memory(self, min_addr: str, max_addr: str,
                    output_file: str | None = None,
                    force: bool = False) -> dict:
        min_int = parse_hex_address(min_addr, "min_address")
        max_int = parse_hex_address(max_addr, "max_address")

        if max_int <= min_int:
            raise PCILeechError("max_address must be greater than min_address")

        size = max_int - min_int
        if size > 256 * 1024 * 1024:
            raise PCILeechError("Dump size exceeds 256MB limit")

        if output_file is None:
            output_file = f"dump_0x{min_int:x}-0x{max_int:x}.raw"

        vmm = self._get_vmm()
        import memprocfs
        flags = memprocfs.FLAG_ZEROPAD_ON_FAIL if force else 0

        try:
            data = vmm.memory.read(min_int, size, flags)
        except Exception as e:
            raise MemoryAccessError(f"Memory dump failed: {e}")

        with open(output_file, 'wb') as f:
            f.write(data)

        return {
            'min_address': f'0x{min_int:x}',
            'max_address': f'0x{max_int:x}',
            'size': len(data),
            'file': os.path.abspath(output_file),
            'success': True,
            'output': f"Dumped {len(data)} bytes to {output_file}"
        }

    def search_memory(self, pattern: str | None = None,
                      min_addr: str | None = None,
                      max_addr: str | None = None,
                      find_all: bool = False) -> list[dict]:
        if not pattern:
            raise PCILeechError("pattern must be provided")

        # Validate hex pattern
        clean = pattern.replace(' ', '')
        if not _HEX_PATTERN.fullmatch(clean):
            raise PCILeechError(f"Invalid hex pattern: {pattern}")
        if len(clean) % 2 != 0:
            raise PCILeechError("Hex pattern must have even length")

        search_bytes = bytes.fromhex(clean)
        min_int = parse_hex_address(min_addr, "min_address") if min_addr else 0
        max_int = parse_hex_address(max_addr, "max_address") if max_addr else 0x100000000

        chunk_size = 0x100000  # 1MB chunks
        matches = []

        vmm = self._get_vmm()
        import memprocfs

        addr = min_int
        while addr < max_int:
            read_size = min(chunk_size, max_int - addr)
            try:
                data = vmm.memory.read(addr, read_size,
                                       memprocfs.FLAG_ZEROPAD_ON_FAIL)
            except Exception:
                addr += read_size
                continue

            offset = 0
            while True:
                idx = data.find(search_bytes, offset)
                if idx == -1:
                    break
                match_addr = addr + idx
                context = data[idx:idx + min(32, len(data) - idx)]
                matches.append({
                    'address': f'0x{match_addr:x}',
                    'line': context.hex()
                })
                if not find_all:
                    return matches
                offset = idx + 1

            addr += read_size

        return matches

    def patch_memory(self, signature: str, min_addr: str | None = None,
                     max_addr: str | None = None,
                     patch_all: bool = False) -> dict:
        raise PCILeechError(
            "Signature-based patching requires .sig files and is not yet "
            "supported in the native Linux version. Use memory_search + "
            "memory_write for manual patching."
        )

    def list_processes(self) -> list[dict]:
        vmm = self._get_vmm()
        processes = []
        try:
            for proc in vmm.process_list():
                processes.append({
                    'pid': proc.pid,
                    'ppid': proc.ppid,
                    'name': proc.name,
                    'state': proc.state,
                    'dtb': f'0x{proc.dtb:x}',
                    'is_usermode': proc.is_usermode,
                })
        except Exception as e:
            raise PCILeechError(f"Process list failed: {e}")

        return processes

    # ==================== Address Translation ====================

    def translate_virt2phys(self, virt_addr: str, cr3: str | None = None,
                           pid: int | None = None) -> dict:
        virt_int = parse_hex_address(virt_addr, "virtual_address")

        if pid is not None:
            proc = self._resolve_process(pid, None)
            try:
                phys = proc.memory.virt2phys(virt_int)
                return {
                    'virtual': f'0x{virt_int:x}',
                    'physical': f'0x{phys:x}',
                    'pid': pid,
                    'success': True,
                    'error': None
                }
            except Exception as e:
                return {
                    'virtual': f'0x{virt_int:x}',
                    'physical': None,
                    'pid': pid,
                    'success': False,
                    'error': str(e)
                }

        if cr3 is None:
            raise PCILeechError("Either cr3 or pid must be provided")

        cr3_int = parse_hex_address(cr3, "cr3")
        # Use low-level LeechCore for CR3-based translation
        # Read page table entries manually
        return {
            'virtual': f'0x{virt_int:x}',
            'cr3': f'0x{cr3_int:x}',
            'physical': None,
            'success': False,
            'error': 'CR3-based translation requires pid-based lookup via memprocfs. '
                     'Use process_virt2phys with a PID instead.'
        }

    def process_virt2phys(self, pid: int, virt_addr: str) -> dict:
        virt_int = parse_hex_address(virt_addr, "virtual_address")

        if not isinstance(pid, int) or pid <= 0:
            raise PCILeechError(f"pid must be a positive integer, got {pid}")

        proc = self._resolve_process(pid, None)
        try:
            phys = proc.memory.virt2phys(virt_int)
            return {
                'pid': pid,
                'virtual': f'0x{virt_int:x}',
                'physical': f'0x{phys:x}',
                'dtb': f'0x{proc.dtb:x}',
                'success': True,
                'error': None
            }
        except Exception as e:
            return {
                'pid': pid,
                'virtual': f'0x{virt_int:x}',
                'physical': None,
                'success': False,
                'error': str(e)
            }

    # ==================== Module Enumeration ====================

    def list_modules(self, pid: int | None = None,
                     process_name: str | None = None) -> list[dict]:
        proc = self._resolve_process(pid, process_name)
        if proc is None:
            raise PCILeechError("pid or process_name is required")

        modules = []
        try:
            for mod in proc.module_list():
                modules.append({
                    'name': mod.name,
                    'base': f'0x{mod.base:x}',
                    'size': f'0x{mod.image_size:x}',
                    'image_size': mod.image_size,
                    'fullname': mod.fullname,
                    'is_wow64': mod.is_wow64,
                })
        except Exception as e:
            raise PCILeechError(f"Module list failed: {e}")

        return modules

    # ==================== FPGA / Advanced ====================

    def benchmark(self, test_type: str = "read",
                  address: str = "0x1000") -> dict:
        addr_int = parse_hex_address(address)
        lc = self._get_lc()

        iterations = 1000
        chunk_size = 4096

        # Read benchmark
        start = time.perf_counter()
        for _ in range(iterations):
            try:
                lc.read(addr_int, chunk_size)
            except Exception:
                pass
        read_elapsed = time.perf_counter() - start
        read_mbps = (iterations * chunk_size / (1024 * 1024)) / read_elapsed

        result = {
            'test_type': test_type,
            'address': f'0x{addr_int:x}',
            'read_iterations': iterations,
            'read_chunk_size': chunk_size,
            'read_elapsed_s': round(read_elapsed, 3),
            'read_mbps': round(read_mbps, 2),
        }

        if test_type in ("readwrite", "full"):
            test_data = b'\x00' * chunk_size
            start = time.perf_counter()
            for _ in range(iterations):
                try:
                    lc.write(addr_int, test_data)
                except Exception:
                    pass
            write_elapsed = time.perf_counter() - start
            write_mbps = (iterations * chunk_size / (1024 * 1024)) / write_elapsed
            result['write_iterations'] = iterations
            result['write_elapsed_s'] = round(write_elapsed, 3)
            result['write_mbps'] = round(write_mbps, 2)

        return result

    def tlp_send(self, tlp_data: str | None = None,
                 wait_seconds: float = 0.5,
                 verbose: bool = True) -> dict:
        lc = self._get_lc()
        import leechcorepyc

        result = {
            'sent': False,
            'received_tlps': [],
        }

        # Send TLP if data provided
        if tlp_data:
            clean = tlp_data.replace(' ', '')
            if not _HEX_PATTERN.fullmatch(clean) or len(clean) % 2 != 0:
                raise PCILeechError(f"Invalid TLP hex data: {tlp_data}")
            raw_tlp = bytes.fromhex(clean)
            try:
                lc.tlp_write([raw_tlp])
                result['sent'] = True
                result['sent_bytes'] = len(raw_tlp)
                if verbose:
                    try:
                        result['sent_info'] = lc.tlp_tostring(raw_tlp)
                    except Exception:
                        pass
            except Exception as e:
                raise PCILeechError(f"TLP send failed: {e}")

        # Listen for TLP responses
        received = []

        def tlp_callback(tlp_bytes, tlp_str_info):
            entry = {'data': tlp_bytes.hex()}
            if verbose:
                entry['info'] = tlp_str_info
            received.append(entry)

        try:
            lc.tlp_read(tlp_callback, False, True)
            time.sleep(wait_seconds)
        except Exception as e:
            raise PCILeechError(f"TLP receive failed: {e}")

        result['received_tlps'] = received
        return result

    def fpga_config(self, action: str = "read",
                    address: str | None = None,
                    data: str | None = None,
                    output_file: str | None = None) -> dict:
        lc = self._get_lc()
        import leechcorepyc

        if action == "read":
            try:
                cfg = lc.command_data(leechcorepyc.LC_CMD_FPGA_PCIECFGSPACE)
            except Exception as e:
                raise PCILeechError(f"FPGA config read failed: {e}")

            result = {
                'action': 'read',
                'size': len(cfg),
                'data_hex': cfg.hex(),
                'success': True,
            }

            if output_file:
                with open(output_file, 'wb') as f:
                    f.write(cfg)
                result['file'] = os.path.abspath(output_file)

            return result

        elif action == "write":
            if not data:
                raise PCILeechError("data is required for write action")
            if address is None:
                raise PCILeechError("address is required for write action")

            addr_int = parse_hex_address(address, "address")
            clean = data.replace(' ', '')
            if not _HEX_PATTERN.fullmatch(clean) or len(clean) % 2 != 0:
                raise PCILeechError(f"Invalid hex data: {data}")
            write_bytes = bytes.fromhex(clean)

            try:
                lc.command_data(
                    leechcorepyc.LC_CMD_FPGA_CFGREGPCIE | addr_int,
                    write_bytes
                )
            except Exception as e:
                raise PCILeechError(f"FPGA config write failed: {e}")

            return {
                'action': 'write',
                'address': f'0x{addr_int:x}',
                'bytes_written': len(write_bytes),
                'success': True,
            }

        else:
            raise PCILeechError(f"Unknown action: {action}. Use 'read' or 'write'.")
