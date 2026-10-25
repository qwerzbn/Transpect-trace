"""Read only fixed, exported counters from a verified collector module."""
from pathlib import Path

COUNTERS = ('begin_lock', 'context_unavailable', 'capture_alloc', 'node_alloc',
            'queue_capacity', 'sspi', 'transport', 'queue_abandoned', 'total')


def snapshot(subject, dll, expected_sha256):
    import ctypes as c
    from ctypes import wintypes as w
    from transpect_trace.observe.windows import identity, modules, exports, digest
    from transpect_trace.guard.native import api
    unavailable = {'state': 'unavailable', 'can_enforce': False}
    try:
        dll = Path(dll).resolve()
        if not expected_sha256 or digest(dll) != expected_sha256:
            return unavailable
        current = identity(subject['pid'])
        if any(current[k] != subject[k] for k in ('creation_filetime', 'image_sha256')):
            return unavailable
        loaded = next((m for m in modules(subject['pid']) if Path(m['path']).resolve() == dll), None)
        symbols = exports(dll)
        names = {key: symbols.get('ecapture_loss_' + key) for key in COUNTERS}
        if not loaded or not all(names.values()):
            return unavailable
        kernel = api()
        handle = kernel.OpenProcess(0x1000 | 0x10, False, subject['pid'])
        if not handle: return unavailable
        try:
            reader = c.WinDLL('kernel32', use_last_error=True)
            reader.ReadProcessMemory.argtypes = [w.HANDLE, c.c_void_p, c.c_void_p, c.c_size_t, c.POINTER(c.c_size_t)]
            counters = {}
            for name, rva in names.items():
                if not 0 <= rva < loaded['size']: return unavailable
                value, count = c.c_longlong(), c.c_size_t()
                if not reader.ReadProcessMemory(handle, loaded['base']+rva, c.byref(value), 8, c.byref(count)) or count.value != 8 or value.value < 0:
                    return unavailable
                counters[name] = value.value
            current = identity(subject['pid'])
            if any(current[k] != subject[k] for k in ('creation_filetime', 'image_sha256')):
                return unavailable
            return {'state': 'observed', 'counters': counters, 'collector_module_sha256': expected_sha256,
                    'memory_read_scope': 'fixed_exported_int64_counters', 'can_enforce': False}
        finally:
            kernel.CloseHandle(handle)
    except (OSError, ValueError, KeyError):
        return unavailable
