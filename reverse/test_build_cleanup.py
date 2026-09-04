import ctypes
from ctypes import wintypes
from pathlib import Path
import tempfile
import threading
import time
import unittest

from build import cleanup_build_dir


@unittest.skipUnless(__import__('os').name == 'nt', 'Windows handle semantics required')
class BuildCleanupTests(unittest.TestCase):
    def test_cleanup_waits_for_a_transient_exclusive_executable_handle(self):
        root = Path(tempfile.mkdtemp(prefix='huochai_offline_build_'))
        target = root/'recently-executed.exe'
        target.write_bytes(b'MZ benchmark fixture')
        kernel = ctypes.WinDLL('kernel32', use_last_error=True)
        kernel.CreateFileW.argtypes = [wintypes.LPCWSTR, wintypes.DWORD, wintypes.DWORD,
                                       ctypes.c_void_p, wintypes.DWORD, wintypes.DWORD, wintypes.HANDLE]
        kernel.CreateFileW.restype = wintypes.HANDLE
        kernel.CloseHandle.argtypes = [wintypes.HANDLE]
        handle = kernel.CreateFileW(str(target), 0x80000000, 0, None, 3, 0, None)
        self.assertNotIn(handle, (None, ctypes.c_void_p(-1).value))

        def release():
            time.sleep(5.5)
            kernel.CloseHandle(handle)

        worker = threading.Thread(target=release, daemon=True)
        worker.start()
        cleanup_build_dir(root)
        worker.join(timeout=2)
        self.assertFalse(root.exists())


if __name__ == '__main__':
    unittest.main()
