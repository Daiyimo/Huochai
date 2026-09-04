import tempfile
import unittest
from pathlib import Path
import ctypes

from shutdown_checks import executable_in_root,read_pid


class ShutdownCheckTests(unittest.TestCase):
    def test_pid_reader_treats_the_truncate_write_window_as_not_ready(self):
        with tempfile.TemporaryDirectory() as directory:
            path=Path(directory)/'engine.ready'
            self.assertIsNone(read_pid(path))
            path.write_text('')
            self.assertIsNone(read_pid(path))
            path.write_text('not-a-pid')
            self.assertIsNone(read_pid(path))
            path.write_text('12345')
            self.assertEqual(read_pid(path),12345)

    def test_process_path_containment_normalizes_windows_short_names(self):
        with tempfile.TemporaryDirectory() as directory:
            root=Path(directory);child=root/'fixture.exe';child.write_bytes(b'MZ')
            self.assertTrue(executable_in_root(child,root))
            buffer=ctypes.create_unicode_buffer(32768)
            length=ctypes.windll.kernel32.GetShortPathNameW(str(child),buffer,len(buffer))
            if length and buffer.value.casefold()!=str(child).casefold():
                self.assertTrue(executable_in_root(buffer.value,root))
            self.assertFalse(executable_in_root(root.parent/'foreign.exe',root))


if __name__=='__main__':
    unittest.main()
