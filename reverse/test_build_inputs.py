import hashlib
from pathlib import Path
import tempfile
import unittest
from build_inputs import ROOT, require_input, private_output


class BuildInputTests(unittest.TestCase):
    def test_missing_and_changed_inputs_fail_before_use(self):
        with tempfile.TemporaryDirectory() as directory:
            path = Path(directory)/'fixture.bin'
            digest = hashlib.sha256(b'fixture').hexdigest()
            with self.assertRaises(FileNotFoundError):
                require_input(path, digest)
            path.write_bytes(b'fixture')
            self.assertEqual(path, require_input(path, digest))
            path.write_bytes(b'changed')
            with self.assertRaises(ValueError):
                require_input(path, digest)

    def test_repository_outputs_must_stay_private(self):
        self.assertEqual((ROOT/'.local/demo').resolve(), private_output(ROOT/'.local/demo'))
        for path in (ROOT/'releases', ROOT/'.local/../releases'):
            with self.assertRaises(ValueError):
                private_output(path)
