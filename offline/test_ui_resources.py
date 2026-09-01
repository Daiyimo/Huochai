"""Static regression tests for removal of disabled ZIPRES UI assets."""
import io
import unittest
import zipfile

from build import REMOVED_UI_RESOURCES, clean_zip


def fixture(omit=None):
    out = io.BytesIO()
    with zipfile.ZipFile(out, 'w', zipfile.ZIP_DEFLATED) as z:
        for name in sorted(REMOVED_UI_RESOURCES):
            if name != omit:
                z.writestr(name, b'not-executed-test-data')
        z.writestr('kept/local-search.png', b'keep')
    return out.getvalue()


class RemovedUiResourceTests(unittest.TestCase):
    def test_startup_preload_resource_is_preserved(self):
        # The startup icon preload loop dereferences the loader result without
        # checking it. Removing this file crashes at HuoChat+0x1A4169 before
        # the main window can be shown.
        self.assertNotIn('add_nav.png', REMOVED_UI_RESOURCES)

    def test_exact_inventory_is_57_entries(self):
        self.assertEqual(57, len(REMOVED_UI_RESOURCES))

    def test_clean_zip_removes_exact_inventory(self):
        cleaned, edits, removed = clean_zip(fixture())
        self.assertEqual([], edits)
        self.assertEqual(REMOVED_UI_RESOURCES, set(removed))
        with zipfile.ZipFile(io.BytesIO(cleaned)) as z:
            self.assertEqual(['kept/local-search.png'], z.namelist())
            self.assertEqual(b'keep', z.read('kept/local-search.png'))

    def test_source_drift_fails_closed(self):
        missing = next(iter(REMOVED_UI_RESOURCES))
        with self.assertRaises(ValueError):
            clean_zip(fixture(omit=missing))


if __name__ == '__main__':
    unittest.main()
