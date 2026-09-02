"""Static regression tests for removal of disabled ZIPRES UI assets."""
import io
import unittest
import zipfile

from PIL import Image
from build import REMOVED_UI_RESOURCES, compact_guide_gif, clean_zip


def fixture(omit=None):
    out = io.BytesIO()
    with zipfile.ZipFile(out, 'w', zipfile.ZIP_DEFLATED) as z:
        for name in sorted(REMOVED_UI_RESOURCES):
            if name != omit:
                z.writestr(name, b'not-executed-test-data')
        z.writestr('kept/local-search.png', b'keep')
    return out.getvalue()


class RemovedUiResourceTests(unittest.TestCase):
    def test_guide_keeps_complete_final_frame_and_canvas(self):
        frames=[Image.new('RGB',(1000,600),color) for color in ('red','green','blue')]
        source=io.BytesIO()
        frames[0].save(source,format='GIF',save_all=True,append_images=frames[1:],duration=100)
        result=compact_guide_gif(source.getvalue())
        self.assertLess(len(result),len(source.getvalue()))
        with Image.open(io.BytesIO(result)) as image:
            self.assertEqual('GIF',image.format)
            self.assertEqual((1000,600),image.size)
            self.assertEqual(1,image.n_frames)
            self.assertEqual((0,0,255),image.convert('RGB').getpixel((500,300)))

    def test_guide_rejects_unexpected_canvas(self):
        source=io.BytesIO()
        Image.new('RGB',(10,10)).save(source,format='GIF')
        with self.assertRaises(ValueError): compact_guide_gif(source.getvalue())

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
