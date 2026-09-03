import tempfile
import unittest
from pathlib import Path
from license_notices import copy_notices, preserved_notice, NOTICES, NOTICE_DIR
from policy import url_hits


class LicenseNoticeTests(unittest.TestCase):
    def test_notice_urls_remain_intact_and_tampering_is_rejected(self):
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            copy_notices(root)
            for name, upstream in NOTICES.items():
                self.assertEqual((root/name).read_bytes(), (NOTICE_DIR/upstream).read_bytes())
                self.assertTrue(preserved_notice(root/name, root))
            target = root/'duilib license.txt'
            self.assertTrue(url_hits(target.read_bytes()))
            target.write_bytes(target.read_bytes().replace(b'https://', b'about://'))
            with self.assertRaises(ValueError):
                preserved_notice(target, root)

    def test_same_name_in_another_directory_is_not_exempt(self):
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            path = root/'untrusted'/'duilib license.txt'
            self.assertFalse(preserved_notice(path, root))
