"""Regression checks for launcher cleanup after an early UI crash."""
from pathlib import Path
import unittest


SOURCE = (Path(__file__).with_name('launcher.c')).read_text(encoding='utf-8')


class LauncherCleanupTests(unittest.TestCase):
    def test_service_rights_are_requested_in_separate_handles(self):
        # Requesting DELETE together with QUERY/STOP makes OpenService fail for
        # users who may stop the Everything service but may not delete it. In
        # that case none of the cleanup ran after HuoChat crashed.
        combined = 'SERVICE_QUERY_CONFIG|SERVICE_QUERY_STATUS|SERVICE_STOP|SVC_DELETE'
        self.assertNotIn(combined, SOURCE)
        self.assertIn('OpenServiceW(scm,L"Everything",SERVICE_QUERY_CONFIG)', SOURCE)
        self.assertIn('OpenServiceW(scm,L"Everything",SERVICE_QUERY_STATUS|SERVICE_STOP)', SOURCE)
        self.assertIn('OpenServiceW(scm,L"Everything",SVC_DELETE)', SOURCE)


if __name__ == '__main__':
    unittest.main()
