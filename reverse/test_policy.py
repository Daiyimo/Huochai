import unittest
from policy import BARE_DENYLIST, scrub_urls, url_hits

class PolicyTests(unittest.TestCase):
    def test_utf16_and_ascii_with_duplicate_domains(self):
        raw = b'huoying666.com.png\0https://stats.huochaipro.com/stats/log\0' + 'https://jf.huoying666.com/api/user/check-login'.encode('utf-16le') + b'\0\0'
        # The resource name embeds a business host, so it is a finding too. The
        # stub inside it is a separate match, so more edits than findings is
        # correct here: both layers are removed.
        self.assertEqual(3, len(url_hits(raw)))
        patched, edits = scrub_urls(raw)
        self.assertGreaterEqual(len(edits), len(url_hits(raw)))
        self.assertEqual(len(raw), len(patched))
        self.assertEqual([], url_hits(patched))
        self.assertNotIn(b'huoying', patched)
        self.assertNotIn(b'huochaipro', patched)

    def test_encoded_host_is_detected_only_when_it_decodes_to_a_url(self):
        import base64
        for host in (b'https://jf.huoying666.com', b'http://cp3.huoying666.com'):
            token = base64.b64encode(host)
            hits = url_hits(token)
            self.assertEqual(1, len(hits), token)
            self.assertIn('->', hits[0]['value'])
        # Base64-shaped data that is not a URL must stay untouched.
        noise = base64.b64encode(b'\x00\x01\x02\x03' * 8)
        self.assertEqual([], url_hits(noise))

    def test_bare_domain_ignores_source_filenames_and_metadata(self):
        for probe in (b'win.cc', b'reflection.pb.cc', b'type.googleapis.com',
                      b'carpenter@voidtools.com', b'plugins\\icon_pan.png'):
            self.assertEqual([], url_hits(probe), probe)

    def test_bare_domain_catches_schemeless_business_host(self):
        for probe in (b'update.huorong.cn', b'stats.huochaipro.com',
                      b'j.huoying666.com', b'pan.baidu.com'):
            hits = url_hits(probe)
            self.assertEqual(1, len(hits), probe)
            self.assertTrue(any(d in hits[0]['value'] for d in BARE_DENYLIST), probe)

    def test_scrub_applies_all_edits_after_a_length_changing_substitution(self):
        """A shortening replacement must not invalidate later offsets.

        The URL pattern shortens the text, so any finding after it used to be
        dropped because the offsets were computed against the original bytes.
        """
        raw = ('说明: 输入"123"即可进入: https://www.hao123.com" '
               'width="685"/> 如: "sc huoying"即可').encode('utf-8')
        confirmed = {h['offset'] for h in url_hits(raw)}
        self.assertIn('https://www.hao123.com', {h['value'] for h in url_hits(raw)})
        self.assertTrue(any(h['value'] == 'huoying' for h in url_hits(raw)), raw)
        patched, edits = scrub_urls(raw, fixed_size=False, only=confirmed)
        self.assertEqual([], url_hits(patched))
        self.assertNotIn(b'huoying', patched)
        self.assertNotIn(b'hao123.com', patched)
        self.assertEqual(len(confirmed), len(edits))

    def test_query_template_and_loopback_are_not_exempt(self):
        raw = b'"https://%s/path?q=%s" http://127.0.0.1/api/offline\0ftp://host/C:/test'
        patched, edits = scrub_urls(raw)
        self.assertEqual(3, len(edits))
        self.assertEqual([], url_hits(patched))

    def test_xml_attribute_keeps_quote_and_is_well_formed(self):
        import xml.etree.ElementTree as ET
        raw = b'<root text="https://www.baidu.com/s?wd=%s" />'
        patched, edits = scrub_urls(raw, fixed_size=False)
        root = ET.fromstring(patched)
        self.assertEqual('about:blank', root.attrib['text'])
        self.assertNotIn(b'\0', patched)

    def test_bare_protocol_is_not_a_full_url(self):
        self.assertEqual([], url_hits(b'http://\0https://\0'))

    def test_url_inside_sql_does_not_truncate_statement(self):
        import sqlite3
        source=b"SELECT 'https://example.invalid/' AS url, 42 AS answer"
        patched,_=scrub_urls(source)
        with sqlite3.connect(':memory:') as con:
            row=con.execute(patched.decode()).fetchone()
        self.assertEqual(42,row[1])
        self.assertEqual('about:blank',row[0].strip())

    def test_license_surrounding_words_are_preserved(self):
        patched,_=scrub_urls(b'license (https://example.invalid/project).All rights.',fixed_size=False)
        self.assertEqual(b'license (about:blank).All rights.',patched)

    def test_schemeless_www_and_non_http_url(self):
        source=b'www.voidtools.com\0ldap://example.invalid\0'+ 'www.example.invalid/help'.encode('utf-16le')
        patched,edits=scrub_urls(source)
        # Overlapping matches (www host inside a bare host) collapse to one edit
        # per region, so assert the outcome rather than a raw edit count.
        self.assertGreaterEqual(len(edits),2)
        self.assertEqual([],url_hits(patched))
        self.assertNotIn(b'voidtools',patched)
        self.assertNotIn(b'example.invalid',patched)
        self.assertEqual(len(source),len(patched))

if __name__ == '__main__':
    unittest.main()
