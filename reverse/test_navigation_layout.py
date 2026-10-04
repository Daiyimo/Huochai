import json
import unittest
from navigation_layout import clean_navigation_layout


class NavigationLayoutTests(unittest.TestCase):
    def test_remove_default_web_tiles_and_pack_four_local_tools(self):
        original={'items':[{'type':3,'x':7,'y':3,'text1':'添加'},
            *({'type':1 if name!='blog' else 8,'icon':'tinynavigation/icon/'+name+'.png'}
              for name in ('baidu','hao123','360','blog')),
            *({'type':kind,'x':i,'y':1,'text1':name} for i,(kind,name) in
              enumerate(zip((4,7,5,6),('我的电脑','记事本','截图','计算器'))))]}
        result=clean_navigation_layout(json.dumps(original).encode())
        items=json.loads(result)['items']
        self.assertEqual([item['text1'] for item in items],['添加','我的电脑','记事本','截图','计算器'])
        self.assertEqual([(item['x'],item['y']) for item in items[1:]],[(0,0),(1,0),(2,0),(3,0)])
        self.assertEqual(clean_navigation_layout(result),result)

    def test_custom_shortcuts_and_metadata_are_preserved(self):
        custom={'type':0,'path':'D:\\Tools\\mine.exe','x':4,'y':2,'custom':{'key':'keep'}}
        original={'items':[custom,{'type':1,'icon':'tinynavigation/icon/baidu.png'}],'unknown':'retain'}
        self.assertEqual(json.loads(clean_navigation_layout(json.dumps(original).encode())),
                         {'items':[custom],'unknown':'retain'})

    def test_the_byte_order_mark_of_the_input_is_preserved(self):
        """Both branches must answer the same question from the same bytes.

        The early return hands the original file back untouched, so it kept a
        UTF-8 BOM while the rewrite dropped it. That made "was this file edited
        by this build?" unanswerable from the bytes alone, and let the
        idempotence test above pass while the two shapes still differed.
        """
        layout={'items':[{'type':1,'icon':'tinynavigation/icon/baidu.png'},
                         {'type':4,'x':9,'y':9,'text1':'我的电脑'}],'unknown':'retain'}
        body=json.dumps(layout,ensure_ascii=False).encode('utf-8')
        for raw in (body, b'\xef\xbb\xbf'+body):
            result=clean_navigation_layout(raw)
            self.assertTrue(result.startswith(raw[:3]),
                            'the BOM of the input must survive the rewrite')
            self.assertEqual(raw[:3], result[:3])
            # Rewriting again must be a no-op, not a second, BOM-less rewrite.
            self.assertEqual(result, clean_navigation_layout(result))

    def test_a_file_that_needs_no_change_is_returned_verbatim(self):
        layout={'items':[{'type':1,'icon':'tinynavigation/icon/keep.png'}],'unknown':'retain'}
        raw=json.dumps(layout).encode('utf-8')
        self.assertEqual(raw, clean_navigation_layout(raw))

