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

