"""Remove the four obsolete default tiles while preserving user shortcuts."""
import json

REMOVED_ICONS=frozenset('tinynavigation/icon/'+name+'.png' for name in
                       ('baidu','hao123','360','blog'))
LOCAL_TYPES=(4,7,5,6)  # My Computer, Notepad, Screenshot, Calculator


def clean_navigation_layout(raw):
    document=json.loads(raw.decode('utf-8-sig'))
    # The input may or may not carry a UTF-8 BOM. Preserve whichever it had so
    # the rewritten file is byte-comparable with the untouched one: otherwise
    # "did this build change the layout?" cannot be answered from the bytes.
    bom=raw[:3] if raw[:3]==b'\xef\xbb\xbf' else b''
    if not isinstance(document,dict) or not isinstance(document.get('items'),list):
        raise ValueError('Unrecognised navigation layout')
    items=document['items']
    if any(not isinstance(item,dict) for item in items):
        raise ValueError('Invalid navigation item')
    kept=[item for item in items if not (item.get('icon') in REMOVED_ICONS and
                                       item.get('type') in (1,8))]
    if len(kept)==len(items): return raw
    # Keep customised coordinates if the user added any other shortcuts.
    local=[item for item in kept if item.get('type')!=3]
    if len(local)==4 and {item.get('type') for item in local}==set(LOCAL_TYPES):
        for item in local:
            item['x']=LOCAL_TYPES.index(item['type']);item['y']=0
    document['items']=kept
    return bom+json.dumps(document,ensure_ascii=True,separators=(',',':')).encode('utf-8')

