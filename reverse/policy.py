"""Static network policy. Targets are data, never imported or executed."""
import base64 as _b64
import re

NETWORK_DLLS = {
    'wininet.dll', 'winhttp.dll', 'ws2_32.dll', 'wsock32.dll', 'urlmon.dll',
    'dnsapi.dll', 'netapi32.dll', 'iphlpapi.dll', 'httpapi.dll', 'webio.dll',
    'rasapi32.dll', 'wldap32.dll', 'sensapi.dll', 'mpr.dll',
    'schannel.dll', 'secur32.dll', 'ncrypt.dll', 'davclnt.dll',
    'nlaapi.dll', 'netiohlp.dll', 'wsnmp32.dll', 'winrnr.dll',
}
GUARDED_DLLS = {'kernel32.dll', 'shell32.dll', 'ole32.dll', 'advapi32.dll', 'shlwapi.dll'}
# Refused at load time rather than stubbed, so legacy code cannot call absent
# wke/COM exports through a fake handle.
INTENTIONALLY_ABSENT = {'node.dll', 'mshtml.dll', 'msxml.dll', 'ieframe.dll'}
# Fixed x86 stdcall argument sizes and failure values, from installed Windows SDK.
# Returning the right sentinel AND popping the right stack size is essential.
NETWORK_APIS = {
    'WSAGetLastError': (0, 10013), 'WSASetLastError': (4, 0),
    'WSAStartup': (8, 10091), 'WSACleanup': (0, -1),
    'socket': (12, -1), 'WSASocketA': (24, -1), 'WSASocketW': (24, -1),
    'connect': (12, -1), 'WSAConnect': (28, -1), 'bind': (12, -1),
    'listen': (8, -1), 'accept': (12, -1), 'closesocket': (4, -1),
    'send': (16, -1), 'recv': (16, -1), 'sendto': (24, -1), 'recvfrom': (24, -1),
    'shutdown': (8, -1), 'select': (20, -1), 'setsockopt': (20, -1),
    'getsockopt': (20, -1), 'getpeername': (12, -1), 'getsockname': (12, -1),
    'gethostname': (8, -1), 'gethostbyname': (4, 0), 'gethostbyaddr': (12, 0),
    'getaddrinfo': (16, 11001), 'GetAddrInfoW': (16, 11001),
    'getnameinfo': (28, 11001), 'GetNameInfoW': (28, 11001),
    'freeaddrinfo': (4, 0), 'FreeAddrInfoW': (4, 0),
    'inet_addr': (4, -1), 'inet_ntoa': (4, 0),
    'htons': (4, 0), 'ntohs': (4, 0), 'htonl': (4, 0), 'ntohl': (4, 0),
    'WSAAsyncSelect': (16, -1), 'WSAEventSelect': (12, -1), 'ioctlsocket': (12, -1),
    'WSAIoctl': (36, -1), 'WSASend': (28, -1), 'WSARecv': (28, -1),
    'WSASendTo': (36, -1), 'WSARecvFrom': (36, -1),
    'InternetOpenA': (20, 0), 'InternetOpenW': (20, 0),
    'InternetConnectA': (32, 0), 'InternetConnectW': (32, 0),
    'InternetOpenUrlA': (24, 0), 'InternetOpenUrlW': (24, 0),
    'InternetCloseHandle': (4, 0), 'InternetReadFile': (16, 0),
    'InternetReadFileExA': (16, 0), 'InternetReadFileExW': (16, 0),
    'InternetWriteFile': (16, 0), 'InternetQueryOptionA': (16, 0),
    'InternetQueryOptionW': (16, 0), 'InternetSetOptionA': (16, 0),
    'InternetSetOptionW': (16, 0), 'InternetGetLastResponseInfoA': (12, 0),
    'InternetGetLastResponseInfoW': (12, 0), 'InternetSetStatusCallbackA': (8, -1),
    'InternetSetStatusCallbackW': (8, -1), 'InternetCrackUrlA': (16, 0),
    'InternetCrackUrlW': (16, 0), 'InternetSetCookieA': (12, 0),
    'InternetSetCookieW': (12, 0), 'InternetCheckConnectionA': (12, 0),
    'InternetCheckConnectionW': (12, 0), 'InternetGetConnectedState': (8, 0),
    'HttpOpenRequestA': (32, 0), 'HttpOpenRequestW': (32, 0),
    'HttpAddRequestHeadersA': (16, 0), 'HttpAddRequestHeadersW': (16, 0),
    'HttpSendRequestA': (20, 0), 'HttpSendRequestW': (20, 0),
    'HttpSendRequestExA': (20, 0), 'HttpSendRequestExW': (20, 0),
    'HttpEndRequestA': (16, 0), 'HttpEndRequestW': (16, 0),
    'HttpQueryInfoA': (20, 0), 'HttpQueryInfoW': (20, 0),
    'FtpOpenFileA': (20, 0), 'FtpOpenFileW': (20, 0),
    'FtpCommandA': (24, 0), 'FtpCommandW': (24, 0), 'FtpGetFileSize': (8, -1),
    'URLDownloadToFileA': (20, 0x800C0008), 'URLDownloadToFileW': (20, 0x800C0008),
    'URLOpenBlockingStreamA': (20, 0x800C0008), 'URLOpenBlockingStreamW': (20, 0x800C0008),
    'WinHttpOpen': (20, 0), 'WinHttpConnect': (16, 0),
    'WinHttpOpenRequest': (28, 0), 'WinHttpSendRequest': (28, 0),
    'WinHttpReceiveResponse': (8, 0), 'WinHttpReadData': (16, 0),
    'WinHttpWriteData': (16, 0), 'WinHttpCloseHandle': (4, 0),
    'Netbios': (4, 0x34),
    # SensApi is a live import whose result is never consumed; denying it keeps
    # the import table uniform and removes the last unguarded network sense API.
    'IsNetworkAlive': (8, 0),
}

# Match full network URLs (including templates), not bare protocol tokens.
ASCII_URL = re.compile(rb'(?i)[a-z][a-z0-9+.-]{1,20}://[^\x00-\x20<>"\'()\x7f-\xff]+')
WIDE_URL = re.compile(rb'(?i)(?:[a-z]\x00)(?:[a-z0-9+.-]\x00){1,20}:\x00/\x00/\x00(?:[^\x00-\x20<>"\'()\x7f-\xff]\x00)+')
ASCII_WWW = re.compile(rb'(?i)\bwww\.(?:[a-z0-9-]+\.)+[a-z]{2,}(?:/[^\x00-\x20<>"\'()\x7f-\xff]*)?')
WIDE_WWW = re.compile(rb'(?i)w\x00w\x00w\x00\.\x00(?:(?:[a-z0-9-]\x00)+\.\x00)+(?:[a-z]\x00){2,}(?:/\x00(?:[^\x00-\x20<>"\'()\x7f-\xff]\x00)*)?')
PATTERNS = [
    (WIDE_URL, 'utf-16le'), (ASCII_URL, 'ascii'),
    (WIDE_WWW, 'utf-16le'), (ASCII_WWW, 'ascii'),
]
# A bare hostname only counts as a network address at an exact host boundary;
# otherwise resource names such as "huoying666.com.png" would be reported.
# Only real registrable suffixes are listed: source/build suffixes such as .cc,
# .io and .ai collide with C++ and language filenames inside these binaries.
_TLD = rb'(?:com|net|org|cn|gov|edu|co|me|app|xyz|top|vip|cc|tv|info|biz)'
BARE_DOMAIN = re.compile(rb'(?i)(?<![a-z0-9.\-])(?:[a-z0-9](?:[a-z0-9\-]*[a-z0-9])?\.)+' + _TLD + rb'(?![a-z0-9\-])')
WIDE_DOMAIN = re.compile(
    rb'(?i)(?<![a-z0-9.\-]\x00)(?:(?:[a-z0-9]\x00)(?:(?:[a-z0-9\-]\x00)*[a-z0-9]\x00)?\.\x00)+'
    rb'(?:c\x00o\x00m\x00|n\x00e\x00t\x00|o\x00r\x00g\x00|c\x00n\x00|g\x00o\x00v\x00|'
    rb'e\x00d\x00u\x00|c\x00o\x00|m\x00e\x00|a\x00p\x00p\x00|x\x00y\x00z\x00|'
    rb't\x00o\x00p\x00|v\x00i\x00p\x00|c\x00c\x00|t\x00v\x00|i\x00n\x00f\x00o\x00|b\x00i\x00z\x00)'
    rb'(?![a-z0-9\-]\x00)')
# base64 carries no NUL bytes, so an encoded host survives the earlier plaintext
# sweep. Only report a token when its decoded form actually contains a URL.
B64_ASCII = re.compile(rb'(?<![A-Za-z0-9+/=])[A-Za-z0-9+/]{24,}={0,2}(?![A-Za-z0-9+/=])')
B64_WIDE = re.compile(rb'(?:(?<![A-Za-z0-9+/=]\x00)[A-Za-z0-9+/]\x00){24,}={0,2}(?![A-Za-z0-9+/=]\x00)')

# A bare hostname is not by itself a network address: these binaries are full of
# source filenames ("win.cc"), protobuf type URLs ("type.googleapis.com") and
# library identifiers that merely look like hosts. Only the entries below are
# confirmed business endpoints, so the general bare-domain rule stays advisory.
BARE_DENYLIST = (
    'huochaipro.com', 'huoying666.com', 'baidu.com', 'baiduwp.com',
    'voidtools.com', 'w3.org', 'google.com', 'googleprod.com',
    'huorong.cn', 'hao123.com', 'taobao.com', 'jd.com', 'zhihu.com',
    'bilibili.com', 'bing.com',
)
# Brand stubs that survive without their TLD, e.g. the base64 tool's help text
# reads "base64 en huoying666". These are UI examples, not addresses, but the
# business trace is still removed so no endpoint name remains in the package.
# Verified against the shipped payload: only three occurrences exist, all in one
# help string inside HuoChat.exe.
BARE_STUBS = ('huoying666', 'huoying', 'huochaipro', 'huorong')
ASCII_STUB = re.compile(rb'(?i)(?<![a-z0-9])(?:' + b'|'.join(s.encode() for s in BARE_STUBS) + rb')(?![a-z0-9])')
WIDE_STUB = re.compile(rb'(?i)(?<![a-z0-9]\x00)(?:' + b'|'.join(
    b'\x00'.join(bytes([c]) for c in s.encode()) + b'\x00' for s in BARE_STUBS) + rb')(?![a-z0-9]\x00)')
PATTERNS += [
    (WIDE_DOMAIN, 'utf-16le'), (BARE_DOMAIN, 'ascii'),
    (B64_WIDE, 'utf-16le'), (B64_ASCII, 'ascii'),
    (WIDE_STUB, 'utf-16le'), (ASCII_STUB, 'ascii'),
]
# A bare host inside an email address is a contact string, not an endpoint.
_EMAIL = re.compile(rb'[A-Za-z0-9._%+\-]+@')

_LOCAL = frozenset(b'abcdefghijklmnopqrstuvwxyzABCDEFGHIJKLMNOPQRSTUVWXYZ0123456789._%+-')

def _inside_email(data, offset):
    """True when a bare-host match is the domain of an ``local@host`` string."""
    head = data[max(0, offset - 128):offset]
    at = head.rfind(b'@')
    if at <= 0: return False
    local = head[:at]
    return bool(local) and all(c in _LOCAL for c in local)

def _b64_candidates(token, encoding):
    """Decode an encoded token, returning any embedded URL-bearing text."""
    if encoding == 'utf-16le':
        try: token = token.decode('utf-16-le')
        except UnicodeDecodeError: return
    else:
        token = token.decode('latin-1')
    text = ''.join(token.split())
    if len(text) < 16 or len(text) % 4: return
    for pad in ('', '=', '==', '==='):
        try:
            raw = _b64.b64decode(text + pad, validate=True)
        except Exception:
            continue
        if not raw: continue
        try:
            yield raw.decode('utf-8')
        except UnicodeDecodeError:
            continue

def url_hits(data):
    hits = []
    spans=[]
    for regex, encoding in PATTERNS:
        for m in regex.finditer(data):
            if any(a<=m.start()<b for a,b in spans): continue
            token = m.group()
            # An encoded token is evidence only when it decodes to a URL.
            if regex in (B64_ASCII, B64_WIDE):
                nested = None
                for text in _b64_candidates(token, encoding):
                    found = url_hits(text.encode('utf-8'))
                    if found:
                        nested = found[0]['value']; break
                if nested is None: continue
                value = token.decode(encoding) + ' -> ' + nested
            else:
                value = token.decode(encoding)
            # Bare hosts are only findings when they are a known business domain;
            # otherwise they are source filenames, library metadata or contacts.
            if regex in (BARE_DOMAIN, WIDE_DOMAIN):
                value_l = value.lower()
                if not any(value_l.endswith('.' + d) or value_l == d
                           for d in BARE_DENYLIST):
                    continue
                if regex is BARE_DOMAIN and _inside_email(data, m.start()):
                    continue
            hits.append({'offset': m.start(), 'value': value, 'encoding': encoding})
            spans.append(m.span())
    return hits

def scrub_urls(data, *, fixed_size=True, only=None):
    """Preserve the size of PE slots; XML/text are rewritten without NUL padding.

    ``only`` restricts the sweep to a caller-supplied set of byte offsets, so a
    confirmation pass cannot rewrite incidental base64-looking data.

    All patterns are matched against the original bytes and every edit is
    collected before anything is applied: applying them one pattern at a time
    would invalidate later offsets whenever a replacement changes the length,
    silently dropping findings that sit after the first substitution.
    """
    edits = []
    for regex, encoding in PATTERNS:
        for m in reversed(list(regex.finditer(data))):
            token = m.group()
            # Skip bare hosts that are not business domains; they must not be
            # rewritten or the plaintext sweep would corrupt source filenames.
            if regex in (BARE_DOMAIN, WIDE_DOMAIN):
                text = token.decode(encoding).lower()
                if not any(text.endswith('.' + d) or text == d for d in BARE_DENYLIST):
                    continue
                if regex is BARE_DOMAIN and _inside_email(data, m.start()):
                    continue
            if only is not None and m.start() not in only: continue
            record = {'offset': m.start(), 'value': token.decode(encoding),
                      'encoding': encoding}
            if regex in (B64_ASCII, B64_WIDE):
                # Re-encoding cannot preserve the slot length, so overwrite in place.
                edits.append((m.start(), m.end(), b'\0' * len(token),
                              dict(record, kind='encoded')))
                continue
            replacement = 'about:blank'.encode(encoding)
            if fixed_size:
                if len(replacement) > len(token):
                    replacement = 'offline'.encode(encoding)
                # Space padding preserves enclosing SQL/format strings; inserting
                # a NUL here would silently truncate the surrounding expression.
                replacement = replacement[:len(token)]
                replacement += ' '.encode(encoding) * ((len(token)-len(replacement)) // len(' '.encode(encoding)))
            edits.append((m.start(), m.end(), replacement, dict(record, kind='url')))
    recorded = []
    # Resolve overlaps before applying anything. Sorting by start lets a wide
    # match absorb the narrower ones nested inside it, so a bare host inside a
    # URL is never rewritten on its own and the leftover scheme cannot turn
    # "https://host" back into a fresh URL.
    claimed = []
    for start, end, _, _ in sorted(edits, key=lambda e: (e[0], -(e[1] - e[0]))):
        if claimed and start < claimed[-1][1]:
            continue
        claimed.append((start, end))
    for start, end, replacement, record in sorted(edits, key=lambda e: e[0], reverse=True):
        if (start, end) not in claimed:
            continue
        data = data[:start] + replacement + data[end:]
        recorded.append(record)
    recorded.reverse()
    # A replacement can expose a scheme prefix that a UTF-16 match started one
    # byte inside, turning "https://host" back into a parseable URL. Sweep the
    # remainder so the result is idempotent instead of leaving a fresh address.
    if url_hits(data):
        for regex, encoding in PATTERNS:
            for m in reversed(list(regex.finditer(data))):
                if regex in (BARE_DOMAIN, WIDE_DOMAIN):
                    text = m.group().decode(encoding).lower()
                    if not any(text.endswith('.' + d) or text == d
                               for d in BARE_DENYLIST):
                        continue
                    if regex is BARE_DOMAIN and _inside_email(data, m.start()):
                        continue
                token = m.group()
                if fixed_size:
                    filler = (b'\0' if regex in (B64_ASCII, B64_WIDE)
                              else b' ') * len(token)
                else:
                    filler = b''
                data = data[:m.start()] + filler + data[m.end():]
                recorded.append({'offset': m.start(),
                                 'value': token.decode(encoding),
                                 'encoding': encoding, 'kind': 'cleanup'})
    return data, recorded
