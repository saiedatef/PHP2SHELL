#!/usr/bin/env python3
"""
Regex unit tests for the PHP2Shell Sigma rules that inspect request bodies / headers.

Loads each rule's |re patterns straight from the YAML, then runs them against realistic
multipart and urlencoded bodies (CRLF line endings, folded headers, quoting variants).
Every pattern is checked with Python `re` (PCRE-like, as used by Splunk) and, when the
`google-re2` package is installed, with RE2 (Cortex XQL, Chronicle, Loki).

Run:  python3 tests/test_sigma_regex.py
"""
import glob, os, re, sys
import yaml

try:
    import re2  # pip install google-re2
except ImportError:
    re2 = None

HERE = os.path.dirname(os.path.abspath(__file__))
RULES = os.path.join(HERE, '..', 'detections', 'sigma')
B = '----WebKitFormBoundary7MA4YWxkTrZu0gW'


def mp(*parts, boundary=B):
    """Build a multipart body. Each part is (header_lines:list[str], content:str)."""
    out = ''
    for headers, content in parts:
        out += f'--{boundary}\r\n' + '\r\n'.join(headers) + '\r\n\r\n' + content + '\r\n'
    return out + f'--{boundary}--\r\n'


def field(name, value, quote='"'):
    return ([f'Content-Disposition: form-data; name={quote}{name}{quote}'], value)


def upload(name, filename, content='hello', ctype='text/plain'):
    return ([f'Content-Disposition: form-data; name="{name}"; filename="{filename}"', f'Content-Type: {ctype}'], content)


def load_patterns():
    pats = {}
    for f in sorted(glob.glob(os.path.join(RULES, '*.yml'))):
        rid = os.path.basename(f)[:5]
        for doc in yaml.safe_load_all(open(f, encoding='utf-8')):
            det = (doc or {}).get('detection') or {}
            for sel, body in det.items():
                if not isinstance(body, dict):
                    continue
                for key, val in body.items():
                    if '|re' in key:
                        flags = re.I if key.endswith('|i') or '|i|' in key else 0
                        for v in (val if isinstance(val, list) else [val]):
                            pats[f'{rid}:{sel}'] = (v, flags)
    return pats


LONG = 'A' * 1200
FOLDED_LONG = ('B' * 600) + '\r\n ' + ('C' * 600)

CASES = {
    # ---- P1-03 oversized field NAME -------------------------------------------------------
    'P1-03:selection_urlencoded_body': [
        (True, 'urlencoded first key 1200 bytes', LONG + '=1&b=2'),
        (True, 'urlencoded later key, no "="', 'a=1&' + LONG + '&b=2'),
        (False, 'urlencoded long VALUE', 'a=' + LONG + '&b=2'),
        (False, 'short form', 'user=admin&pass=x'),
    ],
    'P1-03:selection_multipart_body': [
        (True, 'multipart long quoted name', mp(field(LONG, 'v'))),
        (True, 'multipart long unquoted name', mp(([f'Content-Disposition: form-data; name={LONG}'], 'v'))),
        (True, 'multipart folded long name', mp(([f'Content-Disposition: form-data; name="{FOLDED_LONG}"'], 'v'))),
        (True, 'multipart name with escaped quotes', mp(([f'Content-Disposition: form-data; name="' + ('x\\"' * 600) + '"'], 'v'))),
        (False, 'minified HTML upload containing name=', mp(upload('f', 'page.html', '<input name="' + 'q' * 50 + '" value="' + 'z' * 1500 + '">', 'text/html'))),
        (False, 'normal upload', mp(field('title', 'Report'), upload('file', 'report.pdf', 'x' * 3000))),
    ],
    # ---- P1-18 structural OOM triggers ------------------------------------------------------
    'P1-18:selection_many_part_headers': [
        (True, '60 headers in one part', mp(([f'Content-Disposition: form-data; name="a"'] + [f'X-H{i}: v' for i in range(60)], 'v'))),
        (False, 'normal upload headers', mp(upload('file', 'a.png', 'x', 'image/png'))),
        (False, 'uploaded .eml (headers are file CONTENT)', mp(upload('f', 'm.eml', '\r\n'.join(f'X-H{i}: v' for i in range(60)), 'message/rfc822'))),
    ],
    'P1-18:selection_empty_file_controls': [
        (True, '60 empty file controls', mp(*[upload('f[]', '', '', 'application/octet-stream') for _ in range(60)])),
        (False, '5 empty file controls (normal browser form)', mp(*[upload('f[]', '', '', 'application/octet-stream') for _ in range(5)])),
    ],
    'P1-18:selection_deep_nesting': [
        (True, 'urlencoded 20-level nesting', 'a' + '[x]' * 20 + '=1'),
        (True, 'urlencoded encoded brackets', 'a' + '%5Bx%5D' * 20 + '=1'),
        (True, 'multipart 20-level nesting', mp(field('a' + '[]' * 20, 'v'))),
        (False, 'normal nested form', 'user[address][city]=Doha&items[0][id]=3'),
    ],
    # ---- P2-05 PHPSESSID as form field ------------------------------------------------------
    'P2-05:selection_field': [
        (True, 'quoted', mp(field('PHPSESSID', 'abc'), upload('f', 'a.txt'))),
        (True, 'unquoted', mp(([f'Content-Disposition: form-data; name=PHPSESSID'], 'abc'))),
        (True, 'single quotes', mp(field('PHPSESSID', 'abc', quote="'"))),
        (True, 'lower-case header', mp(([f'content-disposition: form-data; name="PHPSESSID"'], 'abc'))),
        (True, 'folded header', mp((['Content-Disposition: form-data;\r\n name="PHPSESSID"'], 'abc'))),
        (True, 'junk after closing quote', mp((['Content-Disposition: form-data; name="PHPSESSID"x'], 'abc'))),
        (True, '>500 chars of params before name', mp((['Content-Disposition: form-data; ' + 'p=1; ' * 120 + 'name="PHPSESSID"'], 'abc'))),
        (False, 'PHPSESSIDX', mp(field('PHPSESSIDX', 'abc'))),
        (False, 'PHPSESSID only in a part value', mp(field('note', 'name="PHPSESSID"'))),
        (False, 'cookie-style upload', mp(field('title', 'x'), upload('f', 'a.txt'))),
    ],
    # ---- P2-07 PHP code / serialized object in part headers or progress value --------------
    'P2-07:selection_header_payload': [
        (True, '<?php in filename', mp(upload('f', '<?php echo 1;?>.txt'))),
        (True, '<?= in filename', mp(upload('f', '<?=`id`?>'))),
        (True, 'short tag in filename', mp(upload('f', '<? passthru("id"); ?>'))),
        (True, 'gadget in filename', mp(upload('f', 'x|O:8:"stdClass":0:{}'))),
        (True, 'C: object gadget', mp(upload('f', 'x|C:11:"ArrayObject":0:{}'))),
        (True, 'gadget in part name', mp(([f'Content-Disposition: form-data; name="x|O:8:\\"stdClass\\":0:{{}}"; filename="a.txt"'], 'z'))),
        (True, 'folded filename with tag', mp((['Content-Disposition: form-data; name="f";\r\n filename="<?php echo 1;?>.txt"'], 'z'))),
        (True, 'payload after 2,500 chars of filename padding', mp(upload('f', 'p' * 2500 + '<?php echo 1;?>'))),
        (False, 'normal filename', mp(upload('f', 'Q3 report (final).pdf'))),
        (False, 'filename "Chapter:1;"', mp(upload('f', 'Chapter:1; intro.docx'))),
        (False, 'XML file content', mp(upload('f', 'data.xml', '<?xml version="1.0"?><a/>', 'text/xml'))),
        (False, 'PHP source uploaded as CONTENT', mp(upload('f', 'plugin.php', '<?php echo "hi"; ?>', 'application/x-php'))),
    ],
    'P2-07:selection_progress_payload': [
        (True, 'code in progress key', mp(field('PHP_SESSION_UPLOAD_PROGRESS', '<?php echo 1;?>'), upload('f', 'a.txt'))),
        (True, 'gadget in progress key', mp(field('PHP_SESSION_UPLOAD_PROGRESS', 'x|O:8:"stdClass":0:{}'), upload('f', 'a.txt'))),
        (False, 'legit progress key', mp(field('PHP_SESSION_UPLOAD_PROGRESS', 'upload123'), upload('f', 'a.txt'))),
    ],
    # ---- P3-08 oversized PHPSESSID in Set-Cookie -------------------------------------------
    'P3-08:selection': [
        (True, '67 KB leak', 'PHPSESSID=' + 'Q' * 67000 + '; path=/'),
        (False, 'default 32-char id', 'PHPSESSID=3k9f0a1b2c3d4e5f6a7b8c9d0e1f2a3b; path=/; HttpOnly'),
        (False, '256-char id', 'PHPSESSID=' + 'a' * 256 + '; path=/'),
    ],
    # ---- Endpoint image regexes (resolved binary paths) -------------------------------------
    'P5-11:selection_parent': [
        (True, 'php-fpm8.2', '/usr/sbin/php-fpm8.2'), (True, 'apache2', '/usr/sbin/apache2'),
        (True, 'lsphp', '/usr/local/lsws/fcgi-bin/lsphp8'), (True, 'php-cgi8.3', '/usr/bin/php-cgi8.3'),
        (False, 'php CLI', '/usr/bin/php8.2'), (False, 'nginx', '/usr/sbin/nginx'),
    ],
    'P5-11:selection_tools': [
        (True, 'python3.13', '/usr/bin/python3.13'), (True, 'nc.openbsd', '/bin/nc.openbsd'),
        (True, 'curl', '/usr/bin/curl'), (True, 'id', '/usr/bin/id'),
        (False, 'ImageMagick convert', '/usr/bin/convert'), (False, 'identify', '/usr/bin/identify'), (False, 'sync', '/usr/bin/sync'),
    ],
    'P7-16:selection': [
        (True, 'php CLI reverse shell', '/usr/bin/php8.2'), (True, 'dash', '/usr/bin/dash'), (True, 'openssl', '/usr/bin/openssl'),
        (False, 'ssh', '/usr/bin/ssh'), (False, 'php-fpm worker', '/usr/sbin/php-fpm8.2'),
    ],
}


def perf_check():
    """Guard against catastrophic backtracking: every body pattern must finish in < 2 s on 1-2 MB inputs."""
    import time, random, string
    random.seed(1)
    junk = ''.join(random.choice(string.ascii_letters + ' =;:"\'&[]<?|\r\n') for _ in range(1_000_000))
    bodies = [junk, 'A' * 1_048_576 + '=1', mp(field('A' * 1_048_576, 'v')),
              mp(field('t', 'x'), upload('f', 'a.bin', 'B' * 2_000_000)),
              'Content-Disposition: form-data; name="a"; filename=""\r\n' * 20000,
              mp(upload('f', 'a.txt', '\r\n'.join('K%d: v' % i for i in range(50000))))]
    slow = 0
    for key, (pat, flags) in load_patterns().items():
        rx = re.compile(pat, flags)
        for b in bodies:
            t = time.time(); rx.search(b); dt = time.time() - t
            if dt > 2:
                print(f'SLOW {dt:.1f}s {key}'); slow += 1
    print('Performance:', 'OK (all patterns < 2 s on 1-2 MB bodies)' if not slow else f'{slow} slow pattern(s)')
    return slow


def main():
    pats = load_patterns()
    fails = 0
    for key, cases in CASES.items():
        if key not in pats:
            print(f'MISSING pattern {key}')
            fails += 1
            continue
        pat, flags = pats[key]
        rx = re.compile(pat, flags)
        r2 = None
        if re2 is not None:
            opts = re2.Options()
            opts.case_sensitive = not bool(flags & re.I)
            try:
                r2 = re2.compile(pat, opts)
            except Exception as e:
                print(f'FAIL {key}: does not compile in RE2: {e}')
                fails += 1
        for expect, label, text in cases:
            got = bool(rx.search(text))
            got2 = bool(r2.search(text)) if r2 is not None else got
            ok = got == expect and got2 == expect
            fails += 0 if ok else 1
            print(f'{"PASS" if ok else "FAIL"} {key:40s} {"hit " if expect else "miss"} {label}' + ('' if ok else f'  (re={got}, re2={got2})'))
    fails += perf_check()
    print('\nRE2 checks:', 'enabled' if re2 else 'skipped (pip install google-re2)')
    print('ALL PASS' if fails == 0 else f'{fails} FAILURE(S)')
    sys.exit(1 if fails else 0)


if __name__ == '__main__':
    main()
