import hashlib
import logging
import math
import os
import re
import struct
import tempfile
import zipfile
import tarfile
from datetime import datetime, timezone

logger = logging.getLogger(__name__)

# Try optional libraries
try:
    import olefile
    HAS_OLEFILE = True
except ImportError:
    HAS_OLEFILE = False

# ─── helpers ───────────────────────────────────────────────────────

def _now_ts():
    return int(datetime.now(timezone.utc).timestamp())

def _sig(n): return '<' if n == 0 else '>'

# ─── SHA3-256 ──────────────────────────────────────────────────────

def compute_sha3_256(data: bytes) -> str:
    return hashlib.sha3_256(data).hexdigest()

# ─── Shannon Entropy ───────────────────────────────────────────────

def compute_entropy(data: bytes) -> float:
    if not data:
        return 0.0
    counts = [0] * 256
    for b in data:
        counts[b] += 1
    total = len(data)
    entropy = 0.0
    for c in counts:
        if c == 0:
            continue
        p = c / total
        entropy -= p * math.log2(p)
    return round(entropy, 4)

# ─── File Category ─────────────────────────────────────────────────

def detect_file_category(filename: str, magic: str = None) -> dict:
    """Detect broad category: executable, document, archive, script, image, audio, video, data, other."""
    ext = (os.path.splitext(filename)[1] or '').lower()
    magic_lower = (magic or '').lower()

    categories = {
        'executable': ['exe', 'dll', 'sys', 'msi', 'ocx', 'drv', 'cpl', 'scr', 'com', 'pif', 'app', 'elf', 'so', 'dylib'],
        'document_office': ['doc', 'docx', 'xls', 'xlsx', 'ppt', 'pptx', 'pub', 'odt', 'ods', 'odp', 'rtf'],
        'document_pdf': ['pdf'],
        'document_other': ['txt', 'csv', 'tsv', 'log', 'md', 'rst', 'tex', 'nfo'],
        'archive': ['zip', 'rar', '7z', 'tar', 'gz', 'bz2', 'xz', 'z', 'lz', 'lzma', 'tgz', 'tbz2', 'txz', 'iso'],
        'script': ['js', 'vbs', 'ps1', 'psm1', 'bat', 'cmd', 'sh', 'bash', 'py', 'pl', 'rb', 'php', 'tcl', 'lua', 'ahk', 'au3'],
        'image': ['jpg', 'jpeg', 'png', 'gif', 'bmp', 'tiff', 'tif', 'webp', 'svg', 'ico', 'raw', 'psd', 'ai', 'eps'],
        'audio': ['mp3', 'wav', 'flac', 'ogg', 'wma', 'aac', 'm4a', 'opus'],
        'video': ['mp4', 'avi', 'mkv', 'mov', 'wmv', 'flv', 'webm', 'm4v', 'mpg', 'mpeg'],
        'android': ['apk', 'dex', 'odex', 'oat'],
        'java': ['jar', 'class', 'jsp'],
        'windows': ['lnk', 'msc', 'chm', 'hlp'],
        'database': ['db', 'sqlite', 'sql', 'mdb', 'accdb', 'frm', 'ibd', 'myd', 'myi'],
        'certificate': ['pem', 'crt', 'cer', 'key', 'p12', 'pfx', 'der'],
        'font': ['ttf', 'otf', 'woff', 'woff2', 'eot'],
        'email': ['eml', 'msg', 'pst', 'ost'],
        'web': ['html', 'htm', 'xhtml', 'css', 'xml', 'xsl', 'xslt', 'json', 'yaml', 'yml'],
        'firmware': ['bin', 'hex', 'rom', 'eep', 'flash'],
        'macros': ['xlsm', 'xlam', 'docm', 'dotm', 'pptm', 'potm', 'ppsm'],
    }

    ext_stripped = ext.lstrip('.') if ext else ''
    for cat, exts in categories.items():
        if (ext and ext in exts) or ext_stripped in exts:
            return {'category': cat, 'extension': ext}

    if magic_lower and ('pe32' in magic_lower or 'pe64' in magic_lower or 'executable' in magic_lower):
        return {'category': 'executable', 'extension': ext}
    if magic_lower and ('composite document' in magic_lower or 'ole2' in magic_lower):
        return {'category': 'document_office', 'extension': ext}
    if 'pdf document' in magic_lower or 'pdf' in magic_lower:
        return {'category': 'document_pdf', 'extension': ext}

    return {'category': 'other', 'extension': ext}

# ─── Encoding Detection ────────────────────────────────────────────

def detect_encoding(data: bytes) -> str:
    """Simple encoding detection by BOM and null-byte heuristics."""
    if len(data) >= 4:
        if data[:4] == b'\xff\xfe\x00\x00':
            return 'UTF-32LE'
        if data[:4] == b'\x00\x00\xfe\xff':
            return 'UTF-32BE'
    if len(data) >= 3:
        if data[:3] == b'\xef\xbb\xbf':
            return 'UTF-8 with BOM'
    if len(data) >= 2:
        if data[:2] == b'\xff\xfe':
            return 'UTF-16LE'
        if data[:2] == b'\xfe\xff':
            return 'UTF-16BE'
    if data[:2] == b'\x1f\x8b':
        return 'GZip compressed'
    if data[:2] == b'\x78\x9c' or data[:2] == b'\x78\x01':
        return 'zlib compressed'
    if b'\x00\x00' in data[:2000]:
        return 'Binary (UTF-16 or wide chars)'
    try:
        data.decode('utf-8')
        return 'UTF-8'
    except UnicodeDecodeError:
        pass
    try:
        data.decode('latin-1')
        return 'Latin-1 / Windows-1252'
    except UnicodeDecodeError:
        pass
    return 'Binary'

# ─── Compression Ratio ─────────────────────────────────────────────

def compute_compression_ratio(data: bytes) -> float:
    """Estimate compression ratio by comparing raw size to compressed (zlib)."""
    if not data:
        return 0.0
    raw_size = len(data)
    compressed = zlib_compress(data)
    if compressed and len(compressed) > 0:
        ratio = round(raw_size / len(compressed), 2)
        return ratio
    return 1.0

def zlib_compress(data: bytes) -> bytes:
    try:
        import zlib
        return zlib.compress(data, level=9)
    except Exception:
        return b''

# ─── Strings Extraction ────────────────────────────────────────────

def _extract_ascii_strings(data: bytes, min_len=4) -> list:
    result = []
    current = []
    for b in data:
        if 32 <= b <= 126:
            current.append(chr(b))
        else:
            if len(current) >= min_len:
                result.append(''.join(current))
            current = []
    if len(current) >= min_len:
        result.append(''.join(current))
    return result

def _extract_unicode_strings(data: bytes, min_len=4) -> list:
    result = []
    current = []
    i = 0
    while i < len(data) - 1:
        b1, b2 = data[i], data[i+1]
        if 32 <= b1 <= 126 and b2 == 0:
            current.append(chr(b1))
            i += 2
        elif b1 == 0 and 32 <= b2 <= 126:
            current.append(chr(b2))
            i += 2
        else:
            if len(current) >= min_len:
                result.append(''.join(current))
            current = []
            i += 1
    if len(current) >= min_len:
        result.append(''.join(current))
    return result

def extract_strings(data: bytes, min_len=4) -> dict:
    ascii_strs = _extract_ascii_strings(data, min_len)
    unicode_strs = _extract_unicode_strings(data, min_len)
    all_strings = ascii_strs + unicode_strs
    text = '\n'.join(all_strings)

    urls = list(set(re.findall(r'https?://[^\s\'"<>]+', text)))
    ips = list(set(re.findall(r'\b(?:\d{1,3}\.){3}\d{1,3}\b(?!\s*:\s*\d{4,5}\b)', text)))
    domains = list(set(re.findall(r'\b(?:[a-zA-Z0-9-]+\.)+[a-zA-Z]{2,}\b', text)))
    emails = list(set(re.findall(r'\b[a-zA-Z0-9._%+-]+@[a-zA-Z0-9.-]+\.[a-zA-Z]{2,}\b', text)))
    reg_keys = list(set(re.findall(r'[A-Za-z_]+\\(?:[A-Za-z0-9_\\ -]+)(?:\\[A-Za-z0-9_\\ -]+)*',
                                   text)))
    registry_keys = [k for k in reg_keys if k.startswith(('HKEY_', 'HKLM', 'HKCU', 'HKCR',
                                                           'HKU', 'HKCC', 'Software\\', 'System\\',
                                                           'SOFTWARE\\', 'SYSTEM\\'))]
    file_paths = list(set(re.findall(r'(?:[A-Za-z]:)?(?:\\\\|/)?(?:[A-Za-z0-9_ -]+(?:\\\\|/))+[A-Za-z0-9_ -]+(?:\.[A-Za-z0-9]+)?',
                                     text)))
    file_paths = [p for p in file_paths if len(p) > 4]
    commands = list(set(re.findall(r'(?:cmd\.exe|powershell|wscript|cscript|mshta|rundll32|regsvr32|wmic)',
                                   text, re.IGNORECASE)))
    mutexes = list(set(re.findall(r'\{[0-9A-Fa-f-]{36}\}|Global\\[A-Za-z0-9_]+|Local\\[A-Za-z0-9_]+',
                                  text)))
    crypto_wallets = list(set(re.findall(r'\b(1|3|bc1)[A-Za-z0-9]{25,39}\b', text)))

    return {
        'total_strings': len(all_strings),
        'ascii_strings': len(ascii_strs),
        'unicode_strings': len(unicode_strs),
        'urls': list(set(urls))[:100],
        'ips': list(set(ip for ip in ips if not ip.startswith('127.') and not ip.startswith('0.')))[:50],
        'domains': [d for d in list(set(domains)) if '.' in d and not d.endswith('.local')][:50],
        'emails': emails[:30],
        'registry_keys': registry_keys[:30],
        'commands': commands[:20],
        'file_paths': [p for p in file_paths if len(p) > 6][:30],
        'mutexes': mutexes[:20],
        'crypto_wallets': crypto_wallets[:20],
    }

# ─── Document Analysis ─────────────────────────────────────────────

def analyze_document(file_bytes: bytes, filename: str, magic: str = None) -> dict:
    result = {
        'is_document': False,
        'has_macros': False,
        'has_embedded_objects': False,
        'has_javascript': False,
        'has_ole_objects': False,
        'has_autoopen': False,
        'has_hidden_sheets': False,
        'has_hidden_slides': False,
        'has_links': False,
        'has_forms': False,
        'has_attachments': False,
        'has_suspicious_keywords': False,
        'suspicious_keywords': [],
    }

    ext = (os.path.splitext(filename)[1] or '').lower()
    magic_lower = (magic or '').lower()

    is_office = ext in ('.doc', '.docx', '.xls', '.xlsx', '.ppt', '.pptx',
                        '.docm', '.xlsm', '.pptm', '.dotm', '.xlam', '.ppsm',
                        '.odt', '.ods', '.odp', '.rtf')
    is_pdf = ext == '.pdf' or 'pdf' in magic_lower

    if not is_office and not is_pdf:
        return result

    result['is_document'] = True
    result['document_type'] = 'office' if is_office else 'pdf'

    # ── OLE / Office analysis ──
    if is_office:
        if HAS_OLEFILE:
            try:
                ole = olefile.OleFileIO(file_bytes)
                # Check for VBA macros
                all_streams = ole.listdir()
                stream_names = ['/'.join(s).lower() for s in all_streams]
                result['has_macros'] = any('vba' in s or 'macro' in s or 'module' in s for s in stream_names)
                result['has_ole_objects'] = any('ole' in s or 'object' in s or 'embed' in s for s in stream_names)
                result['has_embedded_objects'] = result['has_ole_objects']
                # Check for AutoOpen/Auto_Open
                for s in stream_names:
                    if 'autoopen' in s or 'auto_open' in s or 'autoclose' in s or 'workbook_open' in s:
                        result['has_autoopen'] = True
                        break
                # Check for links in OLE
                result['has_links'] = any('link' in s or 'external' in s for s in stream_names)
                ole.close()
            except Exception as e:
                logger.debug("OLE analysis error: %s", e)
        else:
            # Without olefile, detect macros by searching for VBA signatures
            result['has_macros'] = b'VBA' in file_bytes or b'vba' in file_bytes or b'Attribut' in file_bytes
            result['has_embedded_objects'] = b'Embedded' in file_bytes or b'package' in file_bytes
            result['has_ole_objects'] = result['has_embedded_objects']
            result['has_autoopen'] = b'AutoOpen' in file_bytes or b'Auto_Open' in file_bytes or b'Workbook_Open' in file_bytes
            result['has_links'] = b'HYPERLINK' in file_bytes or b'ExternalLink' in file_bytes or b'DDE' in file_bytes

        # Check for hidden sheets / slides in OOXML
        if ext in ('.xlsx', '.xlsm', '.xls', '.pptx', '.pptm', '.ppt'):
            pattern_hidden = b'hidden="1"' if ext.startswith('.xls') else b'hidden="1"'
            result['has_hidden_sheets'] = pattern_hidden in file_bytes
            result['has_hidden_slides'] = pattern_hidden in file_bytes

        # Check for forms
        result['has_forms'] = b'UserForm' in file_bytes or b'Form' in file_bytes

        # Check for JavaScript in Office
        result['has_javascript'] = b'<script' in file_bytes or b'javascript' in file_bytes.lower()

        # Check for suspicious keywords
        suspicious_kw = [
            'shell', 'execute', 'rundll32', 'powershell', 'cmd.exe', 'wscript',
            'cscript', 'mshta', 'regsvr32', 'wmic', 'dropper', 'payload',
            'encrypt', 'decrypt', 'base64', 'http://', 'https://', 'bypass',
            'elevation', 'uac', 'admin', 'process.start', 'winmgmts',
            'GetObject', 'CreateObject', 'ActiveXObject',
        ]
        text_lower = file_bytes[:200000].lower()
        found_kw = [kw for kw in suspicious_kw if kw.encode() in file_bytes[:200000]]
        if found_kw:
            result['has_suspicious_keywords'] = True
            result['suspicious_keywords'] = found_kw[:20]

    # ── PDF analysis ──
    if is_pdf:
        text = file_bytes.decode('latin-1', errors='replace')
        result['has_javascript'] = '/JavaScript' in text or '/JS' in text or 'javascript' in text.lower()
        result['has_embedded_objects'] = '/EmbeddedFile' in text or '/Embedded' in text
        result['has_forms'] = '/AcroForm' in text or '/XFA' in text
        result['has_attachments'] = '/Attachment' in text or '/EmbeddedFiles' in text
        result['has_ole_objects'] = '/OLE' in text or '/OLE2' in text
        result['has_autoopen'] = '/OpenAction' in text
        result['has_links'] = '/URI' in text or '/Action' in text
        suspicious_pdf = ['/JavaScript', '/Launch', '/OpenAction', '/URI', '/SubmitForm']
        result['suspicious_keywords'] = [kw for kw in suspicious_pdf if kw in text]

    return result

# ─── Archive Analysis ──────────────────────────────────────────────

def analyze_archive(file_bytes: bytes, filename: str) -> dict:
    result = {
        'is_archive': False,
        'file_count': 0,
        'contains_nested': False,
        'password_protected': False,
        'compression_method': None,
        'largest_file': None,
        'largest_file_size': 0,
        'file_list': [],
    }

    ext = (os.path.splitext(filename)[1] or '').lower()
    is_zip = ext == '.zip' or file_bytes[:2] == b'PK'
    is_tar = ext in ('.tar', '.tgz', '.tbz2', '.txz') or tarfile.is_tarfile.__doc__ or file_bytes[257:262] == b'ustar'
    is_gz = ext in ('.gz', '.tgz') or (file_bytes[:2] == b'\x1f\x8b')
    is_bz2 = ext in ('.bz2', '.tbz2') or file_bytes[:3] == b'BZh'
    is_rar = ext == '.rar' or file_bytes[:7] == b'Rar!\x1a\x07\x00'
    is_seven = ext == '.7z' or file_bytes[:6] == b'7z\xbc\xaf\x27\x1c'

    if not (is_zip or is_tar or is_gz or is_bz2 or is_rar or is_seven):
        return result

    result['is_archive'] = True
    result['archive_type'] = 'ZIP' if is_zip else 'TAR' if is_tar else 'GZIP' if is_gz else 'BZIP2' if is_bz2 else 'RAR' if is_rar else '7z'

    # ── ZIP analysis ──
    if is_zip:
        try:
            with tempfile.NamedTemporaryFile(delete=False, suffix='.zip') as tmp:
                tmp.write(file_bytes)
                tmp_path = tmp.name
            try:
                with zipfile.ZipFile(tmp_path, 'r') as zf:
                    finfo_list = zf.infolist()
                    result['file_count'] = len(finfo_list)
                    result['compression_method'] = 'DEFLATE' if any(f.compress_type == 8 for f in finfo_list) else 'STORE'
                    largest = max(finfo_list, key=lambda f: f.file_size) if finfo_list else None
                    if largest:
                        result['largest_file'] = largest.filename
                        result['largest_file_size'] = largest.file_size
                    # Check for password protection
                    for f in finfo_list:
                        if f.flag_bits & 0x1:
                            result['password_protected'] = True
                            break
                    # Check for nested archives
                    nested_exts = ('.zip', '.rar', '.7z', '.tar', '.gz', '.bz2', '.xz')
                    nested = [f.filename for f in finfo_list if f.filename.lower().endswith(nested_exts)]
                    result['contains_nested'] = len(nested) > 0
                    result['file_list'] = [f.filename for f in finfo_list[:200]]
            finally:
                try:
                    os.remove(tmp_path)
                except Exception:
                    pass
        except zipfile.BadZipFile:
            logger.debug("Bad ZIP file")
        except Exception as e:
            logger.debug("ZIP analysis error: %s", e)

    # ── TAR/GZ/BZ2 analysis ──
    if is_tar or is_gz or is_bz2:
        try:
            mode = 'r:gz' if is_gz else 'r:bz2' if is_bz2 else 'r'
            with tempfile.NamedTemporaryFile(delete=False) as tmp:
                tmp.write(file_bytes)
                tmp_path = tmp.name
            try:
                with tarfile.open(tmp_path, mode) as tf:
                    members = tf.getmembers()
                    result['file_count'] = len(members)
                    result['compression_method'] = 'gzip' if is_gz else 'bzip2' if is_bz2 else 'none'
                    largest = max(members, key=lambda m: m.size) if members else None
                    if largest:
                        result['largest_file'] = largest.name
                        result['largest_file_size'] = largest.size
                    # Check for nested
                    nested_exts = ('.zip', '.rar', '.7z', '.tar', '.gz', '.bz2', '.xz')
                    nested = [m.name for m in members if m.name.lower().endswith(nested_exts)]
                    result['contains_nested'] = len(nested) > 0
                    result['file_list'] = [m.name for m in members[:200]]
                    # TAR files can't be password protected natively
                    result['password_protected'] = False
            finally:
                try:
                    os.remove(tmp_path)
                except Exception:
                    pass
        except (tarfile.TarError, Exception) as e:
            logger.debug("TAR analysis error: %s", e)

    return result

# ─── Basic PE Analysis (manual via struct) ─────────────────────────

def analyze_pe_basic(file_bytes: bytes) -> dict:
    """Basic PE analysis without pefile library."""
    result = {
        'is_pe': False,
        'architecture': None,
        'is_64bit': None,
        'subsystem': None,
        'entry_point': None,
        'sections': [],
        'section_count': 0,
        'has_suspicious_sections': False,
        'suspicious_sections': [],
        'dll_count': 0,
    }

    if len(file_bytes) < 64:
        return result
    if file_bytes[:2] != b'MZ':
        return result

    result['is_pe'] = True

    try:
        # Read PE offset at MZ+0x3C
        pe_offset = struct.unpack('<I', file_bytes[0x3C:0x40])[0]
        if pe_offset + 4 > len(file_bytes):
            return result

        # Check PE signature
        if file_bytes[pe_offset:pe_offset+4] != b'PE\x00\x00':
            return result

        # Read COFF header (20 bytes starting at pe_offset+4)
        coff = file_bytes[pe_offset+4:pe_offset+24]
        machine = struct.unpack('<H', coff[0:2])[0]
        characteristics = struct.unpack('<H', coff[18:20])[0]

        # Architecture
        arch_map = {
            0x014c: ('I386', False),
            0x8664: ('x86-64', True),
            0x0200: ('Intel Itanium', True),
            0x01c4: ('ARMv7 Thumb', False),
            0xaa64: ('ARM64', True),
            0x01c2: ('ARM Thumb', False),
            0x5032: ('RISC-V 32', False),
            0x5064: ('RISC-V 64', True),
            0x5128: ('RISC-V 128', True),
        }
        arch, is64 = arch_map.get(machine, ('Unknown', False))
        result['architecture'] = arch
        result['is_64bit'] = is64

        # Optional header offset
        opt_header_size = struct.unpack('<H', coff[16:18])[0]
        opt_offset = pe_offset + 24

        # Read optional header magic
        if opt_header_size >= 2:
            opt_magic = struct.unpack('<H', file_bytes[opt_offset:opt_offset+2])[0]
            is_pe32plus = opt_magic == 0x20b

            if is_pe32plus:
                # PE32+ header
                entry_point = struct.unpack('<I', file_bytes[opt_offset+16:opt_offset+20])[0]
                subsystem = struct.unpack('<H', file_bytes[opt_offset+68:opt_offset+70])[0]
                dll_count_offset = opt_offset + 96  # base reloc table size
                if opt_header_size >= 104:
                    export_va = struct.unpack('<Q', file_bytes[opt_offset+96:opt_offset+104])[0]
                    export_size = struct.unpack('<I', file_bytes[opt_offset+104:opt_offset+108])[0]
                    import_va = struct.unpack('<Q', file_bytes[opt_offset+104+8:opt_offset+104+16])[0]
                else:
                    export_va, export_size, import_va = 0, 0, 0
            else:
                # PE32 header
                entry_point = struct.unpack('<I', file_bytes[opt_offset+16:opt_offset+20])[0]
                subsystem = struct.unpack('<H', file_bytes[opt_offset+68:opt_offset+70])[0]
                if opt_header_size >= 96:
                    export_va = struct.unpack('<I', file_bytes[opt_offset+96:opt_offset+100])[0]
                    export_size = struct.unpack('<I', file_bytes[opt_offset+100:opt_offset+104])[0]
                    import_va = struct.unpack('<I', file_bytes[opt_offset+104:opt_offset+108])[0]
                else:
                    export_va, export_size, import_va = 0, 0, 0

            result['entry_point'] = hex(entry_point) if entry_point else None

            subsystem_map = {
                0: 'Unknown', 1: 'Native', 2: 'Windows GUI',
                3: 'Windows Console', 5: 'OS/2 Console',
                7: 'POSIX Console', 9: 'Windows CE GUI',
                10: 'EFI Application', 11: 'EFI Boot Service',
                12: 'EFI Runtime Driver', 13: 'EFI ROM',
                14: 'XBOX', 16: 'Windows Boot Application',
            }
            result['subsystem'] = subsystem_map.get(subsystem, f'Unknown ({subsystem})')

            # Read sections
            # Section header starts after optional header
            section_offset = pe_offset + 24 + opt_header_size
            num_sections = struct.unpack('<H', coff[2:4])[0]
            result['section_count'] = num_sections

            suspicious_names = ['.upx', '.packed', '.themida', '.vmp', '.enigma',
                                '.armaged', '.nspack', '.morphine', '.pecompact',
                                '.pklz', '.packed', '.taz', '.appended']

            for i in range(min(num_sections, 100)):
                sec_start = section_offset + i * 40
                if sec_start + 40 > len(file_bytes):
                    break
                name_raw = file_bytes[sec_start:sec_start+8]
                name = name_raw.rstrip(b'\x00').decode('latin-1', errors='replace')
                vsize = struct.unpack('<I', file_bytes[sec_start+8:sec_start+12])[0]
                vaddr = struct.unpack('<I', file_bytes[sec_start+12:sec_start+16])[0]
                raw_size = struct.unpack('<I', file_bytes[sec_start+16:sec_start+20])[0]
                raw_addr = struct.unpack('<I', file_bytes[sec_start+20:sec_start+24])[0]
                characteristics = struct.unpack('<I', file_bytes[sec_start+36:sec_start+40])[0]
                is_executable = bool(characteristics & 0x20000000)
                is_writable = bool(characteristics & 0x80000000)
                sec_data = {
                    'name': name,
                    'virtual_size': vsize,
                    'virtual_address': hex(vaddr),
                    'raw_size': raw_size,
                    'is_executable': is_executable,
                    'is_writable': is_writable,
                }
                result['sections'].append(sec_data)
                if name.lower() in suspicious_names:
                    result['has_suspicious_sections'] = True
                    result['suspicious_sections'].append(name)

            # Estimate DLL count from import table
            result['dll_count'] = 0

    except Exception as e:
        logger.debug("PE basic analysis error: %s", e)

    return result

# ─── Security Findings ──────────────────────────────────────────────

def generate_security_findings(local: dict, vt_data: dict = None) -> list:
    findings = []

    # 1. Macros in document
    doc = local.get('document_analysis', {})
    if doc.get('has_macros'):
        findings.append({
            'severity': 'High',
            'title': 'Macros Detected',
            'finding': 'Document contains VBA macros.',
            'evidence': 'Macro code detected in OLE streams or OOXML',
            'recommendation': 'Disable macros before opening. Review macro source code for malicious behavior.',
        })

    # 2. Embedded objects
    if doc.get('has_embedded_objects'):
        findings.append({
            'severity': 'Medium',
            'title': 'Embedded Objects Found',
            'finding': 'Document contains embedded objects or OLE packages.',
            'evidence': 'OLE/embedding streams detected in document',
            'recommendation': 'Extract and scan embedded objects separately before opening the document.',
        })

    # 3. JavaScript in document
    if doc.get('has_javascript'):
        findings.append({
            'severity': 'High',
            'title': 'JavaScript in Document',
            'finding': 'Document contains embedded JavaScript.',
            'evidence': 'JavaScript engine references or <script> tags found',
            'recommendation': 'Do not enable scripting. Scan for malicious payload in the JavaScript code.',
        })

    # 4. AutoOpen macros
    if doc.get('has_autoopen'):
        findings.append({
            'severity': 'High',
            'title': 'Auto-Executing Macro',
            'finding': 'Document has AutoOpen or auto-executing macro.',
            'evidence': 'AutoOpen/AutoClose/Workbook_Open trigger found',
            'recommendation': 'Immediately quarantine. Auto-executing macros are commonly used in malware delivery.',
        })

    # 5. Hidden content
    if doc.get('has_hidden_sheets'):
        findings.append({
            'severity': 'Low',
            'title': 'Hidden Sheets Detected',
            'finding': 'Spreadsheet has hidden sheets or cells.',
            'evidence': 'Hidden sheet attribute detected in OOXML',
            'recommendation': 'Unhide and review all sheets for obfuscated data or formulas.',
        })

    # 6. Archive password protection
    archive = local.get('archive_analysis', {})
    if archive.get('password_protected'):
        findings.append({
            'severity': 'Medium',
            'title': 'Password-Protected Archive',
            'finding': 'Archive is password protected, preventing content analysis.',
            'evidence': 'Archive encryption flags detected',
            'recommendation': 'Request the password and scan contents separately.',
        })

    # 7. Nested archives
    if archive.get('contains_nested'):
        findings.append({
            'severity': 'Medium',
            'title': 'Nested Archive Detected',
            'finding': 'Archive contains other archives within it.',
            'evidence': 'Embedded archive files found',
            'recommendation': 'Extract recursively and scan each layer for threats.',
        })

    # 8. High entropy (packed/encrypted)
    entropy = local.get('entropy', 0)
    if entropy > 7.5:
        findings.append({
            'severity': 'Medium',
            'title': 'High Entropy (Packed/Encrypted)',
            'finding': f'File entropy is {entropy}/8.0, indicating packing or encryption.',
            'evidence': 'Shannon entropy calculation exceeds typical code/data threshold',
            'recommendation': 'Unpack or decrypt the file for deeper static analysis.',
        })

    # 9. Suspicious sections in PE
    pe_basic = local.get('pe_basic', {})
    if pe_basic.get('has_suspicious_sections'):
        sects = ', '.join(pe_basic['suspicious_sections'])
        findings.append({
            'severity': 'High',
            'title': 'Suspicious PE Sections',
            'finding': f'PE file contains packer/protector sections: {sects}.',
            'evidence': f'Sections {sects} are commonly associated with packers',
            'recommendation': 'Unpack the binary before analysis. Run in sandbox for behavioral analysis.',
        })

    # 10. Unsigned executable
    sig = vt_data.get('signature_info', {}) if vt_data else local.get('signature_info', {})
    if pe_basic.get('is_pe'):
        is_signed = sig.get('signed')
        if is_signed is False:
            findings.append({
                'severity': 'Low',
                'title': 'Unsigned Executable',
                'finding': 'Executable file is not digitally signed.',
                'evidence': 'No valid digital signature found',
                'recommendation': 'Reputable software is typically signed. Verify the publisher identity.',
            })

    # 11. Suspicious strings
    strings = local.get('strings', {})
    if strings.get('commands'):
        cmds = ', '.join(strings['commands'][:5])
        findings.append({
            'severity': 'Medium',
            'title': 'Suspicious Commands Found',
            'finding': f'File references suspicious system commands: {cmds}.',
            'evidence': 'Binary strings contain command invocations',
            'recommendation': 'Investigate which component uses these commands and why.',
        })

    # 12. Crypto wallets
    if strings.get('crypto_wallets'):
        count = len(strings['crypto_wallets'])
        findings.append({
            'severity': 'Low',
            'title': 'Cryptocurrency Wallet Addresses',
            'finding': f'File contains {count} cryptocurrency wallet address(es).',
            'evidence': 'Bitcoin/Ethereum address pattern found in file strings',
            'recommendation': 'Verify if the wallet addresses are legitimate or associated with ransomware demands.',
        })

    # 13. Suspicious keywords in doc
    if doc.get('has_suspicious_keywords') and doc.get('suspicious_keywords'):
        kws = ', '.join(doc['suspicious_keywords'][:8])
        findings.append({
            'severity': 'Medium',
            'title': 'Suspicious Keywords in Document',
            'finding': f'Document contains suspicious keywords: {kws}.',
            'evidence': 'Potentially malicious keywords detected in document content',
            'recommendation': 'Manually review the document in a sandboxed environment.',
        })

    # 14. YARA matches
    yara = vt_data.get('crowdsourced_yara_results', []) if vt_data else local.get('yara_results', [])
    if yara and len(yara) > 0:
        rule_names = ', '.join([r.get('rule_name', 'unknown')[:40] for r in yara[:5]])
        findings.append({
            'severity': 'High',
            'title': 'YARA Rule Matches',
            'finding': f'YARA rules matched: {rule_names}{" (+" + str(len(yara)-5) + " more)" if len(yara) > 5 else ""}.',
            'evidence': 'Crowdsourced YARA detection signatures triggered',
            'recommendation': 'Investigate matched rules detail. Correlate with AV detection names.',
        })

    # 15. AV detections
    if vt_data:
        vendors_flagged = vt_data.get('vendors_flagged', 0)
        if vendors_flagged > 0:
            findings.append({
                'severity': 'High',
                'title': 'Antivirus Detections',
                'finding': f'{vendors_flagged} antivirus engines detected this file as malicious.',
                'evidence': f'Detection ratio: {vendors_flagged}/{vt_data.get("vendors_total", 0)}',
                'recommendation': 'Do not execute or open the file. Submit to sandbox for behavioral analysis.',
            })

    # 16. Classification-based findings
    ptc = vt_data.get('popular_threat_classification', {}) if vt_data else {}
    if ptc.get('suggested_threat_label'):
        label = ptc['suggested_threat_label']
        findings.append({
            'severity': 'High',
            'title': 'Threat Classification Available',
            'finding': f'VirusTotal classifies this as: {label}.',
            'evidence': 'Popular threat classification from VT community',
            'recommendation': 'Review classification details and take appropriate action.',
        })

    return findings

# ─── Risk Engine ───────────────────────────────────────────────────

def calculate_risk_score(local: dict, vt_data: dict = None) -> dict:
    score = 0
    reasons = []
    max_score = 100

    # Max 30 points: AV detections
    if vt_data:
        vt_vendors_flagged = vt_data.get('vendors_flagged', 0)
        vt_vendors_total = vt_data.get('vendors_total', 0) or 1
        vt_detection_pct = vt_vendors_flagged / vt_vendors_total
        score += min(30, round(vt_detection_pct * 30))
        if vt_vendors_flagged > 0:
            reasons.append(f'{vt_vendors_flagged}/{vt_vendors_total} AV detections')

    # Max 15 points: Macros
    doc = local.get('document_analysis', {})
    if doc.get('has_macros'):
        score += 10
        reasons.append('VBA macros')
    if doc.get('has_autoopen'):
        score += 5
        reasons.append('Auto-executing macro')

    # Max 10 points: Embedded objects / JS
    if doc.get('has_embedded_objects'):
        score += 5
        reasons.append('Embedded objects')
    if doc.get('has_javascript'):
        score += 5
        reasons.append('JS in document')

    # Max 10 points: Entropy
    entropy = local.get('entropy', 0)
    if entropy > 7.5:
        score += 10
        reasons.append('High entropy (packed/encrypted)')
    elif entropy > 6.5:
        score += 5
        reasons.append('Elevated entropy')

    # Max 10 points: PE suspicious sections
    pe = local.get('pe_basic', {})
    if pe.get('has_suspicious_sections'):
        score += 10
        reasons.append('Suspicious PE sections')

    # Max 5 points: Unsigned PE
    sig = vt_data.get('signature_info', {}) if vt_data else local.get('signature_info', {})
    if pe.get('is_pe') and sig.get('signed') is False:
        score += 5
        reasons.append('Unsigned executable')

    # Max 5 points: Suspicious commands
    strings = local.get('strings', {})
    if strings.get('commands'):
        score += 3
        reasons.append('Suspicious commands')
    if strings.get('crypto_wallets'):
        score += 2
        reasons.append('Crypto wallet addresses')

    # Max 5 points: YARA matches
    yara = vt_data.get('crowdsourced_yara_results', []) if vt_data else local.get('yara_results', [])
    if yara:
        score += min(5, len(yara))
        reasons.append(f'{len(yara)} YARA matches')

    # Max 5 points: Archive nesting
    archive = local.get('archive_analysis', {})
    if archive.get('contains_nested'):
        score += 3
        reasons.append('Nested archive')
    if archive.get('password_protected'):
        score += 2
        reasons.append('Password-protected archive')

    # Max 5 points: Suspicious doc keywords
    if doc.get('has_suspicious_keywords') and doc.get('suspicious_keywords'):
        score += 5
        reasons.append('Suspicious document keywords')

    # Clamp to 0-100
    score = max(0, min(100, score))

    # Classification
    if score == 0:
        classification = 'Safe'
    elif score <= 20:
        classification = 'Low Risk'
    elif score <= 50:
        classification = 'Medium'
    elif score <= 75:
        classification = 'High'
    else:
        classification = 'Critical'

    return {
        'risk_score': score,
        'risk_classification': classification,
        'risk_factors': reasons[:20],
        'max_score': max_score,
    }

# ─── Timeline builder ──────────────────────────────────────────────

def build_timeline(steps: dict) -> list:
    return [
        {'step': 'Upload', 'timestamp': steps.get('upload'), 'status': 'done'},
        {'step': 'Hash Calculation', 'timestamp': steps.get('hashing'), 'status': 'done' if steps.get('hashing') else 'pending'},
        {'step': 'Static Analysis', 'timestamp': steps.get('static_analysis'), 'status': 'done' if steps.get('static_analysis') else 'pending'},
        {'step': 'VirusTotal Scan', 'timestamp': steps.get('vt_scan'), 'status': 'done' if steps.get('vt_scan') else 'pending'},
        {'step': 'Threat Intelligence', 'timestamp': steps.get('threat_intel'), 'status': 'done' if steps.get('threat_intel') else 'pending'},
        {'step': 'Completed', 'timestamp': steps.get('completed'), 'status': 'done' if steps.get('completed') else 'pending'},
    ]

# ─── Complete Local Analysis ───────────────────────────────────────

def run_local_analysis(file_bytes: bytes, filename: str, vt_data: dict = None) -> dict:
    result = {}

    # Hashes
    result['sha3_256'] = compute_sha3_256(file_bytes)

    # Entropy
    result['entropy'] = compute_entropy(file_bytes)

    # File category
    category_info = detect_file_category(filename, vt_data.get('magic') if vt_data else None)
    result['file_category'] = category_info.get('category')
    result['file_category_detail'] = category_info.get('extension')

    # Encoding
    result['encoding'] = detect_encoding(file_bytes)

    # Compression ratio
    result['compression_ratio'] = compute_compression_ratio(file_bytes)

    # Strings
    result['strings'] = extract_strings(file_bytes)

    # Document analysis
    result['document_analysis'] = analyze_document(file_bytes, filename, vt_data.get('magic') if vt_data else None)

    # Archive analysis
    result['archive_analysis'] = analyze_archive(file_bytes, filename)

    # PE basic analysis
    result['pe_basic'] = analyze_pe_basic(file_bytes)

    # Security findings
    combined = dict(vt_data or {})
    combined.update(result)
    result['security_findings'] = generate_security_findings(result, vt_data)

    # Risk score
    result['risk_engine'] = calculate_risk_score(result, vt_data)

    return result
