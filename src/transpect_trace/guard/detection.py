"""Bounded deterministic content inspection shared by Guard and Protect.

Returned matches are content evidence, never a claim that a file was read.
"""
from __future__ import annotations

import json
import re
import time
from dataclasses import dataclass

MAX_TEXT_BYTES = 16 * 1024 * 1024
MAX_INSPECTION_NODES = 200_000
MAX_EMBEDDED_JSON_DEPTH = 8
WINDOW_CHARS = 64 * 1024
WINDOW_OVERLAP = 8192
INSPECTION_SECONDS = 1.25

_ASSIGNMENT = re.compile(r'''(?im)\b(password|passwd|mysql_password|api_secret|private_key|api_key|access_token|client_secret)["']?\s{0,64}[:=]\s{0,64}["']?([^\s"',;{}\[\]]{8,4096})''')
_BEARER = re.compile(r'''(?i)\bauthorization["']?\s{0,64}[:=]\s{0,64}["']?bearer[ \t]{1,32}([A-Za-z0-9._~+/=-]{16,4096})''')
_URI = re.compile(r'''(?i)\b[a-z][a-z0-9+.-]{1,31}://[^\s/:@"'<>]{1,256}:([^\s/@"'<>]{8,4096})@''')
_PHONE = re.compile(r'''(?i)\b(?:phone|mobile|tel)["']?\s{0,16}[:=]\s{0,16}["']?(?:\+?86[- ]?)?1[3-9]\d{9}\b''')
_EMAIL = re.compile(r'''(?i)\bemail["']?\s{0,16}[:=]\s{0,16}["']?[A-Za-z0-9._%+-]+@[A-Za-z0-9.-]+\.[A-Za-z]{2,}\b''')
_PUBLIC_VALUES = {'changeme', 'your_password', 'example_password', 'your_api_key_here',
                  'example_api_key_here', 'your_access_token', 'your_client_secret',
                  'null', 'none', 'undefined', 'redacted', 'placeholder'}


@dataclass(frozen=True)
class RegisteredChunk:
    source_path: str
    text: str
    method: str


def normalize_registered_text(text: str) -> str:
    """Only the documented leading BOM and Windows-newline transformations."""
    return text.removeprefix('\ufeff').replace('\r\n', '\n')


def checked_text(text: str) -> str:
    if len(text) > MAX_TEXT_BYTES or len(text.encode('utf-8')) > MAX_TEXT_BYTES:
        raise ValueError('detector text exceeds the 16 MiB UTF-8 limit')
    return text


def inspection_text(value) -> str:
    """Flatten key/value context and decode bounded JSON embedded in strings."""
    stack = [(value, 0)]
    parts = []
    size = nodes = 0
    while stack:
        item, depth = stack.pop()
        nodes += 1
        if nodes > MAX_INSPECTION_NODES:
            raise ValueError('inspection node budget exceeded')
        if isinstance(item, str):
            checked_text(item)
            parts.append(item)
            size += len(item.encode('utf-8'))
            if size > MAX_TEXT_BYTES * (MAX_EMBEDDED_JSON_DEPTH + 1):
                raise ValueError('expanded inspection budget exceeded')
            candidate = item.strip().removeprefix('\ufeff')
            if candidate.startswith(('{', '[')):
                try:
                    parsed = json.loads(candidate)
                except (ValueError, TypeError):
                    continue  # Raw logs are still inspected, even when not JSON.
                if isinstance(parsed, (dict, list)):
                    if depth >= MAX_EMBEDDED_JSON_DEPTH:
                        raise ValueError('embedded JSON depth exceeded')
                    stack.append((parsed, depth + 1))
        elif isinstance(item, list):
            stack.extend((child, depth) for child in reversed(item))
        elif isinstance(item, dict):
            for key, child in reversed(list(item.items())):
                if isinstance(child, str):
                    stack.append((str(key) + '=' + child, depth))
                    # The key=value copy is sufficient for matching, but decode
                    # a JSON-valued string separately without losing its key.
                    if child.strip().removeprefix('\ufeff').startswith(('{', '[')):
                        stack.append((child, depth))
                elif type(child) is int:
                    # Numeric identifiers retain their explicit field context;
                    # unlabeled numbers and booleans are not promoted to secrets.
                    stack.append((str(key) + '=' + str(child), depth))
                else:
                    stack.append((child, depth))
    return '\n'.join(parts)


def _is_secret(candidate: str) -> bool:
    candidate = candidate.rstrip(',;')
    return (len(candidate) >= 8 and not candidate.startswith(('${', '<', '$', 'TRANSPECT_PUBLIC'))
            and candidate.lower() not in _PUBLIC_VALUES
            and bool(candidate.strip('*xX•')))


def detect_rules(text: str, *, credential_rules=True, pii_rules=False) -> list[str]:
    """Overlapping bounded windows preserve cross-boundary credential matches."""
    if len(text.encode('utf-8')) > MAX_TEXT_BYTES * (MAX_EMBEDDED_JSON_DEPTH + 1):
        raise ValueError('expanded inspection budget exceeded')
    hits = set()
    lowered = text.lower()
    assignment = credential_rules and any(key in lowered for key in ('password', 'passwd', 'api_secret', 'private_key', 'api_key', 'access_token', 'client_secret'))
    bearer = credential_rules and 'authorization' in lowered
    uri = credential_rules and '://' in text
    aws = credential_rules and 'AKIA' in text and 'aws_secret_access_key' in lowered
    personal = pii_rules and any(key in lowered for key in ('phone', 'mobile', 'tel')) and 'email' in lowered
    if credential_rules and 'PRIVATE KEY-----' in text:
        for begin in re.finditer(r'-----BEGIN ((?:RSA |EC |OPENSSH |ENCRYPTED )?PRIVATE KEY)-----', text):
            if text.find('-----END '+begin.group(1)+'-----',begin.end())>begin.end():
                hits.add('PRIVATE_KEY_BLOCK');break
    if aws and re.search(r'\bAKIA[A-Z0-9]{16}\b', text) and re.search(r'''(?im)aws_secret_access_key["']?\s{0,64}[:=]\s{0,64}["']?[A-Za-z0-9/+]{40}\b''', text):
        hits.add('AWS_CREDENTIAL_PAIR')
    if not any((assignment, bearer, uri, personal)):
        return sorted(hits)
    for offset in range(0, len(text), WINDOW_CHARS):
        window = text[max(0, offset - WINDOW_OVERLAP):offset + WINDOW_CHARS]
        if assignment:
            for match in _ASSIGNMENT.finditer(window):
                if _is_secret(match.group(2)):
                    hits.add('CONTEXTUAL_API_CREDENTIAL' if match.group(1).lower() in {'api_key', 'access_token', 'client_secret'} else 'CONFIG_CREDENTIAL')
        if bearer and any(_is_secret(m.group(1)) for m in _BEARER.finditer(window)):
            hits.add('AUTHORIZATION_BEARER_CREDENTIAL')
        if uri and any(_is_secret(m.group(1)) for m in _URI.finditer(window)):
            hits.add('URI_CREDENTIAL')
        if personal and _PHONE.search(window) and _EMAIL.search(window):
            hits.add('CONTEXTUAL_PERSONAL_INFORMATION')
    return sorted(hits)


def _check_deadline(deadline):
    if time.monotonic() > deadline:
        raise ValueError('registered inspection deadline exceeded')


def registered_matches(text, registered, *, deadline=None):
    if deadline is None:
        deadline = time.monotonic() + INSPECTION_SECONDS
    _check_deadline(deadline)
    normalized = None
    for entry in registered:
        _check_deadline(deadline)
        if isinstance(entry, RegisteredChunk):
            if entry.method == 'exact':
                if entry.text in text:
                    yield entry.source_path, 'exact'
            else:
                if normalized is None:
                    normalized = normalize_registered_text(text)
                if entry.text in normalized:
                    yield entry.source_path, 'normalized_bom_crlf'
            continue
        # Preserve existing tuple-based callers. New registrations carry the
        # normalization method explicitly and normalize before chunking.
        path, chunk = entry
        if chunk in text:
            yield path, 'exact'
        else:
            if normalized is None:
                normalized = normalize_registered_text(text)
            if normalize_registered_text(chunk) in normalized:
                yield path, 'normalized_bom_crlf'
    _check_deadline(deadline)


def detect_text(text, policy, registered, *, deadline=None):
    """Compatibility adapter retained for existing observation integrations."""
    if deadline is None:
        deadline = time.monotonic() + INSPECTION_SECONDS
    _check_deadline(deadline)
    hits = detect_rules(text, credential_rules=policy.credential_rules,
                        pii_rules=getattr(policy, 'pii_rules', False))
    _check_deadline(deadline)
    sources = set()
    for marker in policy.content_markers:
        _check_deadline(deadline)
        if marker.source_path not in policy.allowed_source_paths and marker.value in text:
            hits.append(marker.marker_id)
            sources.add(marker.source_path)
    for path, _ in registered_matches(text, registered, deadline=deadline):
        hits.append('REGISTERED_CONTENT')
        sources.add(path)
    return hits, sources
