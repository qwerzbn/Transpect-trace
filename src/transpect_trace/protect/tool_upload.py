"""Literal HTTP upload operands for the pre-execution gate.

This is deliberately not a shell evaluator or a network boundary. An explicit
file upload must be inspectable before process creation; variables, stdin,
globs and unresolved operands are reported as uninspectable, never executed
to discover their values. The eventual file can still change after this check.
"""
from __future__ import annotations

from dataclasses import dataclass
import ntpath
from pathlib import Path
import re


_HTTP_TOOL = re.compile(
    r'''(?i)(?:^|[\s;&|('"\\/])(?P<tool>curl|wget|Invoke-WebRequest|Invoke-RestMethod|iwr|irm)'''
    r'''(?:\.exe)?(?=$|[\s;|&)'"}])''')
_OPTION = re.compile(
    r'''(?i)(?<![^\s'"(])(?P<option>--(?:data-binary|data-ascii|data-urlencode|data|json|form|upload-file|post-file|body-file)|-InFile|(?-i:-d|-F|-T))'''
    r'''(?P<separator>\s+|=|:|(?=[@'"<])|(?<=-[dFT])(?=[^\s-]))''')


@dataclass(frozen=True)
class UploadReference:
    path: Path | None
    error: str | None = None


def _argument(command: str, start: int) -> tuple[str, bool]:
    if start >= len(command):
        return "", False
    quote = command[start] if command[start] in "\"'" else None
    if quote:
        end = command.find(quote, start + 1)
        return (command[start + 1:end], True) if end >= 0 else ("", False)
    match = re.match(r'''[^\s;|&)"']+''', command[start:])
    return (match.group(0), True) if match else ("", False)


def upload_references(command: str, cwd: str) -> list[UploadReference]:
    """Extract curl/wget/PowerShell literal upload sources, including spaces.

    Curl's --data-raw and --form-string intentionally have no file semantics.
    Only known HTTP tools activate these operand rules; helper summaries and
    ordinary local commands are not interpreted as upload operations.
    """
    # Avoid treating a plain `Write-Output 'curl -T example.txt ...'` as an
    # upload. Only inspect an actual command position or a known shell's
    # command argument. This does not evaluate arbitrary shell expressions.
    start = None
    for tool in _HTTP_TOOL.finditer(command):
        prefix = command[:tool.start('tool')].rstrip()
        if (not prefix or prefix[-1:] in ';|&{('
                or re.search(r'''(?i)(?:-Command|-c|/c)\s*["']?\s*$''', prefix)
                or re.fullmatch(r'''[\s&"']*(?:[A-Za-z]:[\\/][^"'\r\n]*)?''', prefix)):
            start = tool.start('tool')
            break
    if start is None:
        return []
    references: list[UploadReference] = []
    for match in _OPTION.finditer(command, start):
        value, complete = _argument(command, match.end())
        option = match['option'].lower()
        file_only = option in {'-t', '--upload-file', '--post-file', '--body-file', '-infile'}
        if not complete:
            references.append(UploadReference(None, 'UPLOAD_OPERAND_UNRESOLVED'))
            continue
        if option in {'-f', '--form'}:
            if '=' not in value:
                continue
            value = value.split('=', 1)[1]
            if not value.startswith(('@', '<')):
                continue
            # Curl form attributes and multiple source files require a parser
            # for that grammar. Do not inspect only the first file and allow.
            if ';' in value or ',' in value:
                references.append(UploadReference(None, 'UPLOAD_OPERAND_UNRESOLVED'))
                continue
            value = value[1:]
        elif option == '--data-urlencode':
            if '@' not in value:
                continue
            value = value.split('@', 1)[1]
        elif not file_only:
            if not value.startswith('@'):
                continue
            value = value[1:]
        if not value or value == '-' or re.search(r'[$%`*?{}\r\n\x00]', value):
            references.append(UploadReference(None, 'UPLOAD_OPERAND_UNRESOLVED'))
        elif value.startswith(('\\\\', '//')):
            # Scanning a UNC operand could itself send credentials/network
            # traffic from the controller. A local file is required here.
            references.append(UploadReference(None, 'UPLOAD_SOURCE_NOT_LOCAL'))
        elif ntpath.isabs(value) or Path(value).is_absolute():
            references.append(UploadReference(Path(value)))
        elif cwd.startswith(('\\\\', '//')):
            references.append(UploadReference(None, 'UPLOAD_SOURCE_NOT_LOCAL'))
        elif cwd:
            references.append(UploadReference(Path(cwd) / value))
        else:
            references.append(UploadReference(None, 'UPLOAD_CWD_MISSING'))
    return list(dict.fromkeys(references))
