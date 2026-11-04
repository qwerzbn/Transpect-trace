"""Bounded extraction of text from supported outbound file bytes.

This module never follows a path from a request.  The caller supplies the exact
bytes that a send gate has captured, so inspection and authorization use the
same immutable snapshot.
"""
from __future__ import annotations

from io import BytesIO
from pathlib import PurePath
from zipfile import BadZipFile, ZipFile

from defusedxml import ElementTree as SafeET
from pypdf import PdfReader


MAX_FILE_BYTES = 16 * 1024 * 1024
MAX_EXTRACTED_BYTES = 16 * 1024 * 1024
MAX_ZIP_UNCOMPRESSED_BYTES = 32 * 1024 * 1024
MAX_ZIP_PARTS = 1024
MAX_PDF_PAGES = 100


class UninspectableFile(ValueError):
    """The complete, supported textual content could not be established."""


_TEXT_EXTENSIONS = {
    ".txt", ".md", ".markdown", ".csv", ".tsv", ".json", ".jsonl",
    ".yaml", ".yml", ".toml", ".xml", ".html", ".htm", ".css",
    ".js", ".jsx", ".ts", ".tsx", ".py", ".rs", ".go", ".java",
    ".c", ".h", ".cpp", ".hpp", ".cs", ".sql", ".sh", ".ps1",
    ".log", ".ini", ".cfg",
}
_OOXML_ROOTS = {
    ".docx": "word/document.xml",
    ".xlsx": "xl/workbook.xml",
    ".pptx": "ppt/presentation.xml",
}
_UNINSPECTABLE_PARTS = (
    "/media/", "/embeddings/", "/externallinks/", "/activex/",
    "/oleobjects/", "vbaproject", "customxml/",
)


def _bounded_text(text: str) -> str:
    if len(text.encode("utf-8")) > MAX_EXTRACTED_BYTES:
        raise UninspectableFile("extracted text limit")
    if not text.strip():
        raise UninspectableFile("empty or image-only content")
    return text


def _pdf_has_unsupported_objects(page) -> bool:
    resources = page.get("/Resources")
    if not resources:
        return False
    resources = resources.get_object()
    xobjects = resources.get("/XObject")
    if not xobjects:
        return False
    for item in xobjects.get_object().values():
        obj = item.get_object()
        # Image data and nested form XObjects are not covered by text extraction.
        if obj.get("/Subtype") in ("/Image", "/Form"):
            return True
    return False


def _extract_pdf(data: bytes) -> str:
    try:
        reader = PdfReader(BytesIO(data), strict=True)
        if reader.is_encrypted:
            raise UninspectableFile("encrypted PDF")
        if not 0 < len(reader.pages) <= MAX_PDF_PAGES:
            raise UninspectableFile("PDF page limit")
        root = reader.trailer.get("/Root")
        if root:
            catalog = root.get_object()
            if any(name in catalog for name in ("/EmbeddedFiles", "/AcroForm", "/JavaScript", "/Names")):
                raise UninspectableFile("PDF embedded or interactive content")
        pages: list[str] = []
        if reader.metadata:
            pages.append("\n".join(str(value) for value in reader.metadata.values() if value is not None))
        for page in reader.pages:
            if page.get("/Annots") or _pdf_has_unsupported_objects(page):
                raise UninspectableFile("PDF annotation or image content")
            text = page.extract_text()
            if not text or not text.strip():
                raise UninspectableFile("PDF page without extractable text")
            pages.append(text)
            if sum(len(value.encode("utf-8")) for value in pages) > MAX_EXTRACTED_BYTES:
                raise UninspectableFile("PDF extracted text limit")
        return _bounded_text("\n".join(pages))
    except UninspectableFile:
        raise
    except Exception as error:
        raise UninspectableFile("PDF parse failure") from error


def _safe_zip_member(name: str) -> bool:
    normalized = name.replace("\\", "/")
    parts = normalized.split("/")
    if normalized.endswith("/"):
        parts = parts[:-1]
    return bool(parts) and not normalized.startswith("/") and ":" not in parts[0] and all(
        part not in ("", ".", "..") for part in parts
    )


def _extract_ooxml(data: bytes, extension: str) -> str:
    try:
        if not data.startswith(b"PK\x03\x04") or len(data) < 22:
            raise UninspectableFile("Office package prefix")
        end_record = data.rfind(b"PK\x05\x06", max(0, len(data) - 65_557))
        if end_record < 0 or end_record + 22 != len(data) or data[end_record + 20:end_record + 22] != b"\x00\x00":
            raise UninspectableFile("Office package trailing data or comment")
        with ZipFile(BytesIO(data)) as archive:
            entries = archive.infolist()
            if not 0 < len(entries) <= MAX_ZIP_PARTS:
                raise UninspectableFile("Office part limit")
            names = [entry.filename for entry in entries if not entry.is_dir()]
            if len(names) != len(set(name.casefold() for name in names)):
                raise UninspectableFile("duplicate Office part")
            if _OOXML_ROOTS[extension] not in names or "[Content_Types].xml" not in names:
                raise UninspectableFile("incomplete Office package")
            total_uncompressed = 0
            chunks: list[str] = []
            for entry in entries:
                name = entry.filename.replace("\\", "/")
                lower = name.casefold()
                if not _safe_zip_member(name) or entry.flag_bits & 1:
                    raise UninspectableFile("unsafe or encrypted Office part")
                if entry.is_dir():
                    continue
                if any(marker in "/" + lower for marker in _UNINSPECTABLE_PARTS) or not lower.endswith((".xml", ".rels")):
                    raise UninspectableFile("unsupported Office part")
                total_uncompressed += entry.file_size
                if (entry.file_size > MAX_FILE_BYTES or total_uncompressed > MAX_ZIP_UNCOMPRESSED_BYTES
                        or entry.file_size > max(1, entry.compress_size) * 200):
                    raise UninspectableFile("Office decompression limit")
                payload = archive.read(entry)
                if len(payload) != entry.file_size:
                    raise UninspectableFile("Office part length mismatch")
                root = SafeET.fromstring(payload)
                if lower.endswith(".rels"):
                    for relation in root.iter():
                        if relation.attrib.get("TargetMode", "").casefold() == "external":
                            raise UninspectableFile("Office external relationship")
                values = [element.text for element in root.iter() if element.text and element.text.strip()]
                values.extend(attribute for element in root.iter() for attribute in element.attrib.values()
                              if attribute and not attribute.startswith(("http://schemas.", "http://www.w3.org/")))
                if values:
                    # Both views matter: Office can split a key between adjacent text runs.
                    chunks.append(" ".join(values))
                    chunks.append("".join(values))
                if sum(len(value.encode("utf-8")) for value in chunks) > MAX_EXTRACTED_BYTES:
                    raise UninspectableFile("Office extracted text limit")
            return _bounded_text("\n".join(chunks))
    except UninspectableFile:
        raise
    except (BadZipFile, RuntimeError, ValueError, KeyError, OSError) as error:
        raise UninspectableFile("Office parse failure") from error
    except Exception as error:
        raise UninspectableFile("Office parse failure") from error


def extract_text(name: str, data: bytes) -> str:
    """Return fully inspected text, or reject the supplied file snapshot."""
    if not isinstance(data, bytes) or not 0 < len(data) <= MAX_FILE_BYTES:
        raise UninspectableFile("file size or type limit")
    extension = PurePath(name).suffix.casefold()
    if extension in _TEXT_EXTENSIONS:
        try:
            return _bounded_text(data.decode("utf-8-sig"))
        except UnicodeDecodeError as error:
            raise UninspectableFile("non-UTF-8 text") from error
    if extension == ".pdf":
        return _extract_pdf(data)
    if extension in _OOXML_ROOTS:
        return _extract_ooxml(data, extension)
    raise UninspectableFile("unsupported file format")
