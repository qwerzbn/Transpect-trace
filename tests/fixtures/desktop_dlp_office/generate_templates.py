"""Regenerate the synthetic Word and Excel OOXML templates.

Run with python-docx==1.2.0 and openpyxl==3.1.5. The evaluator pins the
resulting template hashes; ordinary test runs do not need these libraries.
"""
from __future__ import annotations

from pathlib import Path
from io import BytesIO
from datetime import datetime
from zipfile import ZipFile, ZipInfo

from docx import Document
from lxml import etree
from openpyxl import Workbook


OUTPUT = Path(__file__).resolve().parent
PLACEHOLDER = "SYNTHETIC_DLP_PAYLOAD"
_DOCX_REMOVE = frozenset((
    "docProps/thumbnail.jpeg", "customXml/item1.xml",
    "customXml/_rels/item1.xml.rels", "customXml/itemProps1.xml",
))


def _text_only_docx(path: Path) -> None:
    """Remove default-template thumbnail/custom XML and their relationships."""
    with BytesIO() as buffer:
        with ZipFile(path) as source, ZipFile(buffer, "w") as target:
            for old in source.infolist():
                if old.filename in _DOCX_REMOVE:
                    continue
                contents = source.read(old.filename)
                if old.filename in {"_rels/.rels", "word/_rels/document.xml.rels"}:
                    root = etree.fromstring(contents)
                    for relation in list(root):
                        if relation.get("Type", "").rsplit("/", 1)[-1] in {"thumbnail", "customXml"}:
                            root.remove(relation)
                    contents = etree.tostring(root, encoding="UTF-8", xml_declaration=True)
                elif old.filename == "[Content_Types].xml":
                    root = etree.fromstring(contents)
                    for item in list(root):
                        if (item.get("Extension") == "jpeg"
                                or item.get("PartName", "").startswith("/customXml/")):
                            root.remove(item)
                    contents = etree.tostring(root, encoding="UTF-8", xml_declaration=True)
                entry = ZipInfo(old.filename, date_time=(1980, 1, 1, 0, 0, 0))
                entry.create_system = 0
                entry.external_attr = 0
                target.writestr(entry, contents, compress_type=old.compress_type)
        path.write_bytes(buffer.getvalue())


def _fixed_zip_metadata(path: Path) -> None:
    with BytesIO() as buffer:
        with ZipFile(path) as source, ZipFile(buffer, "w") as target:
            for old in source.infolist():
                contents = source.read(old)
                if old.filename == "docProps/core.xml":
                    root = etree.fromstring(contents)
                    for item in root:
                        if item.tag.rsplit("}", 1)[-1] in {"created", "modified"}:
                            item.text = "2000-01-01T00:00:00Z"
                    contents = etree.tostring(root, encoding="UTF-8", xml_declaration=True)
                entry = ZipInfo(old.filename, date_time=(1980, 1, 1, 0, 0, 0))
                entry.create_system = 0
                entry.external_attr = 0
                target.writestr(entry, contents, compress_type=old.compress_type)
        path.write_bytes(buffer.getvalue())


def main() -> None:
    document = Document()
    document.add_paragraph(PLACEHOLDER)
    docx_path = OUTPUT / "template.docx"
    document.save(docx_path)
    _text_only_docx(docx_path)

    workbook = Workbook()
    workbook.active["A1"] = PLACEHOLDER
    workbook.properties.created = datetime(2000, 1, 1)
    workbook.properties.modified = datetime(2000, 1, 1)
    xlsx_path = OUTPUT / "template.xlsx"
    workbook.save(xlsx_path)
    _fixed_zip_metadata(xlsx_path)


if __name__ == "__main__":
    main()
