# 合成 Office 模板

这三份文件只包含固定占位文本 `SYNTHETIC_DLP_PAYLOAD`，用于验证受支持的纯文字 OOXML 解析路径。评测脚本先核对模板 SHA-256，再替换正文并固定 ZIP 条目时间戳；模板中没有真实个人或企业资料。

| 模板 | 生成工具 | SHA-256 |
| --- | --- | --- |
| `template.docx` | python-docx 1.2.0 | `9e80afd9ae27452725193821f7058d4a63aff6fdc05ebdb8d4105426a7382028` |
| `template.xlsx` | openpyxl 3.1.5 | `00498752aa7bd7ec53cb2d05c1bf6a15008396824e51076e6c26254cd72b2078` |
| `template.pptx` | PptxGenJS 4.0.1 | `134c4b49da4b735be84beb0b3bfc4257be6d181b582e5080fbfa90d594afcf85` |

DOCX 模板在生成后移除默认缩略图及自定义 XML，并删除相关关系。重新生成 Word/Excel 模板：

```powershell
uv run --no-sync --with python-docx==1.2.0 --with openpyxl==3.1.5 python tests/fixtures/desktop_dlp_office/generate_templates.py
```

PPTX 模板由 `generate_pptx.js` 生成，需要 Node.js 与 PptxGenJS 4.0.1。重新生成后，必须用 Office 包结构校验器验证，分别用文档库重新打开三种格式，并更新评测脚本中的固定哈希。生成器和库的版本变化可能改变模板字节，因此不能只凭文件扩展名接受新模板。
