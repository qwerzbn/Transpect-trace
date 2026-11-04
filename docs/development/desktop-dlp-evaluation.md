# 桌面端 DLP 内容识别评测（本地离线判定）

本评测只调用本地四层内容识别引擎，**不启动 Codex 桌面端，也不验证实际发送前 Hook、WFP 或源站零字节**。公开语料是合成 PII；文件夹具也是脚本生成的假密钥、假员工记录和假内部文档。样本文本不写入报告，也不发送给云端分类器。

## 语料与运行

| 语料 | 固定修订 | 文件 SHA-256 | 本次行数 |
| --- | --- | --- | ---: |
| [Gretel PII Masking 英文 test](https://huggingface.co/datasets/gretelai/gretel-pii-masking-en-v1) | `e06eb1499ca8d54470f085021cd8e54f9efac7fd` | `c89a6bffa838edb0f2fc6686bf35da4930944519ac97308b0b6e32298594b5b1` | 5,000 |
| [PII Bench ZH](https://huggingface.co/datasets/wan9yu/pii-bench-zh) | `c350b94897af668517ff5de237d89f2ce2eaa6f0` | `bcaa54909fd69c6737b8e442c4d740ce1bf5b95b7d4af70b2f2692010e1ff7a5` | 5,000 |

语料首次运行时下载到 `runs/desktop-dlp-datasets/`，之后按上述 SHA-256 核验；哈希不符即停止。DuckDB 固定为 `2.0.0`，运行依赖见项目锁文件。全量命令：

```powershell
uv run --no-sync --with duckdb==2.0.0 python scripts/evaluate_desktop_dlp_datasets.py --per-dataset 0
```

生成的详细报告在 `runs/desktop-dlp-datasets/report.json`。默认命令使用固定种子 `2026-11-04`，每套语料取 500 行，供快速回归；`--per-dataset 0` 读取固定文件的全部行。

## 结果与口径

| 语料 | BLOCK | REVIEW | ALLOW | 脱敏副本 ALLOW | 原始文本判定 P95 |
| --- | ---: | ---: | ---: | ---: | ---: |
| Gretel 英文 | 1,170 | 589 | 3,241 | 4,975 / 5,000 | 0.221 ms |
| PII Bench ZH | 2,652 | 1,292 | 1,056 | 5,000 / 5,000 | 0.087 ms |

`REVIEW` 在实际门控中按拒绝处理。语料含姓名、邮箱、电话等强弱不同的实体，不能把每个 `ALLOW` 都算作漏检，也不能把上表的阻断比例称为准确率或召回率。脱敏副本通过替换标注实体生成；Gretel 副本仍有 18 条 `REVIEW`、7 条 `BLOCK`，约占 0.5%，但未标注的敏感内容可能仍在文本中，因此这只是**误报诊断**，不是经人工核验的误报率。耗时为一次实测，会随机器负载变化，且仅测内容引擎，不含采集、加密落盘、IPC 和发送。

另以明确标注期望动作的合成夹具制作文本、PDF、DOCX、XLSX 和 PPTX 请求。混淆矩阵：期望 `BLOCK` 的 13 项中，12 项返回 `BLOCK`，1 项返回 `ALLOW`；期望 `ALLOW` 的 9 项全部放行。漏检项是**仅保留含义、改写全部字面内容的内部文档**，四层词面/结构识别无法稳定抓到。未知二进制格式和无可提取文字的 PDF 均因无法完整检查而拒绝，这两项未算入内容识别检出率。

本次公开语料的汇总结果曾用于修正中文数字前的匹配边界，并补充身份证、银行卡和护照上下文规则；因此它属于**开发诊断数据**，不能宣称为未见过的盲测集。下一步若要报告正式准确率和召回率，需要另建独立的策略级人工标注集，并与真实桌面端发送前、源站侧验证分开统计。
