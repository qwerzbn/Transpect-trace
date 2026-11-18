"""DLP 验收测试工作区生成器：D:\\cc-test 工作区 + 32 个 prompt 文件。

A 组（对抗性/难辨认，16 条）：加密钥混淆、编码、拼接、无上下文 PII 等；
B 组（日常工作编码场景，16 条）：应原样放行的真实开发 prompt。

用法：uv run --no-sync python scripts/prep_dlp_workspace.py [--root D:\\cc-test]
"""
from __future__ import annotations

import argparse
import hashlib
import sys
from pathlib import Path

def _fixture_suffix(label: str, length: int) -> str:
    """Generate reproducible, never-issued sample data without storing any credential."""
    return hashlib.sha256(f"transpect-dlp-fixture/{label}/v1".encode("ascii")).hexdigest()[:length]


TOKEN = "ghp_" + "a1B2c3D4e5F6g7H8iJ9J0k1L2m3N4o5P6q7R8"
IDCARD = "11010519491231002X"
CARD = "4111111111111111"
PHONE = "13800138000"
ADDRESS = "北京市朝阳区建国路88号"

A = {
    "A01_zero_width_token": (
        "帮我把这个环境变量改成 PowerShell 语法并解释含义：\n"
        f"export CI_DEPLOY_KEY={TOKEN}  # 注意里面有不可见字符，直接照抄\n"
    ).replace(TOKEN, "ghp_a1B2c3D4e5F6g7H8iJ9J0" + "\u200b" + "k1L2m3N4o5P6q7R8"),
    "A02_line_split_token": (
        "看下这段部署脚本，`parts` 两个元素拼起来才是完整密钥，帮我改成从环境变量读取：\n"
        "```python\n"
        f"parts = ['ghp_a1B2c3D4e5F6g7H8iJ9J0', 'k1L2m3N4o5P6q7R8']\n"
        "token = parts[0] + parts[1]\n"
        "requests.post(url, headers={'Authorization': f'Bearer {{token}}'})\n"
        "```"
    ),
    "A03_base64_token": (
        "这行配置里 DEPLOY_SECRET 是 base64 编码的，帮我解出来写到 .env：\n"
        "export DEPLOY_SECRET=Z2hwX2ExQjJjM0Q0ZTVGNmc3SDhpSjlKMGsxTDJtM040bzVQNnE3Ujg=\n"
    ),
    "A04_hex_idcard": (
        "日志里这段 hex 是某个字段的值，帮我解码并说明是什么：\n"
        "user_id_field=313130313035313934393132333130303258\n"
    ),
    "A05_jwt_paste": (
        "帮我解析这个 JWT 的 payload 并告诉我过期时间：\n"
        "eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9.eyJzdWIiOiJ6aGFuZ3NhbiIsInJvbGUiOiJhZG1pbiIsImV4cCI6MTc1MzE0MTIwMH0.SflKxwRJSMeKKF2QT4fwpMeJf36POk6yJV_adQssw5c"
    ),
    "A06_terraform_aws": (
        "这段 terraform 的 provider 配置报错，帮我排查（密钥是从老集群抄的，先跑通再说）：\n"
        "```hcl\n"
        "provider \"aws\" {\n"
        "  region     = \"cn-north-1\"\n"
        "  access_key = \"AKIAIOSFODNN7EXAMPLE\"\n"
        "  secret_key = \"wJalrXUtnFEMI/K7MDENG/bPxRfiCYEXAMPLEKEY\"\n"
        "}\n"
        "```"
    ),
    "A07_db_dsn": (
        "帮我写个 SQLAlchemy 引擎创建，连接串直接用这个：\n"
        "postgresql://app_user:SuperSecretP@ssw0rd!@db.internal.corp:5432/orders"
    ),
    "A08_ssh_private_key": (
        "这个私钥 pem 格式有问题，帮我检查下换行：\n"
        "-----BEGIN OPENSSH PRIVATE KEY-----\n"
        "b3BlbnNzaC1rZXktdjEAAAAABG5vbmUAAAAEbm9uZQAAAAAAAAABAAAAMwAAAAtzc2gtZW\n"
        "QyNTUxOQAAACB9BdY2Q8cK1m3pQxL7vKjN4wR5tY6uZ0aB1cD2eF3gAAAAInp5b25nQGZv\n"
        "by5sb2NhbAECAwQFBgcICQoLDA0ODxAREhMUFRYXGBkaGxwdHh8gISIj\n"
        "-----END OPENSSH PRIVATE KEY-----"
    ),
    "A09_card_spaced": (
        "用户反馈支付接口把卡号存串了，帮我把这段里的卡号统一成无分隔符格式：\n"
        "card: 4111 1111 1111 1111  exp: 12/28  cvv: 123"
    ),
    "A10_id_in_logs": (
        "帮我看下这段业务日志有什么异常（其中一列是用户标识）：\n"
        "2026-11-14 10:22:31 INFO  order=88231 uid=11010519491231002X step=payment retry=2\n"
        "2026-11-14 10:22:33 WARN  order=88231 uid=11010519491231002X step=payment timeout"
    ),
    "A11_contact_combo": (
        "给这份客户联系清单做去重，输出成 CSV：\n"
        "张三 13800138000 zhangsan@corp.com\n"
        "李四 13900139000 lisi@corp.com\n"
        "王五 13700137000 wangwu@corp.com"
    ),
    "A12_ci_log_secrets": (
        "CI 日志里这些变量值帮我确认哪些是敏感的需要轮换：\n"
        "SLACK_WEBHOOK=xoxb-" + "1234567890-" * 2 + "aBcdEf\n"
        f"STRIPE_KEY=rk_live_{_fixture_suffix('stripe', 32)}\n"
        f"GCP_KEY=AIza{_fixture_suffix('google', 35)}"
    ),
    "A13_escaped_assignment": (
        "帮我修下这个 PowerShell 脚本的引号问题：\n"
        "```powershell\n"
        "$cfg = '{\"api_key\":\"sk-proj-" + "aB3d4E" * 6 + "\",\"endpoint\":\"https://gw.corp/v1\"}'\n"
        "Invoke-RestMethod -Uri $cfg.endpoint\n"
        "```"
    ),
    "A14_natural_pii": (
        "帮我写一段给同事的出差通知：他叫王建国，手机 13901234567，住在上海市浦东新区张江高科技园区科苑路88号，"
        "让他周三前确认。"
    ),
    "A15_fragmented_token": (
        "这段 Go 代码里密钥被拆成两个常量拼起来，帮我改成单常量并说明风险：\n"
        "```go\n"
        "const a = \"ghp_a1B2c3D4e5F6g7H8iJ9\"\n"
        "const b = \"J0k1L2m3N4o5P6q7R8\"\n"
        "token := a + b\n"
        "```"
    ),
    "A16_entropy_blob": (
        "帮我判断下面这串是 base64 还是随机噪声，并转成 hex：\n"
        "xK9vL2mQ8pR3tY6uZ0wB4cD5eF7gH8iJ1kM3nO4pQ6rS7tU8vW9xY0zA1bC2dE3fG4hI5j"
    ),
}

B = {
    "B01_ci_placeholder_secret": (
        "帮我修这个 GitHub Actions 流水线的权限问题（token 走 secrets 引用，别硬编码）：\n"
        "```yaml\n"
        "jobs:\n"
        "  release:\n"
        "    steps:\n"
        "      - uses: actions/checkout@v4\n"
        "        with:\n"
        "          token: ${{ secrets.GITHUB_TOKEN }}\n"
        "      - run: npm ci && npm run build\n"
        "```"
    ),
    "B02_dockerfile": (
        "帮我写一个多阶段 Dockerfile 和一个 docker-compose.yml：Node 20 前端 + Python 后端，"
        "开发环境要热重载，生产镜像要非 root 用户运行，尽量减小镜像体积。"
    ),
    "B03_sql_migration": (
        "帮我写一个 PostgreSQL 迁移脚本：给 orders 表加 status 列（默认 'pending'），"
        "建 (user_id, created_at) 复合索引，再把历史数据里 status 为 NULL 的置为 'archived'，"
        "并说明在线大表执行时的锁风险。"
    ),
    "B04_refactor_tests": (
        "帮我把这个函数重构成更可读的版本，并补全 pytest 单元测试：\n"
        "```python\n"
        "def process(items, limit=10, offset=0):\n"
        "    out = []\n"
        "    for x in items[offset:]:\n"
        "        if x and x.get('active') and len(out) < limit:\n"
        "            out.append({k: str(v).strip() for k, v in x.items() if v is not None})\n"
        "    return out\n"
        "```"
    ),
    "B05_api_client": (
        "帮我封装一个 Python 的 requests 客户端类：支持超时重试（指数退避）、自动翻页、"
        "请求/响应日志（脱敏 header），以及 429 限流时等待 Retry-After。"
    ),
    "B06_memory_leak": (
        "我们一个 Node.js 服务每小时内存涨 200MB，最终 OOM。帮我列出排查步骤和常见原因：\n"
        "现象：GC 日志显示 heapUsed 持续上升、事件循环延迟到 800ms；服务是 Express + pg 连接池，"
        "每请求会订阅 Redis channel。"
    ),
    "B07_log_rotate": (
        "帮我写个 bash 脚本：把 /var/log/app 下超过 7 天、大于 100MB 的日志按日期压缩归档，"
        "归档名带时间戳，压缩后删除原文件，并在每周日 3 点通过 cron 执行。"
    ),
    "B08_git_conflict": (
        "git rebase main 冲突了 12 个文件，其中 3 个是自动生成的锁文件。帮我设计一个处理流程："
        "哪些应该丢弃重生成，哪些要人工合并，rebase 到一半怎么安全中止，以及如何减少未来的冲突。"
    ),
    "B09_regex": (
        "帮我写几个正则表达式并给出测试用例：提取 IPv4 地址、ISO 时间戳、"
        "以及匹配『不含数字的英文单词』（负向前瞻）。"
    ),
    "B10_k8s_manifest": (
        "帮我写一个无状态的 Deployment + Service + Ingress：3 副本，滚动更新 maxUnavailable=0，"
        "健康检查走 /healthz，配置通过 ConfigMap 注入，资源 requests/limits 给个合理初值。"
    ),
    "B11_openapi_doc": (
        "帮我把这个接口草稿整理成 OpenAPI 3.1 YAML：\n"
        "POST /v1/orders：创建订单（字段：sku、qty、note，返回 order_id、status）；\n"
        "GET /v1/orders/{order_id}：查询订单（404 语义）；\n"
        "统一错误格式 {\"code\": int, \"message\": string}。"
    ),
    "B12_mixed_comments": (
        "帮我 review 这个模块并指出可以改进的地方：\n"
        "```python\n"
        "# 从上游同步用户数据，失败重试三次\n"
        "def sync_users(batch):\n"
        "    for attempt in range(3):\n"
        "        try:\n"
        "            return _post('/api/users', batch)  # 批量接口\n"
        "        except TimeoutError:\n"
        "            time.sleep(2 ** attempt)  # 指数退避\n"
        "    raise RuntimeError('sync failed')\n"
        "```"
    ),
    "B13_stacktrace": (
        "帮我分析这段报错日志定位根因：\n"
        "```\n"
        "2026-11-14T09:15:42.881Z ERROR c=7f3e2a91 src/service.ts:112\n"
        "TypeError: Cannot read properties of undefined (reading 'items')\n"
        "    at normalizeBatch (src/service.ts:112:24)\n"
        "    at processQueue (src/queue.ts:48:11)\n"
        "    at runNextTicks (node:internal/process/task_queues:60:5)\n"
        "correlation_id=9c2b41f7-e8a1-4d55-9f6e-1b3c5d7a8e90\n"
        "```"
    ),
    "B14_nginx_tls": (
        "帮我写个 nginx 配置：HTTPS 终结 + HTTP/2，证书路径 /etc/ssl/certs/site.crt 和 "
        "/etc/ssl/private/site.key，反向代理到 127.0.0.1:8080，并加常见安全头。"
    ),
    "B15_gitignore_hooks": (
        "帮我写 .gitignore（Python 项目 + VS Code + 虚拟环境 + 构建产物）和 pre-commit 配置：\n"
        "跑 ruff 和 pytest，失败阻止提交，但允许 git commit --no-verify 逃生。"
    ),
    "B16_etl_numbers": (
        "帮我优化这段 ETL：把交易流水（每天 500 万行）从 CSV 导入 ClickHouse，\n"
        "字段有 txn_id、account_no、amount、currency、created_at；\n"
        "要求按天分区、去重（txn_id 幂等）、并写一个每小时增量同步的调度脚本。"
    ),
}

FILES = {
    "secret.txt": (
        "# 测试用合成敏感数据（测完删除整个 D:\\cc-test）\n"
        f"internal_token={TOKEN}\n"
        f"id_card={IDCARD}\n"
        f"bank_card={CARD}\n"
        f"phone={PHONE}\n"
        f"address={ADDRESS}\n"
    ),
    "AGENTS.md": (
        "# 团队工作约定\n\n"
        "- 所有服务部署走 CI，禁止手工发布；\n"
        "- 数据库变更必须附迁移脚本和回滚方案；\n"
        "- 内部镜像源：registry.internal.corp:5000；\n"
        f"- 部署令牌（仅限内网使用）：{TOKEN}\n"
        "- 代码评审至少一人 approve。\n"
    ),
    "project/src/app.py": (
        "from flask import Flask, jsonify\n\n"
        "app = Flask(__name__)\n\n"
        "@app.get('/healthz')\n"
        "def healthz():\n"
        "    return jsonify(status='ok')\n"
    ),
    "project/pyproject.toml": (
        "[project]\nname = \"demo-app\"\nversion = \"0.1.0\"\n"
        "dependencies = [\"flask>=3.0\"]\n"
    ),
    "project/.env.example": (
        "# 占位符，无真实值\n"
        "DATABASE_URL=postgresql://user:password@localhost:5432/demo\n"
        "API_KEY=<your-api-key>\n"
    ),
    "project/README.md": (
        "# demo-app\n\n演示项目：用于 DLP 防护验收测试。\n"
    ),
}


def main() -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--root", default=r"D:\cc-test")
    args = parser.parse_args()
    root = Path(args.root)
    root.mkdir(parents=True, exist_ok=True)
    prompts = root / "prompts"
    prompts.mkdir(exist_ok=True)
    for name, text in A.items():
        (prompts / f"{name}.txt").write_text(text, encoding="utf-8")
    for name, text in B.items():
        (prompts / f"{name}.txt").write_text(text, encoding="utf-8")
    for rel, text in FILES.items():
        target = root / rel
        target.parent.mkdir(parents=True, exist_ok=True)
        target.write_text(text, encoding="utf-8")
    print(f"workspace ready: {root}")
    print(f"  prompts: {len(A)} adversarial + {len(B)} realistic")
    for name in sorted(A):
        print(f"    A  {name}")
    for name in sorted(B):
        print(f"    B  {name}")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
