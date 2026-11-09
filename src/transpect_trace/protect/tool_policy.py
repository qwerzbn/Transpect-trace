"""Tool-call policy the content engine cannot express: *where* a call reaches.

The DLP engine judges bytes. A tool call is also an action: `Get-Content .env`
carries nothing sensitive in its own text, yet its output will. Two of those
actions are cheap to recognize before the call runs and matter for a coding
agent:

* reading a well-known credential store (`SENSITIVE_PATH`), and
* opening a network connection to a host outside the allow list
  (`NETWORK_EGRESS`).

A third rule protects the gate itself (`GATE_TAMPER`): an agent that edits
`hooks.json`, the Codex config holding hook trust, or the gate's own directory
can switch the gate off for every later turn.

These are lexical rules over the call's arguments. They are bypassable by a
script written to disk and then run, by string building, or by a binary that is
not listed; they reduce the obvious paths and do not replace a network boundary.
Each finding is (category, rule_id, score) like the engine's evidence, and the
rule IDs carry only a fixed label, never the matched path or host.
"""
from __future__ import annotations

from dataclasses import dataclass, field
import ipaddress
import re
from typing import Iterable

Finding = tuple[str, str, float]

# A path token ends where a shell would end it.
_LEFT = r"(?:^|(?<=[\s'\"=(,;|&<>\\/:`]))"
_RIGHT = r"(?=$|[\s'\"),;|&<>`])"

# High-confidence credential stores: their only purpose is to hold secrets.
_STRONG_PATHS = (
    ("ssh_private_key", r"id_(?:rsa|dsa|ecdsa|ed25519)(?:_sk)?" + _RIGHT),
    ("aws_credentials", r"\.aws[\\/](?:credentials|config)" + _RIGHT),
    ("git_credentials", r"\.git-credentials" + _RIGHT),
    ("netrc", r"[._]netrc" + _RIGHT),
    ("pgpass", r"\.pgpass" + _RIGHT),
    ("password_db", r"[^\s'\"\\/]+\.kdbx?" + _RIGHT),
    ("codex_auth", r"\.codex[\\/]auth\.json" + _RIGHT),
    ("docker_auth", r"\.docker[\\/]config\.json" + _RIGHT),
    ("kube_config", r"\.kube[\\/]config" + _RIGHT),
    ("browser_secrets", r"(?:Login Data|Cookies|Web Data|Local State|logins\.json|key4\.db)" + _RIGHT),
    ("windows_hives", r"(?:config[\\/](?:SAM|SECURITY|SYSTEM)|ntds\.dit)" + _RIGHT),
    ("gnupg", r"\.gnupg[\\/]"),
    ("ssh_dir", r"\.ssh[\\/](?!known_hosts|config\b|authorized_keys|[^\s'\"]*\.pub\b)[^\s'\"]+"),
)
# Usually secret, sometimes a template: denied as REVIEW, so a user can approve.
_WEAK_PATHS = (
    ("dotenv", r"\.env(?:\.(?!example\b|sample\b|template\b|dist\b|defaults?\b)[\w-]+)?" + _RIGHT),
    ("key_material", r"[^\s'\"\\/]+\.(?:pem|key|p12|pfx|jks|keystore|ppk|ovpn)" + _RIGHT),
    ("credential_file", r"(?:credentials|client_secrets?|service[-_]account[^\s'\"\\/]*)\.json" + _RIGHT),
    ("secrets_file", r"secrets?\.(?:ya?ml|json|toml|ini|txt)" + _RIGHT),
    ("package_tokens", r"\.(?:npmrc|pypirc|yarnrc\.yml)" + _RIGHT),
    ("terraform_state", r"[^\s'\"\\/]*\.(?:tfstate|tfvars)(?:\.backup)?" + _RIGHT),
)
_COMPILED_STRONG = tuple((name, re.compile(_LEFT + expr, re.I)) for name, expr in _STRONG_PATHS)
_COMPILED_WEAK = tuple((name, re.compile(_LEFT + expr, re.I)) for name, expr in _WEAK_PATHS)
# Writing an ignore rule names the file without reading it.
_IGNORE_FILE = re.compile(r"\.(?:git|docker|npm|prettier|eslint)ignore\b", re.I)

# Tools grouped by what a foreign destination means for them.
_HTTP_TOOLS = re.compile(
    r"(?i)(?:^|[\s;|&(`'\"{])(curl|wget|Invoke-WebRequest|Invoke-RestMethod|iwr|irm)"
    r"(?:\.exe)?(?=$|[\s;|&)`'\"}])")
# Upload flags: data leaves in a request body. A plain GET only fetches.
_HTTP_UPLOAD = re.compile(
    r"(?i)(?:^|\s)(?:-d|--data(?:-[a-z]+)?|-F|--form(?:-string)?|-T|--upload-file|--json|"
    r"-X\s*(?:POST|PUT|PATCH)|--request\s+(?:POST|PUT|PATCH)|--post-(?:data|file)|"
    r"--body-(?:data|file)|-InFile|-Body|-Form|-Method\s+[\"']?(?:Post|Put|Patch))\b")
_TRANSFER_TOOLS = re.compile(
    r"(?i)(?:^|[\s;|&(`'\"{])(scp|sftp|ftp|tftp|rsync|ssh|nc|ncat|netcat|telnet|socat|"
    r"bitsadmin|Start-BitsTransfer)(?:\.exe)?(?=$|[\s;|&)`'\"}])")
_MAIL = re.compile(r"(?i)\bSend-MailMessage\b")
_EGRESS_APIS = re.compile(
    r"(?i)Net\.WebClient|System\.Net\.Http|Net\.Sockets|\bTcpClient\b|\bUdpClient\b|"
    r"WebRequest\]::Create|certutil(?:\.exe)?\s+[^|;&]*-urlcache|"
    # Interpreter flags may precede -c/-e (`python -I -c`, `node --no-warnings -e`).
    r"\b(?:python[\d.]*|py)(?:\.exe)?\b[^|;&]*?\s-c\b[^|;&]*\b(?:requests|urllib|http\.client|socket|httpx|aiohttp)\b|"
    r"\bnode(?:\.exe)?\b[^|;&]*?\s-e\b[^|;&]*\b(?:fetch|https?\.request|net\.connect)\b")
_PUBLISH = re.compile(
    r"(?i)\b(?:npm\s+publish|twine\s+upload|gh\s+gist\s+create|gh\s+release\s+upload|"
    r"git\s+remote\s+(?:add|set-url)|docker\s+push)\b")
_EXPLICIT_GIT_PUSH = re.compile(r"(?i)\bgit\s+push\s+(?:-\S+\s+)*(\S+://\S+|\S+@\S+:\S+)")
_URL_HOST = re.compile(r"(?i)\b[a-z][a-z0-9+.-]{1,15}://(?:[^\s/@'\"]+@)?(\[[0-9a-f:.]+\]|[^\s/:'\"?#]+)")
_USER_AT_HOST = re.compile(r"(?<![\w/.@-])[\w.-]+@(\[[0-9a-fA-F:.]+\]|[A-Za-z0-9.-]+)(?=[:\s'\"]|$)")

DEFAULT_ALLOWED_HOSTS = (
    "localhost", "github.com", "api.github.com", "raw.githubusercontent.com",
    "objects.githubusercontent.com", "codeload.github.com", "pypi.org",
    "files.pythonhosted.org", "registry.npmjs.org", "registry.npmmirror.com",
    "mirrors.aliyun.com", "pypi.tuna.tsinghua.edu.cn",
)


def _host_allowed(host: str, allowed: frozenset[str]) -> bool:
    host = host.strip("[]").rstrip(".").casefold()
    try:
        address = ipaddress.ip_address(host)
    except ValueError:
        return any(host == name or host.endswith("." + name) for name in allowed)
    # Only globally routable addresses leave the organization's network:
    # loopback, RFC 1918, CGNAT/Tailscale (100.64/10) and link-local stay inside.
    return not address.is_global or str(address) in allowed


def _is_destination(host: str) -> bool:
    """A literal IP or a dotted DNS name. A bare word is an SSH alias or a variable."""
    host = host.strip("[]")
    try:
        ipaddress.ip_address(host)
        return True
    except ValueError:
        return bool(re.fullmatch(r"(?:[a-z0-9-]{1,63}\.)+[a-z]{2,24}", host, re.I))


@dataclass(frozen=True)
class ToolPolicy:
    allowed_hosts: frozenset[str] = frozenset(DEFAULT_ALLOWED_HOSTS)
    # Paths whose modification disables the gate: hooks.json, config.toml,
    # the gate directory. Compared case-insensitively with either separator.
    protected_paths: tuple[str, ...] = ()
    _protected: tuple[re.Pattern, ...] = field(default=(), repr=False, compare=False)

    def __post_init__(self) -> None:
        patterns = []
        for path in self.protected_paths:
            parts = [re.escape(part) for part in re.split(r"[\\/]+", path.strip()) if part]
            if parts:
                patterns.append(re.compile(r"[\\/]+".join(parts), re.I))
        object.__setattr__(self, "_protected", tuple(patterns))

    def inspect(self, tool_name: str, leaves: Iterable[str]) -> list[Finding]:
        findings: dict[str, Finding] = {}
        texts = [leaf for leaf in leaves if isinstance(leaf, str) and leaf]
        joined = "\n".join(texts)
        for pattern in self._protected:
            if pattern.search(joined):
                findings["GATE_TAMPER"] = ("GATE_TAMPER", "GATE_TAMPER:protected_path", 0.95)
                break
        for name, pattern in _COMPILED_STRONG:
            if pattern.search(joined):
                findings[name] = ("SENSITIVE_PATH", f"SENSITIVE_PATH:{name}", 0.90)
        if not _IGNORE_FILE.search(joined):
            for name, pattern in _COMPILED_WEAK:
                if pattern.search(joined):
                    findings[name] = ("SENSITIVE_PATH", f"SENSITIVE_PATH:{name}", 0.60)
        if _is_shell(tool_name):
            for rule in self._egress(joined):
                findings[rule] = ("NETWORK_EGRESS", rule, 0.60)
        return list(findings.values())

    def _egress(self, command: str) -> list[str]:
        """Flag data leaving for a foreign destination, not every network use.

        Measured on this machine's own tool history, the first version -- any
        network tool whose destination was foreign *or unrecognizable* --
        denied 14% of tool calls, nearly all `ssh`/`scp` to SSH config aliases
        and plain downloads. The rules below follow the direction of data:
        an HTTP upload, a transfer/remote-shell session, or an API call to a
        globally routable host outside the allow list.
        """
        rules = []
        hosts = [m.group(1) for m in _URL_HOST.finditer(command)]
        hosts += [m.group(1) for m in _USER_AT_HOST.finditer(command)]
        hosts = [host for host in hosts if _is_destination(host)]
        foreign = [host for host in hosts if not _host_allowed(host, self.allowed_hosts)]
        if _HTTP_TOOLS.search(command) and _HTTP_UPLOAD.search(command):
            # An upload to an unrecognizable destination (`curl -d @x $URL`) is
            # treated as foreign: the gate cannot show it is internal.
            if foreign or not hosts:
                rules.append("EGRESS_HTTP_UPLOAD")
        if _TRANSFER_TOOLS.search(command) and foreign:
            rules.append("EGRESS_TRANSFER")
        if _EGRESS_APIS.search(command) and (foreign or not hosts):
            rules.append("EGRESS_API")
        if _MAIL.search(command):
            rules.append("EGRESS_MAIL")
        if _PUBLISH.search(command):
            rules.append("EGRESS_PUBLISH")
        if _EXPLICIT_GIT_PUSH.search(command) and foreign:
            rules.append("EGRESS_GIT_PUSH_URL")
        return rules


def _is_shell(tool_name: str) -> bool:
    return tool_name.casefold() in {"bash", "shell", "exec_command", "local_shell",
                                    "shell_command", "powershell", "exec"}
