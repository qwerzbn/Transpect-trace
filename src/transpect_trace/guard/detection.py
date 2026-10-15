"""Pure content detection shared by enforcement and observation.

This function neither decides actions nor changes session state.
"""
import re


def detect_text(text,policy,registered):
    hits=[];sources=set()
    for marker in policy.content_markers:
        if marker.source_path not in policy.allowed_source_paths and marker.value in text:
            hits.append(marker.marker_id);sources.add(marker.source_path)
    for path,chunk in registered:
        if chunk in text:hits.append("REGISTERED_CONTENT");sources.add(path)
    if policy.credential_rules:
        if re.search(r"-----BEGIN (?:RSA |EC |OPENSSH |ENCRYPTED )?PRIVATE KEY-----[\s\S]+?-----END (?:RSA |EC |OPENSSH |ENCRYPTED )?PRIVATE KEY-----",text):
            hits.append("PRIVATE_KEY_BLOCK")
        for match in re.finditer(r"(?im)\b(?:password|passwd|mysql_password|api_secret|private_key)\s*[:=]\s*[\"']?([^\s\"']{8,})",text):
            secret=match.group(1).rstrip(",;")
            if not secret.startswith(("${","<","TRANSPECT_PUBLIC")) and secret.lower() not in {"changeme","your_password","example_password","********"}:
                hits.append("CONFIG_CREDENTIAL")
        if re.search(r"\bAKIA[A-Z0-9]{16}\b",text) and re.search(r"(?im)aws_secret_access_key\s*[:=]\s*[\"']?[A-Za-z0-9/+]{40}\b",text):
            hits.append("AWS_CREDENTIAL_PAIR")
    return hits,sources
