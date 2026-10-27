"""Private payload entry, released only after the existing Native gate is ready."""
import json
import sys
from pathlib import Path

from transpect_trace.flow.knowledge_mail.tools import KnowledgeMailTools, ToolError, strict_json


def main():
    try:
        config = strict_json(Path(sys.argv[1]).read_bytes())
        draft = strict_json(Path(sys.argv[2]).read_bytes())
        result = KnowledgeMailTools(config).send_mail(draft)
    except Exception as error:
        result = {'kind': 'tool_failed', 'reason': str(error) if isinstance(error, ToolError)
                  else 'MAIL_WORKER_FAILED'}
    print(json.dumps(result, separators=(',', ':')), flush=True)
    # Keep the registered process alive until the controller drains Native
    # execution acknowledgements and closes the audit session.
    sys.stdin.buffer.readline(32)


if __name__ == '__main__':
    main()
