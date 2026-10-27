"""Run the real BookStack -> official Codex -> Native-gated Mailpit experiment."""
import sys
from transpect_trace.flow.knowledge_mail.cli import app


if __name__ == '__main__':
    app(['run', *sys.argv[1:]])
