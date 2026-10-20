"""Windows Codex core entry points; no legacy gateway or desktop adapters."""
import typer
from transpect_trace.guard.cli import app as guard_app
from transpect_trace.observe.cli import app as observe_app
from transpect_trace.behavior.cli import app as behavior_app
from transpect_trace.protect.cli import app as protect_app

app = typer.Typer(no_args_is_help=True, help="Windows fixed Codex content gate, TLS observation and behavior evidence.")
app.add_typer(guard_app, name="guard")
app.add_typer(observe_app, name="observe")
app.add_typer(behavior_app, name="behavior")
app.add_typer(protect_app, name="protect")

def main():
    app()

if __name__ == "__main__":
    main()
