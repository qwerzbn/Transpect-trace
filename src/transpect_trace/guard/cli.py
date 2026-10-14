import json
from pathlib import Path
import shutil

import typer

app=typer.Typer(no_args_is_help=True,help="Fixed-version native Codex request gate; limited, explicit coverage.")


@app.command("baseline")
def baseline(binary:Path=typer.Option(None,"--codex",exists=True)):
    from .baseline import inspect_binary
    path=binary or Path(shutil.which("codex") or "")
    if not path.is_file():raise typer.BadParameter("Codex executable not found")
    result=inspect_binary(path);typer.echo(json.dumps(result,indent=2))
    if not result["supported"]:raise typer.Exit(1)


@app.command("codex",context_settings={"allow_extra_args":True,"ignore_unknown_options":True})
def codex(ctx:typer.Context,policy_file:Path=typer.Option(...,exists=True),
          dll:Path=typer.Option(Path("build/guard/ttrace-guard.dll"),exists=True),
          binary:Path=typer.Option(None,"--codex",exists=True),
          engine_command_file:Path=typer.Option(None,exists=True,help="JSON argv array for any-language named-pipe engine; no shell."),
          runs_dir:Path=typer.Option(Path("runs/guard"))):
    from .manager import launch
    from uuid import uuid4
    path=binary or Path(shutil.which("codex") or "")
    args=list(ctx.args)
    if args and args[0]=="--":args=args[1:]
    engine=json.loads(engine_command_file.read_text(encoding="utf-8")) if engine_command_file else None
    if engine is not None and (not isinstance(engine,list) or not engine or not all(isinstance(x,str) for x in engine)):
        raise typer.BadParameter("engine-command-file must contain a nonempty argv string array")
    try:code,state=launch(path,args,dll,policy_file,runs_dir/uuid4().hex,engine_command=engine)
    except (ValueError,RuntimeError,OSError) as error:typer.echo(str(error),err=True);raise typer.Exit(1)
    typer.echo(json.dumps(state,indent=2));raise typer.Exit(code)


@app.command("attach")
def attach(pid:int=typer.Option(...,min=1),policy_file:Path=typer.Option(...,exists=True),
           dll:Path=typer.Option(Path("build/guard/ttrace-guard.dll"),exists=True),
           engine_command_file:Path=typer.Option(None,exists=True),
           runs_dir:Path=typer.Option(Path("runs/guard"))):
    from .manager import attach_guard,monitor
    from uuid import uuid4
    engine=json.loads(engine_command_file.read_text(encoding="utf-8")) if engine_command_file else None
    if engine is not None and (not isinstance(engine,list) or not engine or not all(isinstance(x,str) for x in engine)):
        raise typer.BadParameter("engine-command-file must contain a nonempty argv string array")
    try:server,state,status=attach_guard(pid,dll,policy_file,runs_dir/uuid4().hex,engine_command=engine)
    except (ValueError,RuntimeError,OSError) as error:typer.echo(str(error),err=True);raise typer.Exit(1)
    typer.echo(json.dumps(state,indent=2));monitor(pid,server,state,status)


@app.command("status")
def status(run_directory:Path=typer.Argument(...,exists=True,file_okay=False)):
    path=run_directory/"status.json"
    if not path.is_file():raise typer.BadParameter("No guard status in this run")
    state=json.loads(path.read_text(encoding="utf-8"))
    # Persisted state alone is not a live native-attestation claim.
    state["snapshot_only"]=True
    typer.echo(json.dumps(state,indent=2))


@app.command("etw")
def etw(pid:int=typer.Option(...,min=1),output:Path=typer.Option(Path("runs/guard-etw/events.jsonl")),
        collector:Path=typer.Option(Path("build/guard/etw.exe"),exists=True)):
    from .native import process_identity
    from .etw import collect
    identity=process_identity(pid)
    code,index=collect(collector,pid,identity["creation_filetime"],output)
    typer.echo(json.dumps({"exit_code":code,"events_lost":index.dropped_events,"byte_level_taint_proof":False}))
    raise typer.Exit(code)


@app.command("validate")
def validate(run_directory:Path=typer.Argument(...,exists=True,file_okay=False),
             output:Path=typer.Option(None,help="Save the metadata-only capability report.")):
    from .validation import validate_run
    rendered=json.dumps(validate_run(run_directory),indent=2)+"\n"
    if output:
        output.parent.mkdir(parents=True,exist_ok=True);output.write_text(rendered,encoding="utf-8")
    typer.echo(rendered)
