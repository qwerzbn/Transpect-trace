import json
from pathlib import Path
from uuid import uuid4
import typer
app=typer.Typer(no_args_is_help=True,help='Explicit Native adapters; uncertified channels refuse activation.')

@app.command('run',context_settings={'allow_extra_args':True,'ignore_unknown_options':True})
def run(ctx:typer.Context,channel:str=typer.Option(...),
        binary:Path|None=typer.Option(None,exists=True),policy_file:Path|None=typer.Option(None,exists=True),
        index_file:Path|None=typer.Option(None,exists=True),dll:Path|None=typer.Option(None,exists=True),
        runs_dir:Path=typer.Option(Path('runs/protect'))):
    try:
        if channel=='cli':
            from transpect_trace.guard.manager import launch
            from .guard_bridge import GuardPolicyBridge
            from .policy import ProtectionEngine,ProtectionPolicy
            from .detection import ContentIndex
            if binary is None or policy_file is None:raise ValueError('--binary and Protect v1 --policy-file required')
            policy=ProtectionPolicy.model_validate_json(policy_file.read_text(encoding='utf-8'))
            index=ContentIndex.model_validate_json(index_file.read_text(encoding='utf-8')) if index_file else None
            args=list(ctx.args)
            if args[:1]==['--']:args=args[1:]
            code,state=launch(binary,args,dll or Path('build/guard/ttrace-guard.dll'),policy_file,runs_dir/uuid4().hex,
                engine_factory=lambda subject:GuardPolicyBridge(subject,engine=ProtectionEngine(policy,index)))
        else:raise ValueError('Native safe refusal not certified for this channel; protection activation refused')
    except (OSError,ValueError,RuntimeError) as error:typer.echo(str(error),err=True);raise typer.Exit(1)
    typer.echo(json.dumps(state,indent=2));raise typer.Exit(code)

@app.command('attach')
def attach(channel:str=typer.Option(...),pid:int=typer.Option(...,min=1),policy_file:Path=typer.Option(...,exists=True),
           dll:Path=typer.Option(Path('build/guard/ttrace-guard.dll'),exists=True),runs_dir:Path=typer.Option(Path('runs/protect'))):
    if channel!='cli':raise typer.BadParameter('This distribution supports only fixed Codex CLI attachment')
    from transpect_trace.guard.manager import attach_guard,monitor
    try:
        from .guard_bridge import GuardPolicyBridge
        from .policy import ProtectionEngine,ProtectionPolicy
        policy=ProtectionPolicy.model_validate_json(policy_file.read_text(encoding='utf-8'))
        server,state,status=attach_guard(pid,dll,policy_file,runs_dir/uuid4().hex,
            engine_factory=lambda subject:GuardPolicyBridge(subject,engine=ProtectionEngine(policy)))
        typer.echo(json.dumps(state,indent=2));monitor(pid,server,state,status)
    except (OSError,ValueError,RuntimeError) as error:typer.echo(str(error),err=True);raise typer.Exit(1)

@app.command('status')
def status(run_directory:Path=typer.Argument(...,exists=True,file_okay=False)):
    data=json.loads((run_directory/'status.json').read_text())
    data['snapshot_only']=True;data['live_native_attestation']='not_performed'
    subject=data.get('identity',{})
    try:
        from transpect_trace.observe.windows import identity
        current=identity(subject['pid'])
        data['process_still_matches']=current['creation_filetime']==subject['creation_filetime']
    except (OSError,ValueError,KeyError):data['process_still_matches']=False
    if not data['process_still_matches']:
        data['persisted_state']=data.get('state');data['state']='inactive_process_exited_or_changed';data['gate_ready']=False
    typer.echo(json.dumps(data,indent=2))

@app.command('discover')
def discover(pid:int=typer.Option(...,min=1),output:Path|None=typer.Option(None)):
    from .discovery import snapshot
    data=snapshot(pid);text=json.dumps(data,indent=2)
    if output:output.parent.mkdir(parents=True,exist_ok=True);output.write_text(text+'\n')
    typer.echo(text)

@app.command('evaluate')
def evaluate(dataset:Path=typer.Option(...,exists=True),output:Path=typer.Option(...)):
    """Offline deterministic detector evaluation. Never enables a live policy."""
    from .evaluation import evaluate_dataset
    result=evaluate_dataset(json.loads(dataset.read_text(encoding='utf-8')))
    output.parent.mkdir(parents=True,exist_ok=True);output.write_text(json.dumps(result,indent=2)+'\n')
    typer.echo(json.dumps(result,indent=2))

@app.command('register')
def register(file:Path=typer.Option(...,exists=True,dir_okay=False),registration_id:str=typer.Option(...),
             level:str=typer.Option('CONFIDENTIAL'),version:str=typer.Option(...),output:Path=typer.Option(...)):
    """Create a hash-only text index; does not copy the registered file."""
    from .detection import ContentIndex
    if file.stat().st_size>1024*1024:raise typer.BadParameter('registration size limit: 1 MiB')
    index=ContentIndex.register(version,[(registration_id,file.read_text(encoding='utf-8'),level,['registered_text'])])
    output.parent.mkdir(parents=True,exist_ok=True);output.write_text(index.model_dump_json(indent=2)+'\n',encoding='utf-8')
    typer.echo(str(output.resolve()))
