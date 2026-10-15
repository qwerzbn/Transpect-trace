from __future__ import annotations
import json
from pathlib import Path
import time
from uuid import uuid4
import typer
from transpect_trace.guard.policy import GuardPolicy
from .pipeline import Pipeline,report as render_report
from .policy import load_policy

app=typer.Typer(no_args_is_help=True,help="Passive Windows LLM visibility; never blocks requests.")


def finalize_capture(root,status,collector,etw,pipeline):
    """Finalize each component independently; never copy exception payloads."""
    errors=[]
    if collector:
        try:collector.close()
        except Exception as error:errors.append({'component':'collector','error_type':type(error).__name__})
        status['collector_errors']=list(collector.errors)
    index=None
    if etw:
        try:
            etw.close([],root/'etw-finalization.jsonl');index=etw.index
        except Exception as error:
            errors.append({'component':'etw','error_type':type(error).__name__})
            status['etw']={'state':'unavailable','confidence':'Unknown','reason':'finalization_failed'}
    if pipeline:
        try:pipeline.finish(index)
        except Exception as error:errors.append({'component':'pipeline','error_type':type(error).__name__})
    if errors:status['finalization_errors']=errors
    return bool(errors or status.get('collector_errors'))


@app.command()
def inventory(output:Path|None=None,pid:int|None=typer.Option(None,min=1),
              application:str="unknown",mode:str|None=None,profile_output:Path|None=None):
    from .windows import inventory as inspect,discover_profile,identity,modules
    result=inspect()
    if pid:
        subject=identity(pid);result["target"]=subject
        result["loaded_modules"]=modules(pid)
        try:
            _,profile=discover_profile(pid,application,mode);result["proposed_profile"]=profile.model_dump()
            if profile_output:
                profile_output.parent.mkdir(parents=True,exist_ok=True);profile_output.write_text(profile.model_dump_json(indent=2)+"\n",encoding="utf-8")
        except ValueError:
            result["capture_status"]="unsupported_no_verified_entry"
    if output:output.parent.mkdir(parents=True,exist_ok=True);output.write_text(json.dumps(result,indent=2)+"\n",encoding="utf-8")
    typer.echo(json.dumps(result,indent=2))


@app.command()
def run(pid:int=typer.Option(...,min=1),profile_file:Path=typer.Option(...,exists=True),
        provider:str="native-observer",duration:float=typer.Option(30,min=1,max=86400),
        policy_file:Path|None=typer.Option(None,exists=True),dll:Path=Path("build/observe/ttrace-observe.dll"),
        ecapture:Path=Path("build/observe/ecapture.exe"),runs_dir:Path=Path("runs/observe")):
    from .windows import Profile,identity
    from .native import NativeCollector
    from .ecapture import ECaptureCollector
    from transpect_trace.guard.etw import EtwSession
    root=runs_dir/uuid4().hex;root.mkdir(parents=True,exist_ok=False)
    status={"schema_version":"transpect.observe.status/1.0","state":"initializing","can_enforce":False,
            "actual_ai_channel_certified":False,"provider":provider,"started_at_unix_ns":time.time_ns()}
    collector=None;etw=None;pipeline=None;failed=False
    try:
        profile=Profile.model_validate_json(profile_file.read_text(encoding="utf-8"));subject=identity(pid)
        if profile.image_sha256!=subject["image_sha256"] or profile.can_enforce:raise ValueError("observation profile identity mismatch")
        if provider not in {"native-observer","ecapture-windows"}:raise ValueError("unknown observation provider")
        pipeline=Pipeline(root,load_policy(policy_file) if policy_file else GuardPolicy())
        status["target"]=subject;status["profile"]=profile.model_dump()
        etw=EtwSession(Path("build/guard/etw.exe"),subject,root/"etw.jsonl");etw.start();status["etw"]=etw.state
        collector=NativeCollector(subject,profile,dll,pipeline) if provider=="native-observer" else ECaptureCollector(subject,profile,ecapture,pipeline)
        collector.start();status.update(state="observing",observing_since_unix_ns=time.time_ns())
        (root/"status.json").write_text(json.dumps(status,indent=2)+"\n")
        typer.echo(str(root.resolve()))
        deadline=time.monotonic()+duration
        from transpect_trace.guard.native import api
        k=api();handle=k.OpenProcess(0x100000,False,pid)
        try:
            while handle and time.monotonic()<deadline and k.WaitForSingleObject(handle,200)==258:
                collector.check_health()
        finally:
            if handle:k.CloseHandle(handle)
    except KeyboardInterrupt:pass
    except (OSError,ValueError,RuntimeError,StopIteration) as error:
        failed=True;status.update(state="capture_unavailable",reason=type(error).__name__)
    finally:
        if finalize_capture(root,status,collector,etw,pipeline):
            failed=True;status['state']='capture_degraded' if collector and collector.ready.is_set() else 'capture_unavailable'
        if not failed:status["state"]="stopped"
        status["ended_at_unix_ns"]=time.time_ns();(root/"status.json").write_text(json.dumps(status,indent=2)+"\n")
        result=render_report(root);(root/"report.json").write_text(json.dumps(result,indent=2)+"\n")
    typer.echo(json.dumps({"directory":str(root.resolve()),"state":status["state"],"can_enforce":False}))
    if failed:raise typer.Exit(1)


@app.command()
def report(directory:Path=typer.Argument(...,exists=True,file_okay=False),output:Path|None=None):
    result=render_report(directory);rendered=json.dumps(result,indent=2)+"\n"
    if output:output.parent.mkdir(parents=True,exist_ok=True);output.write_text(rendered,encoding="utf-8")
    typer.echo(rendered)
