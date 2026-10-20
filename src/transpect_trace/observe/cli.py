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


@app.command("extract")
def extract(body_file:Path=typer.Option(...,exists=True,dir_okay=False),
            output:Path|None=None,content_encoding:str="identity",
            synthetic_content:bool=typer.Option(False,help="Explicit fake-data export of values; requires a new output file.")):
    """Extract four semantic groups from a saved body; does not certify live capture."""
    from .models import BODY_LIMIT
    from .semantics import extract_request
    if synthetic_content and output is None:
        raise typer.BadParameter("--synthetic-content requires --output")
    if body_file.stat().st_size>BODY_LIMIT:
        raise typer.BadParameter("Body exceeds extraction size limit")
    result=extract_request(body_file.read_bytes(),observation_id=uuid4().hex,
        capture_source="offline-body",content_encoding=content_encoding)
    if output:
        output.parent.mkdir(parents=True,exist_ok=True)
        with output.open("x",encoding="utf-8") as destination:
            json.dump(result.synthetic_export() if synthetic_content else result.model_dump(),
                      destination,ensure_ascii=False,indent=2)
            destination.write("\n")
    # Content never goes to the terminal, even when an explicit fixture file is written.
    typer.echo(result.model_dump_json(indent=2))
    if result.status in {"failed","unsupported"}:
        raise typer.Exit(2)


def finalize_capture(root,status,collector,etw,pipeline):
    """Finalize each component independently; never copy exception payloads."""
    errors=[]
    if collector:
        try:collector.close()
        except Exception as error:errors.append({'component':'collector','error_type':type(error).__name__})
        status['collector_errors']=list(collector.errors)
        if hasattr(collector,'elevation_state'):
            status['ecapture_elevation']=collector.elevation_state
            status['ecapture_etw_session_started']=collector.etw_started
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
        ecapture:Path=Path("build/observe/ecapture.exe"),runs_dir:Path=Path("runs/observe"),
        elevate_ecapture:bool=typer.Option(False,help="Request Windows UAC for the enhanced eCapture collector only.")):
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
        if elevate_ecapture and provider!='ecapture-windows':raise ValueError('elevation requires ecapture-windows provider')
        pipeline=Pipeline(root,load_policy(policy_file) if policy_file else GuardPolicy())
        status["target"]=subject;status["profile"]=profile.model_dump()
        etw=EtwSession(Path("build/guard/etw.exe"),subject,root/"etw.jsonl");etw.start();status["etw"]=etw.state
        collector=NativeCollector(subject,profile,dll,pipeline) if provider=="native-observer" else ECaptureCollector(subject,profile,ecapture,pipeline,elevate=elevate_ecapture)
        if elevate_ecapture:typer.echo('Windows UAC may request confirmation for eCapture; the target stays at its existing integrity level.')
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


@app.command()
def validate(manifest:Path=typer.Option(...,exists=True,dir_okay=False),root:Path=Path('.'),output:Path|None=None):
    """Validate an explicit eCapture experiment manifest, never infer enforcement."""
    from .validation import validate_manifest
    result=validate_manifest(manifest,root.resolve())
    rendered=json.dumps(result,ensure_ascii=False,indent=2)+'\n'
    if output:
        output.parent.mkdir(parents=True,exist_ok=True);output.write_text(rendered,encoding='utf-8')
    typer.echo(rendered)


@app.command('channels')
def channels(manifest:Path=typer.Option(...,exists=True,dir_okay=False),output:Path|None=None):
    """Compare eCapture and fallback evidence; never enable a Hook or Gate."""
    from .channels import channel_matrix
    result=channel_matrix(manifest.resolve())
    rendered=json.dumps(result,ensure_ascii=False,indent=2)+'\n'
    if output:
        output.parent.mkdir(parents=True,exist_ok=True)
        output.write_text(rendered,encoding='utf-8')
    typer.echo(rendered)
