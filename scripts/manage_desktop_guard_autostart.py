"""Manage the per-user Windows logon task for the desktop Native supervisor.

The task watches for Codex desktop backends. Registration alone does not prove
that a model request is protected. The default installation is observation
only; requesting Native activation also requires the controller's live gate.
No Codex application hook or hooks.json entry is installed here.
"""
from __future__ import annotations

import argparse
import json
import os
from pathlib import Path
import subprocess
import sys


ROOT = Path(__file__).resolve().parents[1]
SUPERVISOR = ROOT / "scripts" / "desktop_guard_supervisor.py"
DEFAULT_STATE_DIR = ROOT / "runs" / "desktop-guard-supervisor"
SCHEMA = "transpect.desktop-guard-autostart/1.0"

# Paths and arguments are supplied as environment values, never interpolated
# into the PowerShell source. A pre-existing task is changed or removed only
# after its principal and exact action have been verified.
_TASK_SCRIPT = r"""
$ErrorActionPreference = 'Stop'
[Console]::OutputEncoding = [System.Text.UTF8Encoding]::new($false)
$identity = [System.Security.Principal.WindowsIdentity]::GetCurrent()
$sid = $identity.User.Value
# The RID alone is not unique across local/domain accounts. Bind the task
# name to the whole SID while keeping it short enough for Task Scheduler.
$sha = [System.Security.Cryptography.SHA256]::Create()
try {
    $sidHash = [BitConverter]::ToString(
        $sha.ComputeHash([System.Text.Encoding]::UTF8.GetBytes($sid))).Replace('-', '')
} finally { $sha.Dispose() }
$name = 'Transpect-Desktop-Native-Supervisor-' + $sidHash.Substring(0, 16)
$exe = $env:TTRACE_DESKTOP_TASK_EXE
$repository = $env:TTRACE_DESKTOP_TASK_ROOT
$supervisor = $env:TTRACE_DESKTOP_TASK_SCRIPT
$stateDir = $env:TTRACE_DESKTOP_TASK_STATE
$operation = $env:TTRACE_DESKTOP_TASK_OPERATION
$startNow = $env:TTRACE_DESKTOP_TASK_START -eq '1'
$activate = $env:TTRACE_DESKTOP_TASK_ACTIVATE -eq '1'
$baseArgs = '"' + $supervisor + '" watch --state-dir "' + $stateDir + '" --poll-seconds 2'
$observerArgs = $baseArgs
$activeArgs = $baseArgs + ' --activate'
$targetArgs = if ($activate) { $activeArgs } else { $observerArgs }

function Resolve-AccountSid([string]$account) {
    if ([string]::IsNullOrWhiteSpace($account)) { return '' }
    if ($account -eq $sid) { return $sid }
    try {
        return ([System.Security.Principal.NTAccount]$account).
            Translate([System.Security.Principal.SecurityIdentifier]).Value
    } catch { return '' }
}

function Test-OwnedTask($task) {
    if ($null -eq $task) { return $false }
    $actions = @($task.Actions)
    $triggers = @($task.Triggers)
    if ($actions.Count -ne 1 -or $triggers.Count -ne 1) { return $false }
    $argument = $actions[0].Arguments
    $logonTrigger = $triggers[0].CimClass.CimClassName -eq 'MSFT_TaskLogonTrigger'
    return ((Resolve-AccountSid $task.Principal.UserId) -eq $sid -and
        $task.Principal.LogonType -eq 'Interactive' -and
        $task.Principal.RunLevel -eq 'Limited' -and
        $logonTrigger -and
        (Resolve-AccountSid $triggers[0].UserId) -eq $sid -and
        $actions[0].Execute -eq $exe -and
        $actions[0].WorkingDirectory -eq $repository -and
        ($argument -ceq $observerArgs -or $argument -ceq $activeArgs))
}

$task = Get-ScheduledTask -TaskPath '\' -TaskName $name -ErrorAction SilentlyContinue
$owned = Test-OwnedTask $task
if ($operation -ne 'status' -and $task -and -not $owned) {
    throw 'Task name is already in use by a different configuration; refusing to change it'
}
if ($operation -eq 'install') {
    $mutated = $false
    $wanted = if ($activate) { $activeArgs } else { $observerArgs }
    if ($task -and $task.Actions[0].Arguments -cne $wanted) {
        throw 'Existing supervisor mode differs; remove it gracefully before reinstalling'
    }
    if (-not $task) {
        $action = New-ScheduledTaskAction -Execute $exe -Argument $wanted -WorkingDirectory $repository
        $trigger = New-ScheduledTaskTrigger -AtLogOn -User $identity.Name
        $principal = New-ScheduledTaskPrincipal -UserId $identity.Name -LogonType Interactive -RunLevel Limited
        $settings = New-ScheduledTaskSettingsSet -AllowStartIfOnBatteries `
            -DontStopIfGoingOnBatteries -ExecutionTimeLimit ([TimeSpan]::Zero) `
            -RestartCount 3 -RestartInterval (New-TimeSpan -Minutes 1) `
            -MultipleInstances IgnoreNew
        Register-ScheduledTask -TaskPath '\' -TaskName $name -Action $action `
            -Trigger $trigger -Principal $principal -Settings $settings `
            -Description 'Transpect read-only Codex desktop process supervisor' `
            -Force -ErrorAction Stop | Out-Null
        $mutated = $true
    }
    $task = Get-ScheduledTask -TaskPath '\' -TaskName $name -ErrorAction Stop
    if (-not (Test-OwnedTask $task) -or $task.Actions[0].Arguments -cne $wanted) {
        throw 'Registered task did not pass identity and action verification'
    }
    if ($startNow -and $task.State -ne 'Running') {
        Start-ScheduledTask -TaskPath '\' -TaskName $name -ErrorAction Stop | Out-Null
    }
} elseif ($operation -eq 'remove') {
    $mutated = $false
    if ($task) {
        if ($task.State -eq 'Running') {
            Stop-ScheduledTask -TaskPath '\' -TaskName $name -ErrorAction Stop | Out-Null
        }
        Unregister-ScheduledTask -TaskPath '\' -TaskName $name -Confirm:$false -ErrorAction Stop | Out-Null
        $mutated = $true
    }
    $task = Get-ScheduledTask -TaskPath '\' -TaskName $name -ErrorAction SilentlyContinue
    if ($task) { throw 'Task still exists after removal' }
} elseif ($operation -ne 'status') {
    throw 'Invalid operation'
}

$owned = Test-OwnedTask $task
$isActive = $owned -and $task.Actions[0].Arguments -ceq $activeArgs
[pscustomobject]@{
    schema = 'transpect.desktop-guard-autostart/1.0'
    operation = $operation
    task_name = $name
    account_sid = $sid
    task_present = [bool]$task
    configuration_matches = [bool]$owned
    activation_requested = [bool]$isActive
    task_state = if ($task) { [string]$task.State } else { 'Absent' }
    changed = if ($operation -eq 'status') { $false } else { [bool]$mutated }
    model_egress_status = 'MODEL_EGRESS_NOT_COVERED'
} | ConvertTo-Json -Compress -Depth 3
"""


def _state_dir(path: Path) -> Path:
    resolved = path.resolve()
    runs = (ROOT / "runs").resolve()
    if not resolved.is_relative_to(runs) or resolved == runs:
        raise ValueError("state directory must be a child of repository runs")
    return resolved


def _pythonw() -> Path:
    executable = ROOT / ".venv" / "Scripts" / "pythonw.exe"
    if not executable.is_file():
        raise FileNotFoundError(f"pinned repository pythonw.exe is missing: {executable}")
    return executable.resolve()


def _activation_preflight() -> None:
    sys.path.insert(0, str(ROOT / "scripts"))
    import desktop_demo  # noqa: PLC0415

    if desktop_demo.LIVE_TRIALS_PAUSED:
        raise ValueError("live Native activation is paused after desktop errors")
    current = desktop_demo.status(guard="nonretry_lease")
    if not current.get("ready_for_live_trial"):
        raise ValueError("desktop Native controller preflight is not ready")


def operate(operation: str, *, state_dir: Path = DEFAULT_STATE_DIR,
            activate: bool = False, start_now: bool = True) -> dict:
    if sys.platform != "win32":
        raise RuntimeError("Windows Task Scheduler is required")
    if operation not in {"status", "install", "remove"}:
        raise ValueError("invalid operation")
    state_dir = _state_dir(state_dir)
    if not SUPERVISOR.is_file():
        raise FileNotFoundError(f"supervisor script is missing: {SUPERVISOR}")
    executable = _pythonw()
    if operation == "install" and activate:
        _activation_preflight()
    if operation == "remove":
        current = operate("status", state_dir=state_dir)
        if current.get("task_present"):
            if not current.get("configuration_matches"):
                raise ValueError("refusing to stop or remove an unrecognized scheduled task")
            python = executable.with_name("python.exe")
            if not python.is_file():
                raise FileNotFoundError(f"pinned repository python.exe is missing: {python}")
            stopped = subprocess.run(
                [str(python), str(SUPERVISOR), "stop", "--state-dir", str(state_dir)],
                cwd=ROOT, capture_output=True, text=True, encoding="utf-8", timeout=55,
                check=False)
            if stopped.returncode:
                raise RuntimeError("supervisor did not confirm stop; scheduled task was retained: "
                                   + (stopped.stderr.strip() or stopped.stdout.strip()))
            try:
                stop_result = json.loads(stopped.stdout.strip())
            except json.JSONDecodeError as error:
                raise RuntimeError("supervisor stop response was invalid; task retained") from error
            if stop_result.get("stop_confirmed") is not True:
                raise RuntimeError("supervisor stop and Native lease release were not "
                                   "confirmed; scheduled task was retained")
    if operation == "install":
        state_dir.mkdir(parents=True, exist_ok=True)
    env = os.environ.copy()
    env.update({
        "TTRACE_DESKTOP_TASK_EXE": str(executable),
        "TTRACE_DESKTOP_TASK_ROOT": str(ROOT.resolve()),
        "TTRACE_DESKTOP_TASK_SCRIPT": str(SUPERVISOR.resolve()),
        "TTRACE_DESKTOP_TASK_STATE": str(state_dir),
        "TTRACE_DESKTOP_TASK_OPERATION": operation,
        "TTRACE_DESKTOP_TASK_START": "1" if start_now else "0",
        "TTRACE_DESKTOP_TASK_ACTIVATE": "1" if activate else "0",
    })
    completed = subprocess.run(
        ["powershell.exe", "-NoProfile", "-NonInteractive", "-Command", _TASK_SCRIPT],
        env=env, capture_output=True, text=True, encoding="utf-8", timeout=60,
        check=False)
    if completed.returncode:
        detail = completed.stderr.strip() or completed.stdout.strip()
        raise RuntimeError(f"Task Scheduler operation failed: {detail}")
    result = json.loads(completed.stdout.strip())
    if result.get("schema") != SCHEMA or result.get("operation") != operation:
        raise RuntimeError("Task Scheduler returned an unexpected result")
    return result


def main() -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("operation", choices=("status", "install", "remove"))
    parser.add_argument("--state-dir", type=Path, default=DEFAULT_STATE_DIR)
    parser.add_argument("--activate", action="store_true",
                        help="Request Native activation; rejected while the live gate is closed")
    parser.add_argument("--no-start", action="store_true",
                        help="Register at next logon without starting the watcher now")
    args = parser.parse_args()
    if args.operation != "install" and (args.activate or args.no_start):
        parser.error("--activate and --no-start are only valid with install")
    try:
        result = operate(args.operation, state_dir=args.state_dir,
                         activate=args.activate, start_now=not args.no_start)
    except (OSError, RuntimeError, ValueError, json.JSONDecodeError) as error:
        print(json.dumps({"schema": SCHEMA, "operation": args.operation,
                          "error": f"{type(error).__name__}: {error}",
                          "model_egress_status": "MODEL_EGRESS_NOT_COVERED"},
                         ensure_ascii=False, indent=2))
        return 2
    print(json.dumps(result, ensure_ascii=False, indent=2))
    return 0 if args.operation in {"status", "remove"} or result["configuration_matches"] else 2


if __name__ == "__main__":
    raise SystemExit(main())
