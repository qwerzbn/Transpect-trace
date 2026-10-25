"""Controlled fixture stress tests: real local IPC, mocked HTTP for control logic.

No test here certifies eCapture/ETW, installs trust, or sends to an external LLM.
"""
from concurrent.futures import ThreadPoolExecutor
import io
import json
from pathlib import Path
import queue
import subprocess
import sys
import threading
from uuid import uuid4

import pytest

from transpect_trace.flow.agents import participant, protocol
from transpect_trace.flow.participant import PIPE_PREFIX

WINDOWS = pytest.mark.skipif(sys.platform != 'win32', reason='real synchronous Win32 fixture')
PAYLOAD = {'public_text':'ordinary report','api_key':'fake-stress-credential-a81c954e','document':'registered-fake-document'}


class AgentA:
    def __init__(self, source, pipe, message, *options):
        self.rows, self.queue = [], queue.Queue()
        self.process = subprocess.Popen([sys._base_executable,'-I','-S','-B',str(Path(participant.__file__).resolve()),
            '--role','A','--task-id','a'*32,'--message-id',message,'--source',str(source),'--handoff',pipe,*options],
            stdin=subprocess.PIPE,stdout=subprocess.PIPE,stderr=subprocess.PIPE)
        def read():
            try:
                for line in self.process.stdout:
                    row = json.loads(line)
                    self.rows.append(row)
                    self.queue.put(row)
            finally:
                self.queue.put({'kind':'eof'})
        self.reader = threading.Thread(target=read,daemon=True)
        self.reader.start()

    def send(self, command):
        self.process.stdin.write((command+'\n').encode())
        self.process.stdin.flush()

    def wait(self, kind):
        for _ in range(20):
            row = self.queue.get(timeout=10)
            if row['kind'] == kind:
                return row
            assert row['kind'] not in {'error','eof'}, row
        raise AssertionError('missing fixture marker')

    def close(self):
        if self.process.poll() is None:
            self.process.terminate()
        self.process.wait(timeout=5)
        self.reader.join(2)
        for stream in (self.process.stdin,self.process.stdout,self.process.stderr):
            stream.close()


@WINDOWS
@pytest.mark.parametrize('mode',['unique','repeat','conflict'])
def test_real_pipe_reconnect_preserves_or_conflicts_identity_only_when_requested(tmp_path,mode):
    source = tmp_path/'fake-dataset.json'
    source.write_bytes(protocol.encode(PAYLOAD))
    pipe,message = PIPE_PREFIX+uuid4().hex,uuid4().hex
    agent = AgentA(source,pipe,message,'--rounds','2','--message-mode',mode)
    api, captured = participant.io_api(), []
    try:
        agent.wait('ready')
        with ThreadPoolExecutor(max_workers=1) as pool:
            for iteration in range(2):
                ready = threading.Event()
                incoming = pool.submit(participant.receive,api,pipe,ready=ready.set,timeout_seconds=5)
                assert ready.wait(3)
                agent.send('release' if iteration == 0 else 'next')
                agent.wait('transfer_complete')
                captured.append(incoming.result(timeout=3))
                # The explicit repeated-message experiment reuses its query
                # snapshot even if the source is changed between delegations.
                source.write_bytes(protocol.encode({**PAYLOAD,'document':'later-file-version'}))
        agent.send('finish');agent.wait('finished')
        assert agent.process.wait(timeout=5) == 0
        first,second = map(protocol.parse_message,captured)
        assert first['message_id'] == message and first['payload'] == PAYLOAD
        if mode == 'unique':
            assert second['message_id'] != message and second['payload'] == PAYLOAD
        elif mode == 'repeat':
            assert captured[0] == captured[1]
        else:
            assert second['message_id'] == message
            assert second['payload'] == {'public_text':PAYLOAD['public_text']}
        assert sum(row.get('step') == 'query' for row in agent.rows) == 1
        serialized = json.dumps(agent.rows)
        assert PAYLOAD['api_key'] not in serialized and message not in serialized
    finally:
        agent.close()


@WINDOWS
def test_split_read_holds_real_handle_across_controlled_source_rewrite(tmp_path):
    source = tmp_path/'changing-fake-source.json'
    initial = protocol.encode({**PAYLOAD,'document':'A'*4096})
    source.write_bytes(initial)
    pipe = PIPE_PREFIX+uuid4().hex
    agent = AgentA(source,pipe,uuid4().hex,'--split-read')
    api = participant.io_api()
    try:
        agent.wait('ready');agent.send('release')
        row = agent.wait('source_read_part')
        split = row['bytes']
        assert split == len(initial)//2
        changed = initial[:split]+initial[split:].replace(b'A',b'B')
        source.write_bytes(changed)
        with ThreadPoolExecutor(max_workers=1) as pool:
            ready = threading.Event()
            incoming = pool.submit(participant.receive,api,pipe,ready=ready.set,timeout_seconds=5)
            assert ready.wait(3)
            agent.send('continue_read');agent.wait('transfer_complete')
            envelope = protocol.parse_message(incoming.result(timeout=3))
        assert envelope['payload'] == protocol.query_payload(changed)
        assert 'A' in envelope['payload']['document'] and 'B' in envelope['payload']['document']
        agent.send('finish');agent.wait('finished')
        assert agent.process.wait(timeout=5) == 0
        assert PAYLOAD['api_key'] not in json.dumps(agent.rows)
    finally:
        agent.close()


def configure_b(monkeypatch, messages, commands, upload):
    monkeypatch.setattr(participant,'io_api',lambda:object())
    monkeypatch.setattr(participant.winhttp,'preload',lambda:None)
    iterator = iter(messages)
    def receive(*args,ready=None,**kwargs):
        if ready:ready()
        return next(iterator)
    monkeypatch.setattr(participant,'receive',receive)
    monkeypatch.setattr(participant.winhttp,'upload',upload)
    monkeypatch.setattr(sys,'stdin',commands if hasattr(commands,'readline') else io.StringIO(commands))
    return ['--role','B','--task-id','a'*32,'--handoff',PIPE_PREFIX+'unit-fixture',
            '--url','https://localhost:443/upload']


@pytest.mark.parametrize('same',[False,True])
def test_b_reconnect_and_multiple_attempts_keep_attempts_independent(monkeypatch,capsys,same):
    messages = [protocol.make_message('a'*32,key*32,PAYLOAD) for key in ('b','c')]
    uploads = []
    def upload(url,body):
        uploads.append(protocol.parse_outbound(body))
        return {'bytes':len(body),'http_status':200}
    args = configure_b(monkeypatch,messages,'release\nnext\nfinish\n',upload)
    assert participant.main([*args,'--rounds','2','--attempts','3',*(['--same-attempt-id'] if same else [])]) == 0
    assert len(uploads) == 6
    assert len({row['attempt_id'] for row in uploads}) == (1 if same else 6)
    assert len({row['tool_call_id'] for row in uploads[:3]}) == 1
    assert uploads[0]['tool_call_id'] != uploads[3]['tool_call_id']
    assert {row['parent_message_id'] for row in uploads[:3]} == {'b'*32}
    assert {row['parent_message_id'] for row in uploads[3:]} == {'c'*32}
    truth = [json.loads(line) for line in capsys.readouterr().out.splitlines()]
    assert sum(row['kind']=='pipe_ready' for row in truth) == 2
    assert sum(row['kind']=='sent' for row in truth) == 6
    assert PAYLOAD['api_key'] not in json.dumps(truth)


def test_hold_after_read_never_calls_transport_before_upload_command(monkeypatch,capsys):
    uploads = []
    class Controller(io.StringIO):
        def readline(self,*args):
            line = super().readline(*args)
            if line.strip() == 'upload':assert uploads == []
            return line
    def upload(url,body):
        uploads.append(body)
        return {'bytes':len(body),'http_status':200}
    args = configure_b(monkeypatch,[protocol.make_message('a'*32,'b'*32,PAYLOAD)],
                       Controller('release\nupload\nfinish\n'),upload)
    assert participant.main([*args,'--hold-after-read']) == 0
    assert len(uploads) == 1
    truth = [json.loads(line) for line in capsys.readouterr().out.splitlines()]
    assert [row['kind'] for row in truth] == ['ready','pipe_ready','received','agent_step','agent_step','sent','finished']


@pytest.mark.parametrize('failure',['retryable','unrelated_value','os_error','second_http_error'])
def test_retry_only_handles_first_explicit_status_failure(monkeypatch,capsys,failure):
    uploads = []
    def upload(url,body):
        uploads.append(protocol.parse_outbound(body))
        if failure == 'os_error':raise OSError('fake transport failure')
        if failure == 'unrelated_value':raise ValueError('fake parser failure')
        if len(uploads)==1 or failure=='second_http_error':raise ValueError('unexpected_http_status')
        return {'bytes':len(body),'http_status':200}
    args = configure_b(monkeypatch,[protocol.make_message('a'*32,'b'*32,PAYLOAD)],'release\nfinish\n',upload)
    result = participant.main([*args,'--attempts','2','--retry-first-error'])
    truth = [json.loads(line) for line in capsys.readouterr().out.splitlines()]
    assert result == (0 if failure=='retryable' else 2)
    assert sum(row['kind']=='attempt_failed' for row in truth) == (1 if failure in {'retryable','second_http_error'} else 0)
    assert sum(row['kind']=='sent' for row in truth) == (1 if failure=='retryable' else 0)
    if len(uploads)==2:assert uploads[0]['attempt_id'] != uploads[1]['attempt_id']
    assert 'fake transport failure' not in json.dumps(truth)


def test_pause_upload_supplies_checkpoint_and_waits_for_continue_upload(monkeypatch,capsys):
    checkpoints = []
    def upload(url,body,*,checkpoint):
        checkpoints.append('prefix')
        checkpoint()
        checkpoints.append('suffix')
        return {'bytes':len(body),'http_status':200}
    args = configure_b(monkeypatch,[protocol.make_message('a'*32,'b'*32,PAYLOAD)],
                       'release\ncontinue_upload\nfinish\n',upload)
    assert participant.main([*args,'--pause-upload']) == 0
    assert checkpoints == ['prefix','suffix']
    kinds = [json.loads(line)['kind'] for line in capsys.readouterr().out.splitlines()]
    assert kinds.index('upload_paused') < kinds.index('sent')


@pytest.mark.parametrize('options',[['--rounds','0'],['--rounds','5'],['--attempts','0'],['--attempts','4'],
    ['--retry-first-error'],['--pause-upload','--attempts','2'],['--pause-upload','--rounds','2'],['--split-read']])
def test_invalid_b_experiment_ranges_fail_before_ready(monkeypatch,capsys,options):
    def forbidden(*args,**kwargs):raise AssertionError('invalid arguments must not upload')
    args = configure_b(monkeypatch,[],'',forbidden)
    assert participant.main([*args,*options]) == 2
    truth = [json.loads(line) for line in capsys.readouterr().out.splitlines()]
    assert len(truth) == 1 and truth[0]['kind'] == 'error' and truth[0]['stage'] == 'arguments'
