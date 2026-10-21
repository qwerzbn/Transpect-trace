"""Separate default-trust and custom-CA Codex TLS evidence without root changes.

Native request snapshots are independent controls, never eCapture TLS success.
This probe never imports a certificate into an OS trust store. Optional UAC
elevates the collector only. Default trust requires a pretrusted local source.
"""
from __future__ import annotations

import argparse
from collections import Counter
import hashlib
import json
import sys
from pathlib import Path

from _build_support import ROOT, enter_repository
sys.path.insert(0,str(ROOT/'src'))
from probe_codex_request_capture import experiment
from transpect_trace.guard import BINARY_SHA256
from transpect_trace.guard.policy import GuardPolicy
from transpect_trace.observe.ecapture import ECaptureCollector, verify_build
from transpect_trace.observe.pipeline import Pipeline
from transpect_trace.observe.windows import Profile, digest, modules


def save(path, row):
    path.parent.mkdir(parents=True, exist_ok=True)
    path.write_text(json.dumps(row, indent=2) + '\n', encoding='utf-8')


class TLSProbe:
    def __init__(self, root, executable, *, elevate=False, runtime_trace=False):
        self.root, self.executable = root, executable
        self.pipeline = Pipeline(root, GuardPolicy(credential_rules=False))
        self.collector, self.subject = None, None
        self.build = None
        self.failure = None
        self.closed = False
        self.module_evidence = []
        self.elevate=elevate
        self.runtime_trace=None
        if runtime_trace:
            from probe_codex_handshake import HandshakeTrace
            self.runtime_trace=HandshakeTrace(root/'research-runtime',exports=False)

    def discover(self, subject):
        # A loaded module is identity evidence; its mere presence does not
        # establish which backend handled any particular request.
        rows = []
        for module in modules(subject['pid']):
            name = Path(module['path']).name.lower()
            if any(part in name for part in ('codex', 'schannel', 'secur32', 'sspicli', 'libssl', 'libcrypto', 'ncrypt', 'bcrypt')):
                rows.append(dict(module=name, sha256=digest(module['path']), evidence='loaded_module_identity'))
        self.module_evidence = rows

    def start(self, subject):
        self.subject = subject
        try:
            self.discover(subject)
            self.build = verify_build(self.executable)
            profile = Profile(image_sha256=subject['image_sha256'], application='codex-cli', mode='schannel')
            self.collector = ECaptureCollector(subject, profile, self.executable, self.pipeline, elevate=self.elevate)
            self.collector.start()
        except (OSError, ValueError, RuntimeError) as error:
            # Do not persist raw errors; paths and application data can occur.
            self.failure = type(error).__name__
        if self.runtime_trace:self.runtime_trace.start(subject)

    def close(self, subject=None):
        if self.closed:return
        self.closed = True
        if self.runtime_trace:self.runtime_trace.close(subject)
        if subject:
            try:self.discover(subject)
            except (OSError, ValueError):self.failure = self.failure or 'module_snapshot_unavailable'
        if self.collector:self.collector.close()
        self.pipeline.finish()

    def report(self, receipts):
        collector = self.collector
        structured = getattr(collector, 'structured', None)
        ready = bool(collector and collector.ready.is_set())
        terminal = bool(structured and structured.terminal)
        lost = getattr(structured, 'lost', None)
        errors = sorted(set(getattr(collector, 'errors', [])))
        healthy = self.build is not None and ready and terminal and lost == 0 and not errors and not self.pipeline.gaps
        source_hashes = Counter(r['sha256'] for r in receipts)
        rows = self.pipeline.rows
        captured_hashes = Counter(r['content_sha256'] for r in rows)
        hashes_match = (bool(rows) and bool(source_hashes) and captured_hashes == source_hashes
            and all(r['completeness'] == 'complete' for r in rows))
        if healthy and hashes_match:
            state = 'complete'
        elif healthy:
            state = 'partial' if rows else 'unknown'
        else:
            state = 'unavailable'
        result = dict(provider='ecapture-windows', capture_layer='tls-plaintext', status=state,
            collector_identity_verified=self.build is not None,
            collector_variant=self.build.get('variant') if self.build else None,
            ready=ready, terminal=terminal, lost=lost, errors=errors,
            failure_type=self.failure, observed_requests=len(rows), source_hashes_match=hashes_match,
            coverage_gaps=self.pipeline.gaps, can_enforce=False,
            actual_tls_backend='schannel' if healthy and hashes_match else 'unknown',
            backend_reason='sspi_application_data_with_same_layer_source_hash' if healthy and hashes_match else
                'no_sspi_requests_with_healthy_collector_does_not_identify_backend' if healthy and not rows else
                'collector_or_permission_failure_cannot_be_used_to_identify_backend',
            modules=self.module_evidence)
        result['elevation_state']=getattr(collector,'elevation_state','not_started')
        result['etw_session_started']=getattr(collector,'etw_started',False)
        result['native_initialization']=getattr(collector,'native_initialization',None)
        save(self.root/'tls-evidence.json', result)
        return result


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('--codex', type=Path, required=True)
    parser.add_argument('--dll', type=Path, default=ROOT/'build/observe/ttrace-observe.dll')
    parser.add_argument('--ecapture', type=Path, default=ROOT/'build/observe/ecapture-enhanced/ecapture.exe')
    parser.add_argument('--output', type=Path, required=True)
    parser.add_argument('--trusted-cert', type=Path)
    parser.add_argument('--trusted-key', type=Path)
    parser.add_argument('--trust-source', help='Non-secret label for a pre-provisioned isolated trust environment')
    parser.add_argument('--trust-mode',choices=['default-trust','custom-ca'],action='append')
    parser.add_argument('--elevate-ecapture',action='store_true',help='Explicit UAC for the collector only; Codex remains unelevated.')
    parser.add_argument('--research-runtime-trace',action='store_true',help='Frida research-only Rustls anchors, separate from eCapture Hook ownership.')
    args = parser.parse_args();enter_repository()
    if bool(args.trusted_cert) != bool(args.trusted_key):parser.error('trusted-cert and trusted-key are a pair')
    if args.trusted_cert and not args.trust_source:parser.error('default-trust evidence requires --trust-source')
    if args.trust_source and (len(args.trust_source)>80 or not all(c.isalnum() or c in '-_. ' for c in args.trust_source)):
        parser.error('trust-source must be a short non-secret environment label')
    if hashlib.sha256(args.codex.read_bytes()).hexdigest()!=BINARY_SHA256:parser.error('fixed Codex baseline mismatch')
    root=args.output.resolve();root.mkdir(parents=True,exist_ok=False)
    cases=[]
    for trust in args.trust_mode or ('default-trust','custom-ca'):
        for protocol in ('http','wss'):
            directory=root/trust/protocol
            if trust=='default-trust' and not args.trusted_cert:
                row=dict(trust_mode=trust,protocol=protocol,status='unavailable',
                    reason='isolated_pretrusted_localhost_certificate_not_supplied',
                    native_request_control_passed=False,ecapture_tls_complete=False,actual_tls_backend='unknown',
                    os_trust_store_changed=False,certificate_verification_disabled=False)
            else:
                probe=TLSProbe(directory/'ecapture',args.ecapture.resolve(),elevate=args.elevate_ecapture,runtime_trace=args.research_runtime_trace)
                try:
                    control=experiment(args.codex.resolve(),args.dll.resolve(),directory/'native-control',protocol,65536,
                        tls_probe=probe,trusted_cert=args.trusted_cert if trust=='default-trust' else None,
                        trusted_key=args.trusted_key if trust=='default-trust' else None)
                    tls=probe.report(control['source_request_hashes'])
                    row=dict(trust_mode=trust,protocol=protocol,status=tls['status'],
                        native_request_control_passed=control['passed'],ecapture_tls_complete=tls['status']=='complete',
                        native_control_layer='request-body',actual_tls_backend=tls['actual_tls_backend'],
                        tls_evidence=tls,trust_source=args.trust_source if trust=='default-trust' else 'explicit_custom_ca',
                        source_tls_handshakes=control['source_tls_handshakes'],
                        os_trust_store_changed=False,certificate_verification_disabled=False)
                    if probe.runtime_trace:
                        runtime=probe.runtime_trace.report(control);row['runtime_backend_evidence']=runtime
                        if runtime['actual_tls_backend']!='unknown':row['actual_tls_backend']=runtime['actual_tls_backend']
                        if (runtime['actual_tls_backend']=='rustls' and tls['status']=='unknown' and not tls['observed_requests']):
                            row.update(status='unsupported',reason='selected_schannel_adapter_does_not_cover_observed_rustls_backend')
                except (OSError,ValueError,RuntimeError,TimeoutError) as error:
                    probe.close()
                    row=dict(trust_mode=trust,protocol=protocol,status='unavailable',
                        reason=type(error).__name__,native_request_control_passed=False,ecapture_tls_complete=False,
                        actual_tls_backend='unknown',tls_evidence=probe.report([]),
                        os_trust_store_changed=False,certificate_verification_disabled=False)
            save(directory/'summary.json',row);cases.append(row)
            print(json.dumps({k:row[k] for k in ('trust_mode','protocol','status','native_request_control_passed')}),flush=True)
    default_rows=[r for r in cases if r['trust_mode']=='default-trust']
    result=dict(cases=cases,passed=bool(cases) and all(r['ecapture_tls_complete'] and r['native_request_control_passed'] for r in cases),
        fixed_codex_sha256=BINARY_SHA256,default_trust_certified=len(default_rows)==2 and all(r['ecapture_tls_complete'] for r in default_rows),
        no_uac_requested=not args.elevate_ecapture,os_trust_store_changed=False,can_enforce=False,
        limitation='Request-layer controls cannot certify Schannel, rustls, or all TLS traffic')
    save(root/'summary.json',result)
    if not result['passed']:raise SystemExit(2)


if __name__=='__main__':main()
