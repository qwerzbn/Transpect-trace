// Research only. The shipping native runtime must not depend on Frida.
'use strict';
const options = PROBE_OPTIONS;
const main = Process.mainModule;
// The isolated fixture uses piped output. Give its stdin EOF instead of leaving
// Frida's input pipe open and making `codex exec` wait for additional input.
if (options.synthetic_input_null) {
    const kernel = Process.getModuleByName('kernel32.dll');
    const open = new NativeFunction(kernel.getExportByName('CreateFileW'), 'pointer',
        ['pointer', 'uint32', 'uint32', 'pointer', 'uint32', 'uint32', 'pointer']);
    const set = new NativeFunction(kernel.getExportByName('SetStdHandle'), 'bool', ['uint32', 'pointer']);
    const handle = open(Memory.allocUtf16String('NUL'), 0x80000000, 3, ptr(0), 3, 0, ptr(0));
    set(0xfffffff6, handle);
}
let sequence = 0;
let sessionBlocked = false;
function emit(kind, fields) {
    send({kind, sequence: ++sequence, pid: Process.id,
          tid: Process.getCurrentThreadId(), ...fields});
}
function attachExport(module, name, callbacks) {
    try {
        const address = Process.getModuleByName(module).findExportByName(name);
        if (address === null) { emit('hook.unavailable', {module, name}); return; }
        Interceptor.attach(address, callbacks);
        emit('hook.installed', {module, name});
    } catch (error) { emit('hook.unavailable', {module, name, error: String(error)}); }
}
function shouldDeny(payload) {
    if (options.action === 'observe') return false;
    const hit = payload.includes(options.synthetic_marker);
    if (options.action === 'block_session' && hit) sessionBlocked = true;
    return hit || sessionBlocked;
}
const kernel = Process.getModuleByName('kernel32.dll');
const heap = new NativeFunction(kernel.getExportByName('GetProcessHeap'), 'pointer', []);
const allocate = new NativeFunction(kernel.getExportByName('HeapAlloc'), 'pointer', ['pointer', 'uint32', 'uint64']);
const terminate = new NativeFunction(kernel.getExportByName('TerminateProcess'), 'bool', ['pointer', 'uint32']);
function recordDenial(protocol) {
    emit('gate.denied', {protocol, action: options.action, reason: 'synthetic_marker'});
    if (options.action === 'terminate_process') terminate(ptr('0xffffffffffffffff'), 76);
}
if (options.candidate_rva !== null) {
    Interceptor.attach(main.base.add(options.candidate_rva), {
        onEnter(args) {
            try {
                const kindLength = args[1].toUInt32();
                const length = args[3].toUInt32();
                if (kindLength > 128 || length > 16 * 1024 * 1024) {
                    emit('candidate.invalid_layout', {kindLength, length}); return;
                }
                const label = args[0].readUtf8String(kindLength);
                const payload = args[2].readUtf8String(length);
                emit('candidate.payload', {layer: 'received_event', candidate_rva: options.candidate_rva,
                      label, bytes: length, payload});
            } catch (error) { emit('candidate.error', {error: String(error)}); }
        }
    });
    emit('hook.installed', {module: main.name, name: 'candidate_serialized_request', rva: options.candidate_rva});
}
// Candidates located from same-version format strings and unwind boundaries.
// Their argument/return layouts are verified independently by the fixture.
Interceptor.attach(main.base.add(0x3d6daa0), {
    onEnter(args) { this.result = args[0]; },
    onLeave() {
        try {
            const tag = this.result.readU64().toNumber();
            if (tag !== 0x1c) { emit('serialization.result', {protocol: 'wss', tag}); return; }
            const length = this.result.add(24).readU64().toNumber();
            if (length <= 0 || length > 16 * 1024 * 1024) return;
            const payload = this.result.add(16).readPointer().readUtf8String(length);
            emit('outbound.payload', {layer: 'serialization', protocol: 'wss',
                 candidate_rva: 0x3d6daa0, bytes: length, payload});
            if (shouldDeny(payload)) {
                recordDenial('wss');
                // The same-version machine code shows both String-bearing
                // variants use [tag, capacity, pointer, length]. Reuse the
                // serializer-owned allocation, preserving Rust's ownership.
                const reason = 'Transpect: synthetic request denied';
                const capacity = this.result.add(8).readU64().toNumber();
                if (capacity < reason.length + 1) throw new Error('insufficient owned error buffer');
                this.result.add(16).readPointer().writeUtf8String(reason);
                this.result.add(24).writeU64(reason.length);
                this.result.writeU64(0x0d); // ApiError::Stream(String), verified fixed layout.
            }
        } catch (error) { emit('outbound.error', {protocol: 'wss', error: String(error)}); }
    }
});
const httpAddress = main.base.add(0x9d96b10);
const httpOriginal = new NativeFunction(httpAddress, 'pointer', ['pointer', 'pointer', 'pointer', 'pointer']);
const dropHeaders = new NativeFunction(main.base.add(0xeeb20), 'void', ['pointer']);
Interceptor.replace(httpAddress, new NativeCallback((result, request, headers, body) => {
    let payload;
    try {
        const length = body.add(16).readU64().toNumber();
        if (length > 0 && length <= 16 * 1024 * 1024) {
            payload = body.add(8).readPointer().readUtf8String(length);
            emit('outbound.payload', {layer: 'http_body_preparation', protocol: 'http',
                 candidate_rva: 0x9d96b10, bytes: length, payload,
                 already_prepared: body.add(64).readU8() !== 0});
        }
    } catch (error) { emit('outbound.error', {protocol: 'http', error: String(error)}); }
    if (payload !== undefined && shouldDeny(payload)) {
        recordDenial('http');
        const reason = 'Transpect: synthetic request denied';
        const buffer = allocate(heap(), 0, reason.length + 1);
        if (buffer.isNull()) throw new Error('HeapAlloc failed');
        buffer.writeUtf8String(reason);
        // Mirrors the native function's existing Result::Err(String) branch,
        // including destruction of its moved HeaderMap argument.
        dropHeaders(headers);
        result.writeU64(3);
        result.add(8).writeU64(reason.length + 1);
        result.add(16).writePointer(buffer);
        result.add(24).writeU64(reason.length);
        return result;
    }
    return httpOriginal(result, request, headers, body);
}, 'pointer', ['pointer', 'pointer', 'pointer', 'pointer']));
attachExport('secur32.dll', 'EncryptMessage', {
    onEnter(args) {
        try {
            const descriptor = args[2];
            const count = descriptor.add(4).readU32();
            const buffers = descriptor.add(8).readPointer();
            let bytes = 0;
            for (let i = 0; i < Math.min(count, 16); i++) {
                const buffer = buffers.add(i * 16);
                if ((buffer.add(4).readU32() & 0x0fffffff) === 1) bytes += buffer.readU32();
            }
            emit('tls.schannel.input', {bytes, capability: 'buffer_metadata_only'});
        } catch (error) { emit('tls.schannel.error', {error: String(error)}); }
    }
});
attachExport('ws2_32.dll', 'WSASend', {
    onEnter(args) {
        try {
            const count = args[2].toUInt32();
            let bytes = 0;
            for (let i = 0; i < Math.min(count, 64); i++) bytes += args[1].add(i * 16).readU32();
            emit('network.send', {api: 'WSASend', socket: args[0].toString(), bytes,
                 capability: 'network_evidence_only'});
        } catch (error) { emit('network.error', {error: String(error)}); }
    }
});
attachExport('ws2_32.dll', 'send', {
    onEnter(args) { emit('network.send', {api: 'send', socket: args[0].toString(),
                 bytes: args[2].toUInt32(), capability: 'network_evidence_only'}); }
});
emit('probe.ready', {module: main.name, base: main.base.toString(), production_component: false});
