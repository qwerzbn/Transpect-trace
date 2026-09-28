/*
 * Transpect Frida Gadget agent.
 *
 * The script opens its log file before any hook is installed and writes short
 * append-only records with the libc write function. strace remains the
 * kernel-side record for the whole process tree.
 */

'use strict';

const RAW_SCHEMA = 'transpect.raw.frida/1.0';
const BASE64_ALPHABET = 'ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789+/';
const O_WRONLY = 1;
const O_CREAT = 64;
const O_APPEND = 1024;
const O_CLOEXEC = 0x80000;

let sequence = 0;
let emitting = false;
let logFd = -1;
let captureBytes = 4096;
let backtraceFrames = 8;
const fdPaths = Object.create(null);
const hookedAddresses = Object.create(null);
const suppressed = Object.create(null);
const logDirectory = readEnv('TTRACE_FRIDA_LOG_DIR') || '/evidence/raw/frida';

function findExport(name) {
  try {
    return Module.findGlobalExportByName(name);
  } catch (_) {
    return null;
  }
}

function readEnv(name) {
  const address = findExport('getenv');
  if (address === null) return null;
  try {
    const getenv = new NativeFunction(address, 'pointer', ['pointer']);
    const value = getenv(Memory.allocUtf8String(name));
    if (value.isNull()) return null;
    return value.readUtf8String();
  } catch (_) {
    return null;
  }
}

function safeUtf8(pointer, limit) {
  if (pointer === null || pointer.isNull()) return null;
  try {
    const value = pointer.readUtf8String();
    if (value === null) return null;
    const maximum = limit || 4096;
    return value.length > maximum ? value.slice(0, maximum) : value;
  } catch (_) {
    return null;
  }
}

function intValue(value) {
  try {
    return value.toInt32();
  } catch (_) {
    return null;
  }
}

function sizeValue(value) {
  try {
    return Number(value.toString());
  } catch (_) {
    return null;
  }
}

function bytesToBase64(buffer) {
  if (buffer === null) return null;
  const bytes = new Uint8Array(buffer);
  let result = '';
  for (let i = 0; i < bytes.length; i += 3) {
    const a = bytes[i];
    const b = i + 1 < bytes.length ? bytes[i + 1] : 0;
    const c = i + 2 < bytes.length ? bytes[i + 2] : 0;
    const triplet = (a << 16) | (b << 8) | c;
    result += BASE64_ALPHABET[(triplet >> 18) & 63];
    result += BASE64_ALPHABET[(triplet >> 12) & 63];
    result += i + 1 < bytes.length ? BASE64_ALPHABET[(triplet >> 6) & 63] : '=';
    result += i + 2 < bytes.length ? BASE64_ALPHABET[triplet & 63] : '=';
  }
  return result;
}

function capture(pointer, requested) {
  const wanted = Math.max(0, Math.min(Number(requested) || 0, captureBytes));
  if (wanted === 0 || pointer === null || pointer.isNull()) {
    return { captured_bytes: 0, payload_base64: null, truncated: Number(requested) > 0 };
  }
  try {
    const buffer = pointer.readByteArray(wanted);
    return {
      captured_bytes: wanted,
      payload_base64: bytesToBase64(buffer),
      truncated: Number(requested) > wanted
    };
  } catch (error) {
    return { captured_bytes: 0, payload_base64: null, truncated: true, capture_error: String(error) };
  }
}

function stack(context) {
  try {
    return Thread.backtrace(context, Backtracer.FUZZY)
      .slice(0, backtraceFrames)
      .map(address => DebugSymbol.fromAddress(address).toString());
  } catch (_) {
    return [];
  }
}

function utf8ByteLength(pointer) {
  let size = 0;
  while (pointer.add(size).readU8() !== 0) size += 1;
  return size;
}

function emit(kind, fields) {
  if (logFd < 0 || emitting) return;
  emitting = true;
  try {
    sequence += 1;
    const row = Object.assign({
      schema: RAW_SCHEMA,
      collector_seq: sequence,
      captured_at: new Date().toISOString(),
      kind: kind,
      pid: Process.id,
      tid: Process.getCurrentThreadId()
    }, fields || {});
    const encoded = Memory.allocUtf8String(JSON.stringify(row) + '\n');
    const write = new NativeFunction(findExport('write'), 'int', ['int', 'pointer', 'int']);
    write(logFd, encoded, utf8ByteLength(encoded));
  } catch (_) {
    // A failed log write must not recurse into the hooks or stop the process.
  } finally {
    emitting = false;
  }
}

function noteSuppressed(kind) {
  suppressed[kind] = (suppressed[kind] || 0) + 1;
}

function pathClass(path) {
  if (path === null || path === undefined) return 'anonymous';
  if (path.indexOf('pipe:') === 0) return 'pipe';
  if (path.indexOf('socket:') === 0) return 'socket';
  if (path === '/proc' || path.indexOf('/proc/') === 0) return 'proc';
  if (path === '/dev' || path.indexOf('/dev/') === 0) return 'dev';
  if (path === '/evidence' || path.indexOf('/evidence/') === 0) return 'evidence';
  if (path === logDirectory || path.indexOf(logDirectory + '/') === 0) return 'evidence';
  return 'file';
}

function rememberedPath(fd) {
  if (fd === null) return null;
  return fdPaths[fd] || null;
}

function hook(name, callbacks) {
  const address = findExport(name);
  if (address === null) {
    emit('frida.hook.unavailable', { function: name });
    return;
  }
  const addressKey = address.toString();
  if (hookedAddresses[addressKey] !== undefined) return;
  try {
    hookedAddresses[addressKey] = name;
    Interceptor.attach(address, callbacks);
  } catch (error) {
    delete hookedAddresses[addressKey];
    emit('frida.hook.error', { function: name, error: String(error) });
  }
}

function hookOpen(name, pathIndex, flagsIndex) {
  hook(name, {
    onEnter(args) {
      this.path = safeUtf8(args[pathIndex], 4096);
      this.flags = intValue(args[flagsIndex]);
      this.trace = stack(this.context);
    },
    onLeave(retval) {
      const fd = intValue(retval);
      if (fd !== null && fd >= 0 && this.path !== null) fdPaths[fd] = this.path;
      const observed = pathClass(this.path);
      if (observed !== 'file') {
        noteSuppressed(observed);
        return;
      }
      emit('frida.file.open', {
        function: name,
        path: this.path,
        flags: this.flags,
        fd: fd,
        result: fd,
        backtrace: this.trace
      });
    }
  });
}

function hookRead(name, fdIndex, bufferIndex, countIndex) {
  hook(name, {
    onEnter(args) {
      this.fd = intValue(args[fdIndex]);
      this.buffer = args[bufferIndex];
      this.requested = sizeValue(args[countIndex]);
      this.path = rememberedPath(this.fd);
    },
    onLeave(retval) {
      if (this.fd === logFd) return;
      const observed = pathClass(this.path);
      if (observed !== 'file') {
        noteSuppressed(observed);
        return;
      }
      const result = sizeValue(retval);
      const payload = result !== null && result > 0 ? capture(this.buffer, result) : capture(null, 0);
      emit('frida.io.read', Object.assign({
        function: name,
        fd: this.fd,
        path: this.path,
        requested_bytes: this.requested,
        result: result
      }, payload));
    }
  });
}

function hookWrite(name, fdIndex, bufferIndex, countIndex) {
  hook(name, {
    onEnter(args) {
      this.fd = intValue(args[fdIndex]);
      this.requested = sizeValue(args[countIndex]);
      this.path = rememberedPath(this.fd);
      this.payload = pathClass(this.path) === 'file' ? capture(args[bufferIndex], this.requested) : null;
    },
    onLeave(retval) {
      if (this.fd === logFd) return;
      const observed = pathClass(this.path);
      if (observed !== 'file') {
        noteSuppressed(observed);
        return;
      }
      emit('frida.io.write', Object.assign({
        function: name,
        fd: this.fd,
        path: this.path,
        requested_bytes: this.requested,
        result: sizeValue(retval)
      }, this.payload || {}));
    }
  });
}

function sockaddr(pointer, length) {
  if (pointer === null || pointer.isNull()) return null;
  try {
    const family = pointer.readU16();
    if (family === 2 && length >= 8) {
      const port = (pointer.add(2).readU8() << 8) | pointer.add(3).readU8();
      const ip = [4, 5, 6, 7].map(offset => pointer.add(offset).readU8()).join('.');
      return { family: 'AF_INET', address: ip, port: port };
    }
    if (family === 10 && length >= 24) {
      const port = (pointer.add(2).readU8() << 8) | pointer.add(3).readU8();
      const groups = [];
      for (let i = 8; i < 24; i += 2) {
        groups.push(((pointer.add(i).readU8() << 8) | pointer.add(i + 1).readU8()).toString(16));
      }
      return { family: 'AF_INET6', address: groups.join(':'), port: port };
    }
    if (family === 1) {
      return { family: 'AF_UNIX', path: safeUtf8(pointer.add(2), Math.max(0, length - 2)) };
    }
    return { family: family };
  } catch (error) {
    return { error: String(error) };
  }
}

function readArgv(pointer, maxItems) {
  const values = [];
  if (pointer === null || pointer.isNull()) return values;
  try {
    for (let i = 0; i < maxItems; i += 1) {
      const item = pointer.add(i * Process.pointerSize).readPointer();
      if (item.isNull()) break;
      values.push(safeUtf8(item, 4096));
    }
  } catch (_) {}
  return values;
}

function openLog() {
  const openAddress = findExport('open');
  if (openAddress === null) return -1;
  const open = new NativeFunction(openAddress, 'int', ['pointer', 'int', 'int']);
  const path = logDirectory + '/events.' + Process.id + '.jsonl';
  return open(Memory.allocUtf8String(path), O_WRONLY | O_CREAT | O_APPEND | O_CLOEXEC, 420);
}

function installHooks() {
  hookOpen('open', 0, 1);
  hookOpen('openat', 1, 2);
  hookRead('read', 0, 1, 2);
  hookWrite('write', 0, 1, 2);

  hook('close', {
    onEnter(args) {
      this.fd = intValue(args[0]);
    },
    onLeave(retval) {
      if (this.fd === logFd) return;
      const path = rememberedPath(this.fd);
      const observed = pathClass(path);
      if (observed !== 'file') {
        noteSuppressed(observed);
      } else {
        emit('frida.fd.close', { function: 'close', fd: this.fd, path: path, result: intValue(retval) });
      }
      if (this.fd !== null) delete fdPaths[this.fd];
    }
  });

  hook('connect', {
    onEnter(args) {
      this.fd = intValue(args[0]);
      this.address = sockaddr(args[1], intValue(args[2]) || 0);
      this.trace = stack(this.context);
    },
    onLeave(retval) {
      emit('frida.network.connect', {
        function: 'connect',
        fd: this.fd,
        address: this.address,
        result: intValue(retval),
        backtrace: this.trace
      });
    }
  });

  hook('execve', {
    onEnter(args) {
      emit('frida.process.exec', {
        function: 'execve',
        path: safeUtf8(args[0], 4096),
        argv: readArgv(args[1], 32),
        backtrace: stack(this.context)
      });
    }
  });

  for (const name of ['exit', '_exit']) {
    hook(name, {
      onEnter(args) {
        emit('frida.io.suppressed', { counts: suppressed });
        emit('frida.process.exiting', { function: name, status: intValue(args[0]) });
      }
    });
  }
}

logFd = openLog();
if (logFd >= 0) {
  emit('frida.runtime.loaded', {
    mode: 'gadget-preload',
    architecture: Process.arch,
    platform: Process.platform,
    capture_bytes: captureBytes,
    backtrace_frames: backtraceFrames,
    log_directory: logDirectory
  });
  installHooks();
}
