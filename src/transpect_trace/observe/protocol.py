"""Bounded passive HTTP/1, HTTP/2 and WebSocket reconstruction.

No network traffic is generated here. Unrecoverable gaps quarantine the stream.
"""
from __future__ import annotations

import base64
import hashlib
import zlib
from dataclasses import dataclass, field
from .models import BODY_LIMIT, CaptureEvent

PREFACE=b"PRI * HTTP/2.0\r\n\r\nSM\r\n\r\n"


class CoverageGap(ValueError):pass


def decode_body(data:bytes,encoding:str) -> bytes:
    encoding=encoding.strip().lower()
    if not encoding or encoding=="identity":return data
    if encoding in {"gzip","deflate"}:
        decoder=zlib.decompressobj(16+zlib.MAX_WBITS if encoding=="gzip" else zlib.MAX_WBITS)
        result=decoder.decompress(data,BODY_LIMIT+1)
        if len(result)>BODY_LIMIT or decoder.unconsumed_tail or not decoder.eof:
            raise CoverageGap("compressed_body_incomplete_or_oversized")
        if decoder.unused_data:raise CoverageGap("multiple_compressed_members_unverified")
        return result
    if encoding=="zstd":
        import zstandard
        # stream_reader returns available output even when the checksum/footer
        # is missing. Validate the entire frame, including its final bytes.
        try:
            size=zstandard.frame_content_size(data)
            if size>BODY_LIMIT:raise CoverageGap("decoded_body_limit")
            result=zstandard.ZstdDecompressor().decompress(data,max_output_size=BODY_LIMIT,allow_extra_data=False)
            if size<0:
                # The cext backend ignores allow_extra_data for frames without
                # a declared size. After the bounded decode succeeded, validate
                # the same first frame's EOF/trailing bytes explicitly.
                validator=zstandard.ZstdDecompressor().decompressobj()
                validator.decompress(data)
                if not validator.eof or validator.unused_data:raise CoverageGap("zstd_incomplete_or_extra_frames")
            return result
        except zstandard.ZstdError as error:
            raise CoverageGap("zstd_incomplete_or_invalid_frame") from error
    raise CoverageGap("unsupported_content_encoding")


@dataclass
class Body:
    data: bytes
    headers: dict[str,str]
    protocol: str
    stream_id: int | None = None
    limitations: list[str] = field(default_factory=list)


class HTTP1:
    def __init__(self):
        import h11
        self.h11=h11;self.connection=h11.Connection(h11.SERVER,max_incomplete_event_size=65536)
        self.headers={};self.body=bytearray();self.upgrade=False;self.complete_closed=False

    def feed(self,data):
        self.connection.receive_data(data);out=[]
        while True:
            event=self.connection.next_event()
            if event is self.h11.NEED_DATA:break
            if event is self.h11.PAUSED:break
            if isinstance(event,self.h11.Request):
                self.headers={k.decode("ascii").lower():v.decode("latin1") for k,v in event.headers}
                self.headers[":method"]=event.method.decode("ascii")
                self.headers[":path"]=event.target.decode("latin1")
                self.body.clear()
            elif isinstance(event,self.h11.Data):
                self.body.extend(event.data)
                if len(self.body)>BODY_LIMIT:raise CoverageGap("body_limit")
            elif isinstance(event,self.h11.EndOfMessage):
                if self.headers.get("upgrade","").lower()=="websocket":
                    self.upgrade=True;break
                out.append(Body(bytes(self.body),dict(self.headers),"http/1.1"))
                self.connection.send(self.h11.Response(status_code=200,headers=[("content-length","0")]))
                self.connection.send(self.h11.EndOfMessage())
                self.body.clear()
                if self.connection.our_state is self.h11.DONE and self.connection.their_state is self.h11.DONE:
                    self.connection.start_next_cycle()
                else:self.complete_closed=True;break
            elif isinstance(event,self.h11.ConnectionClosed):break
        return out

    @property
    def pending(self):return not self.upgrade and not self.complete_closed and (bool(self.body) or bool(self.connection._receive_buffer) or self.connection.their_state not in {self.h11.IDLE,self.h11.CLOSED})


class HTTP2:
    def __init__(self):
        from hpack import Decoder
        self.decoder=Decoder(max_header_list_size=65536)
        self.buffer=bytearray();self.streams={};self.header_block=bytearray();self.header_stream=None
        self.header_end=False;self.prefaced=False

    def feed(self,data):
        from hyperframe.frame import Frame,HeadersFrame,ContinuationFrame,DataFrame,RstStreamFrame,GoAwayFrame
        self.buffer.extend(data);out=[]
        if not self.prefaced:
            if len(self.buffer)<len(PREFACE):return out
            if bytes(self.buffer[:24])!=PREFACE:raise CoverageGap("http2_missing_preface")
            del self.buffer[:24];self.prefaced=True
        while len(self.buffer)>=9:
            frame,length=Frame.parse_frame_header(memoryview(bytes(self.buffer[:9])))
            if length>BODY_LIMIT:raise CoverageGap("http2_frame_limit")
            if len(self.buffer)<9+length:break
            frame.parse_body(memoryview(bytes(self.buffer[9:9+length])));del self.buffer[:9+length]
            if self.header_stream is not None and not isinstance(frame,ContinuationFrame):
                raise CoverageGap("http2_header_continuation_gap")
            if isinstance(frame,(HeadersFrame,ContinuationFrame)):
                if isinstance(frame,HeadersFrame):
                    if frame.stream_id not in self.streams:
                        if len(self.streams)>=128:raise CoverageGap("http2_stream_limit")
                        self.streams[frame.stream_id]=[{},bytearray()]
                    self.header_stream=frame.stream_id;self.header_end="END_STREAM" in frame.flags
                elif frame.stream_id!=self.header_stream:raise CoverageGap("http2_wrong_continuation_stream")
                self.header_block.extend(frame.data)
                if len(self.header_block)>65536:raise CoverageGap("http2_header_limit")
                if "END_HEADERS" in frame.flags:
                    headers=dict(self.decoder.decode(bytes(self.header_block)))
                    self.streams[frame.stream_id][0].update(headers)
                    self.header_block.clear();self.header_stream=None
                    if self.header_end:out.append(self.finish(frame.stream_id))
            elif isinstance(frame,DataFrame):
                if frame.stream_id not in self.streams:raise CoverageGap("http2_data_without_headers")
                self.streams[frame.stream_id][1].extend(frame.data)
                if sum(len(v[1]) for v in self.streams.values())>BODY_LIMIT:raise CoverageGap("http2_body_limit")
                if "END_STREAM" in frame.flags:out.append(self.finish(frame.stream_id))
            elif isinstance(frame,RstStreamFrame):
                if frame.stream_id in self.streams:raise CoverageGap("http2_stream_reset")
            elif isinstance(frame,GoAwayFrame):raise CoverageGap("http2_goaway_unfinished")
        return out

    def finish(self,stream):
        headers,data=self.streams.pop(stream)
        if "content-length" in headers and int(headers["content-length"])!=len(data):
            raise CoverageGap("http2_content_length_mismatch")
        return Body(bytes(data),headers,"http/2",stream)

    @property
    def pending(self):return bool(self.streams or self.buffer or self.header_block)


class WebSocket:
    def __init__(self,headers):self.buffer=bytearray();self.message=bytearray();self.opcode=None;self.headers=headers

    def feed(self,data):
        self.buffer.extend(data);out=[]
        while len(self.buffer)>=2:
            a,b=self.buffer[:2];fin=bool(a&128);opcode=a&15;masked=bool(b&128);length=b&127;pos=2
            if a&112:raise CoverageGap("websocket_extension_unverified")
            if not masked:raise CoverageGap("websocket_client_mask_missing")
            if length in (126,127):
                count=2 if length==126 else 8
                if len(self.buffer)<pos+count:return out
                length=int.from_bytes(self.buffer[pos:pos+count],"big");pos+=count
            if length>BODY_LIMIT:raise CoverageGap("websocket_frame_limit")
            if len(self.buffer)<pos+4+length:break
            mask=self.buffer[pos:pos+4];pos+=4
            payload=bytes(x^mask[i%4] for i,x in enumerate(self.buffer[pos:pos+length]));del self.buffer[:pos+length]
            if opcode>=8:
                if opcode not in (8,9,10) or not fin or length>125:raise CoverageGap("websocket_invalid_control")
                continue
            if opcode in (1,2):
                if self.opcode is not None:raise CoverageGap("websocket_interleaved_message")
                self.opcode=opcode
            elif opcode!=0 or self.opcode is None:raise CoverageGap("websocket_bad_continuation")
            self.message.extend(payload)
            if len(self.message)>BODY_LIMIT:raise CoverageGap("websocket_message_limit")
            if fin:
                limits=[] if self.opcode==1 else ["binary_websocket_not_inspected"]
                out.append(Body(bytes(self.message),dict(self.headers),"wss",limitations=limits))
                self.message.clear();self.opcode=None
        return out

    @property
    def pending(self):return bool(self.buffer or self.message or self.opcode is not None)


class Connection:
    def __init__(self):
        self.buffer=bytearray();self.parser=None;self.sequences={};self.failed=False;self.ws=None
        self.response=bytearray();self.pending_ws=bytearray()

    def memory_bytes(self):
        n=len(self.buffer)+len(self.response)+len(self.pending_ws)
        if isinstance(self.parser,HTTP1):n+=len(self.parser.body)+len(self.parser.connection._receive_buffer)
        if isinstance(self.parser,HTTP2):n+=len(self.parser.buffer)+len(self.parser.header_block)+sum(len(v[1]) for v in self.parser.streams.values())
        if self.ws:n+=len(self.ws.buffer)+len(self.ws.message)
        return n

    def quarantine(self):
        self.failed=True;self.parser=None;self.ws=None;self.buffer.clear();self.response.clear();self.pending_ws.clear()

    def feed(self,event:CaptureEvent):
        if self.failed:return [],[]
        try:
            expected=self.sequences.get(event.direction,0)+1
            if event.sequence!=expected or event.truncated or event.lost_events:raise CoverageGap("capture_gap_or_truncation")
            self.sequences[event.direction]=event.sequence
            if event.connection_identity!="stable":raise CoverageGap("connection_identity_missing")
            if event.event=="closed":
                if (self.parser and self.parser.pending) or self.buffer or self.pending_ws or (self.ws and self.ws.pending):
                    raise CoverageGap("connection_closed_with_incomplete_request")
                return [],[]
            if event.event=="gap":raise CoverageGap("provider_reported_gap")
            if event.event=="ready":return [],[]
            if event.capture_point!="tls":
                protocol="wss" if event.capture_point=="wss-message" else "http-json"
                return [Body(event.data,{"content-type":"application/json"},protocol)],[]
            data=event.data
            if event.direction=="recv":
                if isinstance(self.parser,HTTP1) and self.parser.upgrade and self.ws is None:
                    self.response.extend(data)
                    if len(self.response)>65536:raise CoverageGap("websocket_handshake_limit")
                    if b"\r\n\r\n" in self.response:
                        lines=bytes(self.response).split(b"\r\n\r\n",1)[0].split(b"\r\n")
                        response_headers={k.strip().lower():v.strip() for k,v in (line.split(b":",1) for line in lines[1:])}
                        key=self.parser.headers.get("sec-websocket-key","")
                        expected=base64.b64encode(hashlib.sha1((key+"258EAFA5-E914-47DA-95CA-C5AB0DC85B11").encode("ascii")).digest())
                        request_tokens={x.strip().lower() for x in self.parser.headers.get("connection","").split(",")}
                        response_tokens={x.strip().lower() for x in response_headers.get(b"connection",b"").split(b",")}
                        if (not lines[0].startswith(b"HTTP/1.1 101 ") or
                            response_headers.get(b"upgrade",b"").lower()!=b"websocket" or
                            b"upgrade" not in response_tokens or "upgrade" not in request_tokens or
                            len(base64.b64decode(key,validate=True))!=16 or
                            response_headers.get(b"sec-websocket-accept")!=expected):
                            raise CoverageGap("websocket_upgrade_not_confirmed")
                        if b"sec-websocket-extensions" in response_headers:raise CoverageGap("websocket_extension_unverified")
                        self.ws=WebSocket(self.parser.headers)
                        queued=bytes(self.pending_ws);self.pending_ws.clear();return self.ws.feed(queued),[]
                return [],[]
            if self.ws:return self.ws.feed(data),[]
            if isinstance(self.parser,HTTP1) and self.parser.upgrade:
                self.pending_ws.extend(data)
                if len(self.pending_ws)>BODY_LIMIT:raise CoverageGap("websocket_pending_limit")
                return [],[]
            if self.parser is None:
                self.buffer.extend(data)
                if len(self.buffer)>BODY_LIMIT:raise CoverageGap("connection_buffer_limit")
                if len(self.buffer)<24:return [],[]
                self.parser=HTTP2() if self.buffer.startswith(PREFACE) else HTTP1()
                data=bytes(self.buffer);self.buffer.clear()
            bodies=self.parser.feed(data)
            if isinstance(self.parser,HTTP1) and self.parser.upgrade and self.parser.connection.trailing_data[0]:
                raise CoverageGap('websocket_premature_client_data')
            return bodies,[]
        except Exception as error:
            self.quarantine()
            return [],[str(error) if isinstance(error,CoverageGap) else "protocol_parse_failure"]
