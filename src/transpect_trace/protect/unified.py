"""Whole-request observations map to existing UnifiedLLMRequest v1 unchanged."""
import hashlib,json,zlib
from transpect_trace.observe.unified import UnifiedLLMRequest,extract_fields
from transpect_trace.observe.classification import classify
from transpect_trace.observe.protocol import decode_body,CoverageGap

def normalize(event):
    value=None;fields=[];parsing='failed';limits=list(event.limitations);decoded=None;encoding_state=event.encoding_state
    try:
        decoded=decode_body(event.body,event.content_encoding)
        encoding_state='identity' if event.content_encoding=='identity' else 'decoded'
        value=json.loads(decoded);fields=extract_fields(value);parsing='parsed'
    except (ValueError,TypeError,RecursionError,zlib.error):limits.append('semantic_parsing_failed')
    classification=classify(event.observation_id,value,{':path':event.api_path,':method':event.method},event.application,
        complete=event.completeness=='complete' and len(event.body)==event.body_bytes,decoded=decoded is not None)
    return UnifiedLLMRequest(observation_id=event.observation_id,capture_source=event.adapter_id,application=event.application,
        channel=event.channel,pid=event.pid,creation_filetime=event.creation_filetime,image_sha256=event.image_sha256,
        connection_id=event.connection_id or 'unknown',stream_id=event.stream_id,transport_protocol='unknown',
        application_protocol=event.protocol,destination=event.destination_host,destination_evidence='request_object_host',
        completeness=event.completeness,encoding_state=encoding_state,parsing_state=parsing,
        raw_payload_sha256=event.body_sha256,raw_payload_bytes=event.body_bytes,
        decoded_payload_sha256=hashlib.sha256(decoded).hexdigest() if decoded is not None else None,
        decoded_payload_bytes=len(decoded) if decoded is not None else None,
        classification=classification,fields=fields,limitations=limits,capture_point=event.capture_stage,
        send_evidence='constructed')
