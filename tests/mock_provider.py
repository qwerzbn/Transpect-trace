from __future__ import annotations

import argparse
import json
import time
from uuid import uuid4

from aiohttp import web


async def rejected(_: web.Request) -> web.Response:
    return web.json_response({"error": {"message": "intentional integration-test rejection"}}, status=401)


def response_object(response_id: str, model: str, output: list[dict], status: str = "completed") -> dict:
    return {
        "id": response_id,
        "object": "response",
        "created_at": int(time.time()),
        "status": status,
        "background": False,
        "error": None,
        "incomplete_details": None,
        "instructions": None,
        "max_output_tokens": None,
        "model": model,
        "output": output,
        "parallel_tool_calls": True,
        "previous_response_id": None,
        "reasoning": {"effort": None, "summary": None},
        "service_tier": "default",
        "store": False,
        "temperature": None,
        "text": {"format": {"type": "text"}, "verbosity": "medium"},
        "tool_choice": "auto",
        "tools": [],
        "top_p": None,
        "truncation": "disabled",
        "usage": {
            "input_tokens": 10,
            "input_tokens_details": {"cached_tokens": 0},
            "output_tokens": 10,
            "output_tokens_details": {"reasoning_tokens": 0},
            "total_tokens": 20,
        },
        "user": None,
        "metadata": {},
    }


async def successful(request: web.Request) -> web.StreamResponse:
    body = await request.json()
    model = str(body.get("model") or "mock")
    items = body.get("input") if isinstance(body.get("input"), list) else []
    has_tool_result = any(isinstance(item, dict) and item.get("type") == "function_call_output" for item in items)
    response_id = f"resp_{uuid4().hex}"
    sequence = 0
    events: list[dict] = []

    def add(event_type: str, **fields: object) -> None:
        nonlocal sequence
        sequence += 1
        events.append({"type": event_type, "sequence_number": sequence, **fields})

    add("response.created", response=response_object(response_id, model, [], "in_progress"))
    if not has_tool_result:
        call_id = f"call_{uuid4().hex}"
        item_id = f"fc_{uuid4().hex}"
        arguments = json.dumps({"cmd": "cat public.txt", "workdir": "/workspace"})
        started = {"id": item_id, "type": "function_call", "status": "in_progress", "arguments": "", "call_id": call_id, "name": "exec_command"}
        completed = {**started, "status": "completed", "arguments": arguments}
        add("response.output_item.added", output_index=0, item=started)
        add("response.function_call_arguments.delta", item_id=item_id, output_index=0, delta=arguments)
        add("response.function_call_arguments.done", item_id=item_id, output_index=0, name="exec_command", arguments=arguments)
        add("response.output_item.done", output_index=0, item=completed)
        output = [completed]
    else:
        item_id = f"msg_{uuid4().hex}"
        part = {"type": "output_text", "annotations": [], "logprobs": [], "text": "The public fixture contains public information."}
        started = {"id": item_id, "type": "message", "status": "in_progress", "role": "assistant", "content": []}
        completed = {**started, "status": "completed", "content": [part]}
        add("response.output_item.added", output_index=0, item=started)
        add("response.content_part.added", item_id=item_id, output_index=0, content_index=0, part={**part, "text": ""})
        add("response.output_text.delta", item_id=item_id, output_index=0, content_index=0, delta=part["text"], logprobs=[])
        add("response.output_text.done", item_id=item_id, output_index=0, content_index=0, text=part["text"], logprobs=[])
        add("response.content_part.done", item_id=item_id, output_index=0, content_index=0, part=part)
        add("response.output_item.done", output_index=0, item=completed)
        output = [completed]
    add("response.completed", response=response_object(response_id, model, output))
    response = web.StreamResponse(status=200, headers={"Content-Type": "text/event-stream", "X-Request-ID": response_id})
    await response.prepare(request)
    for event in events:
        await response.write(f"event: {event['type']}\ndata: {json.dumps(event)}\n\n".encode())
    await response.write_eof()
    return response


async def anthropic_successful(request: web.Request) -> web.StreamResponse:
    if request.path.endswith("/count_tokens"):
        return web.json_response({"input_tokens": 10})
    body = await request.json()
    messages = body.get("messages") if isinstance(body.get("messages"), list) else []
    has_tool_result = any(
        isinstance(block, dict) and block.get("type") == "tool_result"
        for message in messages
        if isinstance(message, dict)
        for block in (message.get("content") if isinstance(message.get("content"), list) else [])
    )
    message_id = f"msg_{uuid4().hex}"
    model = str(body.get("model") or "mock-claude")
    events: list[tuple[str, dict]] = [
        ("message_start", {
            "type": "message_start",
            "message": {
                "id": message_id, "type": "message", "role": "assistant", "model": model,
                "content": [], "stop_reason": None, "stop_sequence": None,
                "usage": {"input_tokens": 10, "output_tokens": 0},
            },
        }),
    ]
    if not has_tool_result:
        tool_id = f"toolu_{uuid4().hex}"
        arguments = json.dumps({"command": "cat public.txt", "description": "Read public fixture"})
        events.extend([
            ("content_block_start", {
                "type": "content_block_start", "index": 0,
                "content_block": {"type": "tool_use", "id": tool_id, "name": "Bash", "input": {}},
            }),
            ("content_block_delta", {
                "type": "content_block_delta", "index": 0,
                "delta": {"type": "input_json_delta", "partial_json": arguments},
            }),
            ("content_block_stop", {"type": "content_block_stop", "index": 0}),
            ("message_delta", {
                "type": "message_delta", "delta": {"stop_reason": "tool_use", "stop_sequence": None},
                "usage": {"output_tokens": 10},
            }),
        ])
    else:
        answer = "The public fixture contains public information."
        events.extend([
            ("content_block_start", {
                "type": "content_block_start", "index": 0,
                "content_block": {"type": "text", "text": ""},
            }),
            ("content_block_delta", {
                "type": "content_block_delta", "index": 0,
                "delta": {"type": "text_delta", "text": answer},
            }),
            ("content_block_stop", {"type": "content_block_stop", "index": 0}),
            ("message_delta", {
                "type": "message_delta", "delta": {"stop_reason": "end_turn", "stop_sequence": None},
                "usage": {"output_tokens": 10},
            }),
        ])
    events.append(("message_stop", {"type": "message_stop"}))
    response = web.StreamResponse(
        status=200,
        headers={
            "Content-Type": "text/event-stream",
            "request-id": message_id,
            "anthropic-request-id": message_id,
        },
    )
    await response.prepare(request)
    for event_type, event in events:
        await response.write(f"event: {event_type}\ndata: {json.dumps(event)}\n\n".encode())
    await response.write_eof()
    return response


def main() -> None:
    parser = argparse.ArgumentParser()
    parser.add_argument("--port", type=int, default=18765)
    parser.add_argument("--mode", choices=["reject", "success", "anthropic-success"], default="reject")
    args = parser.parse_args()
    app = web.Application()
    handler = {
        "reject": rejected,
        "success": successful,
        "anthropic-success": anthropic_successful,
    }[args.mode]
    app.router.add_route("*", "/{tail:.*}", handler)
    web.run_app(app, host="0.0.0.0", port=args.port, print=None)


if __name__ == "__main__":
    main()
