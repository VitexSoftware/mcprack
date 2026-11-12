import asyncio

from fastmcp import FastMCP

from mcprack import composition_proxy


def test_composition_mounts_tools_resources_and_prompts_with_namespace():
    backend = FastMCP("backend")

    @backend.tool
    def lookup_record(record_id: str) -> str:
        return record_id

    @backend.resource("data://records")
    def records() -> str:
        return "records"

    @backend.prompt
    def explain_record(record_id: str) -> str:
        return f"Explain {record_id}"

    server = composition_proxy.build_composition_server(
        {"servers": [{"namespace": "records_3", "url": "http://unused.test/mcp"}]},
        proxy_factory=lambda _url: backend,
    )

    async def list_components():
        return (
            await server.list_tools(),
            await server.list_resources(),
            await server.list_prompts(),
        )

    tools, resources, prompts = asyncio.run(list_components())

    assert [tool.name for tool in tools] == ["records_3_lookup_record"]
    assert [str(resource.uri) for resource in resources] == ["data://records_3/records"]
    assert [prompt.name for prompt in prompts] == ["records_3_explain_record"]

def test_a_backend_that_never_answers_does_not_hide_the_others():
    """One silent backend used to make tools/list of the whole aggregate time
    out, so the client saw no tools at all."""
    import socket
    import threading
    import time

    from fastmcp import Client

    silent = socket.socket()
    silent.bind(("127.0.0.1", 0))
    silent.listen(5)
    port = silent.getsockname()[1]
    held = []
    threading.Thread(target=lambda: [held.append(silent.accept()) for _ in range(10)], daemon=True).start()

    healthy = FastMCP("healthy")

    @healthy.tool
    def ping() -> str:
        return "pong"

    def factory(url):
        return healthy if "unused" in url else composition_proxy._bounded_proxy(url, timeout=2)

    server = composition_proxy.build_composition_server(
        {"servers": [
            {"namespace": "ok_1", "url": "http://unused.test/mcp"},
            {"namespace": "stuck_2", "url": f"http://127.0.0.1:{port}/mcp"},
        ]},
        proxy_factory=factory,
    )

    async def list_tools():
        async with Client(server, timeout=30) as client:
            return await client.list_tools()

    started = time.monotonic()
    tools = asyncio.run(list_tools())
    silent.close()
    assert [t.name for t in tools] == ["ok_1_ping"]
    assert time.monotonic() - started < 15


def test_default_backend_timeout_is_bounded():
    assert 0 < composition_proxy.BACKEND_TIMEOUT <= 60
