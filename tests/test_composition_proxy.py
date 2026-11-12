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