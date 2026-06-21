import ast
from pathlib import Path


def _load_merge_routing_usage():
    middleware_path = Path(__file__).resolve().parents[2] / 'utils' / 'middleware.py'
    source = middleware_path.read_text(encoding='utf-8')
    module_ast = ast.parse(source)

    fn_node = next(
        node for node in module_ast.body if isinstance(node, ast.FunctionDef) and node.name == 'merge_routing_usage'
    )
    fn_source = ast.get_source_segment(source, fn_node)
    namespace = {}
    exec(fn_source, namespace)
    return namespace['merge_routing_usage']


merge_routing_usage = _load_merge_routing_usage()


def test_merge_routing_usage_adds_requested_model_id():
    usage = {'input_tokens': 10, 'output_tokens': 5}
    metadata = {"routing": {"requested_model_id": "GPT-5-nano"}}

    result = merge_routing_usage(usage, metadata)

    assert result['input_tokens'] == 10
    assert result['output_tokens'] == 5
    assert result["routing"]["requested_model_id"] == "GPT-5-nano"
    assert result["routing"]["routed"] is True


def test_merge_routing_usage_noop_without_routing_metadata():
    usage = {'input_tokens': 7, 'output_tokens': 3}

    result = merge_routing_usage(usage, {"model": {"id": "some-model"}})

    assert result == usage
    assert "routing" not in result
