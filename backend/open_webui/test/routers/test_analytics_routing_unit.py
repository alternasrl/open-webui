import ast
from pathlib import Path


def _load_routing_helpers():
    chat_messages_path = Path(__file__).resolve().parents[2] / 'models' / 'chat_messages.py'
    source = chat_messages_path.read_text(encoding='utf-8')
    module_ast = ast.parse(source)

    helper_nodes = [
        node
        for node in module_ast.body
        if isinstance(node, ast.FunctionDef) and node.name in {'_routing_match', '_summarize_routing_pairs'}
    ]
    helper_source = '\n\n'.join(ast.get_source_segment(source, node) for node in helper_nodes)
    namespace = {'Optional': str}
    exec(helper_source, namespace)
    return namespace['_routing_match'], namespace['_summarize_routing_pairs']


_routing_match, _summarize_routing_pairs = _load_routing_helpers()


def test_summarize_pairs_counts_requested_selected():
    events = [
        {'requested_model_id': 'GPT-5-nano', 'selected_model_id': 'DeepSeek-V4-flash'},
        {'requested_model_id': 'GPT-5-nano', 'selected_model_id': 'DeepSeek-V4-flash'},
        {'requested_model_id': 'GPT-5-nano', 'selected_model_id': 'Mistral-large-3'},
    ]

    pairs = _summarize_routing_pairs(events)

    assert pairs[0]['requested_model_id'] == 'GPT-5-nano'
    assert pairs[0]['selected_model_id'] == 'DeepSeek-V4-flash'
    assert pairs[0]['count'] == 2
    assert pairs[0]['percentage'] == 66.67

    assert pairs[1]['requested_model_id'] == 'GPT-5-nano'
    assert pairs[1]['selected_model_id'] == 'Mistral-large-3'
    assert pairs[1]['count'] == 1
    assert pairs[1]['percentage'] == 33.33


def test_summarize_pairs_ignores_missing_requested_or_selected():
    events = [
        {'requested_model_id': None, 'selected_model_id': 'A'},
        {'requested_model_id': 'A', 'selected_model_id': None},
        {'requested_model_id': 'A', 'selected_model_id': 'B'},
    ]

    pairs = _summarize_routing_pairs(events)

    assert len(pairs) == 1
    assert pairs[0]['requested_model_id'] == 'A'
    assert pairs[0]['selected_model_id'] == 'B'
    assert pairs[0]['count'] == 1
    assert pairs[0]['percentage'] == 100.0


def test_routing_match_selected_mode():
    assert _routing_match('A', 'B', model_selected='A', model_requested=None, model_mode='selected') is True
    assert _routing_match('B', 'A', model_selected='A', model_requested=None, model_mode='selected') is False


def test_routing_match_requested_mode():
    assert _routing_match('A', 'B', model_selected=None, model_requested='B', model_mode='requested') is True
    assert _routing_match('A', 'C', model_selected=None, model_requested='B', model_mode='requested') is False


def test_routing_match_or_mode_with_dual_axis_filters():
    assert _routing_match('SEL', 'REQ', model_selected='SEL', model_requested='X', model_mode='or') is True
    assert _routing_match('SEL', 'REQ', model_selected='X', model_requested='REQ', model_mode='or') is True
    assert _routing_match('SEL', 'REQ', model_selected='X', model_requested='Y', model_mode='or') is False


def test_routing_match_and_mode_with_dual_axis_filters():
    assert _routing_match('SEL', 'REQ', model_selected='SEL', model_requested='REQ', model_mode='and') is True
    assert _routing_match('SEL', 'REQ', model_selected='SEL', model_requested='X', model_mode='and') is False
    assert _routing_match('SEL', 'REQ', model_selected='X', model_requested='REQ', model_mode='and') is False