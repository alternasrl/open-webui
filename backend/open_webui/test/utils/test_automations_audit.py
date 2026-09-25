import asyncio
import sys
from pathlib import Path
from types import SimpleNamespace

sys.path.append(str(Path(__file__).resolve().parents[3]))

from open_webui.utils import automations as automations_module


def test_scheduled_automation_permission_error_emits_audit_log(monkeypatch):
    async def scenario():
        calls = []

        async def get_user_by_id(user_id):
            return SimpleNamespace(id=user_id, email='owner@example.com', role='user')

        async def config_get(key, default=None):
            return {}

        async def has_permission(user_id, permission, permissions):
            return False

        async def record_run(*args, **kwargs):
            calls.append(('record_run', args, kwargs))

        async def publish_event(*args, **kwargs):
            calls.append(('publish_event', args, kwargs))

        def log_scheduled_activity(*args, **kwargs):
            calls.append(('audit', args, kwargs))

        import open_webui.middleware.access_log as access_log_module
        import open_webui.utils.access_control as access_control_module

        monkeypatch.setattr(automations_module.Users, 'get_user_by_id', get_user_by_id)
        monkeypatch.setattr(automations_module.Config, 'get', config_get)
        monkeypatch.setattr(access_control_module, 'has_permission', has_permission)
        monkeypatch.setattr(automations_module, '_record_run', record_run)
        monkeypatch.setattr(automations_module, 'publish_event', publish_event)
        monkeypatch.setattr(access_log_module, 'log_scheduled_activity', log_scheduled_activity)

        automation = SimpleNamespace(
            id='auto-denied',
            user_id='user-1',
            name='Denied automation',
            data={'prompt': 'hello', 'model_id': 'model-a'},
            folder_id=None,
        )

        await automations_module.execute_automation(SimpleNamespace(), automation, trigger='scheduler')

        audit_calls = [call for call in calls if call[0] == 'audit']
        assert audit_calls
        args = audit_calls[0][1]
        assert args[0] == 'TASK_AUTOMATION_SCHEDULED_ERROR'
        assert args[5] == 403
        assert 'owner_not_permitted' in audit_calls[0][2]['meta']

    asyncio.run(scenario())


def test_scheduled_channel_automation_success_emits_audit_log(monkeypatch):
    async def scenario():
        calls = []

        async def get_user_by_id(user_id):
            return SimpleNamespace(id=user_id, email='owner@example.com', role='admin')

        async def config_get(key, default=None):
            return '1h' if key == 'automations.auth_token_expires_in' else default

        async def prompt_template(prompt, user):
            return prompt

        async def execute_channel_automation(*args, **kwargs):
            calls.append(('channel', args, kwargs))

        def create_token(*args, **kwargs):
            return 'automation-token'

        def log_scheduled_activity(*args, **kwargs):
            calls.append(('audit', args, kwargs))

        import open_webui.middleware.access_log as access_log_module

        monkeypatch.setattr(automations_module.Users, 'get_user_by_id', get_user_by_id)
        monkeypatch.setattr(automations_module.Config, 'get', config_get)
        monkeypatch.setattr(automations_module, 'prompt_template', prompt_template)
        monkeypatch.setattr(automations_module, '_execute_channel_automation', execute_channel_automation)
        monkeypatch.setattr(automations_module, 'create_token', create_token)
        monkeypatch.setattr(access_log_module, 'log_scheduled_activity', log_scheduled_activity)

        automation = SimpleNamespace(
            id='auto-channel',
            user_id='user-1',
            name='Channel automation',
            data={
                'prompt': 'hello',
                'model_id': 'model-a',
                'target': {'type': 'channel', 'id': 'channel-1'},
            },
            folder_id=None,
        )

        await automations_module.execute_automation(SimpleNamespace(), automation, trigger='scheduler')

        audit_calls = [call for call in calls if call[0] == 'audit']
        assert audit_calls
        args = audit_calls[0][1]
        assert args[0] == 'TASK_AUTOMATION_SCHEDULED'
        assert args[5] == 200
        assert 'channel_id=channel-1' in audit_calls[0][2]['meta']

    asyncio.run(scenario())
