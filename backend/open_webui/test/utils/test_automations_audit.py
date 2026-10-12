import asyncio
import sys
from pathlib import Path
from types import SimpleNamespace

import pytest

sys.path.append(str(Path(__file__).resolve().parents[3]))

from open_webui.models.auths import Auths
from open_webui.utils import automations as automations_module


@pytest.fixture(autouse=True)
def active_owner_auth(monkeypatch):
    async def get_auth_by_id(user_id):
        return SimpleNamespace(id=user_id, active=True, session_stamp='current-stamp')

    monkeypatch.setattr(Auths, 'get_auth_by_id', get_auth_by_id)


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
        assert args[1] == 'owner@example.com'
        assert args[2] == 'user'
        assert args[3] == 'auto-denied'
        assert args[4] == 'automation'
        assert args[5] == 403
        assert args[6] >= 0
        meta = audit_calls[0][2]['meta']
        assert 'trigger=scheduler' in meta
        assert 'automation_id=auto-denied' in meta
        assert 'status=error' in meta
        assert 'error_code=owner_not_permitted' in meta
        assert 'Denied automation' not in meta

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
            assert kwargs['data'] == {'id': 'user-1', 'typ': 'automation', 'session_stamp': 'current-stamp'}
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
                'target': {'type': 'channel', 'channel_id': 'channel-1'},
            },
            folder_id=None,
        )

        app = SimpleNamespace(state=SimpleNamespace(MODELS={'model-a': {}}))
        await automations_module.execute_automation(app, automation, trigger='scheduler')

        audit_calls = [call for call in calls if call[0] == 'audit']
        assert audit_calls
        args = audit_calls[0][1]
        assert args[0] == 'TASK_AUTOMATION_SCHEDULED'
        assert args[1] == 'owner@example.com'
        assert args[2] == 'admin'
        assert args[3] == 'auto-channel'
        assert args[4] == 'automation'
        assert args[5] == 200
        assert args[6] >= 0
        meta = audit_calls[0][2]['meta']
        assert 'trigger=scheduler' in meta
        assert 'automation_id=auto-channel' in meta
        assert 'status=success' in meta
        assert 'channel_id=channel-1' in meta
        assert 'Channel automation' not in meta

    asyncio.run(scenario())


def test_scheduled_automation_exception_audit_uses_stable_error_code(monkeypatch):
    async def scenario():
        calls = []

        async def get_user_by_id(user_id):
            return SimpleNamespace(id=user_id, email='owner@example.com', role='admin')

        async def config_get(key, default=None):
            return '1h' if key == 'automations.auth_token_expires_in' else default

        async def prompt_template(prompt, user):
            return prompt

        def create_token(*args, **kwargs):
            return 'automation-token'

        async def insert_new_chat(*args, **kwargs):
            raise RuntimeError('provider returned secret token sk-live-123')

        async def record_run(*args, **kwargs):
            calls.append(('record_run', args, kwargs))

        async def publish_event(*args, **kwargs):
            calls.append(('publish_event', args, kwargs))

        def log_scheduled_activity(*args, **kwargs):
            calls.append(('audit', args, kwargs))

        import open_webui.middleware.access_log as access_log_module

        monkeypatch.setattr(automations_module.Users, 'get_user_by_id', get_user_by_id)
        monkeypatch.setattr(automations_module.Config, 'get', config_get)
        monkeypatch.setattr(automations_module, 'prompt_template', prompt_template)
        monkeypatch.setattr(automations_module, 'create_token', create_token)
        monkeypatch.setattr(automations_module.Chats, 'insert_new_chat', insert_new_chat)
        monkeypatch.setattr(automations_module, '_record_run', record_run)
        monkeypatch.setattr(automations_module, 'publish_event', publish_event)
        monkeypatch.setattr(access_log_module, 'log_scheduled_activity', log_scheduled_activity)

        automation = SimpleNamespace(
            id='auto-error',
            user_id='user-1',
            name='Secret automation name',
            data={'prompt': 'hello', 'model_id': 'model-a'},
            folder_id=None,
        )

        app = SimpleNamespace(state=SimpleNamespace(MODELS={'model-a': {}}))
        await automations_module.execute_automation(app, automation, trigger='scheduler')

        audit_calls = [call for call in calls if call[0] == 'audit']
        assert audit_calls
        args = audit_calls[0][1]
        assert args[0] == 'TASK_AUTOMATION_SCHEDULED_ERROR'
        assert args[1] == 'owner@example.com'
        assert args[2] == 'admin'
        assert args[3] == 'auto-error'
        assert args[4] == 'automation'
        assert args[5] == 500
        assert args[6] >= 0
        meta = audit_calls[0][2]['meta']
        assert 'trigger=scheduler' in meta
        assert 'automation_id=auto-error' in meta
        assert 'status=error' in meta
        assert 'error_code=execution_exception' in meta
        assert 'Secret automation name' not in meta
        assert 'sk-live-123' not in meta
        assert [call[1][1] for call in calls if call[0] == 'record_run'] == ['error']

    asyncio.run(scenario())


@pytest.mark.parametrize('trigger', ['manual', 'scheduler'])
@pytest.mark.parametrize('auth_active', [True, False, None])
@pytest.mark.parametrize('owner_role', ['admin', 'pending'])
def test_owner_auth_and_trigger_control_execution_outcome(monkeypatch, trigger, auth_active, owner_role):
    async def scenario():
        calls = []

        async def get_user(user_id):
            return SimpleNamespace(id=user_id, email='owner@example.com', role=owner_role)

        async def get_auth(user_id):
            return (
                None
                if auth_active is None
                else SimpleNamespace(active=auth_active, session_stamp='revoked-and-renewed')
            )

        async def config_get(key, default=None):
            return default

        async def template(prompt, user):
            return prompt

        async def channel(*args, **kwargs):
            calls.append(('channel', args))

        async def record(*args, **kwargs):
            calls.append(('record', args))

        async def publish(*args, **kwargs):
            calls.append(('event', args))

        def token(**kwargs):
            calls.append(('token', kwargs['data']))
            return 'test-token'

        import open_webui.middleware.access_log as access_log

        monkeypatch.setattr(automations_module.Users, 'get_user_by_id', get_user)
        monkeypatch.setattr(Auths, 'get_auth_by_id', get_auth)
        monkeypatch.setattr(automations_module.Config, 'get', config_get)
        monkeypatch.setattr(automations_module, 'prompt_template', template)
        monkeypatch.setattr(automations_module, '_execute_channel_automation', channel)
        monkeypatch.setattr(automations_module, '_record_run', record)
        monkeypatch.setattr(automations_module, 'publish_event', publish)
        monkeypatch.setattr(automations_module, 'create_token', token)
        monkeypatch.setattr(access_log, 'log_scheduled_activity', lambda *args, **kwargs: calls.append(('audit', args)))
        app = SimpleNamespace(state=SimpleNamespace(MODELS={'model-a': {}}))
        automation = SimpleNamespace(
            id='auto',
            user_id='user-1',
            name='Automation',
            folder_id=None,
            data={'prompt': 'hello', 'model_id': 'model-a', 'target': {'type': 'channel', 'channel_id': 'channel-1'}},
        )
        await automations_module.execute_automation(app, automation, trigger=trigger)
        allowed = auth_active is True and owner_role == 'admin'
        assert len([c for c in calls if c[0] == 'channel']) == int(allowed)
        assert [c[1] for c in calls if c[0] == 'token'] == (
            [{'id': 'user-1', 'typ': 'automation', 'session_stamp': 'revoked-and-renewed'}] if allowed else []
        )
        audits = [c[1][0] for c in calls if c[0] == 'audit']
        assert audits == (
            ['TASK_AUTOMATION_SCHEDULED' if allowed else 'TASK_AUTOMATION_SCHEDULED_ERROR']
            if trigger == 'scheduler'
            else []
        )
        if not allowed:
            assert [c[1][1] for c in calls if c[0] == 'record'] == ['error']
            assert not any(
                c[1][1] == automations_module.EVENTS.AUTOMATION_RUN_COMPLETED for c in calls if c[0] == 'event'
            )

    asyncio.run(scenario())
