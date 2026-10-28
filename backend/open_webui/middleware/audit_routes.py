"""Reviewed mounted HTTP route catalog for v0.12.4 (including conditional SCIM).

Each row is METHOD TEMPLATE ACTION ACTOR SEVERITY. NIS2 access events record only
sanitized identifiers, actor, correlation, status/outcome and timing, never
request/response content. Actor describes the route's admission contract, not
permission to trust inbound claims. Authentication remains the router's job.
New business routes require explicit review here; no prefix/method exemptions.
Actors: admin/authenticated/human/scim are authenticated admission contracts;
optional permits anonymous reads; public needs no actor; protocol resolves
identity through its login, MFA, OAuth or webhook protocol, not a user dependency.
"""

from typing import NamedTuple

from starlette.routing import compile_path


class RoutePolicy(NamedTuple):
    action: str
    actor: str
    security: bool


# Exact technical exceptions, deliberately not business prefixes.
TECHNICAL_EXCEPTIONS = {
    ('GET', '/health'): 'Liveness probe; no actor or business object.',
    ('GET', '/health/db'): 'Database health probe; no business data.',
    ('GET', '/ready'): 'Readiness probe; no business operation.',
    ('GET', '/manifest.json'): 'Public PWA manifest metadata.',
    ('GET', '/opensearch.xml'): 'Public browser search descriptor.',
}
TECHNICAL_EXCEPTIONS.update(
    {
        ('GET', '/openapi.json'): 'Development-only generated API schema.',
        ('GET', '/docs'): 'Development-only Swagger UI.',
        ('GET', '/docs/oauth2-redirect'): 'Development-only Swagger OAuth callback.',
    }
)

_CATALOG = """\
GET /api/changelog SYSTEM_CHANGELOG_READ public access
POST /api/chat/actions/{action_id} CHAT_ACTION authenticated security
POST /api/chat/completed CHAT_COMPLETED authenticated security
POST /api/chat/completions CHAT_COMPLETION authenticated security
GET /api/config SYSTEM_CONFIG_READ public access
POST /api/embeddings OLLAMA_EMBEDDINGS authenticated access
GET /api/events EVENT_TYPES_READ admin access
GET /api/events/webhooks EVENT_WEBHOOK_LIST_READ admin access
POST /api/events/webhooks EVENT_WEBHOOK_CREATE admin security
DELETE /api/events/webhooks/{webhook_id} EVENT_WEBHOOK_DELETE admin security
PUT /api/events/webhooks/{webhook_id} EVENT_WEBHOOK_UPDATE admin security
POST /api/message MESSAGE_GENERATE authenticated security
POST /api/message/count_tokens MESSAGE_TOKENS_COUNT authenticated security
GET /api/models MODEL_LIST_READ authenticated access
GET /api/models/base MODEL_BASE_LIST_READ admin access
POST /api/models/unload MODEL_UNLOAD admin security
GET /api/tasks TASK_LIST_READ admin access
GET /api/tasks/chat/{chat_id:path} CHAT_TASK_LIST_READ authenticated access
POST /api/tasks/chat/{chat_id:path}/stop CHAT_TASK_STOP authenticated security
POST /api/tasks/stop/{task_id} TASK_STOP admin security
GET /api/usage USAGE_READ authenticated access
GET /api/v1/analytics/daily ANALYTICS_DAILY_READ admin access
GET /api/v1/analytics/messages ANALYTICS_MESSAGES_READ admin access
GET /api/v1/analytics/models ANALYTICS_MODELS_READ admin access
GET /api/v1/analytics/models/{model_id:path}/chats ANALYTICS_MODEL_CHATS_READ admin access
GET /api/v1/analytics/models/{model_id:path}/overview ANALYTICS_MODEL_OVERVIEW_READ admin access
GET /api/v1/analytics/summary ANALYTICS_SUMMARY_READ admin access
GET /api/v1/analytics/tokens ANALYTICS_TOKENS_READ admin access
GET /api/v1/analytics/users ANALYTICS_USERS_READ admin access
GET /api/v1/apps APP_LIST_READ authenticated access
POST /api/v1/apps APP_CREATE admin security
POST /api/v1/apps/manifest/preview APP_MANIFEST_PREVIEW admin security
DELETE /api/v1/apps/{app_id} APP_DELETE admin security
GET /api/v1/apps/{app_id} APP_READ admin access
PATCH /api/v1/apps/{app_id} APP_UPDATE admin security
POST /api/v1/apps/{app_id}/connect APP_CONNECT admin security
POST /api/v1/apps/{app_id}/interactions APP_INTERACTION authenticated security
GET /api/v1/audio/config CONFIG_AUDIO_READ admin security
POST /api/v1/audio/config/update CONFIG_AUDIO admin security
GET /api/v1/audio/models AUDIO_MODELS_READ authenticated access
POST /api/v1/audio/speech AUDIO_SPEECH authenticated security
POST /api/v1/audio/transcriptions AUDIO_TRANSCRIBE authenticated security
GET /api/v1/audio/voices AUDIO_VOICES_READ authenticated access
GET /api/v1/auths/ AUTH_SESSION_READ human security
POST /api/v1/auths/add USER_CREATE admin security
GET /api/v1/auths/admin/config CONFIG_AUTH_READ admin security
POST /api/v1/auths/admin/config CONFIG_AUTH admin security
GET /api/v1/auths/admin/config/ldap CONFIG_LDAP_READ admin security
POST /api/v1/auths/admin/config/ldap CONFIG_LDAP admin security
GET /api/v1/auths/admin/config/ldap/server CONFIG_LDAP_SERVER_READ admin security
POST /api/v1/auths/admin/config/ldap/server CONFIG_LDAP_SERVER admin security
GET /api/v1/auths/admin/config/oauth CONFIG_OAUTH_ADMIN_READ admin access
POST /api/v1/auths/admin/config/oauth CONFIG_OAUTH_ADMIN admin security
GET /api/v1/auths/admin/details AUTH_ADMIN_DETAILS_READ authenticated security
DELETE /api/v1/auths/api_key AUTH_API_KEY_DELETE authenticated security
GET /api/v1/auths/api_key AUTH_API_KEY_READ authenticated security
POST /api/v1/auths/api_key AUTH_API_KEY_CREATE authenticated security
POST /api/v1/auths/ldap AUTH_LOGIN_LDAP protocol security
POST /api/v1/auths/mfa/challenge AUTH_MFA_CHALLENGE protocol security
POST /api/v1/auths/mfa/enroll/confirm AUTH_MFA_ENROLL_CONFIRM protocol security
POST /api/v1/auths/mfa/enroll/start AUTH_MFA_ENROLL_START protocol security
POST /api/v1/auths/mfa/recover AUTH_MFA_RECOVER protocol security
POST /api/v1/auths/mfa/recovery/codes AUTH_MFA_RECOVERY_ROTATE human security
POST /api/v1/auths/mfa/replace AUTH_MFA_REPLACE human security
GET /api/v1/auths/mfa/status AUTH_MFA_STATUS human access
POST /api/v1/auths/mfa/verify AUTH_MFA_VERIFY protocol security
DELETE /api/v1/auths/oauth/sessions/{provider:path} AUTH_LOGOUT authenticated security
POST /api/v1/auths/oauth/{provider}/token/exchange AUTH_OAUTH_TOKEN protocol security
POST /api/v1/auths/signin AUTH_LOGIN protocol security
POST /api/v1/auths/signout AUTH_LOGOUT protocol security
POST /api/v1/auths/signup AUTH_SIGNUP protocol security
POST /api/v1/auths/update/password AUTH_PASSWORD_CHANGE authenticated security
POST /api/v1/auths/update/profile AUTH_PROFILE_UPDATE authenticated access
POST /api/v1/auths/update/timezone AUTH_TIMEZONE_UPDATE authenticated access
POST /api/v1/automations/create RESOURCE_CREATE_AUTOMATION authenticated security
GET /api/v1/automations/list AUTOMATION_LIST_READ authenticated access
GET /api/v1/automations/{id} AUTOMATION_READ authenticated access
DELETE /api/v1/automations/{id}/delete RESOURCE_DELETE_AUTOMATION authenticated security
POST /api/v1/automations/{id}/run RESOURCE_RUN_AUTOMATION authenticated security
GET /api/v1/automations/{id}/runs RESOURCE_VIEW_AUTOMATION_RUNS authenticated access
POST /api/v1/automations/{id}/toggle RESOURCE_TOGGLE_AUTOMATION authenticated access
POST /api/v1/automations/{id}/update RESOURCE_UPDATE_AUTOMATION authenticated security
GET /api/v1/calendars/ CALENDAR_LIST_READ authenticated access
POST /api/v1/calendars/create CALENDAR_CREATE authenticated access
GET /api/v1/calendars/events CALENDAR_EVENTS_READ authenticated access
POST /api/v1/calendars/events/create CALENDAR_EVENT_CREATE authenticated access
GET /api/v1/calendars/events/search CALENDAR_EVENTS_SEARCH authenticated access
GET /api/v1/calendars/events/{event_id} CALENDAR_EVENT_READ authenticated access
DELETE /api/v1/calendars/events/{event_id}/delete CALENDAR_EVENT_DELETE authenticated access
POST /api/v1/calendars/events/{event_id}/rsvp CALENDAR_EVENT_RSVP authenticated access
POST /api/v1/calendars/events/{event_id}/update CALENDAR_EVENT_UPDATE authenticated access
GET /api/v1/calendars/{calendar_id} CALENDAR_READ authenticated access
POST /api/v1/calendars/{calendar_id}/access/update CALENDAR_ACCESS_UPDATE authenticated security
POST /api/v1/calendars/{calendar_id}/default CALENDAR_SET_DEFAULT authenticated access
DELETE /api/v1/calendars/{calendar_id}/delete CALENDAR_DELETE authenticated security
POST /api/v1/calendars/{calendar_id}/update CALENDAR_UPDATE authenticated access
GET /api/v1/channels/ CHANNEL_LIST_READ authenticated access
POST /api/v1/channels/create CHANNEL_CREATE authenticated security
GET /api/v1/channels/list CHANNEL_LIST_READ authenticated access
GET /api/v1/channels/users/{user_id} CHANNEL_USER_LIST_READ authenticated access
GET /api/v1/channels/webhooks/{webhook_id}/profile/image CHANNEL_WEBHOOK_IMAGE_READ authenticated access
POST /api/v1/channels/webhooks/{webhook_id}/{token} CHANNEL_WEBHOOK_INVOKE protocol security
GET /api/v1/channels/{channel_id}/apps CHANNEL_APPS_READ authenticated access
POST /api/v1/channels/{channel_id}/apps CHANNEL_APP_ADD authenticated security
DELETE /api/v1/channels/{channel_id}/apps/{app_id} CHANNEL_APP_REMOVE authenticated security
GET /api/v1/channels/{id} CHANNEL_READ authenticated access
POST /api/v1/channels/{id}/access/update CHANNEL_ACCESS_UPDATE authenticated security
DELETE /api/v1/channels/{id}/delete CHANNEL_DELETE authenticated security
GET /api/v1/channels/{id}/members CHANNEL_MEMBERS_READ authenticated access
POST /api/v1/channels/{id}/members/active CHANNEL_MEMBER_ACTIVE authenticated security
POST /api/v1/channels/{id}/members/mute CHANNEL_MEMBER_MUTE authenticated security
GET /api/v1/channels/{id}/messages CHANNEL_MESSAGES_READ authenticated access
GET /api/v1/channels/{id}/messages/pinned CHANNEL_PINNED_MESSAGES_READ authenticated access
POST /api/v1/channels/{id}/messages/post CHANNEL_MESSAGE_POST authenticated access
GET /api/v1/channels/{id}/messages/{message_id} CHANNEL_MESSAGE_READ authenticated access
GET /api/v1/channels/{id}/messages/{message_id}/data CHANNEL_MESSAGE_DATA_READ authenticated access
DELETE /api/v1/channels/{id}/messages/{message_id}/delete CHANNEL_MESSAGE_DELETE authenticated access
POST /api/v1/channels/{id}/messages/{message_id}/pin CHANNEL_MESSAGE_PIN authenticated security
POST /api/v1/channels/{id}/messages/{message_id}/reactions/add CHANNEL_REACTION_ADD authenticated security
POST /api/v1/channels/{id}/messages/{message_id}/reactions/remove CHANNEL_REACTION_REMOVE authenticated security
GET /api/v1/channels/{id}/messages/{message_id}/thread CHANNEL_THREAD_READ authenticated access
POST /api/v1/channels/{id}/messages/{message_id}/update CHANNEL_MESSAGE_UPDATE authenticated access
POST /api/v1/channels/{id}/update CHANNEL_UPDATE authenticated security
POST /api/v1/channels/{id}/update/members/add CHANNEL_MEMBER_ADD authenticated security
POST /api/v1/channels/{id}/update/members/remove CHANNEL_MEMBER_REMOVE authenticated security
GET /api/v1/channels/{id}/webhooks CHANNEL_WEBHOOK_LIST_READ authenticated access
POST /api/v1/channels/{id}/webhooks/create CHANNEL_WEBHOOK_CREATE authenticated security
DELETE /api/v1/channels/{id}/webhooks/{webhook_id}/delete CHANNEL_WEBHOOK_DELETE authenticated security
POST /api/v1/channels/{id}/webhooks/{webhook_id}/update CHANNEL_WEBHOOK_UPDATE authenticated security
POST /api/v1/chat/completions CHAT_COMPLETION authenticated security
DELETE /api/v1/chats/ CHAT_DELETE_ALL authenticated security
GET /api/v1/chats/ CHAT_LIST_READ authenticated access
GET /api/v1/chats/all CHAT_LIST_ALL_READ authenticated access
GET /api/v1/chats/all/archived CHAT_ARCHIVED_LIST_READ authenticated access
GET /api/v1/chats/all/db DATA_EXPORT admin security
GET /api/v1/chats/all/tags CHAT_TAGS_LIST_READ authenticated access
POST /api/v1/chats/archive/all CHAT_ARCHIVE_ALL authenticated access
GET /api/v1/chats/archived CHAT_ARCHIVED_LIST_READ authenticated access
GET /api/v1/chats/archived/count CHAT_ARCHIVED_COUNT authenticated access
GET /api/v1/chats/config CONFIG_CHATS_READ admin access
POST /api/v1/chats/config CONFIG_CHATS admin security
GET /api/v1/chats/folder/{folder_id} FOLDER_CHATS_READ authenticated access
GET /api/v1/chats/folder/{folder_id}/list FOLDER_CHATS_READ authenticated access
POST /api/v1/chats/import DATA_IMPORT authenticated security
GET /api/v1/chats/list CHAT_LIST_READ authenticated access
GET /api/v1/chats/list/user/{user_id} USER_CHATS_READ admin access
POST /api/v1/chats/new CHAT_CREATE authenticated access
GET /api/v1/chats/pinned CHAT_PINNED_LIST_READ authenticated access
POST /api/v1/chats/read CHAT_READ authenticated access
GET /api/v1/chats/search CHAT_SEARCH authenticated access
DELETE /api/v1/chats/share/all CHAT_DELETE_ALL_SHARED authenticated security
GET /api/v1/chats/share/{share_id} SHARED_CHAT_READ optional access
GET /api/v1/chats/shared SHARED_CHATS_READ authenticated access
GET /api/v1/chats/shared/{id}/access SHARED_CHAT_ACCESS_READ authenticated access
POST /api/v1/chats/shared/{id}/access/update ACCESS_SHARE_CHAT_UPDATE authenticated security
GET /api/v1/chats/stats/export DATA_EXPORT authenticated security
GET /api/v1/chats/stats/export/{chat_id} DATA_EXPORT authenticated security
GET /api/v1/chats/stats/usage CHAT_USAGE_READ authenticated access
POST /api/v1/chats/tags CHAT_TAG_FILTER_READ authenticated access
POST /api/v1/chats/unarchive/all CHAT_UNARCHIVE_ALL authenticated access
DELETE /api/v1/chats/{id} CHAT_DELETE authenticated access
GET /api/v1/chats/{id} CHAT_CONTENT_READ authenticated access
POST /api/v1/chats/{id} CHAT_UPDATE authenticated access
POST /api/v1/chats/{id}/archive CHAT_ARCHIVE authenticated access
POST /api/v1/chats/{id}/clone CHAT_CLONE authenticated access
POST /api/v1/chats/{id}/clone/shared CHAT_CLONE_SHARED authenticated access
POST /api/v1/chats/{id}/compact CHAT_COMPACT authenticated access
POST /api/v1/chats/{id}/folder CHAT_MOVE_FOLDER authenticated access
POST /api/v1/chats/{id}/fork CHAT_FORK authenticated access
DELETE /api/v1/chats/{id}/messages/{message_id} CHAT_MESSAGE_DELETE authenticated access
POST /api/v1/chats/{id}/messages/{message_id} CHAT_MESSAGE_UPDATE authenticated security
POST /api/v1/chats/{id}/messages/{message_id}/event CHAT_MESSAGE_EVENT authenticated security
POST /api/v1/chats/{id}/messages/{message_id}/resolve CHAT_MESSAGE_RESOLVE authenticated security
PATCH /api/v1/chats/{id}/params CHAT_PARAMS_UPDATE authenticated security
POST /api/v1/chats/{id}/pin CHAT_PIN authenticated access
GET /api/v1/chats/{id}/pinned CHAT_PIN_STATUS_READ authenticated access
DELETE /api/v1/chats/{id}/share ACCESS_UNSHARE_CHAT authenticated security
POST /api/v1/chats/{id}/share ACCESS_SHARE_CHAT authenticated security
DELETE /api/v1/chats/{id}/tags CHAT_TAGS_DELETE authenticated security
GET /api/v1/chats/{id}/tags CHAT_TAGS_READ authenticated access
POST /api/v1/chats/{id}/tags CHAT_TAG_ADD authenticated security
POST /api/v1/chats/{id}/unread CHAT_UNREAD authenticated access
GET /api/v1/configs/banners CONFIG_BANNERS_READ authenticated security
POST /api/v1/configs/banners CONFIG_BANNERS admin access
GET /api/v1/configs/code_execution CONFIG_CODE_EXECUTION_READ admin security
POST /api/v1/configs/code_execution CONFIG_CODE_EXECUTION admin security
GET /api/v1/configs/connections CONFIG_CONNECTIONS_READ admin security
POST /api/v1/configs/connections CONFIG_CONNECTIONS admin security
GET /api/v1/configs/export CONFIG_EXPORT admin security
POST /api/v1/configs/import CONFIG_IMPORT admin security
POST /api/v1/configs/interface/visibility INTERFACE_VISIBILITY_UPDATE admin security
GET /api/v1/configs/models CONFIG_MODELS_READ admin security
POST /api/v1/configs/models CONFIG_MODELS admin security
GET /api/v1/configs/models/defaults CONFIG_MODELS_DEFAULTS_READ authenticated security
GET /api/v1/configs/namespace/{namespace} CONFIG_NAMESPACE_READ admin access
POST /api/v1/configs/oauth/clients/register CONFIG_OAUTH_CLIENT admin security
GET /api/v1/configs/subagents CONFIG_SUBAGENTS_READ admin security
POST /api/v1/configs/subagents CONFIG_SUBAGENTS admin access
POST /api/v1/configs/suggestions CONFIG_SUGGESTIONS admin access
GET /api/v1/configs/terminal_servers CONFIG_TERMINAL_SERVERS_READ admin security
POST /api/v1/configs/terminal_servers CONFIG_TERMINAL_SERVERS admin security
POST /api/v1/configs/terminal_servers/lifecycle CONFIG_TERMINAL_SERVERS_LIFECYCLE admin security
POST /api/v1/configs/terminal_servers/policy CONFIG_TERMINAL_SERVERS_POLICY admin security
POST /api/v1/configs/terminal_servers/refresh CONFIG_TERMINAL_SERVERS_REFRESH admin security
POST /api/v1/configs/terminal_servers/verify CONFIG_TERMINAL_SERVERS_VERIFY admin security
GET /api/v1/configs/tool_servers CONFIG_TOOL_SERVERS_READ admin security
POST /api/v1/configs/tool_servers CONFIG_TOOL_SERVERS admin security
POST /api/v1/configs/tool_servers/verify CONFIG_TOOL_SERVERS_VERIFY admin security
POST /api/v1/embeddings OLLAMA_EMBEDDINGS authenticated access
GET /api/v1/evaluations/config CONFIG_EVALUATIONS_READ admin security
POST /api/v1/evaluations/config CONFIG_EVALUATIONS admin security
POST /api/v1/evaluations/feedback EVAL_CREATE_FEEDBACK authenticated access
DELETE /api/v1/evaluations/feedback/{id} EVAL_DELETE_FEEDBACK authenticated access
GET /api/v1/evaluations/feedback/{id} EVAL_FEEDBACK_READ authenticated access
POST /api/v1/evaluations/feedback/{id} EVAL_UPDATE_FEEDBACK authenticated access
DELETE /api/v1/evaluations/feedbacks EVAL_DELETE_FEEDBACKS authenticated security
DELETE /api/v1/evaluations/feedbacks/all EVAL_DELETE_ALL_FEEDBACKS admin security
GET /api/v1/evaluations/feedbacks/all/export DATA_EXPORT admin security
GET /api/v1/evaluations/feedbacks/all/ids EVAL_FEEDBACK_IDS_READ admin access
GET /api/v1/evaluations/feedbacks/list EVAL_FEEDBACK_LIST_READ admin access
GET /api/v1/evaluations/feedbacks/models EVAL_FEEDBACK_MODELS_READ admin access
GET /api/v1/evaluations/feedbacks/user EVAL_USER_FEEDBACK_READ authenticated access
GET /api/v1/evaluations/leaderboard EVAL_LEADERBOARD_READ admin access
GET /api/v1/evaluations/leaderboard/{model_id:path}/history EVALUATION_LEADERBOARD_HISTORY_READ admin access
GET /api/v1/files/ FILE_LIST_READ authenticated access
POST /api/v1/files/ FILE_UPLOAD authenticated access
DELETE /api/v1/files/all FILE_DELETE_ALL admin security
GET /api/v1/files/count FILE_COUNT authenticated access
GET /api/v1/files/search FILES_SEARCH_READ authenticated access
GET /api/v1/files/user/count FILES_COUNT_READ authenticated access
GET /api/v1/files/user/search FILES_SEARCH_READ authenticated access
DELETE /api/v1/files/{id} FILE_DELETE authenticated access
GET /api/v1/files/{id} FILE_READ authenticated access
GET /api/v1/files/{id}/content FILE_CONTENT_READ authenticated access
GET /api/v1/files/{id}/content/html FILE_CONTENT_READ authenticated access
GET /api/v1/files/{id}/content/{file_name} FILE_CONTENT_READ authenticated access
GET /api/v1/files/{id}/data/content FILE_CONTENT_READ authenticated access
POST /api/v1/files/{id}/data/content/update FILE_CONTENT_UPDATE authenticated access
GET /api/v1/files/{id}/process/status FILE_PROCESS_STATUS_READ authenticated access
POST /api/v1/files/{id}/rename FILE_RENAME authenticated access
GET /api/v1/folders/ FOLDER_LIST_READ authenticated access
POST /api/v1/folders/ FOLDER_CREATE authenticated access
GET /api/v1/folders/shared FOLDER_SHARED_READ authenticated access
DELETE /api/v1/folders/{id} FOLDER_DELETE authenticated access
GET /api/v1/folders/{id} FOLDER_ACCESS_READ authenticated access
POST /api/v1/folders/{id}/access/update ACCESS_FOLDER_UPDATE authenticated security
POST /api/v1/folders/{id}/read FOLDER_READ authenticated access
GET /api/v1/folders/{id}/shared/chats FOLDER_SHARED_CHATS_READ authenticated access
POST /api/v1/folders/{id}/update FOLDER_UPDATE authenticated access
POST /api/v1/folders/{id}/update/expanded FOLDER_EXPANDED_UPDATE authenticated security
POST /api/v1/folders/{id}/update/parent FOLDER_MOVE authenticated access
GET /api/v1/functions/ FUNCTION_LIST_READ authenticated access
POST /api/v1/functions/create RESOURCE_CREATE_FUNCTION admin security
GET /api/v1/functions/export DATA_EXPORT admin security
GET /api/v1/functions/id/{id} FUNCTION_READ admin access
DELETE /api/v1/functions/id/{id}/delete RESOURCE_DELETE_FUNCTION admin security
GET /api/v1/functions/id/{id}/history WORKSPACE_HISTORY_READ admin access
GET /api/v1/functions/id/{id}/history/diff WORKSPACE_HISTORY_READ admin access
DELETE /api/v1/functions/id/{id}/history/{history_id} FUNCTION_HISTORY_DELETE admin security
GET /api/v1/functions/id/{id}/history/{history_id} WORKSPACE_HISTORY_READ admin access
POST /api/v1/functions/id/{id}/toggle RESOURCE_TOGGLE_FUNCTION admin access
POST /api/v1/functions/id/{id}/toggle/global RESOURCE_TOGGLE_FUNCTION_GLOBAL admin access
POST /api/v1/functions/id/{id}/update RESOURCE_UPDATE_FUNCTION admin security
POST /api/v1/functions/id/{id}/update/version FUNCTION_VERSION_RESTORE admin security
GET /api/v1/functions/id/{id}/valves FUNCTION_VALVES_READ admin access
GET /api/v1/functions/id/{id}/valves/spec FUNCTION_VALVES_SPEC_READ admin access
POST /api/v1/functions/id/{id}/valves/update RESOURCE_UPDATE_FUNCTION_VALVES admin access
GET /api/v1/functions/id/{id}/valves/user FUNCTION_USER_VALVES_READ authenticated access
GET /api/v1/functions/id/{id}/valves/user/spec FUNCTION_USER_VALVES_SPEC_READ authenticated access
POST /api/v1/functions/id/{id}/valves/user/update FUNCTION_USER_VALVES_UPDATE authenticated security
GET /api/v1/functions/list FUNCTION_LIST_READ admin access
POST /api/v1/functions/load/url RESOURCE_LOAD_FUNCTION_URL admin security
POST /api/v1/functions/sync RESOURCE_SYNC_FUNCTIONS admin access
GET /api/v1/groups/ GROUP_LIST_READ authenticated access
POST /api/v1/groups/create GROUP_CREATE admin security
GET /api/v1/groups/id/{id} GROUP_READ admin access
DELETE /api/v1/groups/id/{id}/delete GROUP_DELETE admin security
GET /api/v1/groups/id/{id}/export DATA_EXPORT admin security
GET /api/v1/groups/id/{id}/info GROUP_INFO_READ authenticated access
GET /api/v1/groups/id/{id}/members GROUP_MEMBERS_READ admin access
GET /api/v1/groups/id/{id}/preview GROUP_ACCESS_PREVIEW admin security
POST /api/v1/groups/id/{id}/update GROUP_UPDATE admin security
POST /api/v1/groups/id/{id}/users GROUP_MEMBERS_REPLACE admin security
POST /api/v1/groups/id/{id}/users/add GROUP_MEMBER_ADD admin security
POST /api/v1/groups/id/{id}/users/remove GROUP_MEMBER_REMOVE admin security
GET /api/v1/images/config CONFIG_IMAGES_READ admin security
POST /api/v1/images/config/update CONFIG_IMAGES admin security
POST /api/v1/images/edit IMAGE_EDIT authenticated security
POST /api/v1/images/generations IMAGE_GENERATE authenticated security
GET /api/v1/images/models IMAGE_MODELS_READ authenticated access
POST /api/v1/images/verify CONFIG_IMAGES_VERIFY admin security
GET /api/v1/knowledge/ KNOWLEDGE_LIST_READ authenticated access
POST /api/v1/knowledge/create KNOWLEDGE_CREATE authenticated access
GET /api/v1/knowledge/external/connections KNOWLEDGE_EXTERNAL_CONNECTION_LIST admin access
POST /api/v1/knowledge/external/connections KNOWLEDGE_EXTERNAL_CONNECTION_CREATE admin security
DELETE /api/v1/knowledge/external/connections/{id} KNOWLEDGE_EXTERNAL_CONNECTION_DELETE admin security
GET /api/v1/knowledge/external/connections/{id} KNOWLEDGE_EXTERNAL_CONNECTION_READ admin access
PATCH /api/v1/knowledge/external/connections/{id} KNOWLEDGE_EXTERNAL_CONNECTION_UPDATE admin security
POST /api/v1/knowledge/external/connections/{id}/retrieve-test KNOWLEDGE_EXTERNAL_CONNECTION_RETRIEVE_TEST admin access
POST /api/v1/knowledge/external/connections/{id}/test KNOWLEDGE_EXTERNAL_CONNECTION_TEST admin access
POST /api/v1/knowledge/external/knowledge/create KNOWLEDGE_EXTERNAL_KNOWLEDGE_CREATE admin security
POST /api/v1/knowledge/external/source/create KNOWLEDGE_EXTERNAL_SOURCE_CREATE admin security
POST /api/v1/knowledge/external/source/test KNOWLEDGE_EXTERNAL_SOURCE_TEST admin access
PATCH /api/v1/knowledge/external/source/{id} KNOWLEDGE_EXTERNAL_SOURCE_UPDATE admin security
POST /api/v1/knowledge/metadata/reindex KNOWLEDGE_REINDEX admin access
POST /api/v1/knowledge/reindex KNOWLEDGE_REINDEX authenticated access
GET /api/v1/knowledge/search KNOWLEDGE_SEARCH authenticated access
GET /api/v1/knowledge/search/files KNOWLEDGE_FILES_SEARCH authenticated access
GET /api/v1/knowledge/{id} KNOWLEDGE_READ authenticated access
POST /api/v1/knowledge/{id}/access/update ACCESS_KNOWLEDGE_UPDATE authenticated security
DELETE /api/v1/knowledge/{id}/delete KNOWLEDGE_DELETE authenticated security
POST /api/v1/knowledge/{id}/dirs/create KNOWLEDGE_DIR_CREATE authenticated security
DELETE /api/v1/knowledge/{id}/dirs/{dir_id}/delete KNOWLEDGE_DIR_DELETE authenticated security
POST /api/v1/knowledge/{id}/dirs/{dir_id}/update KNOWLEDGE_DIR_UPDATE authenticated security
GET /api/v1/knowledge/{id}/export DATA_EXPORT admin security
POST /api/v1/knowledge/{id}/file/add KNOWLEDGE_FILE_ADD authenticated access
POST /api/v1/knowledge/{id}/file/move KNOWLEDGE_FILE_MOVE authenticated security
POST /api/v1/knowledge/{id}/file/remove KNOWLEDGE_FILE_REMOVE authenticated access
POST /api/v1/knowledge/{id}/file/update KNOWLEDGE_FILE_UPDATE authenticated access
GET /api/v1/knowledge/{id}/files KNOWLEDGE_FILES_READ authenticated access
POST /api/v1/knowledge/{id}/files/batch/add KNOWLEDGE_FILE_ADD authenticated access
GET /api/v1/knowledge/{id}/files/pending KNOWLEDGE_FILES_PENDING authenticated access
POST /api/v1/knowledge/{id}/reset KNOWLEDGE_RESET authenticated security
POST /api/v1/knowledge/{id}/sync/cleanup KNOWLEDGE_SYNC_CLEANUP authenticated security
POST /api/v1/knowledge/{id}/sync/diff KNOWLEDGE_SYNC_DIFF authenticated security
POST /api/v1/knowledge/{id}/update KNOWLEDGE_UPDATE authenticated access
GET /api/v1/memories/ MEMORY_LIST_READ authenticated access
POST /api/v1/memories/add MEMORY_ADD authenticated access
DELETE /api/v1/memories/delete/user MEMORY_DELETE_ALL authenticated security
POST /api/v1/memories/path MEMORY_PATH authenticated access
POST /api/v1/memories/paths MEMORY_PATHS authenticated access
POST /api/v1/memories/query MEMORY_QUERY authenticated security
POST /api/v1/memories/reindex MEMORY_REINDEX admin security
POST /api/v1/memories/reset MEMORY_RESET authenticated security
POST /api/v1/memories/search MEMORY_SEARCH authenticated access
POST /api/v1/memories/update MEMORY_UPDATE_BULK authenticated access
DELETE /api/v1/memories/{memory_id} MEMORY_DELETE authenticated access
POST /api/v1/memories/{memory_id}/update MEMORY_UPDATE authenticated access
POST /api/v1/messages MESSAGE_GENERATE authenticated security
POST /api/v1/messages/count_tokens MESSAGE_TOKENS_COUNT authenticated security
GET /api/v1/models MODEL_LIST_READ authenticated access
GET /api/v1/models/all MODEL_LIST_ALL admin access
GET /api/v1/models/base MODEL_BASE_LIST_READ admin access
GET /api/v1/models/base/tags MODEL_BASE_TAGS_READ admin access
POST /api/v1/models/create RESOURCE_CREATE_MODEL authenticated access
DELETE /api/v1/models/delete/all RESOURCE_DELETE_ALL_MODELS admin security
GET /api/v1/models/export DATA_EXPORT authenticated security
POST /api/v1/models/import DATA_IMPORT authenticated security
GET /api/v1/models/list MODEL_LIST_READ authenticated access
GET /api/v1/models/model MODEL_READ authenticated access
POST /api/v1/models/model/access/update ACCESS_MODEL_UPDATE authenticated security
POST /api/v1/models/model/delete RESOURCE_DELETE_MODEL authenticated access
GET /api/v1/models/model/history WORKSPACE_HISTORY_READ authenticated access
DELETE /api/v1/models/model/history/{history_id} MODEL_HISTORY_DELETE authenticated security
GET /api/v1/models/model/history/{history_id} WORKSPACE_HISTORY_READ authenticated access
GET /api/v1/models/model/profile/image MODEL_IMAGE_READ authenticated access
POST /api/v1/models/model/toggle RESOURCE_TOGGLE_MODEL authenticated access
POST /api/v1/models/model/update RESOURCE_UPDATE_MODEL authenticated access
POST /api/v1/models/model/update/version MODEL_VERSION_RESTORE authenticated security
POST /api/v1/models/sync RESOURCE_SYNC_MODELS admin access
GET /api/v1/models/tags MODEL_TAGS_READ authenticated access
GET /api/v1/notes/ NOTE_LIST_READ authenticated access
POST /api/v1/notes/create NOTE_CREATE authenticated access
GET /api/v1/notes/pinned NOTE_PINNED_LIST_READ authenticated access
GET /api/v1/notes/search NOTE_SEARCH authenticated access
GET /api/v1/notes/{id} NOTE_READ authenticated access
POST /api/v1/notes/{id}/access/update ACCESS_NOTE_UPDATE authenticated security
GET /api/v1/notes/{id}/chat NOTE_CHAT_READ authenticated access
POST /api/v1/notes/{id}/chat NOTE_CHAT authenticated access
GET /api/v1/notes/{id}/chats NOTE_CHATS_READ authenticated access
DELETE /api/v1/notes/{id}/delete NOTE_DELETE authenticated access
POST /api/v1/notes/{id}/pin NOTE_PIN authenticated access
POST /api/v1/notes/{id}/update NOTE_UPDATE authenticated access
GET /api/v1/notifications/events NOTIFICATION_EVENTS_READ authenticated access
GET /api/v1/notifications/targets NOTIFICATION_TARGETS_READ authenticated access
POST /api/v1/notifications/targets NOTIFICATION_TARGET_CREATE authenticated access
DELETE /api/v1/notifications/targets/{target_id} NOTIFICATION_TARGET_DELETE authenticated access
PUT /api/v1/notifications/targets/{target_id} NOTIFICATION_TARGET_UPDATE authenticated access
PUT /api/v1/notifications/targets/{target_id}/default NOTIFICATION_TARGET_SET_DEFAULT authenticated access
POST /api/v1/notifications/targets/{target_id}/test NOTIFICATION_TARGET_TEST authenticated access
GET /api/v1/pipelines/ PIPELINE_LIST_READ admin access
POST /api/v1/pipelines/add PIPELINE_ADD admin security
DELETE /api/v1/pipelines/delete PIPELINE_DELETE admin security
GET /api/v1/pipelines/list PIPELINE_LIST_READ admin access
POST /api/v1/pipelines/upload PIPELINE_UPLOAD admin security
GET /api/v1/pipelines/{pipeline_id}/valves PIPELINE_VALVES_READ admin access
GET /api/v1/pipelines/{pipeline_id}/valves/spec PIPELINE_VALVES_SPEC_READ admin access
POST /api/v1/pipelines/{pipeline_id}/valves/update PIPELINE_VALVES_UPDATE admin security
GET /api/v1/prompts/ PROMPT_LIST_READ authenticated access
POST /api/v1/prompts/create RESOURCE_CREATE_PROMPT authenticated access
GET /api/v1/prompts/id/{prompt_id} PROMPT_READ authenticated access
POST /api/v1/prompts/id/{prompt_id}/access/update ACCESS_PROMPT_UPDATE authenticated security
DELETE /api/v1/prompts/id/{prompt_id}/delete RESOURCE_DELETE_PROMPT authenticated access
GET /api/v1/prompts/id/{prompt_id}/history WORKSPACE_HISTORY_READ authenticated access
GET /api/v1/prompts/id/{prompt_id}/history/diff WORKSPACE_HISTORY_READ authenticated access
DELETE /api/v1/prompts/id/{prompt_id}/history/{history_id} RESOURCE_DELETE_PROMPT_HISTORY authenticated access
GET /api/v1/prompts/id/{prompt_id}/history/{history_id} WORKSPACE_HISTORY_READ authenticated access
POST /api/v1/prompts/id/{prompt_id}/toggle RESOURCE_TOGGLE_PROMPT authenticated access
POST /api/v1/prompts/id/{prompt_id}/update RESOURCE_UPDATE_PROMPT authenticated access
POST /api/v1/prompts/id/{prompt_id}/update/meta RESOURCE_UPDATE_PROMPT_META authenticated access
POST /api/v1/prompts/id/{prompt_id}/update/version RESOURCE_UPDATE_PROMPT_VERSION authenticated access
GET /api/v1/prompts/list PROMPT_LIST_READ authenticated access
GET /api/v1/prompts/tags PROMPT_TAGS_READ authenticated access
GET /api/v1/retrieval/config CONFIG_RETRIEVAL_READ admin security
POST /api/v1/retrieval/config/update CONFIG_RETRIEVAL admin security
POST /api/v1/retrieval/delete RETRIEVAL_DELETE admin security
GET /api/v1/retrieval/embedding CONFIG_RETRIEVAL_EMBEDDING_READ admin security
POST /api/v1/retrieval/embedding/update CONFIG_RETRIEVAL_EMBEDDING admin security
POST /api/v1/retrieval/process/file RETRIEVAL_PROCESS_FILE authenticated security
POST /api/v1/retrieval/process/files/batch RETRIEVAL_PROCESS_FILES authenticated security
POST /api/v1/retrieval/process/text RETRIEVAL_PROCESS_TEXT authenticated security
POST /api/v1/retrieval/process/url RETRIEVAL_PROCESS_URL authenticated access
POST /api/v1/retrieval/process/web RETRIEVAL_PROCESS_WEB authenticated security
POST /api/v1/retrieval/process/web/search RETRIEVAL_PROCESS_WEB_SEARCH authenticated security
POST /api/v1/retrieval/process/youtube RETRIEVAL_PROCESS_YOUTUBE authenticated security
POST /api/v1/retrieval/query/collection RETRIEVAL_QUERY_COLLECTION authenticated security
POST /api/v1/retrieval/query/doc RETRIEVAL_QUERY_DOC authenticated security
POST /api/v1/retrieval/reset/db DATA_RESET_RETRIEVAL_DB admin security
POST /api/v1/retrieval/reset/uploads DATA_RESET_RETRIEVAL_UPLOADS admin security
GET /api/v1/scim/v2/Groups SCIM_GROUP_LIST_READ scim access
POST /api/v1/scim/v2/Groups SCIM_GROUP_CREATE scim security
DELETE /api/v1/scim/v2/Groups/{group_id} SCIM_GROUP_DELETE scim security
GET /api/v1/scim/v2/Groups/{group_id} SCIM_GROUP_READ scim access
PATCH /api/v1/scim/v2/Groups/{group_id} SCIM_GROUP_PATCH scim security
PUT /api/v1/scim/v2/Groups/{group_id} SCIM_GROUP_UPDATE scim security
GET /api/v1/scim/v2/ResourceTypes SCIM_RESOURCE_TYPES_READ public access
GET /api/v1/scim/v2/Schemas SCIM_SCHEMAS_READ public access
GET /api/v1/scim/v2/ServiceProviderConfig SCIM_PROVIDER_CONFIG_READ public access
GET /api/v1/scim/v2/Users SCIM_USER_LIST_READ scim access
POST /api/v1/scim/v2/Users SCIM_USER_CREATE scim security
DELETE /api/v1/scim/v2/Users/{user_id} SCIM_USER_DELETE scim security
GET /api/v1/scim/v2/Users/{user_id} SCIM_USER_READ scim access
PATCH /api/v1/scim/v2/Users/{user_id} SCIM_USER_PATCH scim security
PUT /api/v1/scim/v2/Users/{user_id} SCIM_USER_UPDATE scim security
GET /api/v1/search WORKSPACE_SEARCH_READ authenticated access
GET /api/v1/skills/ SKILL_LIST_READ authenticated access
POST /api/v1/skills/create RESOURCE_CREATE_SKILL authenticated security
GET /api/v1/skills/export DATA_EXPORT authenticated security
GET /api/v1/skills/id/{id} SKILL_READ authenticated access
POST /api/v1/skills/id/{id}/access/update ACCESS_SKILL_UPDATE authenticated security
POST /api/v1/skills/id/{id}/clone SKILL_CLONE authenticated security
DELETE /api/v1/skills/id/{id}/delete RESOURCE_DELETE_SKILL authenticated security
GET /api/v1/skills/id/{id}/files SKILL_FILE_READ authenticated access
GET /api/v1/skills/id/{id}/files/content SKILL_FILE_READ authenticated access
GET /api/v1/skills/id/{id}/history WORKSPACE_HISTORY_READ authenticated access
GET /api/v1/skills/id/{id}/history/diff WORKSPACE_HISTORY_READ authenticated access
GET /api/v1/skills/id/{id}/history/diff/file WORKSPACE_HISTORY_READ authenticated access
DELETE /api/v1/skills/id/{id}/history/{history_id} SKILL_HISTORY_DELETE authenticated security
GET /api/v1/skills/id/{id}/history/{history_id} WORKSPACE_HISTORY_READ authenticated access
POST /api/v1/skills/id/{id}/toggle RESOURCE_TOGGLE_SKILL authenticated access
POST /api/v1/skills/id/{id}/update RESOURCE_UPDATE_SKILL authenticated security
POST /api/v1/skills/id/{id}/update/version SKILL_VERSION_RESTORE authenticated security
POST /api/v1/skills/import SKILL_IMPORT authenticated security
POST /api/v1/skills/import/preview SKILL_IMPORT_PREVIEW authenticated security
GET /api/v1/skills/list SKILL_LIST_READ authenticated access
POST /api/v1/skills/load/url SKILL_URL_LOAD admin security
POST /api/v1/tasks/auto/completions TASK_AUTOCOMPLETE_GENERATE authenticated access
GET /api/v1/tasks/config CONFIG_TASKS_READ authenticated security
POST /api/v1/tasks/config/update CONFIG_TASKS admin security
POST /api/v1/tasks/emoji/completions TASK_EMOJI_GENERATE authenticated access
POST /api/v1/tasks/follow_up/completions TASK_FOLLOWUP_GENERATE authenticated access
POST /api/v1/tasks/image_prompt/completions TASK_IMAGE_PROMPT_GENERATE authenticated access
POST /api/v1/tasks/moa/completions TASK_MOA_GENERATE authenticated access
POST /api/v1/tasks/queries/completions TASK_QUERY_GENERATE authenticated access
POST /api/v1/tasks/tags/completions TASK_TAGS_GENERATE authenticated access
POST /api/v1/tasks/title/completions TASK_TITLE_GENERATE authenticated access
GET /api/v1/terminals/ TERMINAL_LIST_READ authenticated access
DELETE /api/v1/terminals/{server_id}/chats/{chat_id}/{path:path} TERMINAL_CHAT_PROXY_DELETE authenticated security
GET /api/v1/terminals/{server_id}/chats/{chat_id}/{path:path} TERMINAL_CHAT_PROXY_READ authenticated access
PATCH /api/v1/terminals/{server_id}/chats/{chat_id}/{path:path} TERMINAL_CHAT_PROXY_WRITE authenticated security
POST /api/v1/terminals/{server_id}/chats/{chat_id}/{path:path} TERMINAL_CHAT_PROXY_WRITE authenticated security
PUT /api/v1/terminals/{server_id}/chats/{chat_id}/{path:path} TERMINAL_CHAT_PROXY_WRITE authenticated security
DELETE /api/v1/terminals/{server_id}/{path:path} TERMINAL_PROXY_DELETE authenticated security
GET /api/v1/terminals/{server_id}/{path:path} TERMINAL_PROXY_READ authenticated access
PATCH /api/v1/terminals/{server_id}/{path:path} TERMINAL_PROXY_WRITE authenticated security
POST /api/v1/terminals/{server_id}/{path:path} TERMINAL_PROXY_WRITE authenticated security
PUT /api/v1/terminals/{server_id}/{path:path} TERMINAL_PROXY_WRITE authenticated security
GET /api/v1/tools/ TOOL_LIST_READ authenticated access
POST /api/v1/tools/create RESOURCE_CREATE_TOOL authenticated security
GET /api/v1/tools/export DATA_EXPORT authenticated security
GET /api/v1/tools/id/{id} TOOL_READ authenticated access
POST /api/v1/tools/id/{id}/access/update ACCESS_TOOL_UPDATE authenticated security
DELETE /api/v1/tools/id/{id}/delete RESOURCE_DELETE_TOOL authenticated security
GET /api/v1/tools/id/{id}/history WORKSPACE_HISTORY_READ authenticated access
GET /api/v1/tools/id/{id}/history/diff WORKSPACE_HISTORY_READ authenticated access
DELETE /api/v1/tools/id/{id}/history/{history_id} TOOL_HISTORY_DELETE authenticated security
GET /api/v1/tools/id/{id}/history/{history_id} WORKSPACE_HISTORY_READ authenticated access
GET /api/v1/tools/id/{id}/specs TOOL_SPECS_READ authenticated access
POST /api/v1/tools/id/{id}/update RESOURCE_UPDATE_TOOL authenticated security
POST /api/v1/tools/id/{id}/update/version TOOL_VERSION_RESTORE authenticated security
GET /api/v1/tools/id/{id}/valves TOOL_VALVES_READ authenticated access
GET /api/v1/tools/id/{id}/valves/spec TOOL_VALVES_SPEC_READ authenticated access
POST /api/v1/tools/id/{id}/valves/update RESOURCE_UPDATE_TOOL_VALVES authenticated access
GET /api/v1/tools/id/{id}/valves/user TOOL_USER_VALVES_READ authenticated access
GET /api/v1/tools/id/{id}/valves/user/spec TOOL_USER_VALVES_SPEC_READ authenticated access
POST /api/v1/tools/id/{id}/valves/user/update TOOL_USER_VALVES_UPDATE authenticated security
GET /api/v1/tools/list TOOL_LIST_READ authenticated access
POST /api/v1/tools/load/url RESOURCE_LOAD_TOOL_URL admin security
GET /api/v1/users/ USER_LIST_READ admin access
GET /api/v1/users/all USER_LIST_ALL_READ admin access
GET /api/v1/users/default/permissions USER_PERMISSIONS_DEFAULT_READ admin access
POST /api/v1/users/default/permissions USER_PERMISSIONS_DEFAULT admin security
GET /api/v1/users/default/permissions/defaults USER_PERMISSIONS_DEFAULTS_READ admin access
GET /api/v1/users/groups USER_OWN_GROUPS_READ authenticated access
GET /api/v1/users/permissions USER_PERMISSIONS_READ authenticated access
GET /api/v1/users/search USER_SEARCH authenticated access
GET /api/v1/users/usage USER_USAGE_READ authenticated access
GET /api/v1/users/user/info USER_INFO_READ authenticated access
POST /api/v1/users/user/info/update USER_INFO_UPDATE authenticated access
GET /api/v1/users/user/settings USER_SETTINGS_READ authenticated access
POST /api/v1/users/user/settings/update USER_SETTINGS_UPDATE authenticated access
GET /api/v1/users/user/status USER_STATUS_READ authenticated access
POST /api/v1/users/user/status/update USER_STATUS_UPDATE authenticated access
GET /api/v1/users/user/variables USER_VARIABLES_READ authenticated access
POST /api/v1/users/user/variables/update USER_VARIABLES_UPDATE authenticated access
DELETE /api/v1/users/{user_id} USER_DELETE admin security
GET /api/v1/users/{user_id} USER_READ admin access
GET /api/v1/users/{user_id}/active USER_ACTIVE_READ authenticated access
GET /api/v1/users/{user_id}/groups USER_GROUPS_READ admin access
GET /api/v1/users/{user_id}/info USER_INFO_READ authenticated access
GET /api/v1/users/{user_id}/oauth/sessions USER_OAUTH_SESSIONS_VIEW admin access
GET /api/v1/users/{user_id}/preview USER_ACCESS_PREVIEW admin security
GET /api/v1/users/{user_id}/profile/image USER_IMAGE_READ authenticated access
POST /api/v1/users/{user_id}/sessions/revoke AUTH_SESSIONS_REVOKE admin security
POST /api/v1/users/{user_id}/update USER_UPDATE admin security
POST /api/v1/utils/code/execute CODE_EXECUTE authenticated security
POST /api/v1/utils/code/format CODE_FORMAT admin security
GET /api/v1/utils/db/download DATA_EXPORT admin security
GET /api/v1/utils/gravatar USER_GRAVATAR_READ authenticated access
GET /api/version SYSTEM_VERSION_READ public access
GET /api/version/updates SYSTEM_VERSION_UPDATES_READ authenticated access
GET /cache/{path:path} CACHE_FILE_READ authenticated access
POST /oauth/backchannel-logout AUTH_LOGOUT protocol security
GET /oauth/clients/{client_id}/authorize AUTH_OAUTH_AUTHORIZE authenticated security
GET /oauth/clients/{client_id}/callback OAUTH_CLIENT_AUTHORIZE protocol security
GET /oauth/{provider}/callback AUTH_OIDC_LOGIN protocol security
GET /oauth/{provider}/login AUTH_OIDC_START protocol security
GET /oauth/{provider}/login/callback AUTH_OIDC_LOGIN protocol security
GET /ollama/ OLLAMA_STATUS_READ public access
POST /ollama/api/chat OLLAMA_CHAT authenticated security
POST /ollama/api/chat/{url_idx} OLLAMA_CHAT authenticated security
POST /ollama/api/copy OLLAMA_MODEL_COPY admin security
POST /ollama/api/copy/{url_idx} OLLAMA_MODEL_COPY admin security
POST /ollama/api/create OLLAMA_MODEL_CREATE admin security
POST /ollama/api/create/{url_idx} OLLAMA_MODEL_CREATE admin security
DELETE /ollama/api/delete OLLAMA_MODEL_DELETE admin security
DELETE /ollama/api/delete/{url_idx} OLLAMA_MODEL_DELETE admin security
POST /ollama/api/embed OLLAMA_EMBEDDINGS authenticated access
POST /ollama/api/embed/{url_idx} OLLAMA_EMBEDDINGS authenticated access
POST /ollama/api/embeddings OLLAMA_EMBEDDINGS authenticated access
POST /ollama/api/embeddings/{url_idx} OLLAMA_EMBEDDINGS authenticated access
POST /ollama/api/generate OLLAMA_GENERATE authenticated security
POST /ollama/api/generate/{url_idx} OLLAMA_GENERATE authenticated security
GET /ollama/api/ps OLLAMA_MODELS_RUNNING_READ admin access
POST /ollama/api/pull OLLAMA_MODEL_PULL admin security
POST /ollama/api/pull/{url_idx} OLLAMA_MODEL_PULL admin security
DELETE /ollama/api/push OLLAMA_MODEL_PUSH admin security
DELETE /ollama/api/push/{url_idx} OLLAMA_MODEL_PUSH admin security
POST /ollama/api/show OLLAMA_MODEL_READ authenticated security
GET /ollama/api/tags OLLAMA_TAGS_READ authenticated access
GET /ollama/api/tags/{url_idx} OLLAMA_COMPAT_TAGS_READ admin access
POST /ollama/api/unload OLLAMA_MODEL_UNLOAD admin security
GET /ollama/api/version OLLAMA_VERSION_READ authenticated access
GET /ollama/api/version/{url_idx} OLLAMA_COMPAT_VERSION_READ admin access
GET /ollama/config CONFIG_OLLAMA_READ admin security
POST /ollama/config/update CONFIG_OLLAMA_UPDATE admin security
POST /ollama/models/download OLLAMA_MODEL_DOWNLOAD admin security
POST /ollama/models/download/{url_idx} OLLAMA_MODEL_DOWNLOAD admin security
POST /ollama/models/upload OLLAMA_MODEL_UPLOAD admin security
POST /ollama/models/upload/{url_idx} OLLAMA_MODEL_UPLOAD admin security
POST /ollama/v1/chat/completions OLLAMA_CHAT authenticated security
POST /ollama/v1/chat/completions/{url_idx} OLLAMA_CHAT authenticated security
POST /ollama/v1/completions OLLAMA_GENERATE authenticated security
POST /ollama/v1/completions/{url_idx} OLLAMA_GENERATE authenticated security
POST /ollama/v1/embeddings OLLAMA_EMBEDDINGS authenticated access
POST /ollama/v1/embeddings/{url_idx} OLLAMA_EMBEDDINGS authenticated access
POST /ollama/v1/messages OLLAMA_MESSAGES authenticated security
POST /ollama/v1/messages/{url_idx} OLLAMA_MESSAGES authenticated security
GET /ollama/v1/models OLLAMA_MODELS_READ authenticated access
GET /ollama/v1/models/{url_idx} OLLAMA_COMPAT_MODELS_READ admin access
POST /ollama/v1/responses OLLAMA_RESPONSES authenticated security
POST /ollama/v1/responses/{url_idx} OLLAMA_RESPONSES authenticated security
POST /ollama/verify CONFIG_OLLAMA_VERIFY admin security
POST /openai/audio/speech OPENAI_SPEECH authenticated security
POST /openai/chat/completions OPENAI_CHAT authenticated security
GET /openai/config CONFIG_OPENAI_READ admin security
POST /openai/config/update CONFIG_OPENAI_UPDATE admin security
GET /openai/models OPENAI_MODELS_READ authenticated access
DELETE /openai/models/{url_idx} MODEL_PROVIDER_DELETE admin security
GET /openai/models/{url_idx} MODEL_PROVIDER_LIST admin access
GET /openai/models/{url_idx}/catalog MODEL_PROVIDER_CATALOG admin access
POST /openai/models/{url_idx}/download MODEL_PROVIDER_DOWNLOAD admin security
GET /openai/models/{url_idx}/download/status/{job_id} MODEL_PROVIDER_DOWNLOAD_STATUS admin access
POST /openai/models/{url_idx}/load MODEL_PROVIDER_LOAD admin security
GET /openai/models/{url_idx}/sse MODEL_PROVIDER_SSE admin access
POST /openai/models/{url_idx}/unload MODEL_PROVIDER_UNLOAD admin security
POST /openai/responses OPENAI_RESPONSES authenticated security
POST /openai/verify CONFIG_OPENAI_VERIFY admin security
DELETE /openai/{path:path} OPENAI_PROXY_DELETE authenticated security
GET /openai/{path:path} OPENAI_PROXY_READ authenticated access
POST /openai/{path:path} OPENAI_PROXY_WRITE authenticated security
PUT /openai/{path:path} OPENAI_PROXY_WRITE authenticated security
"""

ROUTE_POLICIES = {}
for _row in _CATALOG.splitlines():
    _method, _path, _action, _actor, _severity = _row.split()
    assert (_method, _path) not in ROUTE_POLICIES
    ROUTE_POLICIES[(_method, _path)] = RoutePolicy(_action, _actor, _severity == 'security')

# Prefer literal routes over parameters and ordinary parameters over path
# converters, just as the mounted routers do for their reserved subpaths.
_MATCHERS = [
    (method, path, compile_path(path.rstrip('/') or '/')[0], policy)
    for (method, path), policy in sorted(
        ROUTE_POLICIES.items(),
        key=lambda item: (
            ':path}' in item[0][1],
            -sum(len(segment) for segment in item[0][1].split('/') if '{' not in segment),
            item[0][1].count('{'),
        ),
    )
]


def match_route_policy(method: str, path: str) -> RoutePolicy | None:
    path = path.rstrip('/') or '/'
    return next(
        (policy for verb, _, pattern, policy in _MATCHERS if verb == method.upper() and pattern.fullmatch(path)),
        None,
    )


def audit_route_template(method: str, path: str) -> str:
    """Never put embedded credentials or arbitrary proxy paths in an audit URI."""
    path = path.rstrip('/') or '/'
    return next(
        (template for verb, template, pattern, _ in _MATCHERS if verb == method.upper() and pattern.fullmatch(path)),
        '[unmatched]',
    )
