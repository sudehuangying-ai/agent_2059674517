"""login_with_credentials 对自动签到 provider 的退出重登回归测试。

背景:agentrouter 这类 sign_in_path=None 的 provider,签到是重新登录的副作用。
persist_profile=True 会复用持久化 profile 里的旧 session cookie,导致 is_logged_in()
短路重新登录,签到永远不触发。修复方案:对这类 provider 在登录页加载后清除 session
cookie(保留 WAF cookie),强制走邮箱重新登录。
"""

import pytest

import checkin
from utils.config import ProviderConfig


class FakeContext:
	def __init__(self, cookies):
		self._cookies = cookies
		self.closed = False
		self.cookie_names_cleared = []

	async def new_page(self):
		return FakePage(self)

	async def cookies(self):
		return [dict(c) for c in self._cookies]

	async def clear_cookies(self, *, name=None):
		self.cookie_names_cleared.append(name)
		self._cookies = [c for c in self._cookies if c.get('name') != name]

	async def close(self):
		self.closed = True


class FakePage:
	def __init__(self, context):
		self.context = context
		self.url = 'https://agentrouter.org/login'
		self.reloaded = 0

	async def reload(self, wait_until=None, timeout=None):
		self.reloaded += 1


def _provider(*, sign_in_path, persist_profile=True):
	return ProviderConfig(
		name='agentrouter',
		domain='https://agentrouter.org',
		login_path='/login',
		sign_in_path=sign_in_path,
		user_info_path='/api/user/self',
		api_user_key='new-api-user',
		bypass_method='waf_cookies',
		waf_cookie_names=['acw_tc'],
		use_proxy=True,
		persist_profile=persist_profile,
	)


@pytest.fixture
def stub_browser_flow(monkeypatch, tmp_path):
	"""桩掉浏览器交互,记录调用顺序;返回一个共享的 calls 列表。"""
	calls = []

	class FakeSettings:
		headless = True
		humanize = False
		wait_timeout_ms = 1000
		profile_dir = tmp_path / 'profile'
		cloakbrowser_binary_path = None
		persist_profile = True

	async def fake_launch_login_context(settings, *, use_proxy=False):
		calls.append('launch_login_context')
		# 初始 cookies:既有 WAF cookie,也有 stale session cookie
		return FakeContext(
			[
				{'name': 'acw_tc', 'value': 'waf-value'},
				{'name': 'session', 'value': 'stale-session-value'},
			]
		)

	async def fake_prepare_browser_page(page):
		calls.append('prepare_browser_page')

	async def fake_navigate_login_page(page, login_url, timeout_ms, *, provider='', account_name=''):
		calls.append('navigate_login_page')

	async def fake_has_session_cookie(page):
		# 反映 context 当前真实 cookie 状态
		return any(c.get('name') == 'session' and c.get('value') for c in page.context._cookies)

	async def fake_clear_session_cookie(page):
		calls.append('clear_session_cookie')
		await page.context.clear_cookies(name='session')

	async def fake_is_logged_in(page):
		calls.append('is_logged_in')
		return False

	async def fake_save_login_screenshot(page, provider, account_name, label):
		calls.append(f'screenshot:{label}')

	async def fake_login_with_email_form(page, email, password, timeout_ms, *, provider='', account_name=''):
		calls.append('login_with_email_form')
		# 模拟登录成功后写入新 session cookie
		page.context._cookies.append({'name': 'session', 'value': 'fresh-session-value'})

	async def fake_verify_browser_login(page, console_url, timeout_ms):
		calls.append('verify_browser_login')
		return {'id': 123, 'username': 'tester'}

	def fake_load_settings(account_name, provider, *, persist_profile=True):
		return FakeSettings()

	monkeypatch.setattr(checkin, 'launch_login_context', fake_launch_login_context)
	monkeypatch.setattr(checkin, 'prepare_browser_page', fake_prepare_browser_page)
	monkeypatch.setattr(checkin, 'navigate_login_page', fake_navigate_login_page)
	monkeypatch.setattr(checkin, 'has_session_cookie', fake_has_session_cookie)
	monkeypatch.setattr(checkin, 'clear_session_cookie', fake_clear_session_cookie)
	monkeypatch.setattr(checkin, 'is_logged_in', fake_is_logged_in)
	monkeypatch.setattr(checkin, 'save_login_screenshot', fake_save_login_screenshot)
	monkeypatch.setattr(checkin, 'login_with_email_form', fake_login_with_email_form)
	monkeypatch.setattr(checkin, 'verify_browser_login', fake_verify_browser_login)
	monkeypatch.setattr(checkin, 'load_browser_login_settings', fake_load_settings)
	return calls


@pytest.mark.asyncio
async def test_auto_checkin_provider_clears_stale_session(stub_browser_flow):
	"""sign_in_path=None 的 provider 必须清除旧 session 并重新登录。"""
	calls = stub_browser_flow
	provider = _provider(sign_in_path=None, persist_profile=True)

	result = await checkin.login_with_credentials('acct', provider, 'agentrouter', 'e@x.com', 'pw')

	assert result is not None
	assert result.api_user == '123'
	# 清除发生在重新登录之前
	assert 'clear_session_cookie' in calls
	assert calls.index('clear_session_cookie') < calls.index('login_with_email_form')
	assert 'login_with_email_form' in calls


@pytest.mark.asyncio
async def test_auto_checkin_provider_no_session_skips_clear(stub_browser_flow, monkeypatch):
	"""没有旧 session cookie 时不调用 clear_session_cookie(避免多余 reload)。"""

	# 覆盖 fake_launch_login_context:初始只有 WAF cookie,无 session
	async def fake_launch_no_session(settings, *, use_proxy=False):
		return FakeContext([{'name': 'acw_tc', 'value': 'waf-value'}])

	monkeypatch.setattr(checkin, 'launch_login_context', fake_launch_no_session)

	calls = stub_browser_flow
	provider = _provider(sign_in_path=None, persist_profile=True)

	await checkin.login_with_credentials('acct', provider, 'agentrouter', 'e@x.com', 'pw')

	assert 'clear_session_cookie' not in calls
	assert 'login_with_email_form' in calls


@pytest.mark.asyncio
async def test_manual_checkin_provider_preserves_session(stub_browser_flow):
	"""sign_in_path 有值的 provider(如手动签到)不清除 session,保持原行为。"""
	calls = stub_browser_flow
	provider = _provider(sign_in_path='/api/user/sign_in', persist_profile=True)

	await checkin.login_with_credentials('acct', provider, 'agentrouter', 'e@x.com', 'pw')

	assert 'clear_session_cookie' not in calls


@pytest.mark.asyncio
async def test_clear_session_cookie_preserves_waf_cookies(stub_browser_flow):
	"""清除 session 后,WAF cookie(acw_tc)仍保留在 context 中。"""
	calls = stub_browser_flow
	provider = _provider(sign_in_path=None, persist_profile=True)

	result = await checkin.login_with_credentials('acct', provider, 'agentrouter', 'e@x.com', 'pw')

	assert result is not None
	# 结果 cookies 里应同时包含 WAF cookie 和登录后的新 session
	assert result.cookies.get('acw_tc') == 'waf-value'
	assert result.cookies.get('session') == 'fresh-session-value'
