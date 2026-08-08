"""login_with_credentials 对自动签到 provider 的退出重登回归测试。

背景:agentrouter 这类 sign_in_path=None 的 provider,签到是重新登录的副作用。
persist_profile=True 会复用持久化 profile 里的旧 session cookie 和 localStorage token,
导致 is_logged_in() 短路重新登录,签到永远不触发(余额长期不变)。修复方案:对这类
provider 在登录页加载后执行 force_logout(清 session cookie + localStorage,保留 WAF
cookie),重新导航登录页并无条件走邮箱重新登录。
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
		self.localStorage_cleared = False
		self.sessionStorage_cleared = False

	async def evaluate(self, expression):
		if 'localStorage.clear' in expression:
			self.localStorage_cleared = True
			self.sessionStorage_cleared = True
		return None

	async def reload(self, wait_until=None, timeout=None):
		pass


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
		return any(c.get('name') == 'session' and c.get('value') for c in page.context._cookies)

	async def fake_force_logout(page):
		calls.append('force_logout')
		await page.context.clear_cookies(name='session')
		try:
			await page.evaluate('() => { localStorage.clear(); sessionStorage.clear(); }')
		except Exception:
			pass

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
	monkeypatch.setattr(checkin, 'force_logout', fake_force_logout)
	monkeypatch.setattr(checkin, 'is_logged_in', fake_is_logged_in)
	monkeypatch.setattr(checkin, 'save_login_screenshot', fake_save_login_screenshot)
	monkeypatch.setattr(checkin, 'login_with_email_form', fake_login_with_email_form)
	monkeypatch.setattr(checkin, 'verify_browser_login', fake_verify_browser_login)
	monkeypatch.setattr(checkin, 'load_browser_login_settings', fake_load_settings)
	return calls


@pytest.mark.asyncio
async def test_auto_checkin_provider_forces_relogin_with_stale_session(stub_browser_flow):
	"""sign_in_path=None 且有旧 session 时必须 force_logout 后重新登录。"""
	calls = stub_browser_flow
	provider = _provider(sign_in_path=None, persist_profile=True)

	result = await checkin.login_with_credentials('acct', provider, 'agentrouter', 'e@x.com', 'pw')

	assert result is not None
	assert result.api_user == '123'
	# force_logout 发生在重新登录之前
	assert 'force_logout' in calls
	assert calls.index('force_logout') < calls.index('login_with_email_form')
	assert 'login_with_email_form' in calls


@pytest.mark.asyncio
async def test_auto_checkin_provider_no_session_skips_force_logout(stub_browser_flow, monkeypatch):
	"""没有旧 session cookie 时不调用 force_logout。"""

	async def fake_launch_no_session(settings, *, use_proxy=False):
		return FakeContext([{'name': 'acw_tc', 'value': 'waf-value'}])

	monkeypatch.setattr(checkin, 'launch_login_context', fake_launch_no_session)

	calls = stub_browser_flow
	provider = _provider(sign_in_path=None, persist_profile=True)

	await checkin.login_with_credentials('acct', provider, 'agentrouter', 'e@x.com', 'pw')

	assert 'force_logout' not in calls
	assert 'login_with_email_form' in calls


@pytest.mark.asyncio
async def test_manual_checkin_provider_preserves_session(stub_browser_flow):
	"""sign_in_path 有值的 provider(如手动签到)不执行 force_logout。"""
	calls = stub_browser_flow
	provider = _provider(sign_in_path='/api/user/sign_in', persist_profile=True)

	await checkin.login_with_credentials('acct', provider, 'agentrouter', 'e@x.com', 'pw')

	assert 'force_logout' not in calls


@pytest.mark.asyncio
async def test_force_logout_clears_local_and_session_storage():
	"""force_logout 必须清除 session cookie + localStorage + sessionStorage。"""
	from utils.browser import force_logout

	ctx = FakeContext(
		[
			{'name': 'acw_tc', 'value': 'waf-value'},
			{'name': 'session', 'value': 'stale-session-value'},
		]
	)
	page = await ctx.new_page()

	await force_logout(page)

	# session cookie 被清,WAF cookie 保留
	names = [c.get('name') for c in ctx._cookies]
	assert 'session' not in names
	assert 'acw_tc' in names
	# localStorage / sessionStorage 被清
	assert page.localStorage_cleared is True
	assert page.sessionStorage_cleared is True


@pytest.mark.asyncio
async def test_force_logout_preserves_waf_cookies(stub_browser_flow):
	"""force_logout 后,WAF cookie(acw_tc)仍保留在最终 cookies 中。"""
	calls = stub_browser_flow
	provider = _provider(sign_in_path=None, persist_profile=True)

	result = await checkin.login_with_credentials('acct', provider, 'agentrouter', 'e@x.com', 'pw')

	assert result is not None
	assert result.cookies.get('acw_tc') == 'waf-value'
	assert result.cookies.get('session') == 'fresh-session-value'
