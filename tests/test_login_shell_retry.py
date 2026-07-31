"""登录页渲染重试与 WAF 拦截文本识别的回归测试。

背景：agentrouter 的 WAF 滑块验证页会间歇性替换登录页内容，此时 readyState 已是
complete，因此依赖长超时无效，只能靠更多次重试命中未被拦截的窗口。
"""

import asyncio

import pytest

from utils import browser
from utils.browser import (
	_LOGIN_SHELL_READY_JS,
	_SITE_READY_JS,
	LOGIN_SHELL_MAX_ATTEMPTS,
	LOGIN_SHELL_TIMEOUT_MS,
	navigate_login_page,
)

LOGIN_URL = 'https://agentrouter.org/login'

# 实测到的阿里云 WAF 拦截页文案，中英双语各取一例。
WAF_BLOCKED_TEXTS = (
	'请进行验证',
	'为了更好的访问体验',
	'访问受限',
	'滑动完成验证',
	'Access denied',
	'verify you are human',
	'Access Verification',
	'please slide to verify',
)


class FakePage:
	"""按指定尝试次数才渲染出登录页的伪 Page。

	ready_on_attempt 为 None 时表示始终被 WAF 拦截。
	"""

	def __init__(self, ready_on_attempt: int | None):
		self.ready_on_attempt = ready_on_attempt
		self.goto_urls: list[str] = []
		self.reload_count = 0
		self.shell_wait_timeouts: list[int] = []
		self.screenshot_labels: list[str] = []

	@property
	def login_attempts(self) -> int:
		"""登录页导航次数（仅 goto 计入，预热与 reload 不计入）。"""
		return len([url for url in self.goto_urls if url == LOGIN_URL])

	def _is_ready(self) -> bool:
		if self.ready_on_attempt is None:
			return False
		return self.login_attempts >= self.ready_on_attempt

	async def goto(self, url, wait_until=None, timeout=None):
		self.goto_urls.append(url)

	async def reload(self, wait_until=None, timeout=None):
		"""reload 重新加载当前登录页，本身不产生新的 goto 计数。"""
		self.reload_count += 1

	async def wait_for_load_state(self, state, timeout=None):
		return None

	async def wait_for_function(self, expression, timeout=None):
		if expression == _LOGIN_SHELL_READY_JS:
			self.shell_wait_timeouts.append(timeout)
		if not self._is_ready():
			raise TimeoutError('shell not ready')
		return True

	async def evaluate(self, expression):
		if expression in (_LOGIN_SHELL_READY_JS, _SITE_READY_JS):
			return self._is_ready()
		# _log_login_page_state 的探测脚本
		return {'url': LOGIN_URL, 'readyState': 'complete'}

	async def screenshot(self, path=None, full_page=None, timeout=None):
		return None


@pytest.fixture(autouse=True)
def _stub_slow_paths(monkeypatch):
	"""消除重试等待并隔离弹窗处理，使测试无需真实浏览器。"""

	async def instant_sleep(seconds):
		return None

	async def no_popups(page):
		return 0

	monkeypatch.setattr(asyncio, 'sleep', instant_sleep)
	monkeypatch.setattr(browser, 'dismiss_popups', no_popups)
	monkeypatch.delenv('DEBUG_MODE', raising=False)


@pytest.mark.parametrize('blocked_text', WAF_BLOCKED_TEXTS)
def test_waf_blocked_pattern_covers_observed_texts(blocked_text):
	"""中英文拦截文案都必须被同一份正则覆盖，否则拦截页会被误判为已渲染。"""
	assert blocked_text.lower() in browser._WAF_BLOCKED_TEXT_JS.lower() or any(
		fragment and fragment.lower() in blocked_text.lower()
		for fragment in browser._WAF_BLOCKED_TEXT_JS.strip('/i').split('|')
	)


def test_ready_js_shares_single_blocked_pattern():
	"""两处检测脚本必须复用同一份拦截文本正则，避免只改一处。"""
	assert browser._WAF_BLOCKED_TEXT_JS in _SITE_READY_JS
	assert browser._WAF_BLOCKED_TEXT_JS in _LOGIN_SHELL_READY_JS


async def test_navigate_login_page_returns_on_first_ready_attempt():
	page = FakePage(ready_on_attempt=1)

	await navigate_login_page(page, LOGIN_URL, 60_000)

	assert page.login_attempts == 1
	assert page.reload_count == 0


async def test_navigate_login_page_recovers_after_third_attempt():
	"""第 4 次才渲染成功的场景：旧实现只重试 3 次会直接失败。"""
	page = FakePage(ready_on_attempt=4)

	await navigate_login_page(page, LOGIN_URL, 60_000)

	assert page.login_attempts == 4


async def test_navigate_login_page_exhausts_all_attempts_before_failing():
	page = FakePage(ready_on_attempt=None)

	with pytest.raises(TimeoutError):
		await navigate_login_page(page, LOGIN_URL, 60_000)

	assert page.login_attempts == LOGIN_SHELL_MAX_ATTEMPTS
	# 末次失败后不应再重载，避免无谓等待。
	assert page.reload_count == LOGIN_SHELL_MAX_ATTEMPTS - 1


async def test_shell_wait_uses_short_timeout_even_when_caller_allows_more():
	"""调用方给出 60s 预算时仍按较短超时等待，以换取更多重试次数。"""
	page = FakePage(ready_on_attempt=None)

	with pytest.raises(TimeoutError):
		await navigate_login_page(page, LOGIN_URL, 60_000)

	assert page.shell_wait_timeouts
	assert set(page.shell_wait_timeouts) == {LOGIN_SHELL_TIMEOUT_MS}
