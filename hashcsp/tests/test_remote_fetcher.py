"""Unit-tests for `RemoteFetcher.fetch_remote_site`.

No real browser is launched.  A fully-stubbed Playwright tree plus the
`_AsyncContext` helper lets `async with async_playwright()` work as expected.
"""

from __future__ import annotations

import logging
from unittest.mock import AsyncMock, MagicMock

import pytest

from hashcsp.core.csp_generator import CSPGenerator
from hashcsp.core.remote_fetcher import RemoteFetcher


# --------------------------------------------------------------------------- #
# Helper: turn a plain object into an async context-manager
# --------------------------------------------------------------------------- #
class _AsyncContext:
    def __init__(self, obj):
        self._obj = obj

    async def __aenter__(self):
        return self._obj

    async def __aexit__(self, exc_type, exc, tb):
        return False  # propagate exceptions


# --------------------------------------------------------------------------- #
# Fixtures
# --------------------------------------------------------------------------- #
@pytest.fixture
def csp_generator() -> CSPGenerator:
    return CSPGenerator()


@pytest.fixture
def fetcher(csp_generator: CSPGenerator) -> RemoteFetcher:
    return RemoteFetcher(csp_generator)


@pytest.fixture
def mock_playwright() -> AsyncMock:
    """Return a fully-stubbed Playwright hierarchy."""
    # leaf page --------------------------------------------------------------
    page = AsyncMock(name="page")
    # - default goto() gives a response with a CSP header
    response = MagicMock()
    response.all_headers = AsyncMock(
        return_value={"content-security-policy": "script-src 'self'"}
    )
    page.goto = AsyncMock(return_value=response)
    page.content = AsyncMock(
        return_value="""
            <html>
              <script>console.log('x');</script>
              <style>body{color:red}</style>
            </html>
        """
    )
    page.evaluate = AsyncMock()
    page.wait_for_timeout = AsyncMock()
    page.wait_for_load_state = AsyncMock()
    page.query_selector_all = AsyncMock(return_value=[])
    page.context.request.get = AsyncMock(
        return_value=MagicMock(text=AsyncMock(return_value=""))
    )
    page.on = MagicMock(side_effect=lambda *_: None)

    # browser → context → page ----------------------------------------------
    context = AsyncMock(name="context")
    context.new_page = AsyncMock(return_value=page)

    browser = AsyncMock(name="browser")
    browser.new_context = AsyncMock(return_value=context)

    # root playwright object -------------------------------------------------
    pw_root = AsyncMock(name="pw_root")
    pw_root.chromium.launch = AsyncMock(return_value=browser)
    return pw_root


# convenience for patching ---------------------------------------------------
def _patch_playwright(monkeypatch: pytest.MonkeyPatch, pw: AsyncMock) -> None:
    monkeypatch.setattr(
        "hashcsp.core.remote_fetcher.async_playwright",
        lambda: _AsyncContext(pw),
    )


# --------------------------------------------------------------------------- #
# 1. Happy-path
# --------------------------------------------------------------------------- #
@pytest.mark.asyncio
async def test_fetch_remote_site_success(
    fetcher: RemoteFetcher,
    csp_generator: CSPGenerator,
    mock_playwright: AsyncMock,
    monkeypatch: pytest.MonkeyPatch,
    caplog: pytest.LogCaptureFixture,
):
    _patch_playwright(monkeypatch, mock_playwright)

    with caplog.at_level(logging.INFO):
        success, csp_header = await fetcher.fetch_remote_site(
            url="https://example.com", wait_time=1, interaction_level=0, retries=0
        )

    assert success is True
    assert csp_header == "script-src 'self'"
    assert csp_generator.stats["unique_script_hashes"] == 1
    assert csp_generator.stats["unique_style_hashes"] == 1
    assert csp_generator.stats["external_scripts"] == 0
    assert "Added script hash" in caplog.text
    assert "Added style hash" in caplog.text


# --------------------------------------------------------------------------- #
# 2. No CSP header
# --------------------------------------------------------------------------- #
@pytest.mark.asyncio
async def test_fetch_remote_site_no_csp_header(
    fetcher: RemoteFetcher,
    mock_playwright: AsyncMock,
    monkeypatch: pytest.MonkeyPatch,
):
    page = (
        mock_playwright.chromium.launch.return_value.new_context.return_value.new_page.return_value
    )
    page.goto.return_value.all_headers = AsyncMock(return_value={})
    _patch_playwright(monkeypatch, mock_playwright)

    success, csp_header = await fetcher.fetch_remote_site(
        url="https://example.com", wait_time=1, interaction_level=0, retries=0
    )

    assert success is True
    assert csp_header is None


# --------------------------------------------------------------------------- #
# 3. Invalid URL
# --------------------------------------------------------------------------- #
@pytest.mark.asyncio
async def test_fetch_remote_site_invalid_url(
    fetcher: RemoteFetcher,
    caplog: pytest.LogCaptureFixture,
):
    with caplog.at_level(logging.ERROR):
        success, _ = await fetcher.fetch_remote_site(
            url="example.com", wait_time=1, interaction_level=0, retries=0
        )

    assert success is False
    assert "Invalid URL: 'example.com'" in caplog.text


# --------------------------------------------------------------------------- #
# 4. All attempts fail
# --------------------------------------------------------------------------- #
@pytest.mark.asyncio
async def test_fetch_remote_site_network_failure(
    fetcher: RemoteFetcher,
    mock_playwright: AsyncMock,
    monkeypatch: pytest.MonkeyPatch,
):
    page = (
        mock_playwright.chromium.launch.return_value.new_context.return_value.new_page.return_value
    )
    page.goto.side_effect = Exception("Boom")
    _patch_playwright(monkeypatch, mock_playwright)

    success, _ = await fetcher.fetch_remote_site(
        url="https://example.com", wait_time=1, interaction_level=0, retries=1
    )

    assert success is False


# --------------------------------------------------------------------------- #
# 5. First fail then success (quick retry)
# --------------------------------------------------------------------------- #
@pytest.mark.asyncio
async def test_fetch_remote_site_retry_success(
    fetcher: RemoteFetcher,
    mock_playwright: AsyncMock,
    monkeypatch: pytest.MonkeyPatch,
):
    page = (
        mock_playwright.chromium.launch.return_value.new_context.return_value.new_page.return_value
    )
    good_response = MagicMock()
    good_response.all_headers = AsyncMock(return_value={})
    page.goto.side_effect = [Exception("Boom"), good_response]
    _patch_playwright(monkeypatch, mock_playwright)

    success, _ = await fetcher.fetch_remote_site(
        url="https://example.com", wait_time=1, interaction_level=0, retries=2
    )

    assert success is True


# --------------------------------------------------------------------------- #
# 6. Two fails then success (eventual success)
# --------------------------------------------------------------------------- #
@pytest.mark.asyncio
async def test_fetch_remote_site_retry_eventual_success(
    fetcher: RemoteFetcher,
    mock_playwright: AsyncMock,
    monkeypatch: pytest.MonkeyPatch,
    caplog: pytest.LogCaptureFixture,
):
    page = (
        mock_playwright.chromium.launch.return_value.new_context.return_value.new_page.return_value
    )
    good_response = MagicMock()
    good_response.all_headers = AsyncMock(return_value={})
    page.goto.side_effect = [Exception("Timeout"), Exception("Timeout"), good_response]
    _patch_playwright(monkeypatch, mock_playwright)

    with caplog.at_level(logging.ERROR):
        success, _ = await fetcher.fetch_remote_site(
            url="https://example.com", wait_time=1, interaction_level=0, retries=3
        )

    assert success is True
    assert caplog.text.count("Attempt 1 failed to fetch https://example.com") == 1
    assert caplog.text.count("Attempt 2 failed to fetch https://example.com") == 1


# --------------------------------------------------------------------------- #
# 7. Interaction level 1 (scroll)
# --------------------------------------------------------------------------- #
@pytest.mark.asyncio
async def test_fetch_remote_site_interaction_level_1(
    fetcher: RemoteFetcher,
    mock_playwright: AsyncMock,
    monkeypatch: pytest.MonkeyPatch,
):
    page = (
        mock_playwright.chromium.launch.return_value.new_context.return_value.new_page.return_value
    )
    _patch_playwright(monkeypatch, mock_playwright)

    success, _ = await fetcher.fetch_remote_site(
        url="https://example.com", wait_time=1, interaction_level=1, retries=0
    )

    assert success is True
    page.evaluate.assert_called_with("window.scrollTo(0, document.body.scrollHeight)")
    page.wait_for_timeout.assert_called_with(1000)


# --------------------------------------------------------------------------- #
# 8. Interaction level 2 (click/hover)
# --------------------------------------------------------------------------- #
@pytest.mark.asyncio
async def test_fetch_remote_site_interaction_level_2(
    fetcher: RemoteFetcher,
    mock_playwright: AsyncMock,
    monkeypatch: pytest.MonkeyPatch,
):
    page = (
        mock_playwright.chromium.launch.return_value.new_context.return_value.new_page.return_value
    )
    elements = [AsyncMock(), AsyncMock()]
    page.query_selector_all.return_value = elements
    _patch_playwright(monkeypatch, mock_playwright)

    success, _ = await fetcher.fetch_remote_site(
        url="https://example.com", wait_time=1, interaction_level=2, retries=0
    )

    assert success is True
    assert page.query_selector_all.await_count >= 1
    for el in elements:
        assert el.click.called
        assert el.hover.called


# --------------------------------------------------------------------------- #
# 9. Dynamic content (single external script)
# --------------------------------------------------------------------------- #
@pytest.mark.asyncio
async def test_fetch_remote_site_dynamic_content(
    fetcher: RemoteFetcher,
    csp_generator: CSPGenerator,
    mock_playwright: AsyncMock,
    monkeypatch: pytest.MonkeyPatch,
):
    csp_generator.directives["script-src"] = []

    page = (
        mock_playwright.chromium.launch.return_value.new_context.return_value.new_page.return_value
    )
    page.content = AsyncMock(return_value="<html></html>")

    def trigger_request(event, handler):
        handler(MagicMock(url="https://example.com/script.js", resource_type="script"))

    page.on.side_effect = trigger_request
    _patch_playwright(monkeypatch, mock_playwright)

    success, _ = await fetcher.fetch_remote_site(
        url="https://example.com", wait_time=1, interaction_level=0, retries=0
    )

    assert success is True
    assert csp_generator.stats["external_scripts"] == 1
    assert "https://example.com/script.js" in csp_generator.directives["script-src"]


# --------------------------------------------------------------------------- #
# 10. Dynamic content (multiple scripts + image)
# --------------------------------------------------------------------------- #
@pytest.mark.asyncio
async def test_fetch_remote_site_dynamic_multiple_resources(
    fetcher: RemoteFetcher,
    csp_generator: CSPGenerator,
    mock_playwright: AsyncMock,
    monkeypatch: pytest.MonkeyPatch,
):
    csp_generator.directives["script-src"] = []

    page = (
        mock_playwright.chromium.launch.return_value.new_context.return_value.new_page.return_value
    )
    page.content = AsyncMock(return_value="<html></html>")

    def trigger_request(event, handler):
        # two scripts and one image
        handler(MagicMock(url="https://ex.com/one.js", resource_type="script"))
        handler(MagicMock(url="https://ex.com/two.js", resource_type="script"))
        handler(MagicMock(url="https://ex.com/img.png", resource_type="image"))

    page.on.side_effect = trigger_request
    _patch_playwright(monkeypatch, mock_playwright)

    await fetcher.fetch_remote_site(
        url="https://example.com", wait_time=1, interaction_level=0, retries=0
    )

    assert csp_generator.stats["external_scripts"] == 2
    assert "https://ex.com/one.js" in csp_generator.directives["script-src"]
    assert "https://ex.com/two.js" in csp_generator.directives["script-src"]
    # Images should not increment the external_scripts counter
    assert "https://ex.com/img.png" not in csp_generator.directives.get(
        "script-src", []
    )


# --------------------------------------------------------------------------- #
# 11. Empty page (no resources)
# --------------------------------------------------------------------------- #
@pytest.mark.asyncio
async def test_fetch_remote_site_empty_content(
    fetcher: RemoteFetcher,
    csp_generator: CSPGenerator,
    mock_playwright: AsyncMock,
    monkeypatch: pytest.MonkeyPatch,
):
    page = (
        mock_playwright.chromium.launch.return_value.new_context.return_value.new_page.return_value
    )
    page.content = AsyncMock(return_value="<html></html>")
    _patch_playwright(monkeypatch, mock_playwright)

    success, _ = await fetcher.fetch_remote_site(
        url="https://example.com", wait_time=1, interaction_level=0, retries=0
    )

    assert success is True
    assert csp_generator.stats["unique_script_hashes"] == 0
    assert csp_generator.stats["unique_style_hashes"] == 0
    assert csp_generator.stats["external_scripts"] == 0
