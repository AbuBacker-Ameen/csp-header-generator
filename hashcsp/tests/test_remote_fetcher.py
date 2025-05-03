"""Unit-tests for `RemoteFetcher.fetch_remote_site`.

No real browser is launched. A fully-stubbed Playwright tree plus the
`_AsyncContext` helper lets `async with async_playwright()` work as expected.
"""

from __future__ import annotations

import json
import logging
from typing import Any, Dict
from unittest.mock import AsyncMock, MagicMock

import pytest

from hashcsp.core.csp_generator import CSPGenerator
from hashcsp.core.logging_config import ErrorCodes
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
# Helper: parse structlog JSON logs
# --------------------------------------------------------------------------- #
def get_log_event(record: logging.LogRecord) -> Dict[str, Any]:
    """Extract event and other fields from a structlog log record."""
    if isinstance(record.msg, dict):
        return record.msg
    try:
        return json.loads(record.msg)
    except (json.JSONDecodeError, TypeError):
        print(f"Failed to parse log record: {record.msg}")
        return {"event": str(record.msg), "error_code": None}


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
              <style>body {color: red;}</style>
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
    page.is_visible = AsyncMock(return_value=True)
    page.is_enabled = AsyncMock(return_value=True)

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
    csp_generator.hashes = {
        "script-src": [],
        "style-src": [],
        "style-src-attr": [],
    }  # Reset hashes

    with caplog.at_level(logging.DEBUG):
        success, csp_header = await fetcher.fetch_remote_site(
            url="https://example.com", wait_time=1, interaction_level=0, retries=0
        )

    assert success is True
    assert csp_header == "script-src 'self'"
    assert csp_generator.stats["unique_script_hashes"] == 1
    assert csp_generator.stats["unique_style_hashes"] == 1
    assert csp_generator.stats["external_scripts"] == 0
    assert any(
        get_log_event(record).get("event") == "Added script hash"
        for record in caplog.records
    ), f"Expected 'Added script hash' in logs: {[get_log_event(r).get('event') for r in caplog.records]}"
    assert any(
        get_log_event(record).get("event") == "Added style hash"
        for record in caplog.records
    ), f"Expected 'Added style hash' in logs: {[get_log_event(r).get('event') for r in caplog.records]}"


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
    assert any(
        get_log_event(record).get("event") == "Invalid URL: 'example.com'"
        for record in caplog.records
    ), f"Expected 'Invalid URL: 'example.com'' in logs: {[get_log_event(r).get('event') for r in caplog.records]}"


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
    assert (
        sum(
            1
            for record in caplog.records
            if get_log_event(record).get("event", "").startswith("Attempt")
            and "failed to fetch" in get_log_event(record).get("event", "")
        )
        == 2
    )


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


@pytest.mark.asyncio
async def test_fetch_remote_site_dynamic_dom(
    fetcher: RemoteFetcher,
    csp_generator: CSPGenerator,
    mock_playwright: AsyncMock,
    monkeypatch: pytest.MonkeyPatch,
    caplog: pytest.LogCaptureFixture,
):
    """Test MutationObserver captures dynamic scripts, styles, and style attributes."""
    _patch_playwright(monkeypatch, mock_playwright)
    csp_generator.hashes = {
        "script-src": [],
        "style-src": [],
        "style-src-attr": [],
    }  # Reset hashes
    page = (
        mock_playwright.chromium.launch.return_value.new_context.return_value.new_page.return_value
    )
    page.content = AsyncMock(return_value="<html></html>")
    page.evaluate = AsyncMock(
        side_effect=[
            None,  # MutationObserver setup
            [
                {
                    "tag": "SCRIPT",
                    "content": "console.log('dynamic')",
                    "src": None,
                    "style": None,
                },
                {
                    "tag": "STYLE",
                    "content": "body { color: blue; }",
                    "src": None,
                    "style": None,
                },
                {
                    "tag": "SCRIPT",
                    "content": "",
                    "src": "https://example.com/external.js",
                    "style": None,
                },
                {
                    "tag": "ELEMENT",
                    "content": None,
                    "src": None,
                    "style": "color: green;",
                },
            ],  # Observed elements
            None,  # Disconnect observer
        ]
    )

    with caplog.at_level(logging.DEBUG):
        success, csp_header = await fetcher.fetch_remote_site(
            url="https://example.com",
            wait_time=1,
            interaction_level=0,
            retries=0,
            observe_dom=True,
        )

    assert success is True
    assert csp_generator.stats["unique_script_hashes"] == 1
    assert (
        csp_generator.stats["unique_style_hashes"] == 2
    )  # Inline style + style attribute
    assert csp_generator.stats["external_scripts"] == 1
    assert len(csp_generator.hashes["style-src-attr"]) == 1
    assert any(
        get_log_event(record).get("event") == "MutationObserver enabled"
        for record in caplog.records
    ), f"Expected 'MutationObserver enabled' in logs: {[get_log_event(r).get('event') for r in caplog.records]}"
    assert any(
        get_log_event(record).get("event") == "Added dynamic script hash"
        for record in caplog.records
    ), f"Expected 'Added dynamic script hash' in logs: {[get_log_event(r).get('event') for r in caplog.records]}"
    assert any(
        get_log_event(record).get("event") == "Added dynamic style hash"
        for record in caplog.records
    ), f"Expected 'Added dynamic style hash' in logs: {[get_log_event(r).get('event') for r in caplog.records]}"
    assert any(
        get_log_event(record).get("event") == "Added dynamic external script"
        for record in caplog.records
    ), f"Expected 'Added dynamic external script' in logs: {[get_log_event(r).get('event') for r in caplog.records]}"
    assert any(
        get_log_event(record).get("event") == "Added dynamic style attribute hash"
        for record in caplog.records
    ), f"Expected 'Added dynamic style attribute hash' in logs: {[get_log_event(r).get('event') for r in caplog.records]}"
    assert any(
        get_log_event(record).get("error_code") == ErrorCodes.SUCCESS.value
        for record in caplog.records
    ), f"Expected SUCCESS error_code in logs: {[get_log_event(r).get('error_code') for r in caplog.records]}"


@pytest.mark.asyncio
async def test_fetch_remote_site_mutation_observer_error(
    fetcher: RemoteFetcher,
    csp_generator: CSPGenerator,
    mock_playwright: AsyncMock,
    monkeypatch: pytest.MonkeyPatch,
    caplog: pytest.LogCaptureFixture,
):
    """Test MutationObserver handles Playwright errors."""
    _patch_playwright(monkeypatch, mock_playwright)
    page = (
        mock_playwright.chromium.launch.return_value.new_context.return_value.new_page.return_value
    )
    page.content = AsyncMock(return_value="<html></html>")
    page.evaluate = AsyncMock(side_effect=Exception("Playwright evaluation error"))

    with caplog.at_level(logging.ERROR):
        with pytest.raises(Exception, match="Playwright evaluation error"):
            await fetcher.fetch_remote_site(
                url="https://example.com",
                wait_time=1,
                interaction_level=0,
                retries=0,
                observe_dom=True,
            )

    assert any(
        get_log_event(record).get("event") == "Error during site fetch"
        for record in caplog.records
    ), f"Expected 'Error during site fetch' in logs: {[get_log_event(r).get('event') for r in caplog.records]}"
    assert any(
        get_log_event(record).get("error_code") == ErrorCodes.PLAYWRIGHT_ERROR.value
        for record in caplog.records
    ), f"Expected PLAYWRIGHT_ERROR in logs: {[get_log_event(r).get('error_code') for r in caplog.records]}"


@pytest.mark.asyncio
async def test_fetch_remote_site_mutation_observer_disconnect_error(
    fetcher: RemoteFetcher,
    csp_generator: CSPGenerator,
    mock_playwright: AsyncMock,
    monkeypatch: pytest.MonkeyPatch,
    caplog: pytest.LogCaptureFixture,
):
    """Test graceful handling of MutationObserver disconnect failure."""
    _patch_playwright(monkeypatch, mock_playwright)
    csp_generator.hashes = {
        "script-src": [],
        "style-src": [],
        "style-src-attr": [],
    }  # Reset hashes
    page = (
        mock_playwright.chromium.launch.return_value.new_context.return_value.new_page.return_value
    )
    page.content = AsyncMock(return_value="<html></html>")
    page.evaluate = AsyncMock(
        side_effect=[
            None,  # MutationObserver setup
            [
                {
                    "tag": "SCRIPT",
                    "content": "console.log('dynamic')",
                    "src": None,
                    "style": None,
                },
                {
                    "tag": "STYLE",
                    "content": "body { color: blue; }",
                    "src": None,
                    "style": None,
                },
            ],  # Observed elements
            Exception(
                "TypeError: window.__hashcsp_disconnect_observer is not a function"
            ),  # Disconnect failure
        ]
    )

    with caplog.at_level(logging.WARNING):
        success, csp_header = await fetcher.fetch_remote_site(
            url="https://example.com",
            wait_time=1,
            interaction_level=0,
            retries=0,
            observe_dom=True,
        )

    assert success is True
    assert csp_generator.stats["unique_script_hashes"] == 1
    assert csp_generator.stats["unique_style_hashes"] == 1
    assert any(
        get_log_event(record).get("event") == "Failed to disconnect MutationObserver"
        for record in caplog.records
    ), f"Expected 'Failed to disconnect MutationObserver' in logs: {[get_log_event(r).get('event') for r in caplog.records]}"
    assert any(
        get_log_event(record).get("error_code") == ErrorCodes.PLAYWRIGHT_ERROR.value
        for record in caplog.records
    ), f"Expected PLAYWRIGHT_ERROR in logs: {[get_log_event(r).get('error_code') for r in caplog.records]}"


@pytest.mark.asyncio
async def test_fetch_remote_site_resources_and_style_attributes(
    fetcher: RemoteFetcher,
    csp_generator: CSPGenerator,
    mock_playwright: AsyncMock,
    monkeypatch: pytest.MonkeyPatch,
    caplog: pytest.LogCaptureFixture,
):
    """Test handling of resources (including favicon) and style attributes via add_external_resource."""
    _patch_playwright(monkeypatch, mock_playwright)
    csp_generator.hashes = {
        "script-src": [],
        "style-src": [],
        "style-src-attr": [],
    }  # Reset hashes
    csp_generator.stats = {  # Reset stats
        "unique_script_hashes": 0,
        "unique_style_hashes": 0,
        "external_scripts": 0,
        "external_fonts": 0,
        "external_images": 0,
        "external_media": 0,
        "external_connections": 0,
    }
    page = (
        mock_playwright.chromium.launch.return_value.new_context.return_value.new_page.return_value
    )
    page.content = AsyncMock(
        return_value="""
            <html>
              <div style="color: red;"></div>
              <style>body { background: white; }</style>
              <link rel="icon" href="/favicon.png">
            </html>
        """
    )
    page.evaluate = AsyncMock(
        side_effect=[
            None,  # MutationObserver setup
            [
                {
                    "tag": "ELEMENT",
                    "content": None,
                    "src": None,
                    "style": "font-size: 16px;",
                },
                {
                    "tag": "STYLE",
                    "content": "body {background:white;}",
                    "src": None,
                    "style": None,
                },  # Same as static style
            ],  # Observed elements
            None,  # Disconnect observer
        ]
    )

    def trigger_request(event, handler):
        handler(MagicMock(url="https://example.com/font.woff2", resource_type="font"))
        handler(MagicMock(url="https://example.com/favicon.png", resource_type="image"))
        handler(MagicMock(url="https://example.com/script.js", resource_type="script"))
        handler(MagicMock(url="https://example.com/video.mp4", resource_type="media"))
        handler(MagicMock(url="https://example.com/api", resource_type="fetch"))

    page.on.side_effect = trigger_request

    with caplog.at_level(logging.DEBUG):
        success, csp_header = await fetcher.fetch_remote_site(
            url="https://example.com",
            wait_time=1,
            interaction_level=0,
            retries=0,
            observe_dom=True,
        )

    assert success is True
    assert (
        csp_generator.stats["unique_style_hashes"] == 3
    )  # Static style, static attribute, dynamic attribute
    assert csp_generator.stats["external_fonts"] == 1
    assert csp_generator.stats["external_scripts"] == 1
    assert csp_generator.stats["external_images"] == 1
    assert csp_generator.stats["external_media"] == 1
    assert csp_generator.stats["external_connections"] == 1
    assert "https://example.com/font.woff2" in csp_generator.directives.get(
        "font-src", []
    )
    assert "https://example.com/favicon.png" in csp_generator.directives.get(
        "img-src", []
    )
    assert "https://example.com/script.js" in csp_generator.directives.get(
        "script-src", []
    )
    assert "https://example.com/video.mp4" in csp_generator.directives.get(
        "media-src", []
    )
    assert "https://example.com/api" in csp_generator.directives.get("connect-src", [])
    assert (
        len(csp_generator.hashes["style-src-attr"]) == 2
    )  # Static and dynamic style attributes
    assert (
        len(csp_generator.hashes["style-src"]) == 1
    )  # Deduplicated static and dynamic style
    assert any(
        get_log_event(record).get("event") == "Detected favicon"
        for record in caplog.records
    ), f"Expected 'Detected favicon' in logs: {[get_log_event(r).get('event') for r in caplog.records]}"
    assert any(
        get_log_event(record).get("event") == "Added style attribute hash"
        for record in caplog.records
    ), f"Expected 'Added style attribute hash' in logs: {[get_log_event(r).get('event') for r in caplog.records]}"
    assert any(
        get_log_event(record).get("event") == "Added dynamic style attribute hash"
        for record in caplog.records
    ), f"Expected 'Added dynamic style attribute hash' in logs: {[get_log_event(r).get('event') for r in caplog.records]}"
    assert any(
        get_log_event(record).get("event") == "Added external font"
        for record in caplog.records
    ), f"Expected 'Added external font' in logs: {[get_log_event(r).get('event') for r in caplog.records]}"
    assert any(
        get_log_event(record).get("event") == "Added external script"
        for record in caplog.records
    ), f"Expected 'Added external script' in logs: {[get_log_event(r).get('event') for r in caplog.records]}"
    assert any(
        get_log_event(record).get("error_code") == ErrorCodes.SUCCESS.value
        for record in caplog.records
    ), f"Expected SUCCESS error_code in logs: {[get_log_event(r).get('error_code') for r in caplog.records]}"


# Debug helper to print all log events
def print_log_events(caplog: pytest.LogCaptureFixture) -> None:
    print("Log events captured:")
    for record in caplog.records:
        print(f" - {get_log_event(record)}")
