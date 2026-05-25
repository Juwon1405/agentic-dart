"""Unit tests for the hybrid-architecture result-truncation guardrail.

These exercise dart_agent.live._truncate_tool_result, which caps an
oversized MCP tool result before it's handed back to the model. The
function is pure (no mcp SDK, no API key, no subprocess), so unlike
test_live_mcp.py these run everywhere including CI without the mcp
stdio stack.
"""
import sys

# live.py does lazy imports of anthropic/mcp guarded by try/except, so
# importing it without those packages installed is safe — the module
# loads and the pure helpers are available.
from dart_agent.live import (
    _truncate_tool_result,
    _MCP_RESULT_CHAR_CAP,
    _TRUNCATION_NOTICE,
)


def test_small_result_is_unchanged():
    """A result within budget passes through verbatim."""
    text = '{"findings": [{"id": "F-001", "severity": "high"}]}'
    assert _truncate_tool_result(text) == text


def test_result_exactly_at_cap_is_unchanged():
    """Boundary: a result exactly at the cap is NOT truncated."""
    text = "x" * _MCP_RESULT_CHAR_CAP
    assert _truncate_tool_result(text) == text


def test_oversized_result_is_truncated_with_notice():
    """An over-cap result keeps the leading cap chars + the guidance notice."""
    text = "A" * (_MCP_RESULT_CHAR_CAP + 5000)
    result = _truncate_tool_result(text)
    # Leading content preserved (start of a JSON doc carries schema + first
    # records, which is what the model needs to decide how to narrow).
    assert result[:_MCP_RESULT_CHAR_CAP] == text[:_MCP_RESULT_CHAR_CAP]
    # Notice appended.
    assert result.endswith(_TRUNCATION_NOTICE)
    # Total length is exactly cap + notice (nothing else snuck in).
    assert len(result) == _MCP_RESULT_CHAR_CAP + len(_TRUNCATION_NOTICE)


def test_truncation_notice_steers_toward_narrowing():
    """The notice must tell the model to narrow the query, not eyeball the
    dump — that's the whole point of the hybrid-architecture split."""
    notice = _TRUNCATION_NOTICE.lower()
    assert "limit" in notice
    assert "truncated" in notice
    # Must discourage reading the full dump directly.
    assert "do not" in notice or "don't" in notice


def test_custom_cap_is_respected():
    """The cap is overridable (e.g. for tests or a tighter budget)."""
    text = "Z" * 100
    result = _truncate_tool_result(text, cap=50)
    assert result[:50] == "Z" * 50
    assert result.endswith(_TRUNCATION_NOTICE)


if __name__ == "__main__":
    import pytest
    sys.exit(pytest.main([__file__, "-v"]))
