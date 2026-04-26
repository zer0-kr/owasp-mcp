from __future__ import annotations

from security_framework_mcp.db import sanitize_fts_query, _tokenize_query, _validate_identifier
import pytest


class TestTokenizer:
    def test_empty(self):
        assert _tokenize_query("") == []

    def test_simple(self):
        assert _tokenize_query("hello world") == ["hello", "world"]

    def test_quoted_phrase(self):
        tokens = _tokenize_query('a "b c" d')
        assert tokens == ["a", '"b c"', "d"]

    def test_unclosed_quote(self):
        tokens = _tokenize_query('"unclosed quote')
        assert len(tokens) == 1

    def test_multiple_spaces(self):
        assert _tokenize_query("a   b") == ["a", "b"]

    def test_only_spaces(self):
        assert _tokenize_query("   ") == []

    def test_adjacent_quotes(self):
        tokens = _tokenize_query('"a" "b"')
        assert tokens == ['"a"', '"b"']


class TestSanitizer:
    def test_empty(self):
        assert sanitize_fts_query("") == ""

    def test_spaces_only(self):
        assert sanitize_fts_query("   ") == ""

    def test_normal_words(self):
        assert sanitize_fts_query("hello world") == "hello world"

    def test_quotes_preserved(self):
        assert sanitize_fts_query('"hello world"') == '"hello world"'

    def test_special_chars_quoted(self):
        result = sanitize_fts_query("test; hello'")
        assert '"' in result

    def test_not_in_middle_kept(self):
        assert sanitize_fts_query("a NOT b") == "a NOT b"

    def test_not_at_start_quoted(self):
        assert sanitize_fts_query("NOT b") == '"NOT" b'

    def test_not_at_end_quoted(self):
        assert sanitize_fts_query("a NOT") == 'a "NOT"'

    def test_and_in_middle(self):
        assert sanitize_fts_query("a AND b") == "a AND b"

    def test_and_at_start_quoted(self):
        assert sanitize_fts_query("AND b") == '"AND" b'

    def test_sql_injection(self):
        result = sanitize_fts_query("'; DROP TABLE x; --")
        assert "DROP" not in result or '"' in result

    def test_embedded_quote_split(self):
        result = sanitize_fts_query('hello"world')
        assert result == 'hello "world"'

    def test_underscore_safe(self):
        assert sanitize_fts_query("hello_world") == "hello_world"

    def test_numbers_safe(self):
        assert sanitize_fts_query("test123") == "test123"


class TestValidateIdentifier:
    def test_valid(self):
        _validate_identifier("projects")
        _validate_identifier("asvs_fts")
        _validate_identifier("_private")

    def test_invalid_injection(self):
        with pytest.raises(ValueError):
            _validate_identifier("projects; DROP TABLE")

    def test_invalid_dash(self):
        with pytest.raises(ValueError):
            _validate_identifier("my-table")

    def test_invalid_space(self):
        with pytest.raises(ValueError):
            _validate_identifier("my table")

    def test_invalid_starts_with_number(self):
        with pytest.raises(ValueError):
            _validate_identifier("1table")

    def test_empty_string(self):
        with pytest.raises(ValueError):
            _validate_identifier("")
