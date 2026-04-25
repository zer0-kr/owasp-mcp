from __future__ import annotations

import re
import sqlite3
from pathlib import Path
from typing import Any


_IDENT_RE = re.compile(r"^[a-zA-Z_][a-zA-Z0-9_]*$")


def _validate_identifier(name: str) -> None:
    if not _IDENT_RE.match(name):
        raise ValueError(f"Invalid SQL identifier: {name!r}")


def get_connection(db_path: Path) -> sqlite3.Connection:
    uri = f"file:{db_path}?mode=ro"
    conn = sqlite3.connect(uri, uri=True)
    conn.row_factory = sqlite3.Row
    return conn


def _tokenize_query(query: str) -> list[str]:
    tokens: list[str] = []
    i = 0
    while i < len(query):
        if query[i] == '"':
            end = query.find('"', i + 1)
            if end == -1:
                end = len(query)
            else:
                end += 1
            tokens.append(query[i:end])
            i = end
        elif query[i].isspace():
            i += 1
        else:
            end = i
            while end < len(query) and not query[end].isspace() and query[end] != '"':
                end += 1
            tokens.append(query[i:end])
            i = end
    return tokens


def sanitize_fts_query(query: str) -> str:
    _FTS_OPERATORS = {"AND", "OR", "NOT", "NEAR"}
    _SAFE_TOKEN = re.compile(r"^[a-zA-Z0-9_]+$")

    tokens = _tokenize_query(query)
    safe: list[str] = []
    for i, tok in enumerate(tokens):
        if tok.startswith('"'):
            safe.append(tok)
        elif tok.upper() in _FTS_OPERATORS:
            if 0 < i < len(tokens) - 1:
                safe.append(tok)
            else:
                safe.append(f'"{tok}"')
        elif _SAFE_TOKEN.match(tok):
            safe.append(tok)
        else:
            escaped = tok.replace('"', '""')
            safe.append(f'"{escaped}"')
    return " ".join(safe)


def search_fts(
    db_path: Path,
    table: str,
    query: str,
    filters: dict[str, Any] | None = None,
    limit: int = 20,
    offset: int = 0,
) -> tuple[list[dict[str, Any]], int]:
    _validate_identifier(table)
    sanitized = sanitize_fts_query(query)
    if not sanitized.strip():
        return [], 0

    conn = get_connection(db_path)
    fts_table = f"{table}_fts"

    try:
        cur = conn.execute(
            "SELECT name FROM sqlite_master WHERE type='table' AND name=?",
            (fts_table,),
        )
        if cur.fetchone() is None:
            raise ValueError(f"FTS table '{fts_table}' does not exist.")

        where_clauses = [f"{fts_table} MATCH ?"]
        params: list[Any] = [sanitized]

        if filters:
            for col, val in filters.items():
                _validate_identifier(col)
                where_clauses.append(f"{table}.{col} = ?")
                params.append(val)

        where_sql = " AND ".join(where_clauses)

        count_sql = (
            f"SELECT count(*) FROM {fts_table} "
            f"JOIN {table} ON {table}.rowid = {fts_table}.rowid "
            f"WHERE {where_sql}"
        )
        total = conn.execute(count_sql, params).fetchone()[0]

        result_sql = (
            f"SELECT {table}.* FROM {fts_table} "
            f"JOIN {table} ON {table}.rowid = {fts_table}.rowid "
            f"WHERE {where_sql} "
            f"ORDER BY {fts_table}.rank "
            f"LIMIT ? OFFSET ?"
        )
        rows = conn.execute(result_sql, [*params, limit, offset]).fetchall()
        results = [dict(row) for row in rows]
    finally:
        conn.close()

    return results, total


def get_by_id(db_path: Path, table: str, id_col: str, id_value: str) -> dict[str, Any] | None:
    _validate_identifier(table)
    _validate_identifier(id_col)
    conn = get_connection(db_path)
    try:
        row = conn.execute(
            f"SELECT * FROM {table} WHERE {id_col} = ?", (id_value,)
        ).fetchone()
        return dict(row) if row else None
    finally:
        conn.close()


def get_all(
    db_path: Path,
    table: str,
    filters: dict[str, Any] | None = None,
    limit: int = 100,
    offset: int = 0,
) -> tuple[list[dict[str, Any]], int]:
    _validate_identifier(table)
    conn = get_connection(db_path)

    try:
        where_clauses: list[str] = []
        params: list[Any] = []

        if filters:
            for col, val in filters.items():
                _validate_identifier(col)
                where_clauses.append(f"{col} = ?")
                params.append(val)

        where_sql = " WHERE " + " AND ".join(where_clauses) if where_clauses else ""

        total = conn.execute(f"SELECT count(*) FROM {table}{where_sql}", params).fetchone()[0]
        rows = conn.execute(
            f"SELECT * FROM {table}{where_sql} LIMIT ? OFFSET ?",
            [*params, limit, offset],
        ).fetchall()
        results = [dict(row) for row in rows]
    finally:
        conn.close()

    return results, total
