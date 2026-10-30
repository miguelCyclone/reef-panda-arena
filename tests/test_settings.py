"""Database URL limits match the installed driver's connection contract."""

import inspect

import asyncmy
import pytest
from sqlalchemy.dialects.mysql.asyncmy import MySQLDialect_asyncmy

from reef_panda_arena.settings import ArenaSettings


def settings(query=""):
    return ArenaSettings(
        _env_file=None,
        database_url=f"mysql+asyncmy://test:test@localhost/test?charset=utf8mb4{query}",
        database_socket=None,
    )


@pytest.mark.parametrize("query,expected", [
    ("", (10, 30)),
    ("&connect_timeout=100&read_timeout=100", (10, 30)),
    ("&connect_timeout=2&read_timeout=7", (2, 7)),
    ("&connect_timeout=0&read_timeout=0", (10, 30)),
    ("&connect_timeout=-1&read_timeout=-3", (10, 30)),
])
def test_mysql_timeout_caps_are_supported_driver_arguments(query, expected):
    url = settings(query).sqlalchemy_url
    dialect = MySQLDialect_asyncmy(dbapi=MySQLDialect_asyncmy.import_dbapi())
    args, kwargs = dialect.create_connect_args(url)

    # Bind without connecting: unsupported driver arguments fail this contract.
    inspect.signature(asyncmy.connect).bind(*args, **kwargs)
    assert (kwargs["connect_timeout"], kwargs["read_timeout"]) == expected
    assert kwargs["charset"] == "utf8mb4"
    assert "write_timeout" not in kwargs


@pytest.mark.parametrize("query", [
    "&connect_timeout=invalid", "&read_timeout=1.5", "&read_timeout=1&read_timeout=2",
])
def test_invalid_timeout_values_fail_before_connecting(query):
    with pytest.raises(ValueError, match="integer seconds"):
        settings(query).sqlalchemy_url


def test_unsupported_write_timeout_is_rejected_before_connecting():
    with pytest.raises(ValueError, match="does not support write_timeout"):
        settings("&write_timeout=3").sqlalchemy_url


def test_socket_url_preserves_bounded_timeouts(tmp_path):
    config = settings("&connect_timeout=4&read_timeout=8")
    config.database_socket = tmp_path / "mysql.sock"
    url = config.sqlalchemy_url
    assert url.query["unix_socket"] == str(tmp_path / "mysql.sock")
    assert (url.query["connect_timeout"], url.query["read_timeout"]) == ("4", "8")
