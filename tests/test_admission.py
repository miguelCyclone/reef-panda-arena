"""Cross-family admission has no polling and closes lock-owning sessions."""

import asyncio
import os
from types import SimpleNamespace

import pytest
from sqlalchemy.pool import NullPool

from reef_panda_arena.application import admission
from reef_panda_arena.settings import ArenaSettings


class LockServer:
    def __init__(self):
        self.owners = {}
        self.connections = []
        self.engines = []
        self.calls = []
        self.release_error = False
        self.acquire_null = False
        self.physical_closed = asyncio.Event()
        self.disposed = asyncio.Event()
        self.acquire_wait = False
        self.acquired = asyncio.Event()
        self.release_wait = False
        self.releasing = asyncio.Event()
        self.resume_release = asyncio.Event()

    def engine(self, url, *, poolclass):
        assert poolclass is NullPool
        engine = FakeEngine(self)
        self.engines.append(engine)
        return engine


class FakeDriver:
    def __init__(self, connection):
        self.connection = connection
        self.closed = False

    def close(self):
        self.closed = True
        server = self.connection.server
        server.physical_closed.set()
        for key, owner in tuple(server.owners.items()):
            if owner is self.connection:
                del server.owners[key]


class FakeConnection:
    def __init__(self, server):
        self.server = server
        self.driver = FakeDriver(self)
        self.invalidated = self.closed = False

    async def get_raw_connection(self):
        return SimpleNamespace(driver_connection=self.driver)

    async def scalar(self, sql, parameters):
        query, name = str(sql), parameters["lock_name"]
        self.server.calls.append((query, name))
        if "GET_LOCK" in query:
            assert query == "SELECT GET_LOCK(:lock_name, 0)"
            if self.server.acquire_null:
                return None
            if name in self.server.owners:
                return 0
            self.server.owners[name] = self
            self.server.acquired.set()
            if self.server.acquire_wait:
                await asyncio.Future()
            return 1
        assert query == "SELECT RELEASE_LOCK(:lock_name)"
        self.server.releasing.set()
        if self.server.release_wait:
            await self.server.resume_release.wait()
        if self.server.release_error:
            raise RuntimeError("Controlled release failure")
        if self.server.owners.get(name) is self:
            del self.server.owners[name]
            return 1
        return 0

    async def invalidate(self):
        self.invalidated = True

    async def close(self):
        self.closed = True


class FakeEngine:
    def __init__(self, server):
        self.server = server
        self.disposed = False

    async def connect(self):
        connection = FakeConnection(self.server)
        self.server.connections.append(connection)
        return connection

    async def dispose(self):
        self.disposed = True
        self.server.disposed.set()


def settings(**overrides):
    return ArenaSettings(_env_file=None, database_url="mysql+asyncmy://test:test@localhost/test",
                         database_socket=None, **overrides)


def assert_closed(server):
    assert server.owners == {}
    assert all(connection.driver.closed and connection.closed and connection.invalidated
               for connection in server.connections)
    assert all(engine.disposed for engine in server.engines)


def test_audit_token_is_shared_by_families_and_reacquired_after_exit(monkeypatch):
    async def verify():
        server = LockServer()
        monkeypatch.setattr(admission, "create_async_engine", server.engine)
        config = settings()
        async with admission.run_admission(config, family="core"):
            with pytest.raises(admission.RunAdmissionBusy, match="Concurrent audit run limit"):
                async with admission.run_admission(config, family="unified"):
                    pytest.fail("A second experiment entered")
            assert len(server.owners) == 1
        async with admission.run_admission(config, family="adaptive"):
            assert len(server.owners) == 1
        assert_closed(server)
        assert {name for _, name in server.calls} == {admission.AUDIT_LOCK}

    asyncio.run(verify())


@pytest.mark.parametrize("exit_path", ["error", "cancel", "release_error", "acquire_cancel", "cleanup_cancel"])
def test_admission_closes_session_on_failure_and_cancellation(monkeypatch, exit_path):
    async def verify():
        server = LockServer()
        server.release_error = exit_path == "release_error"
        server.acquire_wait = exit_path == "acquire_cancel"
        server.release_wait = exit_path == "cleanup_cancel"
        monkeypatch.setattr(admission, "create_async_engine", server.engine)
        entered = asyncio.Event()

        async def execute():
            async with admission.run_admission(settings(), family="live"):
                entered.set()
                if exit_path == "error":
                    raise ValueError("Controlled body failure")
                if exit_path == "cancel":
                    await asyncio.Future()

        task = asyncio.create_task(execute())
        if exit_path in {"cancel", "acquire_cancel", "cleanup_cancel"}:
            signal = (server.acquired if exit_path == "acquire_cancel" else
                      server.releasing if exit_path == "cleanup_cancel" else entered)
            await asyncio.wait_for(signal.wait(), timeout=1)
            task.cancel()
            server.resume_release.set()
            with pytest.raises(asyncio.CancelledError):
                await task
        elif exit_path == "error":
            with pytest.raises(ValueError, match="Controlled body"):
                await task
        else:
            await task
        assert_closed(server)
        server.acquire_wait = server.release_wait = server.release_error = False
        async with admission.run_admission(settings(), family="sensitive"):
            pass
        assert_closed(server)

    asyncio.run(verify())



def test_repeated_cleanup_cancellation_closes_lock_before_caller_returns(monkeypatch):
    async def verify():
        server = LockServer()
        server.release_wait = True
        monkeypatch.setattr(admission, "create_async_engine", server.engine)

        async def execute():
            async with admission.run_admission(settings(), family="live"):
                pass

        task = asyncio.create_task(execute())
        await asyncio.wait_for(server.releasing.wait(), timeout=1)
        task.cancel()
        await asyncio.wait_for(server.physical_closed.wait(), timeout=1)
        task.cancel()
        with pytest.raises(asyncio.CancelledError):
            await task
        assert server.owners == {}
        assert not server.engines[0].disposed
        server.resume_release.set()
        await asyncio.wait_for(server.disposed.wait(), timeout=1)
        assert_closed(server)
        server.release_wait = False
        async with admission.run_admission(settings(), family="extension"):
            pass
        assert_closed(server)

    asyncio.run(verify())


def test_null_lock_decision_is_unavailable_and_never_enters_trial(monkeypatch):
    async def verify():
        server = LockServer()
        server.acquire_null = True
        monkeypatch.setattr(admission, "create_async_engine", server.engine)
        with pytest.raises(admission.RunAdmissionUnavailable, match="no valid decision"):
            async with admission.run_admission(settings(), family="core"):
                pytest.fail("An invalid lock decision admitted a trial")
        assert_closed(server)

    asyncio.run(verify())


def test_non_audit_mode_preserves_only_declared_family_locks(monkeypatch):
    async def verify():
        server = LockServer()
        monkeypatch.setattr(admission, "create_async_engine", server.engine)
        config = settings(audit_mode=False)
        async with admission.run_admission(config, family="core"):
            assert server.engines == []
        async with admission.run_admission(config, family="adaptive"):
            async with admission.run_admission(config, family="unified"):
                assert len(server.owners) == 2
        with pytest.raises(ValueError, match="Unknown experiment family"):
            async with admission.run_admission(config, family="unregistered"):
                pytest.fail("An unregistered family entered")
        assert_closed(server)

    asyncio.run(verify())


def test_mysql_cross_family_rejection_precedes_run_creation_and_cancel_releases():
    if os.getenv("ARENA_TEST_MYSQL") != "1":
        pytest.skip("Set ARENA_TEST_MYSQL=1 for the local advisory-lock integration")
    from reef_panda_arena.application.controller import run_replay
    from reef_panda_arena.application.unified import run_unified_replay

    async def verify():
        config = ArenaSettings(audit_mode=True)
        entered = asyncio.Event()

        async def hold():
            async with admission.run_admission(config, family="live"):
                entered.set()
                await asyncio.Future()

        task = asyncio.create_task(hold())
        try:
            await asyncio.wait_for(entered.wait(), timeout=10)
            for execute in (
                lambda: run_replay("C00", "none", 31, settings=config),
                lambda: run_unified_replay("C32", "transitive", 31, settings=config),
            ):
                with pytest.raises(admission.RunAdmissionBusy, match="Concurrent audit"):
                    await execute()
        finally:
            task.cancel()
            with pytest.raises(asyncio.CancelledError):
                await task
        async with admission.run_admission(config, family="extension"):
            pass

    asyncio.run(verify())
