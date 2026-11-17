"""Offline safety checks. All messages, credentials and authorizations below are synthetic."""

from __future__ import annotations

import hashlib
import os
import sqlite3
import tempfile
import unittest
from pathlib import Path
from types import SimpleNamespace
from unittest.mock import AsyncMock, patch

from mcp.server.fastmcp.exceptions import ToolError
from telethon import errors, types

from bridge import (
    Bridge,
    BridgeError,
    ReadOnlySession,
    credentials,
    describe_message,
    make_server,
    parse_peer,
    parse_post,
    safe_error,
)


class ValidationTests(unittest.TestCase):
    def test_safe_errors_preserve_cooldown_without_raw_exception_details(self):
        try:
            try:
                raise BridgeError("flood_wait: retry_after_seconds=123")
            except BridgeError as exc:
                raise ToolError("SDK wrapper with sensitive details") from exc
        except ToolError as wrapped:
            self.assertEqual(safe_error(wrapped), "flood_wait: retry_after_seconds=123")
        self.assertEqual(
            safe_error(ValueError("sensitive raw value")), "invalid_arguments_or_tool_error"
        )

    def test_post_formats(self):
        for url, expected in [
            ("https://t.me/channel_name/992", ("@channel_name", 992)),
            ("https://t.me/s/channel_name/992?single", ("@channel_name", 992)),
            ("https://t.me/c/123456/992", (-1000000123456, 992)),
            ("https://t.me/c/123456/12/992", (-1000000123456, 992)),
        ]:
            with self.subTest(url=url):
                self.assertEqual(parse_post(url), expected)

    def test_reject_invites_and_external_urls(self):
        for url in [
            "https://t.me/+InviteKey",
            "https://t.me/joinchat/abc",
            "https://evil.test/channel_name/1",
            "https://t.me.evil.test/channel_name/1",
            "http://t.me/channel_name/1",
            "https://evil@t.me/channel_name/1",
            "https://t.me:443/channel_name/1",
            "https://t.me/channel_name/0",
            "https://t.me/channel_name/2147483648",
            "https://t.me/c/0/1",
        ]:
            with self.subTest(url=url), self.assertRaises(BridgeError):
                parse_post(url)

    def test_peer_does_not_accept_phones_or_invites(self):
        self.assertEqual(parse_peer("@channel_name"), "@channel_name")
        self.assertEqual(parse_peer("-1000000123456"), -1000000123456)
        for value in ["+12345678901", "https://t.me/+InviteKey", "name; rm -rf", ""]:
            with self.subTest(value=value), self.assertRaises(BridgeError):
                parse_peer(value)

    def test_credential_permissions_and_no_interpolation(self):
        with tempfile.TemporaryDirectory() as tmp:
            path = Path(tmp) / ".env"
            path.write_text(
                "TELEGRAM_API_ID=123\nTELEGRAM_API_HASH="
                + "a" * 32
                + "\nTELEGRAM_OWNER_USER_ID=456\n"
            )
            path.chmod(0o600)
            self.assertEqual(credentials(path), (123, "a" * 32, 456))
            path.chmod(0o644)
            with self.assertRaises(BridgeError):
                credentials(path)
            link = Path(tmp) / "link"
            link.symlink_to(path)
            with self.assertRaises(BridgeError):
                credentials(link)

    def test_session_database_is_read_only_and_entity_lookup_parameterized(self):
        with tempfile.TemporaryDirectory() as tmp:
            path = Path(tmp) / "synthetic.session"
            db = sqlite3.connect(path)
            db.execute("CREATE TABLE sessions(dc_id, server_address, port, auth_key)")
            db.execute("INSERT INTO sessions VALUES (1, '127.0.0.1', 443, ?)", (b"x" * 256,))
            db.execute("CREATE TABLE entities(id INTEGER PRIMARY KEY, hash INTEGER)")
            db.execute("INSERT INTO entities VALUES (-1000000123456, 42)")
            db.commit()
            db.close()
            path.chmod(0o600)
            before = hashlib.sha256(path.read_bytes()).digest()
            modified = path.stat().st_mtime_ns
            session = ReadOnlySession(path)
            self.assertEqual(session.get_entity_rows_by_id(-1000000123456), (-1000000123456, 42))
            with session.database() as connection, self.assertRaises(sqlite3.OperationalError):
                connection.execute("DELETE FROM entities")
            session.save()
            session.close()
            self.assertEqual(before, hashlib.sha256(path.read_bytes()).digest())
            self.assertEqual(modified, path.stat().st_mtime_ns)

    def test_message_serialization_has_no_authorization_fields(self):
        entity = types.Channel(
            id=123,
            title="Synthetic",
            photo=types.ChatPhotoEmpty(),
            date=None,
            username="channel_name",
            broadcast=True,
        )
        message = types.Message(id=992, peer_id=types.PeerChannel(123), message="x" * 12001)
        result = describe_message(message, entity)
        self.assertEqual(result["url"], "https://t.me/channel_name/992")
        self.assertEqual(len(result["text"]), 12000)
        self.assertTrue(result["text_truncated"])
        self.assertFalse({"auth_key", "access_hash", "phone", "api_hash"} & result.keys())


class AsyncSafetyTests(unittest.IsolatedAsyncioTestCase):
    async def asyncSetUp(self):
        self.tmp = tempfile.TemporaryDirectory()
        root = Path(self.tmp.name)
        self.bridge = Bridge(root / ".env", root / "fake.session", root / "runtime")

    async def asyncTearDown(self):
        self.tmp.cleanup()

    async def test_invalid_target_fails_before_credentials_or_network(self):
        with patch("bridge.TelegramClient") as client, patch("bridge.credentials") as loader:
            with self.assertRaises(BridgeError):
                await self.bridge.run("post", url="https://evil.test/invite")
            client.assert_not_called()
            loader.assert_not_called()

    async def test_private_message_read_requires_opt_in(self):
        client = SimpleNamespace(get_entity=AsyncMock(return_value=types.User(id=111)))
        with self.assertRaisesRegex(BridgeError, "private_excluded"):
            await self.bridge.read(client, "messages", "@synthetic_user", "", 20, 0, False, "")

    async def test_owner_mismatch_stops_reads_and_disconnects(self):
        client = SimpleNamespace(
            connect=AsyncMock(),
            disconnect=AsyncMock(),
            get_me=AsyncMock(return_value=SimpleNamespace(id=2, bot=False)),
        )
        with (
            patch("bridge.credentials", return_value=(1, "a" * 32, 1)),
            patch("bridge.ReadOnlySession"),
            patch("bridge.TelegramClient", return_value=client),
            patch.object(self.bridge, "read", new_callable=AsyncMock) as reader,
        ):
            with self.assertRaisesRegex(BridgeError, "owner_mismatch"):
                await self.bridge.run("status")
            reader.assert_not_awaited()
            client.disconnect.assert_awaited_once()

    async def test_floodwait_shared_between_bridge_instances(self):
        with self.assertRaisesRegex(BridgeError, "retry_after_seconds=123"):
            async with self.bridge.request_lock():
                raise errors.FloodWaitError(request=None, capture=123)
        other = Bridge(self.bridge.credential_file, self.bridge.session_file, self.bridge.runtime)
        with self.assertRaisesRegex(BridgeError, "cooldown"):
            async with other.request_lock():
                self.fail("Cooldown must stop the next request")
        self.assertEqual(os.stat(self.bridge.runtime / "request.lock").st_mode & 0o777, 0o600)

    async def test_catalog_only_exposes_read_tools_and_limits(self):
        mocked = SimpleNamespace(run=AsyncMock(return_value={"ok": True}))
        server = make_server(mocked)
        tools = await server.list_tools()
        self.assertEqual(
            {tool.name for tool in tools},
            {
                "telegram_status",
                "telegram_dialogs",
                "telegram_read_post",
                "telegram_messages",
                "telegram_search",
            },
        )
        for tool in tools:
            self.assertTrue(tool.annotations.readOnlyHint)
            self.assertFalse(tool.annotations.destructiveHint)
        for invalid in [0, 101, -1, True, "20"]:
            with self.subTest(limit=invalid), self.assertRaises(ToolError):
                await server.call_tool(
                    "telegram_messages", {"peer": "@channel_name", "limit": invalid}
                )
        with self.assertRaises(ToolError):
            await server.call_tool(
                "telegram_messages",
                {
                    "peer": "@channel_name",
                    "include_private": "false",
                },
            )
        mocked.run.assert_not_awaited()
        result = await server.call_tool("telegram_messages", {"peer": "@channel_name", "limit": 1})
        self.assertEqual(result[1], {"ok": True})


if __name__ == "__main__":
    unittest.main()
