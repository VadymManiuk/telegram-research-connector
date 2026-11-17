# Telegram Research Connector

A read-only Telegram connector for Model Context Protocol clients. It supports bounded channel search, history pagination, and retrieval of individual posts by link over MCP stdio.

## Design

- **Five read tools.** Check authorization, list accessible dialogs, retrieve a post, page through history, or search a selected channel.
- **Local authorization.** The connector opens an existing Telethon session in SQLite read-only mode, uses it from memory, and verifies the configured account before returning data.
- **Bounded requests.** Calls use timeouts, page limits, and a shared cooldown for Telegram FloodWait responses. Private one-to-one chats are excluded by default.

## Setup

Use Python 3.11+ on macOS or Linux.

```sh
python3 -m venv .venv
.venv/bin/python -m pip install -r requirements.lock
.venv/bin/python -m unittest -q test_bridge.py
```

The tests use synthetic inputs and a temporary SQLite database. A live call requires your own authorized Telethon session and an owner-only credential file containing `TELEGRAM_API_ID`, `TELEGRAM_API_HASH`, and `TELEGRAM_OWNER_USER_ID`. Give both files mode `0600` and keep them outside the repository.

```sh
.venv/bin/python bridge.py \
  --credentials-file /path/to/credentials.env \
  --session-file /path/to/telegram-user.session \
  --call telegram_status
```

For MCP stdio, use the same command and file arguments in your client's configuration and omit `--call telegram_status`. The connector uses an existing session. Create and authorize that session separately.
