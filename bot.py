from __future__ import annotations

import asyncio
import hashlib
import hmac
import html
import logging
import os
import re
import secrets
import sqlite3
import unicodedata
from contextlib import contextmanager
from pathlib import Path
from typing import Any

from aiogram import Bot, Dispatcher, F
from aiogram.exceptions import TelegramBadRequest, TelegramForbiddenError
from aiogram.filters import Command, CommandStart
from aiogram.fsm.context import FSMContext
from aiogram.fsm.state import State, StatesGroup
from aiogram.fsm.storage.base import StorageKey
from aiogram.types import CallbackQuery, InlineKeyboardButton, InlineKeyboardMarkup, Message


# ---------------------------------------------------------------------------
# Configuration
# ---------------------------------------------------------------------------

BOT_TOKEN = os.getenv("BOT_TOKEN", "").strip()
DB_PATH = Path(os.getenv("DB_PATH", "./data/spybot.sqlite3")).expanduser()
LOG_LEVEL = os.getenv("LOG_LEVEL", "INFO").upper()
PASSWORD_ITERATIONS = 250_000
MIN_PLAYERS = 3
MAX_ROOM_NAME_LENGTH = 40
MIN_PASSWORD_LENGTH = 1
MAX_PASSWORD_LENGTH = 64
MAX_WORD_LENGTH = 80
REFILL_THRESHOLD = 3
ROOM_INACTIVITY_SECONDS = 24 * 60 * 60

logging.basicConfig(
    level=getattr(logging, LOG_LEVEL, logging.INFO),
    format="%(asctime)s | %(levelname)s | %(name)s | %(message)s",
)
logger = logging.getLogger("spybot")


# ---------------------------------------------------------------------------
# SQLite storage
# ---------------------------------------------------------------------------


@contextmanager
def get_connection():
    DB_PATH.parent.mkdir(parents=True, exist_ok=True)
    connection = sqlite3.connect(DB_PATH, timeout=15)
    connection.row_factory = sqlite3.Row
    connection.execute("PRAGMA foreign_keys = ON")
    connection.execute("PRAGMA busy_timeout = 15000")
    try:
        yield connection
        connection.commit()
    except Exception:
        connection.rollback()
        raise
    finally:
        connection.close()


def init_db() -> None:
    with get_connection() as connection:
        connection.execute("PRAGMA journal_mode = WAL")
        connection.executescript(
            """
            CREATE TABLE IF NOT EXISTS rooms (
                id                  INTEGER PRIMARY KEY AUTOINCREMENT,
                name                TEXT NOT NULL,
                password_salt       BLOB NOT NULL,
                password_hash       BLOB NOT NULL,
                owner_id            INTEGER NOT NULL,
                phase               TEXT NOT NULL DEFAULT 'lobby',
                collection_cycle    INTEGER NOT NULL DEFAULT 0,
                round_no            INTEGER NOT NULL DEFAULT 0,
                created_at          TEXT NOT NULL DEFAULT CURRENT_TIMESTAMP,
                last_activity_at    TEXT NOT NULL DEFAULT CURRENT_TIMESTAMP
            );

            CREATE UNIQUE INDEX IF NOT EXISTS idx_rooms_name_nocase
                ON rooms(name COLLATE NOCASE);

            CREATE TABLE IF NOT EXISTS members (
                room_id       INTEGER NOT NULL REFERENCES rooms(id) ON DELETE CASCADE,
                user_id       INTEGER NOT NULL UNIQUE,
                display_name  TEXT NOT NULL,
                username      TEXT,
                joined_at     TEXT NOT NULL DEFAULT CURRENT_TIMESTAMP,
                PRIMARY KEY (room_id, user_id)
            );

            CREATE TABLE IF NOT EXISTS words (
                id          INTEGER PRIMARY KEY AUTOINCREMENT,
                room_id     INTEGER NOT NULL REFERENCES rooms(id) ON DELETE CASCADE,
                cycle       INTEGER NOT NULL,
                author_id   INTEGER NOT NULL,
                word        TEXT NOT NULL,
                used_round  INTEGER,
                created_at  TEXT NOT NULL DEFAULT CURRENT_TIMESTAMP,
                UNIQUE (room_id, cycle, author_id)
            );

            CREATE INDEX IF NOT EXISTS idx_words_available
                ON words(room_id, used_round);

            CREATE TABLE IF NOT EXISTS room_panels (
                room_id       INTEGER NOT NULL REFERENCES rooms(id) ON DELETE CASCADE,
                user_id       INTEGER NOT NULL,
                message_id    INTEGER NOT NULL,
                PRIMARY KEY (room_id, user_id)
            );
            """
        )
        room_columns = {
            str(column["name"])
            for column in connection.execute("PRAGMA table_info(rooms)").fetchall()
        }
        if "last_activity_at" not in room_columns:
            connection.execute(
                """
                ALTER TABLE rooms
                ADD COLUMN last_activity_at TEXT NOT NULL DEFAULT CURRENT_TIMESTAMP
                """
            )
        connection.execute(
            """
            CREATE INDEX IF NOT EXISTS idx_rooms_last_activity
                ON rooms(last_activity_at)
            """
        )


def hash_password(password: str, salt: bytes | None = None) -> tuple[bytes, bytes]:
    actual_salt = salt or secrets.token_bytes(16)
    digest = hashlib.pbkdf2_hmac(
        "sha256", password.encode("utf-8"), actual_salt, PASSWORD_ITERATIONS
    )
    return actual_salt, digest


def verify_password(password: str, salt: bytes, expected_hash: bytes) -> bool:
    _, actual_hash = hash_password(password, salt)
    return hmac.compare_digest(actual_hash, expected_hash)


def db_create_room(
    name: str,
    password: str,
    owner_id: int,
    display_name: str,
    username: str | None,
) -> tuple[bool, str | int]:
    salt, password_hash = hash_password(password)
    try:
        with get_connection() as connection:
            cursor = connection.execute(
                """
                INSERT INTO rooms(name, password_salt, password_hash, owner_id)
                VALUES (?, ?, ?, ?)
                """,
                (name, salt, password_hash, owner_id),
            )
            room_id = int(cursor.lastrowid)
            connection.execute(
                """
                INSERT INTO members(room_id, user_id, display_name, username)
                VALUES (?, ?, ?, ?)
                """,
                (room_id, owner_id, display_name, username),
            )
        return True, room_id
    except sqlite3.IntegrityError as error:
        if "rooms.name" in str(error).lower() or "idx_rooms_name_nocase" in str(error):
            return False, "Комната с таким названием уже существует. Придумай другое."
        if "members.user_id" in str(error):
            return False, "Ты уже состоишь в другой комнате. Сначала выйди из неё."
        logger.exception("Failed to create room")
        return False, "Не удалось создать комнату из-за ошибки базы данных."


def db_get_room(room_id: int) -> dict[str, Any] | None:
    with get_connection() as connection:
        row = connection.execute(
            "SELECT * FROM rooms WHERE id = ?", (room_id,)
        ).fetchone()
        return dict(row) if row else None


def db_get_user_room(user_id: int) -> dict[str, Any] | None:
    with get_connection() as connection:
        row = connection.execute(
            """
            SELECT r.*
            FROM rooms AS r
            JOIN members AS m ON m.room_id = r.id
            WHERE m.user_id = ?
            """,
            (user_id,),
        ).fetchone()
        return dict(row) if row else None


def db_list_open_rooms() -> list[dict[str, Any]]:
    with get_connection() as connection:
        rows = connection.execute(
            """
            SELECT r.id, r.name, r.owner_id, COUNT(m.user_id) AS member_count
            FROM rooms AS r
            JOIN members AS m ON m.room_id = r.id
            GROUP BY r.id
            ORDER BY r.created_at, r.id
            """
        ).fetchall()
        return [dict(row) for row in rows]


def db_get_members(room_id: int) -> list[dict[str, Any]]:
    with get_connection() as connection:
        rows = connection.execute(
            """
            SELECT user_id, display_name, username
            FROM members
            WHERE room_id = ?
            ORDER BY joined_at, user_id
            """,
            (room_id,),
        ).fetchall()
        return [dict(row) for row in rows]


def db_get_panel_message_id(room_id: int, user_id: int) -> int | None:
    with get_connection() as connection:
        row = connection.execute(
            """
            SELECT message_id
            FROM room_panels
            WHERE room_id = ? AND user_id = ?
            """,
            (room_id, user_id),
        ).fetchone()
        return int(row["message_id"]) if row else None


def db_set_panel_message_id(room_id: int, user_id: int, message_id: int) -> None:
    with get_connection() as connection:
        connection.execute(
            """
            INSERT INTO room_panels(room_id, user_id, message_id)
            VALUES (?, ?, ?)
            ON CONFLICT(room_id, user_id)
            DO UPDATE SET message_id = excluded.message_id
            """,
            (room_id, user_id, message_id),
        )


def db_delete_panel_message_id(room_id: int, user_id: int) -> None:
    with get_connection() as connection:
        connection.execute(
            "DELETE FROM room_panels WHERE room_id = ? AND user_id = ?",
            (room_id, user_id),
        )


def db_join_room(
    room_id: int,
    user_id: int,
    display_name: str,
    username: str | None,
    password: str,
) -> tuple[bool, str]:
    try:
        with get_connection() as connection:
            connection.execute("BEGIN IMMEDIATE")
            room = connection.execute(
                "SELECT * FROM rooms WHERE id = ?", (room_id,)
            ).fetchone()
            if room is None:
                return False, "Эта комната уже не существует."
            existing = connection.execute(
                "SELECT room_id FROM members WHERE user_id = ?", (user_id,)
            ).fetchone()
            if existing:
                if int(existing["room_id"]) == room_id:
                    return False, "Ты уже находишься в этой комнате."
                return False, "Ты уже состоишь в другой комнате. Сначала выйди из неё."
            if not verify_password(password, room["password_salt"], room["password_hash"]):
                return False, "Неверный пароль. Попробуй ещё раз."
            connection.execute(
                """
                INSERT INTO members(room_id, user_id, display_name, username)
                VALUES (?, ?, ?, ?)
                ON CONFLICT(room_id, user_id)
                DO UPDATE SET display_name = excluded.display_name,
                              username = excluded.username
                """,
                (room_id, user_id, display_name, username),
            )
            connection.execute(
                "UPDATE rooms SET last_activity_at = CURRENT_TIMESTAMP WHERE id = ?",
                (room_id,),
            )
        return True, "Ты успешно вошёл в комнату."
    except sqlite3.IntegrityError:
        return False, "Не удалось войти: возможно, ты уже вступил в другую комнату."


def db_start_collection(room_id: int) -> bool:
    with get_connection() as connection:
        cursor = connection.execute(
            """
            UPDATE rooms
            SET phase = 'collecting',
                collection_cycle = collection_cycle + 1,
                last_activity_at = CURRENT_TIMESTAMP
            WHERE id = ? AND phase = 'lobby'
            """,
            (room_id,),
        )
        return cursor.rowcount == 1


def db_submit_word(room_id: int, user_id: int, word: str) -> tuple[bool, str, int, int]:
    with get_connection() as connection:
        connection.execute("BEGIN IMMEDIATE")
        room = connection.execute(
            "SELECT phase, collection_cycle FROM rooms WHERE id = ?", (room_id,)
        ).fetchone()
        if room is None:
            return False, "Комната не найдена.", 0, 0
        if room["phase"] not in ("collecting", "refilling"):
            return False, "Сейчас бот не собирает слова. Обнови панель комнаты.", 0, 0
        member = connection.execute(
            "SELECT 1 FROM members WHERE room_id = ? AND user_id = ?",
            (room_id, user_id),
        ).fetchone()
        if not member:
            return False, "Ты больше не состоишь в этой комнате.", 0, 0
        cycle = int(room["collection_cycle"])
        connection.execute(
            """
            INSERT INTO words(room_id, cycle, author_id, word)
            VALUES (?, ?, ?, ?)
            ON CONFLICT(room_id, cycle, author_id)
            DO UPDATE SET word = excluded.word
            """,
            (room_id, cycle, user_id, word),
        )
        connection.execute(
            "UPDATE rooms SET last_activity_at = CURRENT_TIMESTAMP WHERE id = ?",
            (room_id,),
        )
        submitted = int(
            connection.execute(
                """
                SELECT COUNT(*)
                FROM words AS w
                JOIN members AS m ON m.room_id = w.room_id AND m.user_id = w.author_id
                WHERE w.room_id = ? AND w.cycle = ?
                """,
                (room_id, cycle),
            ).fetchone()[0]
        )
        total = int(
            connection.execute(
                "SELECT COUNT(*) FROM members WHERE room_id = ?", (room_id,)
            ).fetchone()[0]
        )
        return True, "Слово сохранено. Другие игроки его не увидят.", submitted, total


def db_get_readiness(room_id: int) -> tuple[list[dict[str, Any]], int, int, str | None]:
    with get_connection() as connection:
        room = connection.execute(
            "SELECT phase, collection_cycle FROM rooms WHERE id = ?", (room_id,)
        ).fetchone()
        if room is None:
            return [], 0, 0, None
        cycle = int(room["collection_cycle"])
        rows = connection.execute(
            """
            SELECT m.user_id, m.display_name,
                   CASE WHEN w.id IS NULL THEN 0 ELSE 1 END AS submitted
            FROM members AS m
            LEFT JOIN words AS w
              ON w.room_id = m.room_id
             AND w.author_id = m.user_id
             AND w.cycle = ?
            WHERE m.room_id = ?
            ORDER BY m.joined_at, m.user_id
            """,
            (cycle, room_id),
        ).fetchall()
        members = [dict(row) for row in rows]
        submitted = sum(int(member["submitted"]) for member in members)
        return members, submitted, len(members), str(room["phase"])


def db_count_available_words(room_id: int) -> int:
    with get_connection() as connection:
        return int(
            connection.execute(
                "SELECT COUNT(*) FROM words WHERE room_id = ? AND used_round IS NULL",
                (room_id,),
            ).fetchone()[0]
        )


def db_begin_refill(room_id: int, expected_round_no: int) -> bool:
    with get_connection() as connection:
        connection.execute("BEGIN IMMEDIATE")
        room = connection.execute(
            "SELECT phase, round_no FROM rooms WHERE id = ?", (room_id,)
        ).fetchone()
        if (
            room is None
            or room["phase"] != "active"
            or int(room["round_no"]) != expected_round_no
        ):
            return False
        available = int(
            connection.execute(
                "SELECT COUNT(*) FROM words WHERE room_id = ? AND used_round IS NULL",
                (room_id,),
            ).fetchone()[0]
        )
        if available > REFILL_THRESHOLD:
            return False
        connection.execute(
            """
            UPDATE rooms
            SET phase = 'refilling',
                collection_cycle = collection_cycle + 1,
                last_activity_at = CURRENT_TIMESTAMP
            WHERE id = ?
            """,
            (room_id,),
        )
        return True


def db_get_round_data(room_id: int) -> tuple[dict[str, Any] | None, list[dict[str, Any]]]:
    with get_connection() as connection:
        room = connection.execute(
            "SELECT * FROM rooms WHERE id = ?", (room_id,)
        ).fetchone()
        if room is None:
            return None, []
        members = connection.execute(
            "SELECT user_id, display_name FROM members WHERE room_id = ? ORDER BY joined_at, user_id",
            (room_id,),
        ).fetchall()
        words = connection.execute(
            """
            SELECT id, author_id, word
            FROM words
            WHERE room_id = ? AND used_round IS NULL
            """,
            (room_id,),
        ).fetchall()
        if not words:
            return {**dict(room), "selected_word": None}, [dict(row) for row in members]
        selected = secrets.choice([dict(row) for row in words])
        return {**dict(room), "selected_word": selected}, [dict(row) for row in members]


def db_commit_round(
    room_id: int,
    word_id: int,
    expected_round_no: int,
    allowed_phases: tuple[str, ...],
) -> bool:
    with get_connection() as connection:
        connection.execute("BEGIN IMMEDIATE")
        room = connection.execute(
            "SELECT phase, round_no, collection_cycle FROM rooms WHERE id = ?",
            (room_id,),
        ).fetchone()
        if (
            room is None
            or room["phase"] not in allowed_phases
            or int(room["round_no"]) != expected_round_no
        ):
            return False

        if room["phase"] == "refilling":
            member_count = int(
                connection.execute(
                    "SELECT COUNT(*) FROM members WHERE room_id = ?", (room_id,)
                ).fetchone()[0]
            )
            submitted_count = int(
                connection.execute(
                    """
                    SELECT COUNT(*)
                    FROM words AS w
                    JOIN members AS m ON m.room_id = w.room_id AND m.user_id = w.author_id
                    WHERE w.room_id = ? AND w.cycle = ?
                    """,
                    (room_id, int(room["collection_cycle"])),
                ).fetchone()[0]
            )
            if submitted_count < member_count:
                return False

        cursor = connection.execute(
            """
            UPDATE words
            SET used_round = ?
            WHERE id = ? AND room_id = ? AND used_round IS NULL
            """,
            (expected_round_no + 1, word_id, room_id),
        )
        if cursor.rowcount != 1:
            return False
        connection.execute(
            """
            UPDATE rooms
            SET phase = 'active',
                round_no = ?,
                last_activity_at = CURRENT_TIMESTAMP
            WHERE id = ?
            """,
            (expected_round_no + 1, room_id),
        )
        return True


def db_end_game(room_id: int) -> bool:
    with get_connection() as connection:
        cursor = connection.execute(
            """
            UPDATE rooms
            SET phase = 'lobby',
                last_activity_at = CURRENT_TIMESTAMP
            WHERE id = ? AND phase IN ('collecting', 'active', 'refilling')
            """,
            (room_id,),
        )
        return cursor.rowcount == 1


def db_leave_room(room_id: int, user_id: int) -> tuple[bool, str]:
    with get_connection() as connection:
        connection.execute("BEGIN IMMEDIATE")
        room = connection.execute(
            "SELECT owner_id, phase FROM rooms WHERE id = ?", (room_id,)
        ).fetchone()
        if room is None:
            return False, "Комната уже удалена."
        connection.execute(
            "DELETE FROM members WHERE room_id = ? AND user_id = ?",
            (room_id, user_id),
        )
        connection.execute(
            "DELETE FROM room_panels WHERE room_id = ? AND user_id = ?",
            (room_id, user_id),
        )
        if int(room["owner_id"]) == user_id:
            new_owner = connection.execute(
                """
                SELECT user_id
                FROM members
                WHERE room_id = ?
                ORDER BY joined_at, user_id
                LIMIT 1
                """,
                (room_id,),
            ).fetchone()
            if new_owner:
                connection.execute(
                    """
                    UPDATE rooms
                    SET owner_id = ?,
                        last_activity_at = CURRENT_TIMESTAMP
                    WHERE id = ?
                    """,
                    (int(new_owner["user_id"]), room_id),
                )
            else:
                connection.execute("DELETE FROM rooms WHERE id = ?", (room_id,))
        else:
            connection.execute(
                "UPDATE rooms SET last_activity_at = CURRENT_TIMESTAMP WHERE id = ?",
                (room_id,),
            )
        return True, "Ты вышел из комнаты."


def db_delete_room(room_id: int, owner_id: int) -> list[dict[str, Any]] | None:
    with get_connection() as connection:
        connection.execute("BEGIN IMMEDIATE")
        room = connection.execute(
            "SELECT owner_id, phase FROM rooms WHERE id = ?", (room_id,)
        ).fetchone()
        if (
            room is None
            or int(room["owner_id"]) != owner_id
            or room["phase"] != "lobby"
        ):
            return None
        members = connection.execute(
            "SELECT user_id, display_name FROM members WHERE room_id = ?", (room_id,)
        ).fetchall()
        result = [dict(row) for row in members]
        connection.execute("DELETE FROM rooms WHERE id = ?", (room_id,))
        return result


def db_cleanup_expired_rooms(hours: int = 24) -> list[dict[str, Any]]:
    with get_connection() as connection:
        connection.execute("BEGIN IMMEDIATE")
        cutoff = f"-{hours} hours"
        rooms = connection.execute(
            """
            SELECT r.id, r.name
            FROM rooms AS r
            WHERE datetime(r.last_activity_at) <= datetime('now', ?)
            """,
            (cutoff,),
        ).fetchall()
        expired: list[dict[str, Any]] = []
        for room in rooms:
            room_id = int(room["id"])
            members = connection.execute(
                "SELECT user_id, display_name FROM members WHERE room_id = ?",
                (room_id,),
            ).fetchall()
            expired.append({
                "id": room_id,
                "name": str(room["name"]),
                "members": [dict(member) for member in members],
            })
            connection.execute("DELETE FROM rooms WHERE id = ?", (room_id,))
        return expired


def db_touch_room(room_id: int) -> bool:
    with get_connection() as connection:
        cursor = connection.execute(
            """
            UPDATE rooms
            SET last_activity_at = CURRENT_TIMESTAMP
            WHERE id = ?
            """,
            (room_id,),
        )
        return cursor.rowcount == 1


# ---------------------------------------------------------------------------
# Telegram UI and state machine
# ---------------------------------------------------------------------------


class CreateRoom(StatesGroup):
    waiting_for_name = State()
    waiting_for_password = State()


class JoinRoom(StatesGroup):
    waiting_for_password = State()


class SubmitWord(StatesGroup):
    waiting_for_word = State()
    waiting_for_confirmation = State()


dp = Dispatcher()
# Protect round creation from double-clicks and simultaneous admin callbacks.
game_lock = asyncio.Lock()


def user_display_name(user: Any) -> str:
    name = (getattr(user, "full_name", None) or "Игрок").replace("\n", " ").strip()
    return name[:80] or "Игрок"


def member_mention(member: dict[str, Any]) -> str:
    display_name = " ".join(str(member.get("display_name") or "").split())
    username = str(member.get("username") or "").strip()
    valid_username = re.fullmatch(r"[A-Za-z0-9_]{5,32}", username) is not None
    has_readable_name = any(
        unicodedata.category(character)[0] in {"L", "N"}
        for character in display_name
    )
    if not has_readable_name:
        display_name = f"@{username}" if valid_username else f"Игрок {member['user_id']}"
    href = f"tg://user?id={int(member['user_id'])}"
    return (
        f'<a href="{href}">'
        f"{html.escape(display_name)}</a>"
    )


async def set_word_input_state(bot: Bot, user_id: int, room_id: int) -> None:
    key = StorageKey(bot_id=bot.id, chat_id=user_id, user_id=user_id)
    await dp.storage.set_state(key, SubmitWord.waiting_for_word)
    await dp.storage.set_data(key, {"word_room_id": room_id})


def main_menu_keyboard(has_room: bool) -> InlineKeyboardMarkup:
    if has_room:
        rows = [[InlineKeyboardButton(text="🏠 Моя комната", callback_data="menu:room")]]
    else:
        rows = [
            [InlineKeyboardButton(text="➕ Создать комнату", callback_data="menu:create")],
            [InlineKeyboardButton(text="🚪 Войти в комнату", callback_data="menu:join")],
        ]
    return InlineKeyboardMarkup(inline_keyboard=rows)


def room_keyboard(room: dict[str, Any], user_id: int) -> InlineKeyboardMarkup:
    room_id = int(room["id"])
    owner = int(room["owner_id"]) == user_id
    phase = room["phase"]
    round_no = int(room["round_no"])
    rows: list[list[InlineKeyboardButton]] = []

    if phase in ("collecting", "refilling"):
        rows.append([
            InlineKeyboardButton(
                text="✍️ Отправить / изменить слово",
                callback_data=f"word:{room_id}",
            )
        ])
        if owner:
            rows.append([
                InlineKeyboardButton(
                    text="🔎 Проверить готовность", callback_data=f"ready:{room_id}"
                )
            ])
            rows.append([
                InlineKeyboardButton(
                    text="🎲 Начать раунд",
                    callback_data=f"round:{room_id}:{round_no}",
                )
            ])
            rows.append([
                InlineKeyboardButton(
                    text="⏹ Завершить игру", callback_data=f"end:{room_id}"
                )
            ])
    elif phase == "active":
        if owner:
            rows.append([
                InlineKeyboardButton(
                    text="⏭ Следующий раунд",
                    callback_data=f"next:{room_id}:{round_no}",
                )
            ])
            rows.append([
                InlineKeyboardButton(
                    text="⏹ Завершить игру", callback_data=f"end:{room_id}"
                )
            ])
    elif phase == "lobby":
        if owner:
            rows.append([
                InlineKeyboardButton(
                    text="🚀 Начать сбор слов", callback_data=f"start:{room_id}"
                )
            ])
            rows.append([
                InlineKeyboardButton(
                    text="🗑 Закрыть комнату", callback_data=f"close:{room_id}"
                )
            ])
    rows.append([
        InlineKeyboardButton(
            text="🚪 ВЫЙТИ ИЗ ИГРЫ",
            callback_data=f"leave:{room_id}",
        )
    ])

    rows.append([
        InlineKeyboardButton(text="🔄 Обновить", callback_data=f"refresh:{room_id}")
    ])
    rows.append([InlineKeyboardButton(text="⬅️ Главное меню", callback_data="menu:home")])
    return InlineKeyboardMarkup(inline_keyboard=rows)


def room_panel_text(room: dict[str, Any], members: list[dict[str, Any]]) -> str:
    phase_names = {
        "lobby": "Ожидание игроков",
        "collecting": "Сбор слов перед игрой",
        "active": "Игра идёт",
        "refilling": "Пополнение банка слов",
    }
    owner = next(
        (m for m in members if int(m["user_id"]) == int(room["owner_id"])),
        None,
    )
    owner_name = member_mention(owner) if owner else "неизвестен"
    available = db_count_available_words(int(room["id"]))
    lines = [
        f"🏠 Комната: {html.escape(str(room['name']))}",
        f"👑 Создатель: {owner_name}",
        f"👥 Игроков: {len(members)}",
        f"📌 Статус: {phase_names.get(room['phase'], room['phase'])}",
        f"📚 Слов в банке: {available}",
        "",
        "Участники:",
    ]
    for member in members:
        prefix = "👑 " if int(member["user_id"]) == int(room["owner_id"]) else "• "
        lines.append(prefix + member_mention(member))

    if room["phase"] == "lobby":
        lines.extend(["", "Создатель может начать сбор слов, когда все готовы."])
    elif room["phase"] == "collecting":
        _, submitted, total, _ = db_get_readiness(int(room["id"]))
        lines.extend([
            "",
            f"Слова отправили: {submitted} из {total}.",
            "Создатель может запустить раунд, даже если кто-то не отправил слово.",
        ])
    elif room["phase"] == "refilling":
        _, submitted, total, _ = db_get_readiness(int(room["id"]))
        lines.extend([
            "",
            f"Новые слова отправили: {submitted} из {total}.",
            "Для следующего раунда нужно слово от каждого участника.",
        ])
    else:
        lines.extend([
            "",
            f"Текущий раунд: {int(room['round_no'])}.",
            "После обсуждения создатель может запустить следующий раунд.",
        ])
    lines.extend([
        "",
        "Роли и загаданное слово бот отправляет каждому игроку только в личные сообщения.",
    ])
    return "\n".join(lines)


async def show_menu(message: Message, user_id: int, text: str = "Выбери действие:") -> None:
    current_room = db_get_user_room(user_id)
    await message.answer(text, reply_markup=main_menu_keyboard(current_room is not None))


async def delete_sensitive_message(message: Message) -> None:
    """Best-effort deletion of a password message from the private chat."""
    try:
        await message.delete()
    except Exception as error:
        logger.debug("Could not delete sensitive input message: %s", error)


async def show_room_message(message: Message, room_id: int, user_id: int) -> None:
    room = db_get_room(room_id)
    if room is None:
        await message.answer("Комната не найдена или уже удалена.")
        return
    member_ids = {int(member["user_id"]) for member in db_get_members(room_id)}
    if user_id not in member_ids:
        await message.answer("Ты не состоишь в этой комнате.")
        return
    db_touch_room(room_id)
    members = db_get_members(room_id)
    text = room_panel_text(room, members)
    markup = room_keyboard(room, user_id)
    panel_message_id = db_get_panel_message_id(room_id, user_id)
    if panel_message_id is not None:
        try:
            await message.bot.edit_message_text(
                chat_id=user_id,
                message_id=panel_message_id,
                text=text,
                reply_markup=markup,
                parse_mode="HTML",
            )
            return
        except TelegramBadRequest as error:
            if "message is not modified" in str(error).lower():
                return
            if not any(
                phrase in str(error).lower()
                for phrase in ("message to edit not found", "message_id_invalid")
            ):
                logger.warning("Failed to update room panel for %s: %s", user_id, error)
                return
    panel = await message.answer(text, reply_markup=markup, parse_mode="HTML")
    db_set_panel_message_id(room_id, user_id, panel.message_id)


async def replace_room_panel(message: Message, room_id: int, user_id: int) -> None:
    panel_message_id = db_get_panel_message_id(room_id, user_id)
    if panel_message_id is not None:
        try:
            await message.bot.delete_message(
                chat_id=user_id,
                message_id=panel_message_id,
            )
        except TelegramBadRequest as error:
            if "message to delete not found" not in str(error).lower():
                logger.warning("Failed to move room panel for %s: %s", user_id, error)
                await show_room_message(message, room_id, user_id)
                return
        db_delete_panel_message_id(room_id, user_id)
    await show_room_message(message, room_id, user_id)


async def edit_room_panel(callback: CallbackQuery, room_id: int) -> None:
    user_id = callback.from_user.id
    room = db_get_room(room_id)
    if room is None:
        if callback.message:
            await callback.message.answer("Комната уже удалена. Вернись в главное меню: /start")
        return
    members = db_get_members(room_id)
    if user_id not in {int(member["user_id"]) for member in members}:
        if callback.message:
            await callback.message.answer("Ты не состоишь в этой комнате.")
        return
    db_touch_room(room_id)
    text = room_panel_text(room, members)
    markup = room_keyboard(room, user_id)
    if callback.message:
        try:
            await callback.message.edit_text(text, reply_markup=markup, parse_mode="HTML")
            db_set_panel_message_id(room_id, user_id, callback.message.message_id)
        except TelegramBadRequest as error:
            if "message is not modified" not in str(error).lower():
                panel = await callback.message.answer(
                    text, reply_markup=markup, parse_mode="HTML"
                )
                db_set_panel_message_id(room_id, user_id, panel.message_id)


async def send_room_panels(bot: Bot, room_id: int) -> None:
    room = db_get_room(room_id)
    if room is None:
        return
    members = db_get_members(room_id)
    text = room_panel_text(room, members)
    markup_by_user = {
        int(member["user_id"]): room_keyboard(room, int(member["user_id"]))
        for member in members
    }
    for member in members:
        user_id = int(member["user_id"])
        message_id = db_get_panel_message_id(room_id, user_id)
        if message_id is None:
            continue
        try:
            await bot.edit_message_text(
                chat_id=user_id,
                message_id=message_id,
                text=text,
                reply_markup=markup_by_user[user_id],
                parse_mode="HTML",
            )
        except TelegramBadRequest as error:
            if message_id is not None and any(
                phrase in str(error).lower()
                for phrase in ("message to edit not found", "message_id_invalid")
            ):
                try:
                    panel = await bot.send_message(
                        user_id,
                        text,
                        reply_markup=markup_by_user[user_id],
                        parse_mode="HTML",
                    )
                    db_set_panel_message_id(room_id, user_id, panel.message_id)
                except Exception:
                    logger.exception("Failed to replace room panel for %s", user_id)
            elif "message is not modified" not in str(error).lower():
                logger.warning("Failed to update room panel for %s: %s", user_id, error)
        except Exception:
            logger.exception("Failed to update room panel for %s", user_id)


async def prompt_room_for_words(bot: Bot, room_id: int, text: str) -> None:
    for member in db_get_members(room_id):
        member_id = int(member["user_id"])
        await set_word_input_state(bot, member_id, room_id)
        try:
            await bot.send_message(member_id, text)
        except Exception:
            logger.exception("Failed to prompt member %s for a word", member_id)


async def notify_room(
    bot: Bot, room_id: int, text: str, parse_mode: str | None = None
) -> list[str]:
    failed: list[str] = []
    for member in db_get_members(room_id):
        try:
            await bot.send_message(
                int(member["user_id"]), text, parse_mode=parse_mode
            )
        except (TelegramForbiddenError, TelegramBadRequest) as error:
            logger.warning("Cannot notify user %s: %s", member["user_id"], error)
            failed.append(member["display_name"])
        except Exception:
            logger.exception("Failed to notify user %s", member["user_id"])
            failed.append(member["display_name"])
    return failed


async def start_round(
    callback: CallbackQuery,
    room_id: int,
    expected_round_no: int,
    allowed_phases: tuple[str, ...],
) -> None:
    """Deliver private roles first; consume the word only if every DM succeeds."""
    user_id = callback.from_user.id
    room = db_get_room(room_id)
    if room is None:
        await callback.answer("Комната не найдена.", show_alert=True)
        return
    if int(room["owner_id"]) != user_id:
        await callback.answer("Начать раунд может только создатель комнаты.", show_alert=True)
        return
    if room["phase"] not in allowed_phases:
        await callback.answer("Это действие уже недоступно. Обнови комнату.", show_alert=True)
        return
    if int(room["round_no"]) != expected_round_no:
        await callback.answer("Эта кнопка устарела. Обнови комнату.", show_alert=True)
        return

    members = db_get_members(room_id)
    if len(members) < MIN_PLAYERS:
        await callback.answer(
            f"Для игры нужно минимум {MIN_PLAYERS} игрока.", show_alert=True
        )
        return

    if room["phase"] == "refilling":
        submitted_members, submitted, total, _ = db_get_readiness(room_id)
        if submitted < total:
            missing = [m["display_name"] for m in submitted_members if not m["submitted"]]
            await callback.answer(
                "Не все отправили слова: " + ", ".join(missing), show_alert=True
            )
            return

    round_data, members = db_get_round_data(room_id)
    if not round_data or not round_data.get("selected_word"):
        await callback.answer("Банк слов пуст. Сначала соберите слова.", show_alert=True)
        return

    selected_word = round_data["selected_word"]
    word_author_id = int(selected_word["author_id"])
    member_ids = [int(member["user_id"]) for member in members]
    spy_candidates = [member_id for member_id in member_ids if member_id != word_author_id]
    if len(spy_candidates) < 1:
        await callback.answer("Не удалось выбрать шпиона. Проверь состав комнаты.", show_alert=True)
        return

    spy_id = secrets.choice(spy_candidates)
    first_speaker_candidates = [member_id for member_id in member_ids if member_id != spy_id]
    if not first_speaker_candidates:
        await callback.answer("Не удалось выбрать первого игрока.", show_alert=True)
        return
    first_speaker_id = secrets.choice(first_speaker_candidates)
    first_speaker_name = next(
        member["display_name"]
        for member in members
        if int(member["user_id"]) == first_speaker_id
    )
    next_round_no = expected_round_no + 1

    delivered: list[int] = []
    failed_names: list[str] = []
    for member in members:
        member_id = int(member["user_id"])
        role_text = (
            "🕵️ ТЫ ШПИОН!\n\nПопробуй вычислить загаданное слово по описаниям остальных."
            if member_id == spy_id
            else f"🔐 Твоё слово: {selected_word['word']}"
        )
        text = (
            f"Раунд {next_round_no}\n\n"
            f"{role_text}\n\n"
            f"Первым начинает: {first_speaker_name}."
        )
        try:
            await callback.bot.send_message(member_id, text)
            delivered.append(member_id)
        except Exception as error:
            logger.warning("Failed to send round DM to %s: %s", member_id, error)
            failed_names.append(member["display_name"])

    if failed_names:
        for delivered_id in delivered:
            try:
                await callback.bot.send_message(
                    delivered_id,
                    "⚠️ Раунд отменён: не удалось доставить сообщение одному из игроков. "
                    "Игнорируй предыдущее назначение роли.",
                )
            except Exception:
                logger.exception("Failed to send cancellation notice to %s", delivered_id)
        await callback.answer("Не удалось разослать роли всем. Раунд не начат.", show_alert=True)
        if callback.message:
            await callback.message.answer(
                "Не удалось отправить личное сообщение игрокам: "
                + ", ".join(failed_names)
                + ". Пусть они откроют бота и нажмут /start, затем попробуйте снова."
            )
        return

    committed = db_commit_round(
        room_id,
        int(selected_word["id"]),
        expected_round_no,
        allowed_phases,
    )
    if not committed:
        for delivered_id in delivered:
            try:
                await callback.bot.send_message(
                    delivered_id,
                    "⚠️ Раунд отменён из-за изменения состояния комнаты. Игнорируй предыдущее сообщение.",
                )
            except Exception:
                logger.exception("Failed to send rollback notice to %s", delivered_id)
        await callback.answer("Не удалось подтвердить запуск раунда. Обнови комнату.", show_alert=True)
        return

    await callback.answer("Раунд начат! Роли отправлены в личные сообщения.")
    await edit_room_panel(callback, room_id)


# ---------------------------------------------------------------------------
# Commands
# ---------------------------------------------------------------------------


@dp.message(CommandStart(), F.chat.type == "private")
async def command_start(message: Message, state: FSMContext) -> None:
    await state.clear()
    await show_menu(
        message,
        message.from_user.id,
        "Привет! Это бот для игры в «Шпиона».\n\nСоздай комнату или присоединись к уже открытой.",
    )


@dp.message(Command("menu"), F.chat.type == "private")
async def command_menu(message: Message, state: FSMContext) -> None:
    await state.clear()
    await show_menu(message, message.from_user.id)


@dp.message(Command("cancel"), F.chat.type == "private")
async def command_cancel(message: Message, state: FSMContext) -> None:
    await state.clear()
    await show_menu(message, message.from_user.id, "Действие отменено.")


# ---------------------------------------------------------------------------
# Main menu callbacks
# ---------------------------------------------------------------------------


@dp.callback_query(F.data == "menu:home")
async def callback_home(callback: CallbackQuery, state: FSMContext) -> None:
    await state.clear()
    await callback.answer()
    if callback.message:
        current_room = db_get_user_room(callback.from_user.id)
        await callback.message.answer(
            "Главное меню:",
            reply_markup=main_menu_keyboard(current_room is not None),
        )


@dp.callback_query(F.data == "menu:create")
async def callback_create_room(callback: CallbackQuery, state: FSMContext) -> None:
    if db_get_user_room(callback.from_user.id):
        await callback.answer("Ты уже состоишь в комнате.", show_alert=True)
        return
    await state.set_state(CreateRoom.waiting_for_name)
    await callback.answer()
    if callback.message:
        await callback.message.answer(
            f"Введи название комнаты (до {MAX_ROOM_NAME_LENGTH} символов).\n"
            "Для отмены отправь /cancel."
        )


@dp.message(CreateRoom.waiting_for_name, F.chat.type == "private")
async def process_room_name(message: Message, state: FSMContext) -> None:
    name = " ".join((message.text or "").split())
    if not name:
        await message.answer("Название не должно быть пустым. Попробуй ещё раз:")
        return
    if len(name) > MAX_ROOM_NAME_LENGTH:
        await message.answer(f"Слишком длинное название. Максимум {MAX_ROOM_NAME_LENGTH} символов:")
        return
    await state.update_data(room_name=name)
    await state.set_state(CreateRoom.waiting_for_password)
    await message.answer(
        f"Теперь придумай пароль комнаты (от {MIN_PASSWORD_LENGTH} до {MAX_PASSWORD_LENGTH} символов).\n"
        "Пароль будет храниться в базе в виде хеша, а не открытым текстом."
    )


@dp.message(CreateRoom.waiting_for_password, F.chat.type == "private")
async def process_room_password(message: Message, state: FSMContext) -> None:
    password = (message.text or "").strip()
    await delete_sensitive_message(message)
    if not MIN_PASSWORD_LENGTH <= len(password) <= MAX_PASSWORD_LENGTH:
        await message.answer(
            f"Пароль должен содержать от {MIN_PASSWORD_LENGTH} до {MAX_PASSWORD_LENGTH} символов."
        )
        return
    data = await state.get_data()
    success, result = db_create_room(
        str(data["room_name"]),
        password,
        message.from_user.id,
        user_display_name(message.from_user),
        message.from_user.username,
    )
    await state.clear()
    if not success:
        await message.answer(str(result))
        await show_menu(message, message.from_user.id)
        return
    await message.answer(f"Комната «{data['room_name']}» создана. Ты её создатель.")
    await show_room_message(message, int(result), message.from_user.id)


@dp.callback_query(F.data == "menu:join")
async def callback_join_room(callback: CallbackQuery) -> None:
    if db_get_user_room(callback.from_user.id):
        await callback.answer("Ты уже состоишь в комнате.", show_alert=True)
        return
    rooms = db_list_open_rooms()
    await callback.answer()
    if not rooms:
        if callback.message:
            await callback.message.answer("Сейчас нет комнат, в которые можно войти.")
        return
    keyboard = [
        [
            InlineKeyboardButton(
                text=f"{room['name']} · {room['member_count']} игрок(ов)",
                callback_data=f"join:{room['id']}",
            )
        ]
        for room in rooms
    ]
    keyboard.append([InlineKeyboardButton(text="⬅️ Назад", callback_data="menu:home")])
    if callback.message:
        await callback.message.answer(
            "Выбери комнату. Можно войти даже в уже начавшуюся игру:",
            reply_markup=InlineKeyboardMarkup(inline_keyboard=keyboard),
        )


@dp.callback_query(F.data.startswith("join:"))
async def callback_select_room(callback: CallbackQuery, state: FSMContext) -> None:
    try:
        room_id = int((callback.data or "").split(":", 1)[1])
    except (ValueError, IndexError):
        await callback.answer("Некорректная комната.", show_alert=True)
        return
    room = db_get_room(room_id)
    if not room:
        await callback.answer("Комната уже удалена.", show_alert=True)
        return
    if db_get_user_room(callback.from_user.id):
        await callback.answer("Ты уже состоишь в комнате.", show_alert=True)
        return
    await state.update_data(room_id=room_id)
    await state.set_state(JoinRoom.waiting_for_password)
    await callback.answer()
    if callback.message:
        await callback.message.answer(f"Введи пароль от комнаты «{room['name']}»:")


@dp.message(JoinRoom.waiting_for_password, F.chat.type == "private")
async def process_join_password(message: Message, state: FSMContext) -> None:
    password = (message.text or "").strip()
    await delete_sensitive_message(message)
    data = await state.get_data()
    room_id = int(data["room_id"])
    async with game_lock:
        success, result = db_join_room(
            room_id,
            message.from_user.id,
            user_display_name(message.from_user),
            message.from_user.username,
            password,
        )
    if not success:
        await message.answer(result + "\nМожешь попробовать ещё раз или отправить /cancel.")
        return
    await state.clear()
    await message.answer(result)
    await show_room_message(message, room_id, message.from_user.id)
    room = db_get_room(room_id)
    if room:
        await notify_room(
            message.bot,
            room_id,
            f"👋 В комнату «{html.escape(str(room['name']))}» присоединился игрок: "
            f"{member_mention({'user_id': message.from_user.id, 'display_name': user_display_name(message.from_user), 'username': message.from_user.username})}.",
            parse_mode="HTML",
        )
        await send_room_panels(message.bot, room_id)
        if room["phase"] in ("collecting", "refilling"):
            await prompt_room_for_words(
                message.bot,
                room_id,
                "📝 Ты присоединился во время сбора слов.\n"
                "Сразу отправь одно слово или короткое словосочетание "
                f"(до {MAX_WORD_LENGTH} символов).",
            )


@dp.callback_query(F.data == "menu:room")
async def callback_my_room(callback: CallbackQuery) -> None:
    room = db_get_user_room(callback.from_user.id)
    if not room:
        await callback.answer("Ты сейчас не состоишь в комнате.", show_alert=True)
        return
    await callback.answer()
    if callback.message:
        await show_room_message(callback.message, int(room["id"]), callback.from_user.id)


# ---------------------------------------------------------------------------
# Room actions
# ---------------------------------------------------------------------------


@dp.callback_query(F.data.startswith("refresh:"))
async def callback_refresh_room(callback: CallbackQuery) -> None:
    room_id = int((callback.data or "").split(":", 1)[1])
    db_touch_room(room_id)
    await callback.answer()
    await edit_room_panel(callback, room_id)


@dp.callback_query(F.data.startswith("start:"))
async def callback_start_collection(callback: CallbackQuery) -> None:
    room_id = int((callback.data or "").split(":", 1)[1])
    room = db_get_room(room_id)
    if not room or int(room["owner_id"]) != callback.from_user.id:
        await callback.answer("Только создатель комнаты может начать игру.", show_alert=True)
        return
    if len(db_get_members(room_id)) < MIN_PLAYERS:
        await callback.answer(f"Нужно минимум {MIN_PLAYERS} игрока.", show_alert=True)
        return
    if not db_start_collection(room_id):
        await callback.answer("Комната уже не ожидает начала игры.", show_alert=True)
        return
    await callback.answer("Сбор слов начался.")
    await prompt_room_for_words(
        callback.bot,
        room_id,
        "📝 Начался сбор слов для банка.\n"
        "Сразу отправь одно слово или короткое словосочетание "
        f"(до {MAX_WORD_LENGTH} символов).\n"
        "Слово увидишь только ты и бот не покажет его другим игрокам.",
    )
    await edit_room_panel(callback, room_id)


@dp.callback_query(F.data.startswith("word:"))
async def callback_add_word(callback: CallbackQuery, state: FSMContext) -> None:
    room_id = int((callback.data or "").split(":", 1)[1])
    room = db_get_room(room_id)
    if not room or room["phase"] not in ("collecting", "refilling"):
        await callback.answer("Сейчас сбор слов не идёт.", show_alert=True)
        return
    members = {int(member["user_id"]) for member in db_get_members(room_id)}
    if callback.from_user.id not in members:
        await callback.answer("Ты не состоишь в этой комнате.", show_alert=True)
        return
    await state.update_data(word_room_id=room_id)
    await state.set_state(SubmitWord.waiting_for_word)
    await callback.answer()
    if callback.message:
        await callback.message.answer(
            f"Отправь одно слово или короткое словосочетание (до {MAX_WORD_LENGTH} символов).\n"
            "Повторная отправка заменит твоё предыдущее слово в этом цикле. Для отмены — /cancel."
        )


@dp.message(SubmitWord.waiting_for_word, F.chat.type == "private")
async def process_word(message: Message, state: FSMContext) -> None:
    word = " ".join((message.text or "").split())
    if not word:
        await message.answer("Слово не должно быть пустым. Попробуй ещё раз:")
        return
    if len(word) > MAX_WORD_LENGTH:
        await message.answer(f"Слишком длинно. Максимум {MAX_WORD_LENGTH} символов:")
        return
    await state.update_data(pending_word=word)
    await state.set_state(SubmitWord.waiting_for_confirmation)
    await message.answer(
        f"Подходит ли слово «{html.escape(word)}»?",
        reply_markup=InlineKeyboardMarkup(
            inline_keyboard=[
                [
                    InlineKeyboardButton(
                        text="✅ Да, отправить",
                        callback_data="wordconfirm:yes",
                    ),
                    InlineKeyboardButton(
                        text="✏️ Изменить слово",
                        callback_data="wordconfirm:edit",
                    ),
                ]
            ]
        ),
        parse_mode="HTML",
    )


@dp.callback_query(F.data == "wordconfirm:edit")
async def callback_edit_word(callback: CallbackQuery, state: FSMContext) -> None:
    data = await state.get_data()
    if "word_room_id" not in data or await state.get_state() != SubmitWord.waiting_for_confirmation.state:
        await callback.answer("Подтверждение слова уже недоступно.", show_alert=True)
        return
    await state.set_state(SubmitWord.waiting_for_word)
    await callback.answer()
    if callback.message:
        await callback.message.answer("Хорошо, отправь новое слово или словосочетание:")


@dp.callback_query(F.data == "wordconfirm:yes")
async def callback_confirm_word(callback: CallbackQuery, state: FSMContext) -> None:
    data = await state.get_data()
    if "word_room_id" not in data or "pending_word" not in data:
        await callback.answer("Слово уже обработано или устарело.", show_alert=True)
        return
    room_id = int(data["word_room_id"])
    word = str(data["pending_word"])
    async with game_lock:
        success, result, submitted, total = db_submit_word(
            room_id, callback.from_user.id, word
        )
    if not success:
        await state.clear()
        await callback.answer(result, show_alert=True)
        return
    await state.clear()
    await callback.answer("Слово отправлено.")
    if callback.message:
        await callback.message.answer(f"✅ {result}\nСлова отправили: {submitted} из {total}.")
        await replace_room_panel(callback.message, room_id, callback.from_user.id)


@dp.callback_query(F.data.startswith("ready:"))
async def callback_check_readiness(callback: CallbackQuery) -> None:
    room_id = int((callback.data or "").split(":", 1)[1])
    room = db_get_room(room_id)
    if not room or int(room["owner_id"]) != callback.from_user.id:
        await callback.answer("Проверить готовность может только создатель.", show_alert=True)
        return
    if room["phase"] not in ("collecting", "refilling"):
        await callback.answer("Сейчас нет активного сбора слов.", show_alert=True)
        return
    db_touch_room(room_id)
    members, submitted, total, _ = db_get_readiness(room_id)
    lines = [f"Готовность: {submitted}/{total}", ""]
    for member in members:
        symbol = "✅" if member["submitted"] else "⏳"
        lines.append(f"{symbol} {member['display_name']}")
    if callback.message:
        await callback.message.answer("\n".join(lines))
    await callback.answer()


@dp.callback_query(F.data.startswith("round:"))
async def callback_start_round(callback: CallbackQuery) -> None:
    try:
        _, room_id_text, expected_round_text = (callback.data or "").split(":", 2)
        room_id = int(room_id_text)
        expected_round_no = int(expected_round_text)
    except (ValueError, TypeError):
        await callback.answer("Некорректная команда.", show_alert=True)
        return
    async with game_lock:
        await start_round(
            callback,
            room_id,
            expected_round_no,
            ("collecting", "refilling"),
        )


@dp.callback_query(F.data.startswith("next:"))
async def callback_next_round(callback: CallbackQuery) -> None:
    try:
        _, room_id_text, expected_round_text = (callback.data or "").split(":", 2)
        room_id = int(room_id_text)
        expected_round_no = int(expected_round_text)
    except (ValueError, TypeError):
        await callback.answer("Некорректная команда.", show_alert=True)
        return

    async with game_lock:
        room = db_get_room(room_id)
        if not room or int(room["owner_id"]) != callback.from_user.id:
            await callback.answer("Только создатель может запустить следующий раунд.", show_alert=True)
            return
        if room["phase"] != "active" or int(room["round_no"]) != expected_round_no:
            await callback.answer("Эта кнопка устарела. Обнови комнату.", show_alert=True)
            return
        available = db_count_available_words(room_id)
        if available <= REFILL_THRESHOLD:
            if not db_begin_refill(room_id, expected_round_no):
                await callback.answer("Не удалось начать пополнение. Обнови комнату.", show_alert=True)
                return
            await callback.answer("Пора пополнить банк слов.")
            await prompt_room_for_words(
                callback.bot,
                room_id,
                f"📚 В банке осталось {available} слов.\n\n"
                "Сразу отправь новое слово или короткое словосочетание "
                f"(до {MAX_WORD_LENGTH} символов).\n"
                "Старые неиспользованные слова останутся в банке.",
            )
            await edit_room_panel(callback, room_id)
            return
        await start_round(callback, room_id, expected_round_no, ("active",))


@dp.callback_query(F.data.startswith("end:"))
async def callback_end_game(callback: CallbackQuery) -> None:
    room_id = int((callback.data or "").split(":", 1)[1])
    room = db_get_room(room_id)
    if not room or int(room["owner_id"]) != callback.from_user.id:
        await callback.answer("Завершить игру может только создатель.", show_alert=True)
        return
    async with game_lock:
        ended = db_end_game(room_id)
    if not ended:
        await callback.answer("Игра уже завершена или комната находится в лобби.", show_alert=True)
        return
    await callback.answer("Игра завершена.")
    await notify_room(
        callback.bot,
        room_id,
        "⏹ Создатель завершил игру. Комната снова открыта для ожидания. "
        "Можно начать новый сбор слов или выйти из комнаты.",
    )
    await edit_room_panel(callback, room_id)


@dp.callback_query(F.data.startswith("leave:"))
async def callback_leave_room(callback: CallbackQuery) -> None:
    room_id = int((callback.data or "").split(":", 1)[1])
    async with game_lock:
        success, result = db_leave_room(room_id, callback.from_user.id)
    await callback.answer(result, show_alert=not success)
    if success:
        await notify_room(
            callback.bot,
            room_id,
            f"Игрок {member_mention({'user_id': callback.from_user.id, 'display_name': user_display_name(callback.from_user), 'username': callback.from_user.username})} вышел из комнаты.",
            parse_mode="HTML",
        )
        await send_room_panels(callback.bot, room_id)
        if callback.message:
            current_room = db_get_user_room(callback.from_user.id)
            await callback.message.answer(
                result, reply_markup=main_menu_keyboard(current_room is not None)
            )


@dp.callback_query(F.data.startswith("close:"))
async def callback_close_room(callback: CallbackQuery) -> None:
    room_id = int((callback.data or "").split(":", 1)[1])
    room = db_get_room(room_id)
    if not room or int(room["owner_id"]) != callback.from_user.id:
        await callback.answer("Закрыть комнату может только создатель.", show_alert=True)
        return
    if room["phase"] != "lobby":
        await callback.answer("Сначала заверши игру — затем можно удалить комнату.", show_alert=True)
        return
    keyboard = InlineKeyboardMarkup(
        inline_keyboard=[
            [InlineKeyboardButton(text="Да, удалить комнату", callback_data=f"closeyes:{room_id}")],
            [InlineKeyboardButton(text="Отмена", callback_data=f"closeno:{room_id}")],
        ]
    )
    await callback.answer()
    if callback.message:
        await callback.message.answer(
            f"Точно удалить комнату «{room['name']}»? Все участники будут выведены, а банк слов удалён.",
            reply_markup=keyboard,
        )


@dp.callback_query(F.data.startswith("closeno:"))
async def callback_cancel_close(callback: CallbackQuery) -> None:
    room_id = int((callback.data or "").split(":", 1)[1])
    await callback.answer()
    await edit_room_panel(callback, room_id)


@dp.callback_query(F.data.startswith("closeyes:"))
async def callback_confirm_close(callback: CallbackQuery) -> None:
    room_id = int((callback.data or "").split(":", 1)[1])
    members = db_delete_room(room_id, callback.from_user.id)
    if members is None:
        await callback.answer("Не удалось удалить комнату.", show_alert=True)
        return
    await callback.answer("Комната удалена.")
    for member in members:
        if int(member["user_id"]) == callback.from_user.id:
            continue
        try:
            await callback.bot.send_message(
                int(member["user_id"]),
                "🗑 Создатель удалил комнату. Ты больше не состоишь в ней.",
            )
        except Exception:
            logger.exception("Failed to notify member about room deletion")
    if callback.message:
        await callback.message.answer(
            "Комната удалена.", reply_markup=main_menu_keyboard(False)
        )


# ---------------------------------------------------------------------------
# Fallback and startup
# ---------------------------------------------------------------------------


@dp.message(F.chat.type == "private")
async def fallback_message(message: Message) -> None:
    await show_menu(
        message,
        message.from_user.id,
        "Не понял сообщение. Используй кнопки ниже или команду /start.",
    )


async def main() -> None:
    if not BOT_TOKEN:
        raise RuntimeError(
            "BOT_TOKEN is not set. Put your Telegram bot token in the .env file."
        )
    init_db()
    bot = Bot(token=BOT_TOKEN)
    me = await bot.get_me()
    logger.info("Starting @%s (database: %s)", me.username, DB_PATH)

    async def cleanup_expired_rooms_once() -> None:
        expired_rooms = db_cleanup_expired_rooms(24)
        for room in expired_rooms:
            logger.info("Deleted inactive room %s (%s)", room["id"], room["name"])
            for member in room["members"]:
                try:
                    await bot.send_message(
                        int(member["user_id"]),
                        f"🗑 Комната «{room['name']}» удалена автоматически "
                        "после 24 часов без активности.",
                    )
                except Exception:
                    logger.debug(
                        "Could not notify member %s about inactive room cleanup",
                        member["user_id"],
                    )

    async def cleanup_expired_rooms() -> None:
        await cleanup_expired_rooms_once()
        while True:
            await asyncio.sleep(60 * 60)
            await cleanup_expired_rooms_once()

    cleanup_task = asyncio.create_task(cleanup_expired_rooms())
    try:
        await dp.start_polling(bot, allowed_updates=dp.resolve_used_update_types())
    finally:
        cleanup_task.cancel()
        await asyncio.gather(cleanup_task, return_exceptions=True)
        await bot.session.close()


if __name__ == "__main__":
    try:
        asyncio.run(main())
    except (KeyboardInterrupt, SystemExit):
        logger.info("Bot stopped")
