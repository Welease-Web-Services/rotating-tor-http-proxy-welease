#!/usr/bin/env python3
"""Small control API for sticky Tor/Privoxy slots.

The API keeps in-memory leases for Tor slots and can renew one slot by sending
SIGNAL NEWNYM to that Tor instance's ControlPort.
"""

from __future__ import annotations

import json
import os
import random
import socket
import time
import uuid
from datetime import datetime, timedelta, timezone
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer
from threading import RLock
from urllib.error import URLError
from urllib.request import ProxyHandler, build_opener


def utc_now() -> datetime:
    return datetime.now(timezone.utc)


def iso(dt: datetime | None) -> str | None:
    return dt.isoformat().replace("+00:00", "Z") if dt else None


def env_int(name: str, default: int) -> int:
    raw = os.getenv(name)
    if raw is None or raw == "":
        return default
    return int(raw)


TOR_INSTANCES = env_int("TOR_INSTANCES", 10)
PROXY_USER = os.getenv("PROXY_USER", "")
PROXY_PASSWORD = os.getenv("PROXY_PASSWORD", "")
PUBLIC_PROXY_HOST = os.getenv("PUBLIC_PROXY_HOST", os.getenv("PROXY_HOST", ""))
PUBLIC_PROXY_PORT = env_int("PUBLIC_PROXY_PORT", 3128)
TOR_HTTP_PORT_BASE = env_int("TOR_HTTP_PORT_BASE", 30000)
TOR_CONTROL_PORT_BASE = env_int("TOR_CONTROL_PORT_BASE", 20000)
TOR_DATA_DIR_BASE = os.getenv("TOR_DATA_DIR_BASE", "/var/local/tor")
TOR_RENEW_WAIT_SECONDS = env_int("TOR_RENEW_WAIT_SECONDS", 5)
TOR_RENEW_IP_CHECK_ATTEMPTS = env_int("TOR_RENEW_IP_CHECK_ATTEMPTS", 6)
TOR_RENEW_IP_CHECK_DELAY_SECONDS = env_int("TOR_RENEW_IP_CHECK_DELAY_SECONDS", 5)
LEASE_TTL_SECONDS = env_int("TOR_LEASE_TTL_SECONDS", 300)
COOLDOWN_SECONDS = env_int("TOR_SLOT_COOLDOWN_SECONDS", 120)
REQUEST_TIMEOUT_SECONDS = env_int("TOR_CONTROL_REQUEST_TIMEOUT_SECONDS", 20)
AUTH_TOKEN = os.getenv("TOR_CONTROL_TOKEN", "")

IOS_VERSIONS = ["18.0", "18.1", "18.2", "18.3", "18.4", "18.5", "18.6", "18.7", "18.7.3", "26.0", "26.1", "26.2"]
IOS_APP_VERSIONS = ["101.45.0", "101.44.0", "101.43.1", "101.43.0", "101.42.1", "101.42.0", "101.41.0", "101.40.0", "101.39.0", "101.38.0"]
ANDROID_VERSIONS = ["11", "12", "13", "14", "15"]
ANDROID_MODELS = [
    "SM-G991B", "SM-G996B", "SM-G998B", "SM-S911B", "SM-S916B", "SM-S918B",
    "SM-A505F", "SM-A546B", "SM-A137F", "SM-M336B", "Pixel 5", "Pixel 6",
    "Pixel 6a", "Pixel 7", "Pixel 7 Pro", "Pixel 8", "Pixel 8 Pro", "Mi 10",
    "Mi 11", "Mi 11 Lite", "Redmi Note 10", "Redmi Note 11", "Redmi Note 12",
    "POCO F3", "POCO F4", "POCO X3 Pro", "ONEPLUS A6003", "ONEPLUS A6013",
    "ONEPLUS A5000", "ONEPLUS A5010", "OnePlus 8", "OnePlus 9", "OnePlus 10 Pro",
    "OnePlus Nord",
]
ANDROID_APP_VERSIONS = ["100.85.2", "100.84.1", "100.83.1", "100.82.0", "100.81.1"]


class SlotState:
    def __init__(self, slot_id: int):
        self.slot_id = slot_id
        self.status = "available"
        self.lease_id = None
        self.leased_by = None
        self.signature = None
        self.external_ip = None
        self.expires_at = None
        self.failure_count = 0
        self.last_success_at = None
        self.last_block_at = None
        self.last_error = None
        self.last_renew_at = None
        self.cooldown_until = None

    def to_dict(self) -> dict:
        return {
            "slot_id": self.slot_id,
            "status": self.status,
            "lease_id": self.lease_id,
            "leased_by": self.leased_by,
            "signature": self.signature,
            "external_ip": self.external_ip,
            "expires_at": iso(self.expires_at),
            "failure_count": self.failure_count,
            "last_success_at": iso(self.last_success_at),
            "last_block_at": iso(self.last_block_at),
            "last_error": self.last_error,
            "last_renew_at": iso(self.last_renew_at),
            "cooldown_until": iso(self.cooldown_until),
        }


class SlotStore:
    def __init__(self, size: int):
        self.lock = RLock()
        self.slots = [SlotState(i) for i in range(size)]

    def cleanup_expired(self) -> None:
        now = utc_now()
        for slot in self.slots:
            if slot.status == "leased" and slot.expires_at and slot.expires_at <= now:
                slot.status = "available"
                slot.lease_id = None
                slot.leased_by = None
                slot.signature = None
                slot.expires_at = None
                slot.last_error = "lease expired"
            if slot.status == "cooldown" and slot.cooldown_until and slot.cooldown_until <= now:
                slot.status = "available"
                slot.cooldown_until = None

    def list_slots(self) -> list[dict]:
        with self.lock:
            self.cleanup_expired()
            return [slot.to_dict() for slot in self.slots]

    def lease(self, body: dict) -> dict:
        with self.lock:
            self.cleanup_expired()
            available = [slot for slot in self.slots if slot.status == "available"]
            if not available:
                raise ApiError(409, "no available tor slot")
            slot = min(available, key=lambda item: (item.failure_count, item.slot_id))
            lease_id = str(uuid.uuid4())
            ttl = int(body.get("ttl_seconds") or LEASE_TTL_SECONDS)
            signature = build_signature(body.get("signature_policy"))
            slot.status = "leased"
            slot.lease_id = lease_id
            slot.leased_by = body.get("leased_by") or {
                "client": body.get("client"),
                "worker_id": body.get("worker_id"),
                "stage": body.get("stage"),
                "context": body.get("context"),
            }
            slot.signature = signature
            slot.expires_at = utc_now() + timedelta(seconds=ttl)
            slot.last_error = None
            return {
                "lease_id": lease_id,
                "slot_id": slot.slot_id,
                "proxy": proxy_payload(slot.slot_id),
                "signature": signature,
                "expires_at": iso(slot.expires_at),
            }

    def heartbeat(self, slot_id: int, body: dict) -> dict:
        with self.lock:
            slot = self.get_slot(slot_id)
            require_lease(slot, body.get("lease_id"))
            ttl = int(body.get("ttl_seconds") or LEASE_TTL_SECONDS)
            slot.expires_at = utc_now() + timedelta(seconds=ttl)
            return {"status": "ok", "slot_id": slot_id, "expires_at": iso(slot.expires_at)}

    def release(self, slot_id: int, body: dict) -> dict:
        with self.lock:
            slot = self.get_slot(slot_id)
            require_lease(slot, body.get("lease_id"))
            status = body.get("status") or "success"
            now = utc_now()
            slot.lease_id = None
            slot.leased_by = None
            slot.signature = None
            slot.expires_at = None
            if status == "success":
                slot.status = "available"
                slot.failure_count = 0
                slot.last_success_at = now
                slot.last_error = None
            elif status == "blocked":
                renewed_recently = (
                    slot.last_renew_at is not None
                    and (now - slot.last_renew_at).total_seconds() <= 300
                    and slot.last_error is None
                )
                slot.status = "available" if renewed_recently else "dirty"
                slot.failure_count += 1
                slot.last_block_at = now
                slot.last_error = trim_error(body.get("error"))
            else:
                slot.status = "available"
                slot.failure_count += 1
                slot.last_error = trim_error(body.get("error"))
            return {"status": slot.status, "slot_id": slot_id}

    def mark_renewing(self, slot_id: int, lease_id: str | None = None) -> tuple[SlotState, str | None]:
        with self.lock:
            slot = self.get_slot(slot_id)
            if slot.status == "leased":
                require_lease(slot, lease_id)
            elif lease_id:
                raise ApiError(409, "slot is not leased")
            old_ip = slot.external_ip
            slot.status = "renewing"
            slot.last_error = None
            return slot, old_ip

    def finish_renew(self, slot_id: int, old_ip: str | None, new_ip: str | None, error: str | None = None) -> dict:
        with self.lock:
            slot = self.get_slot(slot_id)
            slot.external_ip = new_ip or slot.external_ip
            slot.last_renew_at = utc_now()
            next_status = "leased" if slot.lease_id else "available"
            if error:
                slot.status = next_status if slot.lease_id else "cooldown"
                if not slot.lease_id:
                    slot.cooldown_until = utc_now() + timedelta(seconds=COOLDOWN_SECONDS)
                slot.last_error = trim_error(error)
                return {
                    "status": "renew_failed",
                    "slot_id": slot_id,
                    "old_ip": old_ip,
                    "new_ip": new_ip,
                    "error": trim_error(error),
                    "cooldown_until": iso(slot.cooldown_until),
                }
            slot.status = next_status
            slot.cooldown_until = None
            slot.last_error = None
            return {"status": "renewed", "slot_id": slot_id, "old_ip": old_ip, "new_ip": new_ip}

    def get_slot(self, slot_id: int) -> SlotState:
        if slot_id < 0 or slot_id >= len(self.slots):
            raise ApiError(404, "slot not found")
        return self.slots[slot_id]


def trim_error(value) -> str | None:
    if value is None:
        return None
    return str(value)[:1000]


def require_lease(slot: SlotState, lease_id: str | None) -> None:
    if slot.status != "leased" or not lease_id or slot.lease_id != lease_id:
        raise ApiError(409, "lease does not own this slot")


def proxy_payload(slot_id: int) -> dict:
    return {
        "host": PUBLIC_PROXY_HOST,
        "port": PUBLIC_PROXY_PORT,
        "username": f"{PROXY_USER}-s{slot_id}",
        "password": PROXY_PASSWORD,
    }


def build_signature(policy: str | None) -> dict:
    mobile = random.choice(["ios", "android"])
    if mobile == "ios":
        return {
            "impersonate": "safari_ios",
            "os": "iOS",
            "user_agent": f"LBC;iOS;{random.choice(IOS_VERSIONS)};iPhone;phone;{uuid.uuid4()};wifi;{random.choice(IOS_APP_VERSIONS)}",
        }
    return {
        "impersonate": "chrome_android",
        "os": "Android",
        "user_agent": f"LBC;Android;{random.choice(ANDROID_VERSIONS)};{random.choice(ANDROID_MODELS)};phone;{uuid.uuid4().hex[:16]};wifi;{random.choice(ANDROID_APP_VERSIONS)}",
    }


def tor_control_command(slot_id: int, command: str) -> list[str]:
    port = TOR_CONTROL_PORT_BASE + slot_id
    with socket.create_connection(("127.0.0.1", port), timeout=REQUEST_TIMEOUT_SECONDS) as conn:
        file = conn.makefile("rwb", buffering=0)
        cookie = read_control_cookie(slot_id)
        if cookie:
            file.write(f"AUTHENTICATE {cookie.hex()}\r\n".encode())
        else:
            file.write(b"AUTHENTICATE\r\n")
        auth_response = read_control_response(file)
        if not auth_response[-1].startswith("250"):
            raise RuntimeError("Tor control authentication failed: " + " | ".join(auth_response))
        file.write(f"{command}\r\n".encode())
        command_response = read_control_response(file)
        file.write(b"QUIT\r\n")
        return command_response


def read_control_cookie(slot_id: int) -> bytes | None:
    path = os.path.join(TOR_DATA_DIR_BASE, str(slot_id), "control_auth_cookie")
    try:
        with open(path, "rb") as cookie_file:
            return cookie_file.read()
    except FileNotFoundError:
        return None


def read_control_response(file) -> list[str]:
    lines = []
    while True:
        raw = file.readline()
        if not raw:
            raise RuntimeError("Tor control connection closed")
        line = raw.decode("utf-8", "replace").rstrip("\r\n")
        lines.append(line)
        if len(line) >= 4 and line[:3].isdigit() and line[3] == " ":
            return lines


def get_external_ip(slot_id: int) -> str:
    proxy_url = f"http://127.0.0.1:{TOR_HTTP_PORT_BASE + slot_id}"
    opener = build_opener(ProxyHandler({"http": proxy_url, "https": proxy_url}))
    with opener.open("https://api.ipify.org", timeout=REQUEST_TIMEOUT_SECONDS) as response:
        return response.read().decode("utf-8", "replace").strip()


def renew_slot(slot_id: int, body: dict) -> dict:
    slot, old_ip = STORE.mark_renewing(slot_id, body.get("lease_id"))
    if old_ip is None:
        try:
            old_ip = get_external_ip(slot_id)
            slot.external_ip = old_ip
        except Exception:
            old_ip = None
    try:
        control_response = tor_control_command(slot_id, "SIGNAL NEWNYM")
        if not control_response[-1].startswith("250"):
            raise RuntimeError("Tor NEWNYM failed: " + " | ".join(control_response))
        time.sleep(TOR_RENEW_WAIT_SECONDS)
        new_ip = None
        last_error = None
        for _ in range(TOR_RENEW_IP_CHECK_ATTEMPTS):
            try:
                new_ip = get_external_ip(slot_id)
                if old_ip is None or new_ip != old_ip:
                    return STORE.finish_renew(slot_id, old_ip, new_ip)
                last_error = f"renew kept same ip {new_ip}"
            except (OSError, URLError, RuntimeError) as exc:
                last_error = str(exc)
            time.sleep(TOR_RENEW_IP_CHECK_DELAY_SECONDS)
        return STORE.finish_renew(slot_id, old_ip, new_ip, last_error or "ip check failed")
    except Exception as exc:
        return STORE.finish_renew(slot_id, old_ip, None, str(exc))


class ApiError(Exception):
    def __init__(self, status_code: int, message: str):
        super().__init__(message)
        self.status_code = status_code
        self.message = message


STORE = SlotStore(TOR_INSTANCES)


class Handler(BaseHTTPRequestHandler):
    server_version = "tor-slot-control/1.0"

    def do_GET(self):
        try:
            self.require_auth()
            if self.path == "/slots":
                self.write_json({"slots": STORE.list_slots()})
                return
            raise ApiError(404, "not found")
        except ApiError as exc:
            self.write_error(exc.status_code, exc.message)

    def do_POST(self):
        try:
            self.require_auth()
            body = self.read_json()
            parts = [part for part in self.path.split("/") if part]
            if parts == ["slots", "lease"]:
                self.write_json(STORE.lease(body), status=201)
                return
            if len(parts) == 3 and parts[0] == "slots":
                slot_id = int(parts[1])
                action = parts[2]
                if action == "heartbeat":
                    self.write_json(STORE.heartbeat(slot_id, body))
                    return
                if action == "release":
                    self.write_json(STORE.release(slot_id, body))
                    return
                if action == "renew":
                    self.write_json(renew_slot(slot_id, body))
                    return
            raise ApiError(404, "not found")
        except ValueError:
            self.write_error(400, "invalid slot id")
        except ApiError as exc:
            self.write_error(exc.status_code, exc.message)

    def require_auth(self) -> None:
        expected = f"Bearer {AUTH_TOKEN}"
        if not AUTH_TOKEN or self.headers.get("Authorization") != expected:
            raise ApiError(401, "unauthorized")

    def read_json(self) -> dict:
        content_length = int(self.headers.get("Content-Length") or 0)
        if content_length == 0:
            return {}
        raw = self.rfile.read(content_length).decode("utf-8")
        return json.loads(raw)

    def write_json(self, payload: dict, status: int = 200) -> None:
        data = json.dumps(payload).encode("utf-8")
        self.send_response(status)
        self.send_header("Content-Type", "application/json")
        self.send_header("Content-Length", str(len(data)))
        self.end_headers()
        self.wfile.write(data)

    def write_error(self, status: int, message: str) -> None:
        self.write_json({"error": message}, status=status)

    def log_message(self, fmt, *args):
        print(f"{iso(utc_now())} [control-api] {fmt % args}", flush=True)


def main() -> None:
    host = os.getenv("TOR_CONTROL_API_HOST", "0.0.0.0")
    port = env_int("TOR_CONTROL_API_PORT", 8080)
    server = ThreadingHTTPServer((host, port), Handler)
    print(f"{iso(utc_now())} [control-api] listening on {host}:{port} with {TOR_INSTANCES} slots", flush=True)
    server.serve_forever()


if __name__ == "__main__":
    main()
