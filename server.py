import asyncio
import json
import logging
import time
from collections import defaultdict

import websockets
from websockets.asyncio.server import ServerConnection

from auth import register_user, authenticate_user
from crypto import b64encode, b64decode, generate_challenge

logging.basicConfig(level=logging.INFO, format="%(asctime)s [%(levelname)s] %(message)s")
log = logging.getLogger("securechat.server")

HOST = "localhost"
PORT = 8765

connected_clients: dict[str, ServerConnection] = {}
client_public_keys: dict[str, bytes] = {}
pending_challenges: dict[str, bytes] = {}
sequence_numbers: dict[str, int] = defaultdict(lambda: -1)
message_timestamps: dict[str, list] = defaultdict(list)

RATE_LIMIT = 30
RATE_WINDOW = 10.0


def send(ws: ServerConnection, obj: dict) -> asyncio.Task:
    return asyncio.ensure_future(ws.send(json.dumps(obj)))


def rate_limited(username: str) -> bool:
    now = time.monotonic()
    message_timestamps[username] = [t for t in message_timestamps[username] if now - t < RATE_WINDOW]
    if len(message_timestamps[username]) >= RATE_LIMIT:
        return True
    message_timestamps[username].append(now)
    return False


def check_sequence(username: str, seq: int) -> bool:
    last = sequence_numbers[username]
    if seq <= last:
        return False
    sequence_numbers[username] = seq
    return True


class ClientState:
    HANDSHAKE    = "HANDSHAKE"
    KEY_EXCHANGE = "KEY_EXCHANGE"
    CHALLENGE    = "CHALLENGE"
    MESSAGING    = "MESSAGING"


async def handle_client(ws: ServerConnection):
    state = ClientState.HANDSHAKE
    username: str | None = None
    remote = ws.remote_address
    log.info("New connection established")

    try:
        async for raw in ws:
            try:
                msg = json.loads(raw)
            except json.JSONDecodeError:
                await ws.send(json.dumps({"type": "error", "msg": "Invalid JSON"}))
                continue

            mtype = msg.get("type")

            # --- Phase 1: register or login ---
            if state == ClientState.HANDSHAKE:
                if mtype in ("register", "login"):
                    uname  = msg.get("username", "").strip()
                    passwd = msg.get("password", "")
                    if mtype == "register":
                        ok, info = register_user(uname, passwd)
                        result_type = "register_result"
                    else:
                        ok, info = authenticate_user(uname, passwd)
                        result_type = "login_result"

                    await ws.send(json.dumps({"type": result_type, "success": ok, "msg": info}))

                    if ok:
                        if mtype == "login" and uname in connected_clients:
                            old_ws = connected_clients[uname]
                            await old_ws.send(json.dumps({"type": "error", "msg": "Logged in from another location"}))
                            await old_ws.close()
                        username = uname
                        state = ClientState.KEY_EXCHANGE
                        log.info(f"{'Registered' if mtype == 'register' else 'Authenticated'}: {username}")
                    else:
                        log.warning(f"Failed login for '{uname}' from {remote}")
                else:
                    await ws.send(json.dumps({"type": "error", "msg": "Send 'register' or 'login' first"}))

            # --- Phase 2: key exchange ---
            elif state == ClientState.KEY_EXCHANGE:
                if mtype == "public_key":
                    pub_key_b64 = msg.get("key")
                    if not pub_key_b64:
                        await ws.send(json.dumps({"type": "error", "msg": "Missing key"}))
                        continue
                    try:
                        pub_key_bytes = b64decode(pub_key_b64)
                        if len(pub_key_bytes) not in (32, 65):
                            raise ValueError(f"Unexpected key length: {len(pub_key_bytes)}")
                    except Exception as e:
                        await ws.send(json.dumps({"type": "error", "msg": f"Bad key: {e}"}))
                        continue

                    client_public_keys[username] = pub_key_bytes
                    connected_clients[username] = ws
                    log.info(f"{username} registered public key")

                    # Relay keys between new client and all existing peers
                    for peer_name, peer_ws in connected_clients.items():
                        if peer_name == username:
                            continue
                        await ws.send(json.dumps({"type": "peer_key", "username": peer_name, "key": b64encode(client_public_keys[peer_name])}))
                        await peer_ws.send(json.dumps({"type": "peer_key", "username": username, "key": b64encode(pub_key_bytes)}))

                    challenge = generate_challenge()
                    pending_challenges[username] = challenge
                    await ws.send(json.dumps({"type": "challenge", "challenge": b64encode(challenge)}))
                    state = ClientState.CHALLENGE
                    log.info(f"Issued challenge to {username}")
                else:
                    await ws.send(json.dumps({"type": "error", "msg": "Send your public_key first"}))

            # --- Phase 3: challenge-response ---
            elif state == ClientState.CHALLENGE:
                if mtype == "challenge_response":
                    import hmac as hmac_module
                    response_b64 = msg.get("response")
                    if not response_b64:
                        await ws.send(json.dumps({"type": "error", "msg": "Incomplete challenge response"}))
                        continue
                    try:
                        response_bytes = b64decode(response_b64)
                    except Exception:
                        await ws.send(json.dumps({"type": "error", "msg": "Bad base64"}))
                        continue

                    expected = pending_challenges.get(username, b"")
                    if not hmac_module.compare_digest(response_bytes, expected):
                        await ws.send(json.dumps({"type": "challenge_result", "success": False, "msg": "Challenge verification failed"}))
                        log.warning(f"Challenge failed for {username}")
                        continue

                    del pending_challenges[username]

                    online_peers = [
                        {"username": u, "key": b64encode(client_public_keys[u])}
                        for u, u_ws in connected_clients.items()
                        if u != username and u in client_public_keys
                    ]
                    await ws.send(json.dumps({
                        "type": "challenge_result",
                        "success": True,
                        "msg": "Identity verified — secure channel established",
                        "online_peers": online_peers
                    }))

                    # Re-announce to peers who may have missed the original peer_key
                    reannounce = json.dumps({"type": "peer_key", "username": username, "key": b64encode(client_public_keys[username])})
                    for u, u_ws in connected_clients.items():
                        if u != username:
                            asyncio.ensure_future(u_ws.send(reannounce))

                    state = ClientState.MESSAGING
                    log.info(f"{username} passed challenge — MESSAGING phase")
                else:
                    await ws.send(json.dumps({"type": "error", "msg": "Awaiting challenge_response"}))

            # --- Phase 4: relay encrypted messages (server never decrypts) ---
            elif state == ClientState.MESSAGING:
                if mtype == "message":
                    recipient      = msg.get("to")
                    ciphertext_b64 = msg.get("ciphertext")
                    seq            = msg.get("seq")

                    if not recipient or not ciphertext_b64 or seq is None:
                        await ws.send(json.dumps({"type": "error", "msg": "Missing fields"}))
                        continue
                    if rate_limited(username):
                        await ws.send(json.dumps({"type": "error", "msg": "Rate limit exceeded"}))
                        continue
                    if not check_sequence(username, int(seq)):
                        await ws.send(json.dumps({"type": "error", "msg": f"Rejected: sequence number {seq} is not fresh"}))
                        log.warning(f"Replay detected from {username} (seq={seq})")
                        continue
                    if recipient not in connected_clients:
                        await ws.send(json.dumps({"type": "error", "msg": f"User '{recipient}' is not online"}))
                        continue

                    await connected_clients[recipient].send(json.dumps({
                        "type": "message",
                        "from": username,
                        "ciphertext": ciphertext_b64,
                        "seq": seq,
                        "timestamp": time.time()
                    }))
                    log.info(f"Message relayed (seq={seq})")

                elif mtype == "get_online":
                    await ws.send(json.dumps({"type": "online_users", "users": [u for u in connected_clients if u != username]}))
                elif mtype == "ping":
                    await ws.send(json.dumps({"type": "pong"}))
                else:
                    await ws.send(json.dumps({"type": "error", "msg": f"Unknown message type: {mtype}"}))

    except websockets.exceptions.ConnectionClosed as e:
        log.info(f"Connection closed: {username or remote} — {e}")
    except Exception as e:
        log.error(f"Unhandled error for {username or remote}: {e}", exc_info=True)
    finally:
        if username:
            connected_clients.pop(username, None)
            client_public_keys.pop(username, None)
            pending_challenges.pop(username, None)
            departure = json.dumps({"type": "user_left", "username": username})
            for peer_ws in connected_clients.values():
                asyncio.ensure_future(peer_ws.send(departure))
            log.info(f"{username} disconnected and cleaned up")


async def main():
    log.info(f"SecureChat server starting on ws://{HOST}:{PORT}")
    log.info("Server is a relay only — it cannot read message contents")
    async with websockets.serve(handle_client, HOST, PORT):
        await asyncio.Future()


if __name__ == "__main__":
    asyncio.run(main())
