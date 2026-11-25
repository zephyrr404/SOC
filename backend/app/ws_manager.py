import asyncio
from fastapi import WebSocket

_rooms: dict[str, set[WebSocket]] = {}


async def connect(project_id: int, ws: WebSocket):
    await ws.accept()
    key = str(project_id)
    if key not in _rooms:
        _rooms[key] = set()
    _rooms[key].add(ws)


def disconnect(project_id: int, ws: WebSocket):
    key = str(project_id)
    if key in _rooms:
        _rooms[key].discard(ws)
        if not _rooms[key]:
            del _rooms[key]


async def broadcast(project_id: int, event: dict):
    key = str(project_id)
    if key not in _rooms:
        return
    room = list(_rooms[key])
    if not room:
        return
    # Send to all watchers concurrently so a slow client can't serialize
    # delivery to fast ones.
    results = await asyncio.gather(
        *[ws.send_json(event) for ws in room],
        return_exceptions=True,
    )
    stale = {ws for ws, res in zip(room, results) if isinstance(res, Exception)}
    if stale:
        _rooms[key] -= stale
        if not _rooms[key]:
            del _rooms[key]


def get_stats() -> dict:
    connected_projects = {k: len(v) for k, v in _rooms.items()}
    return {
        "rooms": len(_rooms),
        "connected_projects": connected_projects,
        "total_project_connections": sum(len(v) for v in _rooms.values()),
    }
