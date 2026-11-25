from fastapi import APIRouter, WebSocket, WebSocketException, Query, status
from jose import JWTError, jwt
from app.auth import COOKIE_NAME
from app.config import SECRET_KEY, ALGORITHM
from app.database import get_db
from app.ws_manager import connect, disconnect

router = APIRouter()


@router.websocket("/ws/projects/{project_id}/live")
async def websocket_live(project_id: int, websocket: WebSocket, token: str | None = Query(default=None)):
    """Live event stream for a project; auth via cookie or ?token= (user JWT).

    The ownership check runs BEFORE the connection is accepted: a token that
    is invalid, agent-scoped, or belongs to a user who does not own the
    project is rejected with WS_1008 during the handshake — never accepted
    and then silently starved of events.
    """
    auth_token = websocket.cookies.get(COOKIE_NAME) or token
    if not auth_token:
        raise WebSocketException(code=status.WS_1008_POLICY_VIOLATION)
    try:
        payload = jwt.decode(auth_token, SECRET_KEY, algorithms=[ALGORITHM])
        if payload.get("sub") is None or payload.get("scope") == "agent":
            raise WebSocketException(code=status.WS_1008_POLICY_VIOLATION)
        user_id = int(payload.get("sub"))
    except (JWTError, TypeError, ValueError):
        raise WebSocketException(code=status.WS_1008_POLICY_VIOLATION)

    db = get_db()
    user = db.users.find_one({"id": user_id})
    if not user:
        raise WebSocketException(code=status.WS_1008_POLICY_VIOLATION)
    if int(payload.get("tv", 0)) != int(user.get("token_version", 0)):
        raise WebSocketException(code=status.WS_1008_POLICY_VIOLATION)
    project = db.projects.find_one({"id": project_id, "owner_id": user["id"]}, {"id": 1})
    if not project:
        raise WebSocketException(code=status.WS_1008_POLICY_VIOLATION)

    await connect(project_id, websocket)
    try:
        while True:
            await websocket.receive_text()
    except Exception:
        pass
    finally:
        disconnect(project_id, websocket)
