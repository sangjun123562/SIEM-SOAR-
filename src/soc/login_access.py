"""관제 화면에서 ERP의 임시 로그인 요청을 조회하고 승인한다."""

from http.client import HTTPConnection, HTTPException
import json
from urllib.parse import quote, urlencode

from .models import NormalizedEvent


class LoginAccessError(ValueError):
    pass


class LoginAccessClient:
    def __init__(self, token: str):
        self.token = token

    def lookup(self, event: NormalizedEvent) -> dict | None:
        return self._login_request(event, "GET")

    def lookup_account_access(self, event: NormalizedEvent) -> dict | None:
        return self._login_request(event, "GET", include_active_grant=True)

    def update(self, event: NormalizedEvent, incident_id: str, operator: str, action: str, reason: str) -> dict | None:
        # 계정과 IP는 화면 입력값 대신 관제 DB에 저장된 근거에서 가져온다.
        return self._login_request(event, "POST", {
            "username": event.username, "client_ip": event.client_ip, "incident_id": incident_id,
            "operator": operator, "action": action, "reason": reason,
        })

    def lookup_account_lock(self, incident_id: str, username: str) -> dict | None:
        query = urlencode({"username": username})
        return self._request("GET", f"/internal/account-locks/{quote(incident_id, safe='')}?{query}", username,
                             ("available", "active", "expired", "unlocked"))

    def update_account_lock(
        self, incident_id: str, username: str, operator: str, action: str, duration: int, reason: str,
    ) -> dict | None:
        return self._request("POST", f"/internal/account-locks/{quote(incident_id, safe='')}", username,
                             ("active", "expired", "unlocked"), {
                                 "username": username, "operator": operator, "action": action,
                                 "duration_minutes": duration, "reason": reason,
                             })

    def fetch_permissions(self) -> dict | None:
        return self._request_json("GET", "/internal/permissions")

    def update_permission(
        self,
        *,
        action: str,
        username: str,
        operator: str,
        reason: str,
        document_id: str | None = None,
        duration_minutes: int | None = None,
    ) -> dict | None:
        payload: dict[str, Any] = {
            "action": action, "username": username, "operator": operator, "reason": reason,
        }
        if document_id:
            payload["document_id"] = document_id
        if duration_minutes is not None:
            payload["duration_minutes"] = int(duration_minutes)
        return self._request_json("POST", "/internal/permissions", payload)

    def _request_json(self, method: str, path: str, data: dict | None = None) -> dict | None:
        conn = HTTPConnection("10.250.31.20", 8000, timeout=2)
        try:
            conn.request(
                method,
                path,
                body=json.dumps(data).encode("utf-8") if data is not None else None,
                headers={"Authorization": f"Bearer {self.token}", "Content-Type": "application/json"},
            )
            response = conn.getresponse()
            if response.status == 404 and method == "GET":
                return None
            payload = json.loads(response.read(65536))
            if isinstance(payload, dict):
                if response.status == 200 and payload.get("status") == "ok":
                    return payload
                if response.status in (400, 409) and isinstance(payload.get("error"), str):
                    raise LoginAccessError(payload["error"][:200])
        except (OSError, HTTPException, json.JSONDecodeError, UnicodeError):
            pass
        finally:
            conn.close()
        raise LoginAccessError("ERP 권한 상태를 확인하지 못했습니다. 잠시 후 다시 시도해 주세요.")

    def _login_request(
        self, event: NormalizedEvent, method: str, data: dict | None = None, *, include_active_grant: bool = False,
    ) -> dict | None:
        if not event.request_id:
            raise LoginAccessError("ERP 요청 번호를 확인할 수 없습니다.")
        path = f"/internal/login-access/{quote(event.request_id, safe='')}"
        if include_active_grant:
            path += "?scope=account"
        return self._request(method, path, event.username,
                             ("pending", "active", "expired", "revoked"), data, client_ip=event.client_ip)

    def _request(
        self, method: str, path: str, username: str | None, statuses: tuple[str, ...],
        data: dict | None = None, *, client_ip: str | None = None,
    ) -> dict | None:
        conn = HTTPConnection("10.250.31.20", 8000, timeout=2)
        try:
            conn.request(method, path,
                         body=json.dumps(data).encode("utf-8") if data is not None else None,
                         headers={"Authorization": f"Bearer {self.token}", "Content-Type": "application/json"})
            response = conn.getresponse()
            if response.status == 404 and method == "GET":
                return None
            payload = json.loads(response.read(8192))
            if isinstance(payload, dict):
                if (response.status == 200 and payload.get("username") == username
                        and (client_ip is None or payload.get("client_ip") == client_ip)
                        and payload.get("status") in statuses):
                    return payload
                if response.status in (400, 409) and isinstance(payload.get("error"), str):
                    raise LoginAccessError(payload["error"][:200])
        except (OSError, HTTPException, json.JSONDecodeError, UnicodeError):
            pass
        finally:
            conn.close()
        raise LoginAccessError("ERP 조치 상태를 확인하지 못했습니다. 잠시 뒤 사건 상세를 새로고침해 주세요.")
