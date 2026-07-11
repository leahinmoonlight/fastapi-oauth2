import secrets
import string
import time
from typing import Optional

from jose.exceptions import JOSEError
from starlette.requests import Request
from starlette.responses import Response

class StateBackend:
    def generate_state(self, request: Request) -> str:
        state = "".join([secrets.choice(string.ascii_letters) for _ in range(32)])
        if request.query_params.get("state"):
            state = request.query_params["state"]
        request._oauth2_state = state
        return state

    def store_state(self, request: Request, response: Optional[Response] = None) -> None:
        """Called after the state has been generated during the redirect process.
        Response will only be available if SSR is enabled."""
        raise NotImplementedError

    def read_state(self, request: Request) -> Optional[str]:
        """Called during the callback process to retrieve the expected state."""
        raise NotImplementedError

    def clear_state(self, request: Request, response: Response) -> None:
        """Called after the state has been validated during the callback process."""
        raise NotImplementedError


class InMemoryStateBackend(StateBackend):
    """Stores the state in memory. This is not recommended for production
    because it only allows one user to authenticate at a time, and does not
    work across multiple workers/processes.
    """
    def __init__(self) -> None:
        self._state = None

    def store_state(self, request: Request, response: Optional[Response] = None) -> None:
        self._state = request._oauth2_state

    def read_state(self, request: Request) -> Optional[str]:
        return self._state

    def clear_state(self, request: Request, response: Response) -> None:
        pass


class CookieStateBackend(StateBackend):
    def __init__(
        self,
        cookie_name: str = 'oauth2_state',
        max_age: int = 600,  # 10 minutes
    ):
        self.cookie_name = cookie_name
        self.max_age = max_age

    def store_state(self, request: Request, response: Optional[Response] = None) -> None:
        if not response:
            raise RuntimeError('CookieStateBackend can only be used with SSR enabled.')

        response.set_cookie(
            self.cookie_name,
            request.auth.jwt_encode({
                'state': request._oauth2_state,
                'exp': int(time.time()) + self.max_age,
            }),
            max_age=self.max_age,
            secure=not request.auth.http,
            httponly=True,
            samesite=request.auth.same_site,
        )

    def read_state(self, request: Request) -> Optional[str]:
        token = request.cookies.get(self.cookie_name)
        if not token:
            return None
        try:
            return request.auth.jwt_decode(token).get('state')
        except JOSEError:
            return None

    def clear_state(self, request: Request, response: Response) -> None:
        response.delete_cookie(self.cookie_name)
