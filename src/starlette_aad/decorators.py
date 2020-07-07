#
#
#
import asyncio
import functools
import inspect
import typing

from starlette.requests import HTTPConnection, Request


def require_role(roles: typing.Union[str, typing.Sequence[str]]) -> typing.Callable:
    role_list = [roles] if isinstance(roles, str) else list(roles)

    def decorator(func: typing.Callable) -> typing.Callable:
        type = None
        sig = inspect.signature(func)

    return decorator
