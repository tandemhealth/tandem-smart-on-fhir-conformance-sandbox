from fastapi import Request

from smart_sandbox.config import Settings
from smart_sandbox.crypto import SecretBox
from smart_sandbox.store import Store


def get_store(request: Request) -> Store:
    return request.app.state.store


def get_box(request: Request) -> SecretBox:
    return request.app.state.box


def get_settings(request: Request) -> Settings:
    return request.app.state.settings
