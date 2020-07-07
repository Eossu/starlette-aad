#
#
#
from pydantic import BaseSettings


class AsgiAdAuthConfig(BaseSettings):
    APP_ID: str
    TENANT_ID: str = "common"
    DISCOVERY_ENDPOINT: str = None
    VERIFY: bool = True
