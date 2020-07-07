#
#
#
from typing import List

from pydantic import BaseModel


class OpenIdConnect(BaseModel):
    authorization_endpoint: str
    token_endpoint: str
    token_endpoint_auth_methods_supported: List[str]
    jwks_uri: str
    response_modes_supported: List[str]
    subject_types_supported: List[str]
    id_token_signing_alg_values_supported: List[str]
    http_logout_supported: bool
    frontchannel_logout_suported: bool
    end_session_endpoint: str
    response_types_supported: List[str]
    scopes_supported: List[str]
    issuer: str
    claims_supported: [str]
    microsoft_multi_refresh_token: bool
    check_session_iframe: str
    userinfo_endpoint: str
    tenant_region_scope: str
    cloud_instance_name: str
    cloud_graph_host_name: str
    msgraph_host: str
    rbac_url: str


class AzureAdKey(BaseModel):
    kid: str
    nbf: str
    use: str
    kty: str
    e: str
    n: str


class AzureAdJWKS(BaseModel):
    keys: List[AzureAdKey]


class AadAccessToken(BaseModel):
    aud: str
    iss: str
    name: str
    email: str
    roles: List[str] = None
    groups: List[str] = None


class AadUser:
    """A Azure AD user representation
    """

    def __init__(self, access_token: AadAccessToken):
        self._user_id = access_token.aud
        self._name = access_token.name
        self._authenticated = True
        self._roles: List[str] = access_token.roles
        self._groups: list[str] = access_token.groups

    @property
    def user_id(self) -> str:
        return self._user_id

    @property
    def name(self) -> str:
        return self._name

    @property
    def is_authenticated(self) -> bool:
        return self._authenticated

    @property
    def roles(self) -> List[str]:
        return self._roles

    @property
    def groups(self) -> List[str]:
        return self._groups

    def is_in_role(self, roles: List[str]) -> bool:
        """Check if the user has the roles needed

        Args:
            roles (List[str]): List of roles

        Returns:
            bool: True if user has any of the roles else False
        """
        for role in roles:
            if role in self._roles:
                return True
        return False

    def is_in_group(self, groups: list[str]) -> bool:
        """Check if the user is in the specified group

        Args:
            groups (list[str]): A list of group names to check

        Returns:
            bool: True if in any of the group else False
        """
        for group in groups:
            if group in self._groups:
                return True
        return False
