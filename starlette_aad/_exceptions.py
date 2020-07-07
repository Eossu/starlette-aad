#
#
#


class AzureAdTokenError(Exception):
    pass


class InvalidAuthorizationToken(AzureAdTokenError):

    def __init__(self, details):
        super().__init__(f"Invalid Authorization Token: {details}")
