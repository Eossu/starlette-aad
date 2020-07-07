#
#
#
from typing import Mapping


class BaseCache:

    def __init__(self) -> None:
        pass


class DictCache(BaseCache):

    def __init__(self) -> None:
        super().__init__()
