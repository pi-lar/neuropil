# SPDX-FileCopyrightText: 2016-2024 by pi-lar GmbH
# SPDX-License-Identifier: OSL-3.0

from pydantic import UUID5
from typing import TYPE_CHECKING, Any, Dict, Optional, Tuple, Union, cast
from pydantic.utils import Representation, almost_equal_floats

HeaderTuple = Union[
    Tuple[bytes, bytes, bytes, str, int, int], Tuple[bytes, bytes, bytes, int, int]
]
HeaderType = Union[HeaderTuple, str]


class Header:
    """
    Internal use only as a representation of a color.
    """

    __slots__ = "iss", "sub", "aud", "tstamp", "valid", "uuid"

    def __init__(
        self, iss: bytes, sub: bytes, aud: Optional[bytes], tstamp: int, valid: int
    ):
        self.iss = iss
        self.sub = sub
        self.aud = aud
        self.tstamp = tstamp
        self.valid = valid
        self.uuid = UUID5()

        self._tuple: Tuple[bytes, bytes, bytes, uuid, int, int] = (
            iss,
            sub,
            aud,
            uuid,
            tstamp,
            valid,
        )

    def __getitem__(self, item: Any) -> Any:
        return self._tuple[item]

    @classmethod
    def __get_validators__(cls) -> "CallableGenerator":
        yield cls


class NeuropilHeader(Representation):
    __slots__ = "_original", "_np_header"

    def __init__(self, value: HeaderType) -> None:
        self._np_header: Header
        self._original: HeaderType
        if isinstance(value, (tuple, list)):
            self._np_header = parse_tuple(value)
        elif isinstance(value, str):
            self._np_header = parse_str(value)
        else:
            raise HeaderError(reason="value must be a tuple, list or string")
        # if we've got here value must be a valid color
        self._original = value

    def as_np_header(self, *, alpha: Optional[bool] = None) -> HeaderTuple:
        """ """
        iss, sub, aud, tstamp, valid, uuid = [c for c in self._np_header]
        return iss, sub, aud, uuid, tstamp, valid

    @classmethod
    def __modify_schema__(cls, field_schema: Dict[str, Any]) -> None:
        field_schema.update(type="bytes", format="np_header")

    @classmethod
    def __get_validators__(cls) -> "CallableGenerator":
        yield cls

    def __str__(self) -> str:
        return self.as_named(fallback=True)

    def __repr_args__(self) -> "ReprArgs":
        return [(None, self.as_named(fallback=True))] + [("rgb", self.as_np_header())]  # type: ignore
