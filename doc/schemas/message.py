import abc
from pydantic import BaseModel, Field, UUID5
from typing import Dict, FrozenSet, List, Optional, Sequence, Set, Tuple, Union, Any
from pydantic.types import PositiveInt, ConstrainedList, ConstrainedInt, conint

from np_types import NeuropilHeader, Header

class NeuropilInstructions(BaseModel):
    pass

# class NeuropilHeader(BaseModel):
#     aud: Optional[bytes]
#     sub: bytes
#     iss: Optional[bytes]
#     uuid: UUID5
#     tstamp: int
#     valid: int

class Attribute(BaseModel):
    key: str
    value: Any

class NeuropilAttributes(BaseModel):
    __root__: List[ Attribute ] = None

class NeuropilBody(BaseModel, abc.ABC):
    body: bytes = Field(default=None, max_length=987, min_length=987)

class NeuropilMessage(BaseModel, abc.ABC):
    __root__: Tuple[NeuropilInstructions, NeuropilHeader, NeuropilAttributes, NeuropilBody]

class HandshakeMessage(NeuropilMessage):
    pass

class JoinMessage(NeuropilMessage):
    pass

class NeuropilModel(BaseModel):
    """
    This is the description of the neuropil message format.
    It contains the basic abstract message structure plus instances of specific message types
    """
    abstract_message: NeuropilMessage
    messages: Union[HandshakeMessage, JoinMessage]

    # class Config:
    #     title = 'NeuropilConfig'

class np_pheromone(BaseModel):
    pos: int = Field(default=0)
    pheromone: List[ conint(strict=False, ge=0) ] = Field(default=None, min_items=2, max_items=16)

class PheromonePayload(BaseModel):
    pheromone: List[np_pheromone] = Field(default=None, min_items=1, max_items=2)

print (PheromonePayload.schema_json(indent=2))

# this is equivalent to json.dumps(MainModel.schema(), indent=2):
print(NeuropilModel.schema_json(indent=2))