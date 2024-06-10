from google.protobuf.internal import containers as _containers
from google.protobuf import descriptor as _descriptor
from google.protobuf import message as _message
from typing import ClassVar as _ClassVar, Iterable as _Iterable, Mapping as _Mapping, Optional as _Optional, Union as _Union

DESCRIPTOR: _descriptor.FileDescriptor

class ConnectionStat(_message.Message):
    __slots__ = ["protocol", "l_ip", "r_ip", "l_port", "r_port", "packets_in", "packets_out", "ts_start", "ts_current", "bytes_in", "bytes_out"]
    PROTOCOL_FIELD_NUMBER: _ClassVar[int]
    L_IP_FIELD_NUMBER: _ClassVar[int]
    R_IP_FIELD_NUMBER: _ClassVar[int]
    L_PORT_FIELD_NUMBER: _ClassVar[int]
    R_PORT_FIELD_NUMBER: _ClassVar[int]
    PACKETS_IN_FIELD_NUMBER: _ClassVar[int]
    PACKETS_OUT_FIELD_NUMBER: _ClassVar[int]
    TS_START_FIELD_NUMBER: _ClassVar[int]
    TS_CURRENT_FIELD_NUMBER: _ClassVar[int]
    BYTES_IN_FIELD_NUMBER: _ClassVar[int]
    BYTES_OUT_FIELD_NUMBER: _ClassVar[int]
    protocol: str
    l_ip: str
    r_ip: str
    l_port: int
    r_port: int
    packets_in: int
    packets_out: int
    ts_start: int
    ts_current: int
    bytes_in: int
    bytes_out: int
    def __init__(self, protocol: _Optional[str] = ..., l_ip: _Optional[str] = ..., r_ip: _Optional[str] = ..., l_port: _Optional[int] = ..., r_port: _Optional[int] = ..., packets_in: _Optional[int] = ..., packets_out: _Optional[int] = ..., ts_start: _Optional[int] = ..., ts_current: _Optional[int] = ..., bytes_in: _Optional[int] = ..., bytes_out: _Optional[int] = ...) -> None: ...

class StatsRequest(_message.Message):
    __slots__ = []
    def __init__(self) -> None: ...

class StatsReply(_message.Message):
    __slots__ = ["connstat"]
    CONNSTAT_FIELD_NUMBER: _ClassVar[int]
    connstat: _containers.RepeatedCompositeFieldContainer[ConnectionStat]
    def __init__(self, connstat: _Optional[_Iterable[_Union[ConnectionStat, _Mapping]]] = ...) -> None: ...
