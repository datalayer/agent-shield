# Copyright (c) 2025-2026 Datalayer, Inc.
#
# BSD 3-Clause License

"""``nfnetlink_log``: the packets the firewall's rules logged, read back as connections.

Every logged rule (:mod:`agent_shield.firewall.compile`) sends the first packet
of a new connection to ``NFLOG`` group 7 with its prefix. The listener binds
the group on a ``NETLINK_NETFILTER`` socket in the pod's network namespace
(it needs ``NET_ADMIN``, as the rules do), asks for the packet's first bytes,
and decodes each message into a :class:`Connection`: the decision and rule
from the prefix, the destination and source from the IPv4 header, the ports
from TCP or UDP. Nothing of the payload past the headers is read.

The wire format is the kernel's (``linux/netfilter/nfnetlink_log.h``):
a ``nlmsghdr``, a ``nfgenmsg``, then attributes, each a length, a type and a
value padded to four bytes.
"""

from __future__ import annotations

import ipaddress
import socket
import struct
from collections.abc import Iterator
from dataclasses import dataclass

from agent_shield.firewall.compile import NFLOG_GROUP

NETLINK_NETFILTER = 12
NFNL_SUBSYS_ULOG = 4
NFULNL_MSG_PACKET = 0
NFULNL_MSG_CONFIG = 1
NFULA_PREFIX = 10
NFULA_PAYLOAD = 9
NFULA_CFG_CMD = 1
NFULA_CFG_MODE = 2
NFULNL_CFG_CMD_BIND = 1
NFULNL_CFG_CMD_PF_BIND = 3
NFULNL_CFG_CMD_PF_UNBIND = 4
NFULNL_COPY_PACKET = 2
NLM_F_REQUEST = 1
NLM_F_ACK = 4
NLMSG_ERROR = 2
#: Enough of the packet for the IPv4 header with options and the ports.
COPY_RANGE = 80

_NLMSGHDR = struct.Struct("=IHHII")
_NFGENMSG = struct.Struct("=BBH")
_NLA = struct.Struct("=HH")
_PROTOCOLS = {6: "tcp", 17: "udp", 1: "icmp"}


@dataclass(frozen=True)
class Connection:
    """One logged connection: what was decided, by which rule, to where."""

    decision: str
    rule: str
    protocol: str
    source: str
    destination: str
    source_port: int | None = None
    destination_port: int | None = None

    @property
    def target(self) -> str:
        return f"{self.destination}:{self.destination_port}" if self.destination_port else self.destination


def _align(length: int) -> int:
    return (length + 3) & ~3


def attributes(data: bytes) -> dict[int, bytes]:
    """The attributes of one message's body, by type (the nested flag cleared)."""
    found: dict[int, bytes] = {}
    offset = 0
    while offset + _NLA.size <= len(data):
        length, kind = _NLA.unpack_from(data, offset)
        if length < _NLA.size:
            break
        found[kind & 0x3FFF] = data[offset + _NLA.size : offset + length]
        offset += _align(length)
    return found


def decode_prefix(raw: bytes) -> tuple[str, str] | None:
    """``shield <decision> <rule>`` → (decision, rule); another prefix is not the Shield's."""
    text = raw.split(b"\0", 1)[0].decode("utf-8", "replace")
    parts = text.split(" ", 2)
    if len(parts) < 3 or parts[0] != "shield" or parts[1] not in ("allow", "refuse"):
        return None
    return parts[1], parts[2]


def decode_packet(payload: bytes) -> tuple[str, str, str, int | None, int | None] | None:
    """An IPv4 packet's protocol, source, destination and ports; anything else is None."""
    if len(payload) < 20 or payload[0] >> 4 != 4:
        return None
    header = (payload[0] & 0x0F) * 4
    proto = payload[9]
    source = str(ipaddress.IPv4Address(payload[12:16]))
    destination = str(ipaddress.IPv4Address(payload[16:20]))
    sport = dport = None
    if proto in (6, 17) and len(payload) >= header + 4:
        sport, dport = struct.unpack_from("!HH", payload, header)
    return _PROTOCOLS.get(proto, str(proto)), source, destination, sport, dport


def decode_message(message: bytes) -> Connection | None:
    """One netlink message → a :class:`Connection`, or None for what is not a Shield packet."""
    if len(message) < _NLMSGHDR.size + _NFGENMSG.size:
        return None
    length, kind, _flags, _seq, _pid = _NLMSGHDR.unpack_from(message, 0)
    if kind != (NFNL_SUBSYS_ULOG << 8) | NFULNL_MSG_PACKET:
        return None
    attrs = attributes(message[_NLMSGHDR.size + _NFGENMSG.size : length])
    said = decode_prefix(attrs.get(NFULA_PREFIX, b""))
    packet = decode_packet(attrs.get(NFULA_PAYLOAD, b""))
    if said is None or packet is None:
        return None
    protocol, source, destination, sport, dport = packet
    return Connection(said[0], said[1], protocol, source, destination, sport, dport)


def messages(datagram: bytes) -> Iterator[bytes]:
    """The netlink messages one datagram carries."""
    offset = 0
    while offset + _NLMSGHDR.size <= len(datagram):
        length = _NLMSGHDR.unpack_from(datagram, offset)[0]
        if length < _NLMSGHDR.size:
            break
        yield datagram[offset : offset + length]
        offset += _align(length)


def _attribute(kind: int, value: bytes) -> bytes:
    body = _NLA.pack(_NLA.size + len(value), kind) + value
    return body + b"\0" * (_align(len(body)) - len(body))


def config_message(command: int | None, *, family: int, group: int, seq: int, mode: bool = False) -> bytes:
    """A ``NFULNL_MSG_CONFIG`` request: a command, or the copy mode, for a group."""
    body = _NFGENMSG.pack(family, 0, socket.htons(group))
    if command is not None:
        body += _attribute(NFULA_CFG_CMD, struct.pack("=B", command))
    if mode:
        body += _attribute(NFULA_CFG_MODE, struct.pack("!IBB", COPY_RANGE, NFULNL_COPY_PACKET, 0))
    kind = (NFNL_SUBSYS_ULOG << 8) | NFULNL_MSG_CONFIG
    return _NLMSGHDR.pack(_NLMSGHDR.size + len(body), kind, NLM_F_REQUEST | NLM_F_ACK, seq, 0) + body


class Listener:
    """The bound group: :meth:`connections` yields each logged connection as it comes."""

    def __init__(self, group: int = NFLOG_GROUP) -> None:
        self.group = group
        self.sock = socket.socket(socket.AF_NETLINK, socket.SOCK_RAW, NETLINK_NETFILTER)
        self.sock.bind((0, 0))
        steps = [
            config_message(NFULNL_CFG_CMD_PF_UNBIND, family=socket.AF_INET, group=0, seq=1),
            config_message(NFULNL_CFG_CMD_PF_BIND, family=socket.AF_INET, group=0, seq=2),
            config_message(NFULNL_CFG_CMD_BIND, family=socket.AF_UNSPEC, group=group, seq=3),
            config_message(None, family=socket.AF_UNSPEC, group=group, seq=4, mode=True),
        ]
        for step in steps:
            self.sock.send(step)
            self._acknowledged(step)

    def _acknowledged(self, request: bytes) -> None:
        reply = self.sock.recv(65536)
        for message in messages(reply):
            _length, kind, _f, _s, _p = _NLMSGHDR.unpack_from(message, 0)
            if kind == NLMSG_ERROR:
                (error,) = struct.unpack_from("=i", message, _NLMSGHDR.size)
                # Unbinding a family nobody bound answers an error the kernel means as nothing.
                command = attributes(request[_NLMSGHDR.size + _NFGENMSG.size :]).get(NFULA_CFG_CMD, b"\0")[0]
                if error != 0 and command != NFULNL_CFG_CMD_PF_UNBIND:
                    raise OSError(-error, f"nfnetlink_log refused the configuration (command {command})")

    def connections(self) -> Iterator[Connection]:
        while True:
            datagram = self.sock.recv(65536)
            for message in messages(datagram):
                connection = decode_message(message)
                if connection is not None:
                    yield connection

    def close(self) -> None:
        self.sock.close()


__all__ = ["Connection", "Listener", "config_message", "decode_message", "decode_packet", "decode_prefix", "messages"]
