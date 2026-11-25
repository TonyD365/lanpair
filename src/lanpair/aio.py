"""asyncio versions of :class:`~lanpair.Host` and :class:`~lanpair.Device`.

The network work stays on lanpair's threads; these methods wait for it without blocking
the event loop::

    async with AsyncHost("Front desk") as host:
        async for msg in host.messages():
            await host.send(msg.sender.device_id, {"type": "ok"})
"""

from __future__ import annotations

import asyncio
from collections.abc import AsyncIterator
from typing import Any, Generic, TypeVar

from .node import Device, Host, Message, PeerInfo
from .pairing import PairingOffer

_T = TypeVar("_T", Host, Device)
_A = TypeVar("_A", bound="_AsyncNode[Any]")
_POLL = 0.25


class _AsyncNode(Generic[_T]):
    node: _T

    @property
    def device_id(self) -> str:
        return self.node.device_id

    @property
    def port(self) -> int:
        return self.node.port

    @property
    def dropped(self) -> int:
        return self.node.dropped

    async def start(self) -> None:
        await asyncio.to_thread(self.node.start)

    async def close(self) -> None:
        await asyncio.to_thread(self.node.close)

    async def __aenter__(self: _A) -> _A:
        await self.start()
        return self

    async def __aexit__(self, *exc: object) -> None:
        await self.close()

    async def receive(self, timeout: float | None = None) -> Message | None:
        """The next message, or None after *timeout* seconds."""
        loop = asyncio.get_running_loop()
        end = None if timeout is None else loop.time() + timeout
        while True:
            wait = _POLL if end is None else min(_POLL, max(0.0, end - loop.time()))
            message = await asyncio.to_thread(self.node.receive, wait)
            if message is not None or (end is not None and loop.time() >= end):
                return message

    async def messages(self) -> AsyncIterator[Message]:
        """Every message, as it arrives, until :meth:`close`."""
        while not self.node._stop.is_set():
            message = await asyncio.to_thread(self.node.receive, _POLL)
            if message is not None:
                yield message

    async def reply(self, request: Message, body: Any) -> None:
        await asyncio.to_thread(self.node.reply, request, body)


class AsyncHost(_AsyncNode[Host]):
    """:class:`~lanpair.Host` for asyncio; takes the same arguments."""

    def __init__(self, name: str, **kwargs: Any) -> None:
        self.node = Host(name, **kwargs)

    @property
    def devices(self) -> list[PeerInfo]:
        return self.node.devices

    def pairing_offer(self, **kwargs: Any) -> PairingOffer:
        return self.node.pairing_offer(**kwargs)

    async def wait_for_pairing(self, timeout: float | None = None) -> PeerInfo | None:
        return await asyncio.to_thread(self.node.wait_for_pairing, timeout)

    async def send(self, device_id: str, body: Any, **kwargs: Any) -> None:
        await asyncio.to_thread(self.node.send, device_id, body, **kwargs)

    async def request(self, device_id: str, body: Any, **kwargs: Any) -> Any:
        return await asyncio.to_thread(self.node.request, device_id, body, **kwargs)

    async def broadcast(self, body: Any, **kwargs: Any) -> dict[str, bool]:
        return await asyncio.to_thread(self.node.broadcast, body, **kwargs)

    async def unpair(self, device_id: str) -> None:
        await asyncio.to_thread(self.node.unpair, device_id)


class AsyncDevice(_AsyncNode[Device]):
    """:class:`~lanpair.Device` for asyncio; takes the same arguments."""

    def __init__(self, name: str, **kwargs: Any) -> None:
        self.node = Device(name, **kwargs)

    @property
    def host(self) -> PeerInfo | None:
        return self.node.host

    async def pair(self, offer: str | PairingOffer, **kwargs: Any) -> PeerInfo:
        return await asyncio.to_thread(self.node.pair, offer, **kwargs)

    async def pair_with_code(self, code: str, **kwargs: Any) -> PeerInfo:
        return await asyncio.to_thread(self.node.pair_with_code, code, **kwargs)

    async def send(self, body: Any, **kwargs: Any) -> None:
        await asyncio.to_thread(self.node.send, body, **kwargs)

    async def request(self, body: Any, **kwargs: Any) -> Any:
        return await asyncio.to_thread(self.node.request, body, **kwargs)

    async def unpair(self) -> None:
        await asyncio.to_thread(self.node.unpair)
