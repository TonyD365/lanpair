# 中文快速开始

本指南用当前的 Python API 演示在同一局域网内配对设备并发送消息。高级 API
`Host`/`Device` 会处理传输、发现、密钥存储和重放保护；如果需要自定义传输，
可直接使用底层的 `Identity`、`Sealer` 和 `Opener`。

## 安装

```bash
pip install "lanpair[all]"   # keyring、mDNS discovery 和 QR 配对
```

核心包也可以单独安装：`pip install lanpair`，它只依赖 `cryptography`。

## 配对并通信

主机显示二维码，一台设备扫描后完成配对：

```python
# host.py
from lanpair import Host

with Host("前台") as host:
    if not host.devices:                 # 仅首次运行
        offer = host.pairing_offer()     # 默认 5 分钟、仅允许一台设备
        offer.print_qr()
        room = host.wait_for_pairing(timeout=300)
        print("已配对：", room.name)
    for msg in host.messages():          # 消息已验签、解密并检查重放
        print(msg.sender.name, msg.body)
```

```python
# device.py
from lanpair import Device

with Device("房间 3") as device:
    if device.host is None:              # 首次运行：输入二维码文本
        device.pair(input("扫描到的内容："))
    device.send({"type": "checkout"})
    for msg in device.messages():
        print("主机消息：", msg.body)
```

配对信息会跨重启保存。以后可再次调用 `host.pairing_offer()` 配对更多设备。
`host.send(device_id, body, ack=True)` 可要求确认并自动重试，`host.request(...)`
可等待回复；`AsyncHost` 和 `AsyncDevice` 提供对应的异步 API。

## 底层 API 与设备发现

若要自带 UDP、TCP 或 WebSocket 传输，可交换双方的公钥后封装消息：

```python
from lanpair import Identity, JsonFileSeqStore, Opener, Sealer

desk, room = Identity.generate(), Identity.generate()
inbox = Opener(room, store=JsonFileSeqStore("room-seqs.json"))
inbox.add_peer(desk.public)
wire = Sealer(desk).seal(room.public, {"type": "close"})
sender, body = inbox.open(wire)
```

`Announcer(me.public, "房间 3", port=8765)` 发布 mDNS，另一端用
`find(peer.device_id)` 找到地址。发现只提供地址提示，不决定信任关系；真正的信任
仍由公钥、签名、加密和重放检查保证。
