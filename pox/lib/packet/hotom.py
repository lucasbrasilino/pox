import struct

from pox.lib.packet.packet_base import packet_base
from pox.lib.packet.ethernet import ETHER_ANY
from pox.lib.addresses import *

class hotom(packet_base):
    "HotOM header"

    LEN = 9

    def __init__(self, raw=None, prev=None, **kw):
        packet_base.__init__(self)

        self.prev = prev
        self.next = None

        self.net_id = ETHER_ANY
        self.dst = ETHER_ANY
        self.src = ETHER_ANY

        if raw is not None:
            self.parse(raw)

        self._init(kw)

    def __str__(self):
        s = "[HotOM net_id={0} dst={1} src={2}]".format(
            self.net_id.toStr()[9:],
            self.dst.toStr(),
            self.src.toStr())
        return s

    def parse(self, raw):
        assert isinstance(raw,bytes)
        self.next = None
        self.raw = raw
        alen = len(raw)
        if alen < hotom.LEN:
            self.msg('warning HotOM packet data too short to parse header: data len %u' % (alen,))
            return

        self.net_id = EthAddr('\x00\x00\x00'+raw[:3])
        self.dst = EthAddr('\x00\x00\x00'+raw[3:6])
        self.src = EthAddr('\x00\x00\x00'+raw[6:9])
        self.next = raw[hotom.LEN:]
        self.parsed = True

    def hdr(self,payload):
        return struct.pack('!3s3s3s', self.net_id.toRaw()[3:],
                           self.dst.toRaw()[3:],self.src.toRaw()[3:])
