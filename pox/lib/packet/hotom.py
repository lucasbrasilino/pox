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

        self.net_id = 0
        self.dst = ETHER_ANY
        self.src = ETHER_ANY

        if raw is not None:
            self.parse(raw)

        self._init(kw)

    def __str__(self):
        s = "[HotOM net_id={0} dst={1} src={2}]".format(
            hex(self.net_id),
            self.dst.toStr()[9:],
            self.src.toStr()[9:])
        return s

    def parse(self, raw):
        assert isinstance(raw,bytes)
        self.next = None
        self.raw = raw
        alen = len(raw)
        if alen < hotom.LEN:
            self.msg('warning HotOM packet data too short to parse header: data len %u' % (alen,))
            return

        nid=raw[:3]
        (nid_msb,nid_lsb,dst,src) = struct.unpack("!HB3s3s",raw[:hotom.LEN])
        self.net_id = ((nid_msb<<8)+nid_lsb)
        self.dst = EthAddr(nid+dst)
        self.src = EthAddr(nid+src)
        self.next = raw[hotom.LEN:]
        self.parsed = True

    def net_id_pack(self):
        nid_msb = self.net_id>>8
        nid_lsb = 0x0000ff & self.net_id
        return struct.pack('!HB',nid_msb,nid_lsb)

    def net_id_toStr(self,separator=":"):
        return separator.join(('%02x' % (ord(x),) for x in self.net_id))

    @property
    def src(self):
        return self._src

    @property
    def dst(self):
        return self._dst

    @src.setter
    def src(self,val):
        self._src = self._dstsrc_setter(val)

    @dst.setter
    def dst(self,val):
        self._dst = self._dstsrc_setter(val)

    def _dstsrc_setter(self,val):
        net_id = self.net_id_pack()
        if isinstance(val,EthAddr):
            return EthAddr(net_id+val.toRaw()[3:])
        if isinstance(val,bytes):
            if (len(val) == 6):
                return EthAddr(net_id+val)
            if (len(val) == 17):
                return EthAddr(self.net_id_toStr() + val[9:])

    def hdr(self,payload):
        nid = self.net_id_pack()
        return nid + struct.pack('!3s3s', self.dst.toRaw()[3:], 
                                 self.src.toRaw()[3:])
