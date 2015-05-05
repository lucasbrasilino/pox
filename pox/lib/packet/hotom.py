# Copyright 2014,2015 Lucas Brasilino <lucas.brasilino@gmail.com>
#
# Licensed under the Apache License, Version 2.0 (the "License");
# you may not use this file except in compliance with the License.
# You may obtain a copy of the License at:
#
#     http://www.apache.org/licenses/LICENSE-2.0
#
# Unless required by applicable law or agreed to in writing, software
# distributed under the License is distributed on an "AS IS" BASIS,
# WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
# See the License for the specific language governing permissions and
# limitations under the License.

# This code was inspired, but not developed from, ethernet pox library

#================================
# HotOM Header
#================================

import struct

from pox.lib.packet.packet_base import packet_base
from pox.lib.packet.packet_utils import ethtype_to_str
from pox.lib.packet.ethernet import ETHER_ANY
from pox.lib.addresses import *

class hotom(packet_base):
    "HotOM header"

    LEN = 10
    IP_TYPE = 0x00

    typetable = {
        IP_TYPE : 0x0800
    }

    def __init__(self, raw=None, prev=None, **kw):
        packet_base.__init__(self)

        self.prev = prev
        self.next = None

        self.net_id = 0
        self.dst = ETHER_ANY
        self.src = ETHER_ANY
        self.type = hotom.IP_TYPE

        if raw is not None:
            self.parse(raw)

        self._init(kw)

    def __str__(self):
        s = "[HotOM net_id={0} dst={1} src={2} type={3}]".format(
            hex(self.net_id),
            self.dst.toStr()[9:],
            self.src.toStr()[9:],
            ethtype_to_str(hotom.typetable[self.type]))
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
        (nid_msb,nid_lsb,dst,src,type) = struct.unpack("!HB3s3sB",
                                                       raw[:hotom.LEN])
        self.net_id = ((nid_msb<<8)+nid_lsb)
        self.dst = EthAddr(b"\x00\x00\x00"+dst)
        self.src = EthAddr(b"\x00\x00\x00"+src)
        self.type = type
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
            return EthAddr(b"\x00\x00\x00"+val.toRaw()[3:])
        if isinstance(val,bytes):
            if (len(val) == 3):
                return EthAddr(b"\x00\x00\x00"+val)
            if (len(val) == 8):
                return EthAddr("00:00:00:" + val)

    def hdr(self,payload):
        nid = self.net_id_pack()
        return nid + struct.pack('!3s3sB', self.dst.toRaw()[3:], 
                                 self.src.toRaw()[3:],self.type)
