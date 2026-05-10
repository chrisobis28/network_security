#!/usr/bin/env python2
# -*- coding: utf-8 -*-

# Taken from https://homework.nwsnet.de/releases/0d09/

"""
ICMP Knock Server
~~~~~~~~~~~~~~~~~

Listen for ICMP packets.

Overview
--------

This program uses a concept similar to port knocking, which basically involves
waiting for a range of packets that match given criteria before executing some
action (typically exposing a port, e.g. for SSH connections, that is kept
closed or blocked otherwise).

But instead of listening for TCP or UDP packets to arrive on specific ports in
a specific order, it accepts ICMP echo requests and checks if their payload
lengths and order of arrival match the given pattern.

The advantage is that this approach works with the standard PING tool.
Programs with custom code or (although common) networking tools like netcat
plus the ability to execute them are not required.


Usage
-----

Using common PING utilities, information can be passed by setting a special
length::

    Windows:    ping -l 123 11.22.33.44
    Linux:      ping -s 123 11.22.33.44


Prospect
--------

This is not yet the end of what can be done using ICMP (or other protocols).
By setting the payload data, there are more possibilities for transmitting a
secret on which the server might react.  It's also possible to tunnel any data
(like shell commands) through ICMP, even bypassing firewalls that don't block
or analyze ICMP packets to that effect.  However, setting the payload is not
supported by common PING utilities and would eleminate the advantage mentioned
above.


TODO/Ideas
----------

- reset accept window and action after X seconds
- shorter output display (leave out type code?)
- no-output/quiet mode
- ignore packets that are too big
- allow special length to be specified as parameter
- make usable as module by accepting a callback or so
- allow for a list of different packet sizes as secret code
- pad sequences smaller than `max(len(seq.key))` to avoid interferences?
- start checking smaller sequences first, break and reset on match


For details, refer to :RFC:`791` (Internet Protocol) and :RFC:`792` (Internet
Control Message Protocol).

.. _RFC 791:            http://www.faqs.org/rfcs/rfc791.html
.. _RFC 297:            http://www.faqs.org/rfcs/rfc792.html
.. _portknocking.org:   http://www.portknocking.org/
.. _Port Knocking:      http://www.linuxjournal.com/article/6811

:Copyright: 2007-2008 Jochen Kupperschmidt
:Date: 04-Apr-2008
:License: MIT `<http://www.opensource.org/licenses/mit-license.php>`_
"""

import socket
from struct import unpack
import time
import subprocess


# Decorator to bind execution of the wrapped callable to the occurence of the
# given value (= payload length) sequence.

actions = {}

def react_on(*values):
    """Decorate a function to be called if the given value sequence is found."""
    def wrapper(func):
        seq = tuple(map(int, values))
        actions[seq] = func
        def inner(*args, **kwargs):
            return func(*args, **kwargs)
        return inner
    return wrapper


# custom action definitions

@react_on(22, 22)
def open_http():
    """Here goes stuff to adjust your firewall or something."""
    print('Opening HTTP...')
    subprocess.call("iptables -I INPUT -p tcp --dport 80 -j ACCEPT", shell=True)


# protocol stuff

ICMP_TYPES = {
     0: 'echo reply',
     3: 'destination unreachable',
     4: 'source quench',
     5: 'redirect',
     8: 'echo',
    11: 'time exceeded',
    12: 'parameter problem',
    13: 'timestamp',
    14: 'timestamp reply',
    15: 'information request',
    16: 'information reply',
    }


class IPPacket(object):
    """An Internet Protocol packet (see :RFC:`791`)."""

    def __init__(self, data):
        header, self.payload = data[:20], data[20:]

        # Unpack IP header.
        (self.version_ihl, self.tos, self.length, self.ident,
            self.flags_fragoffset, self.ttl, self.proto,
            self.hdr_chksum) = unpack('!BBHHHBBH', header[:12])

        # Get IP addresses directly from packed data.
        self.src_addr = socket.inet_ntoa(header[12:16])
        self.dst_addr = socket.inet_ntoa(header[16:20])


class ICMPPacket(object):
    """An Internet Control Message Protocol packet (see :RFC:`792`)."""

    def __init__(self, data):
        header, self.payload = data[:8], data[8:]

        # Unpack header of ICMP echo message.
        (self.type, self.code, self.checksum, self.ident,
            self.seq_num) = unpack('!BBHHH', header)


def parse_packet(data):
    """Parse packet and return the payload length."""
    ip = IPPacket(data)
    icmp = ICMPPacket(ip.payload)
    print('ICMP message from %s, type %d (%s), code %d, %d byte payload.') % (
        ip.src_addr, icmp.type, ICMP_TYPES[icmp.type], icmp.code,
        len(icmp.payload))
    return len(icmp.payload)


# server stuff

class Server(object):

    def __init__(self, actions, knock_delay=5):
        self.actions = actions
        self.key_lengths = tuple(sorted(len(key) for key in actions.iterkeys()))
        self.max_key_length = max(self.key_lengths)
        self.seq = []
        self.knock_delay = knock_delay
        self.last_knock = time.time()

        # Open socket.
        self.sock = socket.socket(
            socket.AF_INET, socket.SOCK_RAW, socket.IPPROTO_ICMP)
        self.sock.bind(('', 1))

    def append_to_seq(self, value):
        now = time.time()
        if now > (self.last_knock + self.knock_delay):
            # Too much time passed since last knock.
            self.seq = []
        self.last_knock = now

        self.seq.append(value)
        if len(self.seq) > self.max_key_length:
            del self.seq[0]

        # Try to find sequence in action mapping.
        for i in self.key_lengths:
            key = tuple(self.seq[-i:])
            try:
                self.actions[key]()
                self.seq = []
                break
            except KeyError:
                pass

    def handle_request(self):
        """Receive and process a request."""
        try:
            data = self.sock.recv(1024)
        except socket.error, e:
            if e[0] == 10040:
                print('Message too long, ignoring.')
                return
            raise
        self.append_to_seq(parse_packet(data))

    def serve_forever(self):
        while True:
            self.handle_request()


if __name__ == '__main__':
    try:
        Server(actions).serve_forever()
    except KeyboardInterrupt:
        exit('Ctrl-C pressed, aborting...')