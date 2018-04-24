#!/usr/bin/python
# -*- coding: UTF-8 -*-
# author: dengxun @ 360 A-TEAM

import serial, re, time, string, sys, binascii
from collections import OrderedDict
from prompt_toolkit import prompt
from prompt_toolkit.history import InMemoryHistory
from prompt_toolkit.auto_suggest import AutoSuggestFromHistory
from capstone import Cs
import capstone

class service_serial ():
    def __init__(self, port = 'COM1',
                baudrate = 9600,
                bytesize = serial.EIGHTBITS,
                stopbits = serial.STOPBITS_ONE,
                timeout = 1):
        self.active = True
        self.port = port
        self.baudrate = baudrate
        self.bytesize = bytesize
        self.stopbits = stopbits
        self.timeout = timeout

        self.__serial =  None
    def __del__(self):
        if self.active:
            self.__serial.close()
    def connect(self):
        try:
            self.__serial = serial.Serial(port = self.port,
                                  baudrate = self.baudrate,
                                  bytesize = self.bytesize,
                                  stopbits = self.stopbits,
                                  timeout = self.timeout)
        except serial.SerialException, e:
            print e
            return False
        self.active = True
    def __check_is_connected(self):
        if not self.active:
            raise RuntimeError('not connected on serial!')
    def write(self, buf):
        self.__check_is_connected()
        self.__serial.write(buf)
    def read(self):
        self.__check_is_connected()
        buf = ''
        while(True):
            dat = self.__serial.read(1024)
            if len(dat) == 0:
                break
            buf += dat
        return buf
    def w2r(self, buf):
        self.write(buf)
        return self.read()

class gdb_ppc32_context:
    def __init__(self):
        self.__registers = OrderedDict([
        ('unknown register', 0),
        ('r0', 0), ('sp', 0), ('r2', 0), ('r3', 0), ('r4', 0), ('r5', 0), ('r6', 0), ('r7', 0), ('r8', 0), ('r9', 0),
        ('r10', 0), ('r11', 0), ('r12', 0), ('r13', 0), ('r14', 0), ('r15', 0), ('r16', 0), ('r17', 0), ('r18', 0),
        ('r19', 0),
        ('r20', 0), ('r21', 0), ('r22', 0), ('r23', 0), ('r24', 0), ('r25', 0), ('r26', 0), ('r27', 0), ('r28', 0),
        ('r29', 0),
        ('r30', 0), ('r31', 0), ('pc', 0), ('msr', 0), ('cr', 0), ('lr', 0), ('ctr', 0), ('xer', 0), ('dar', 0),
        ('dsisr', 0)
        ])
        self.__status_changed = True
        self.__serial = service_serial()
        self.__serial.connect()
        self.read2show_registers()
        self.read2show_stack()
        self.dissemble_pc()
    def __cr_register(self, cr):
        b = bin(cr)[2:]
        b = ('0' * (32 - len(b))) + b
        i = 0
        line = ''
        for r in re.findall(r'\d{4}', b):
            line += 'cr%d(%d)  ' % (i, int(r, 2))
            i += 1
        print line
    def checksum(self, data):
        n = 0
        for c in data:
            n += ord(c)
        n %= 256
        return '%02x' % (n)
    def __convert_rsp_cmd(self, cmd): #gdb command to serial line
        rspcmd = '$%s#%s' % (cmd, self.checksum(cmd))
        #print rspcmd
        return rspcmd

    def compress_binaray_string(self, binstr): #binstr with lowercase
        binlower = binstr.lower()
        if not re.match(r'^[a-f0-9]{2,}$', binlower) or len(binlower) % 2 != 0:
            raise Exception('binary string format error')
        packedstr = ''
        for x in re.findall(r'a+|b+|c+|d+|e+|f+|0+|1+|2+|3+|4+|5+|6+|7+|8+|9+', binlower):
            if len(x) > 4:
                packedstr += x[0] + '*' + '%02x' % (len(x) - 1)
            else:
                packedstr += x
        return packedstr

    def extract_packed_buf(self, regbuf):
        grp = re.search(r'\+\$([a-f0-9*]+)#([a-f0-9]{2})', regbuf).group
        packedbuf = grp(1)
        bufchksum = grp(2)
        if bufchksum != self.checksum(packedbuf):
            print 'checksum verify failed'
        unpackedbuf = ''
        i = 0
        while i < len(packedbuf):
            if packedbuf[i] == '*':
                unpackedbuf += packedbuf[i - 1] * int(packedbuf[i+1 : i + 3], 16)
                i += 3
            else:
                unpackedbuf += packedbuf[i]
                i += 1
        return unpackedbuf

    def extract_registers(self, regbuf):
        regbuf = self.extract_packed_buf(regbuf)
        #print regbuf
        i = 0
        for regname in self.__registers:
            hexstr = regbuf[i: i + 8]
            self.__registers[regname] = int(hexstr, 16)
            i += 8
    def display_registers(self):
        if self.__status_changed:
            self.__load_registers()
        i = 1
        for regname in self.__registers:
            if regname == 'unknown register':
                continue
            print '%8s    %08x' % (regname, self.__registers[regname]),
            if i % 4 == 0:
                print
            i += 1
        self.__cr_register(self.__registers['cr'])
        print '%08s $pc = %08x, stack = %08x\n\n' % ('*', self.get_register_value('$pc'), self.get_register_value('$sp'))
    def sendgdbcmd(self, cmd):
        buf = self.__serial.w2r(self.__convert_rsp_cmd(cmd))
        ack = buf[0 : 1]
        if ack == '-':
            raise Exception('gdb command error')
        if buf[0:3] == '+$E':
            raise Exception('gdb command error witch code 0x%s' % (buf[3:5]))
        return buf
    def sendgdbkey(self, key):
        return self.__serial.w2r(key)
    def read_from_serial(self):
        return self.__serial.read()
    def __load_registers(self):
        buf = self.sendgdbcmd('g')
        if not buf:
            raise Exception('read registers error')
        self.__status_changed = False
        self.extract_registers(buf)
    def read2show_registers(self):
        #print self.__status_changed
        if self.__status_changed:
            self.__load_registers()
        self.display_registers()
    def set_status_flag(self, b):
        self.__status_changed = b
    def read2show_stack(self, n = 8):
        stack = self.get_register_value('$sp')
        print '- - - - - stack at 0x%08x - - - - -' % (stack)
        buf = self.readmemory(stack, 4 * n)
        i = 0
        for x in re.findall(r'.{8}', buf):
            hexstr = '%08x' % (int(x, 16))
            print '$sp + %02x : 0x%s' % (i, hexstr)
            i += 4
    def convert_printtable(self, data):
        line = ''
        for c in data:
            if c == '\t':
                line += '\\t'
                continue
            if c == '\r':
                line += '\\r'
                continue
            if c == '\n':
                line += '\\n'
                continue
            if c in string.printable:
                line += c
            else:
                line += '.'
        return line
    def hexdump(self, data, n):
        i = 1
        line = ''
        for x in re.findall(r'.{2}', data):
            print x,
            line += x.decode('hex')
            if i % n == 0:
                print '\t%s' % (self.convert_printtable(line))
                line = ''
            i += 1
        for x in range(0, n - (i % n) + 1):
            print '  ',
        print '\t%s' % (self.convert_printtable(line))
        print
    def writememory(self, addr, binstr): #binstr like "000f4541"
        cmd = 'M%08x,%02x:%s' % (addr, len(binstr)/2, self.compress_binaray_string(binstr))
        buf = self.sendgdbcmd(cmd)
        return buf
    def readmemory(self, addr, n = 32):
        cmd = 'm%08x,%02x' % (addr, n)
        buf = self.sendgdbcmd(cmd)
        return self.extract_packed_buf(buf)
    def readmemory_binary(self, addr, n = 32):
        bytes = self.readmemory(addr, n)
        bytes = binascii.a2b_hex(bytes)
        return bytes
    def dissemble_code(self, code, baseaddr):
        md = Cs(capstone.CS_ARCH_PPC, capstone.CS_MODE_32 | capstone.CS_MODE_BIG_ENDIAN)
        md.syntax = capstone.CS_OPT_SYNTAX_INTEL
        for (address, size, mnemonic, op_str) in md.disasm_lite(code, baseaddr):
            print "0x%x:\t%s\t%s" % (address, mnemonic, op_str)
    def dissemble_addr(self, baseaddr, n = 32):
        print '\n- - - - - dissemble for 0x%08x - - - - -' % (baseaddr)
        code = self.readmemory_binary(baseaddr, n)
        self.dissemble_code(code, baseaddr)
    def dissemble_pc(self, m = 5):
        if self.__status_changed:
            self.__load_registers()
        regval = self.get_register_value('$pc')
        n = m * 4
        self.dissemble_addr(regval, n)
    def get_register_value(self, register_name):
        fixed_register_name = self.__check2fix__register_name(register_name)
        if self.__status_changed:
            self.__load_registers()
        return self.__registers[fixed_register_name]

    def __check2fix__register_name(self, register_name): #eg: $pc $sp => pc $sp
        reg_fix = register_name[0]
        reg_nam = register_name[1:]
        if reg_fix != '$' or reg_nam not in self.__registers.keys():
            raise Exception('bad register name %s' % (register_name))
        return reg_nam
    def read_register_value(self, register_name): #it's seems cisco c3560 not support command 'p'???
        fixed_register_name = self.__check2fix__register_name(register_name)
        register_index = self.__registers.keys().index(fixed_register_name)
        cmd = 'p%02x' % (register_index)
        buf = self.sendgdbcmd(cmd)
        print buf
        sys.exit(0)

class gdb_ppc32_cmd:
    def __init__(self):
        self.__gdb = gdb_ppc32_context()
        self.__breakpoints = {}
    def cmd_q(self, arc, arg):
        sys.exit(0)

    def handle_cmd(self, cmd):
        arg = re.split(r'[\t\s]+', cmd)
        cmd_func_name = 'cmd_%s' % (arg.pop(0))
        if cmd_func_name in dir(self):
            try:
                cmd_func = getattr(self, cmd_func_name)
                cmd_func(len(arg), arg)
            except Exception, e:
                print e.message
        else:
            print 'unknown command %s' % (cmd)

    def console(self):
        hist = InMemoryHistory()
        suggest = AutoSuggestFromHistory()
        while True:
            gdb_cmd = prompt(u'> ', history=hist, auto_suggest=suggest)
            self.handle_cmd(gdb_cmd.encode('ascii'))
    def __check2fix_register_format(self, register_name):
        if not re.match(r'^\$[a-z\d]{2,5}$', register_name):
            raise Exception('bad register name %s format' % (register_name))
        return register_name
    def __check2fix_address_format(self, addrstr): #return real address
        addrstr = addrstr.lower()
        if not re.match(r'^[a-f\d]{4,8}$|^\$[a-z\d]{2,5}$|^0x[a-f\d]{4,8}$', addrstr):
            raise Exception('error address or register name format: %s' % (addrstr))
        if addrstr[0] == '$':
            return self.__gdb.get_register_value(addrstr)
        if addrstr[0:2] == '0x':
            return int(addrstr[2:], 16)
        return int(addrstr, 16)
    def __check2fix_number_format(self, numberstr):
        if not re.match(r'^\d{1,3}$|^0x[a-f\d]{1,2}$', numberstr):
            raise Exception('error number format: %s' % (numberstr))
        if numberstr[0:2] == '0x':
            return int(numberstr[2:], 16)
        return int(numberstr)
    def cmd_i(self, arc, arg):
        if arc == 1 and arg[0] == 'r':
            self.__gdb.read2show_registers()
            return
        if arc == 2 and arg[0] == 'r':
            reg_nam = self.__check2fix_register_format(arg[1])
            regval = self.__gdb.get_register_value(reg_nam)
            print '%s => %x (%d)' % (reg_nam, regval, regval)
            return
        if arc == 1 and arg[0] == 's':
            self.__gdb.read2show_stack(16)
            return
        if arc == 2 and arg[0] == 's':
            n = self.__check2fix_number_format(arg[1])
            self.__gdb.read2show_stack(n)
            return
        print 'error parameters'

    def cmd_d(self, arc, arg):
        n = 5
        addr = None
        if arc == 0:
            addr = self.__gdb.get_register_value('$pc')
        if arc > 0:
            addr =  self.__check2fix_address_format(arg[0])
        if arc == 2:
            n = self.__check2fix_number_format(arg[1])
        self.__gdb.dissemble_addr(addr, n * 4) #ppc align with 4 bytes
    def cmd_x(self, arc, arg):
        n = 32
        if arc > 2 or arc == 0:
            print 'error parameters'
            return
        if arc == 2:
            n = self.__check2fix_number_format(arg[1])
        addr = self.__check2fix_address_format(arg[0])
        buf = self.__gdb.readmemory(addr, n)
        self.__gdb.hexdump(buf, 16)
    def cmd_c(self, arc, arg):
        buf = self.__gdb.sendgdbkey(chr(0x01))
        print 'remote prompt %s' % (buf)
        if buf == '||||':
            buf = self.__gdb.sendgdbcmd('c')
            if not re.match(r'^\$.*#$', buf):
                print 'recvice error msg? \n %s' % (buf)
            while True:
                if buf[-4:] == '||||':
                    print 'remote stoped'
                    self.__gdb.set_status_flag(True)
                    break
                buf = self.__gdb.read_from_serial()
                if len(buf) == 0:
                    continue
                print buf
                time.sleep(0.1)
        else:
            print 'maybe remote is not in debugging mode?'
    def cmd_ex(self, arc, arg):
        if arc == 0:
            return
        print self.__gdb.sendgdbcmd(arg[0])
    def cmd_si(self, arc, arg):
        if arc == 0:
            print self.__gdb.sendgdbcmd('s')
        if arc == 1:
            addr = self.__check2fix_address_format(arg[0])
            addr -= 4
            print self.__gdb.sendgdbcmd('s%x' % addr)
        self.__gdb.set_status_flag(True)
        self.__gdb.dissemble_pc()
    def cmd_w(self, arc, arg):
        if arc != 2:
            print 'w <addr> <binary string>'
            return
        addr = self.__check2fix_address_format(arg[0])
        print self.__gdb.writememory(addr, arg[1])
    def cmd_fuzz(self, arc, arg):
        for i in range(0, 257):
            print 'check', i
            try:
                print self.__gdb.sendgdbcmd('Z2,13b6a80,%02x' % (i))
                break
            except Exception, e:
                print e.message
        print 'end'
    def cmd_b(self, arc, arg):
        opcode_trap = '7fe00008'
        if arc != 1:
            print 'b <addr>   breakpoint setter\n B <addr>   breakpoint delete'
            print 'breakpoint list'
            for x in self.__breakpoints:
                print x, self.__breakpoints[x]
            return
        addr = self.__check2fix_address_format(arg[0])
        print 'store machine code at 0x%08x' % (addr)
        machcode = self.__gdb.readmemory(addr, 4)
        print 'machine code', machcode
        print 'write instruction "trap" to addr %08x' % (addr)
        print self.__gdb.writememory(addr, opcode_trap)
        if self.__gdb.readmemory(addr, 4) == opcode_trap:
            print 'set breakpoint successfully'
            self.__breakpoints['%08x' % (addr)] = machcode
        else:
            print 'something error occurred?'
    def cmd_B(self, arc, arg):
        if arc != 1:
            print 'B <addr>   breakpoint delete'
            return
        addr = self.__check2fix_address_format(arg[0])
        addrstr = '%08x' % (addr)
        if not addrstr in self.__breakpoints.keys():
            print 'No breakpoint at', addrstr
            return
        print 'write stored opcode to ', addrstr
        machcode = self.__breakpoints[addrstr]
        print self.__gdb.writememory(addr, machcode)
        if self.__gdb.readmemory(addr, 4) == machcode:
            print 'delete breakpoint successfully'
            self.__breakpoints.pop(addrstr)
        else:
            print 'something error occurred?'


#gdb = gdb_ppc32_context()
gdbcmd = gdb_ppc32_cmd()


if __name__ == '__main__':
    gdbcmd.console()


