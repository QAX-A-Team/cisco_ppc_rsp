# author: dengxun @ 360 A-TEAM

from capstone import *
import binascii, re

md = Cs(CS_ARCH_PPC, CS_MODE_32 | CS_MODE_BIG_ENDIAN)
def PPC32_dissemble(base, bytecode):
    retlist = []
    for (address, size, mnemonic, op_str) in md.disasm_lite(bytecode, base):
        #print "0x%x:\t%s\t%s" % (address, mnemonic, op_str)
        #notice that capstone diffent with ida pro
        #   ida     capstone
        #   sync    sync 0
        c = '%s %s' % (mnemonic, op_str)
        retlist.append(c.strip())
    return retlist

def opcode2regex(opcode):
    opcodestr = opcode.replace('(', '\\(').replace(')', '\\)')
    # GREG => r[\d]{1,2}
    # NUMB => [0x]{0,2}[a-f0-9]+
    opcodestr = opcodestr.replace('GREG', 'r[\d]{1,2}')
    opcodestr = opcodestr.replace('NUMB', '[-]{0,1}[0x]{0,2}[a-f0-9]+')
    return opcodestr.strip()
def gadget_index_single(colist, opreg):
    for i in range(0, len(colist)):
        if re.match(opreg, colist[i]):
            return i
    return -1
def gadget_check(colist, reglist):
    for i in range(0, len(reglist)):
        if not re.match(reglist[i], colist[i]):
            return False
    return True
def gadget_index(colist, oplist):
    i = 0
    search = len(colist) - len(oplist)
    retlist = []
    reglist = [opcode2regex(x) for x in oplist]
    while i < search:
        if gadget_check(colist[i:], reglist):
            retlist.append(i)
            i += len(oplist)
        else:
            i += 1
    return retlist






if __name__ == '__main__':
    fp = open('c3560_memory_text.bin', 'rb')
    binary = fp.read(1024)
    offset = 0
    base = 0x01000000

    #disable DEP
    #opcode = ['mtspr 0x3b0, r0', 'sync 0', 'isync', 'mtmsr r11', 'blr']
    #write-4
    #opcode = ['stw r30, NUMB(r31)', 'lwz r0, NUMB(r1)', 'mtlr r0', '.+','.+','blr']
    #write-4 setter
    #opcode = [ 'lwz r0, NUMB(r1)', 'mtlr r0', 'lwz r30, NUMB(r1)', 'lwz r31, NUMB(r1)', '.+', 'blr']
    #opcode = ['mtctr GREG', 'bctrl', 'mtlr GREG', 'blrl']
    #checksum
    #opcode = ['lis r9, NUMB', 'addi r9, r9, NUMB', 'li r3, 0', 'lis r11, NUMB']
    #opcode = ['trap', 'blr']
    opcode = ['lis GREG, NUMB', 'addi GREG, GREG, NUMB', 'li GREG, NUMB', 'lis GREG, NUMB']
    while len(binary) > 0:
        dicode = PPC32_dissemble(base, binary)
        for i in gadget_index(dicode, opcode):
            print '0x%08x' % (base + offset + i * 4)
            print dicode[i:i + len(opcode)]
            print
        binary = fp.read(1024)
        offset += 1024
    fp.close()


