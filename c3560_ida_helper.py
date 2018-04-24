from idaapi import *
from idautils import *
from idc import *
from capstone import *
import binascii

md = Cs(capstone.CS_ARCH_PPC, capstone.CS_MODE_32 | capstone.CS_MODE_BIG_ENDIAN)
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
def list_index(a, b):
    c = None
    idx = -1
    if b[0] in a:
        idx = a.index(b[0])
        end = idx + len(b)
        if end <= len(a):
            c = a[idx : end]
    if c == b:
        return idx
    return -1

def list_index_all(a, b):
    li = []
    idx = 0
    while True:
        t = a[idx:]
        iidx = list_index(t, b)
        if iidx == -1:
            break
        idx += iidx
        li.append(idx)
        idx += len(b)
    return li

def C3560_func_search(opcode_list):
    for seg in Segments():
        print 'search code on segment ', SegName(seg)
        seg_start = SegStart(seg)
        seg_end = SegEnd(seg)
        seg_offset = seg_start
        nopcode = len(opcode_list) * 4
        while seg_offset < seg_end:
            code = get_many_bytes(seg_offset, 128)
            if code == None:
                #print seg_offset
                break
            dissem_code = PPC32_dissemble(seg_offset, code)
            try:
                for idx in list_index_all(dissem_code, opcode_list):
                    print 'find opcode on 0x%08x' % (seg_offset + idx * 4)
            except Exception, e:
                print e.message
            seg_offset += 128
            seg_offset -= (nopcode - 4)




if __name__ == '__main__':
    # smi_ibc_handle_ibd_init_discovery_msg
    opcode_list = ['stwu r1, -0x58(r1)','mflr r0', 'stmw r26, 0x40(r1)', 'stw r0, 0x5c(r1)','mr r27, r3', 'mr r30, r4']
    # search zpr register rop
    #opcode_list = ['mtspr 0x3b0, r0', 'sync 0', 'isync', 'mtmsr r11', 'blr']
    C3560_func_search(opcode_list)
    print 'Script Stoped'