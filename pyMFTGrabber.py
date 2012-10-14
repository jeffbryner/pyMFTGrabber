#!/usr/bin/python2
import os,sys
import ctypes
import struct
import binascii
from StringIO import StringIO
from optparse import OptionParser
import socket

'''
2012 Jeff Bryner
Script to retrieve the Master File Table (MFT) record for an NTFS file system from a live system. 

Usage: 
Victim/Client NTFS/Windows box: 
 pyMFTGrabber.py -f "\\.C:" -s 10.200.1.1 -p 6666

Forensic workstation at 10.200.1.1: 
nc -l -p 6666 >mft.dd

You can then use the analyzeMFT.py ( https://github.com/dkovar/analyzeMFT ) to decode the MFT
and it's associated file records.

'''

#constant size values
longlongsize=ctypes.sizeof(ctypes.c_longlong)
bytesize=ctypes.sizeof(ctypes.c_byte)
wordsize=2
dwordsize=4

#utility functions for printing data as hexdumps
def hexbytes(xs, group_size=1, byte_separator=' ', group_separator=' '):
    def ordc(c):
        return ord(c) if isinstance(c,str) else c
    
    if len(xs) <= group_size:
        s = byte_separator.join('%02X' % (ordc(x)) for x in xs)
    else:
        r = len(xs) % group_size
        s = group_separator.join(
            [byte_separator.join('%02X' % (ordc(x)) for x in group) for group in zip(*[iter(xs)]*group_size)]
        )
        if r > 0:
            s += group_separator + byte_separator.join(['%02X' % (ordc(x)) for x in xs[-r:]])
    return s.lower()



def hexprint(xs):
    def chrc(c):
        return c if isinstance(c,str) else chr(c)
    
    def ordc(c):
        return ord(c) if isinstance(c,str) else c
    
    def isprint(c):
        return ordc(c) in range(32,127) if isinstance(c,str) else c > 31
    
    return ''.join([chrc(x) if isprint(x) else '.' for x in xs])



def hexdump(xs, group_size=4, byte_separator=' ', group_separator='-', printable_separator='  ', address=0, address_format='%04X', line_size=16):
    if address is None:
        s = hexbytes(xs, group_size, byte_separator, group_separator)
        if printable_separator:
            s += printable_separator + hexprint(xs)
    else:
        r = len(xs) % line_size
        s = ''
        bytes_len = 0
        for offset in range(0, len(xs)-r, line_size):
            chunk = xs[offset:offset+line_size]
            bytes = hexbytes(chunk, group_size, byte_separator, group_separator)
            s += (address_format + ': %s%s\n') % (address + offset, bytes, printable_separator + hexprint(chunk) if printable_separator else '')
            bytes_len = len(bytes)
        
        if r > 0:
            offset = len(xs)-r
            chunk = xs[offset:offset+r]
            bytes = hexbytes(chunk, group_size, byte_separator, group_separator)
            bytes = bytes + ' '*(bytes_len - len(bytes))
            s += (address_format + ': %s%s\n') % (address + offset, bytes, printable_separator + hexprint(chunk) if printable_separator else '')
    
    return s

# decode ATRHeader from 
# analyzeMFT.py routines
# Copyright (c) 2010 David Kovar.
def decodeATRHeader(s):
    d = {}
    d['type'] = struct.unpack("<L",s[:4])[0]
    if d['type'] == 0xffffffff:
        return d
    d['len'] = struct.unpack("<L",s[4:8])[0]
    d['res'] = struct.unpack("B",s[8])[0]
    d['nlen'] = struct.unpack("B",s[9])[0]                  # This name is the name of the ADS, I think.
    d['name_off'] = struct.unpack("<H",s[10:12])[0]
    d['flags'] = struct.unpack("<H",s[12:14])[0]
    d['id'] = struct.unpack("<H",s[14:16])[0]
    if d['res'] == 0:
        d['ssize'] = struct.unpack("<L",s[16:20])[0]
        d['soff'] = struct.unpack("<H",s[20:22])[0]
        d['idxflag'] = struct.unpack("<H",s[22:24])[0]
    else:
        d['start_vcn'] = struct.unpack("<d",s[16:24])[0]
        d['last_vcn'] = struct.unpack("<d",s[24:32])[0]
        d['run_off'] = struct.unpack("<H",s[32:34])[0]
        d['compusize'] = struct.unpack("<H",s[34:36])[0]
        d['f1'] = struct.unpack("<I",s[36:40])[0]
        d['alen'] = struct.unpack("<d",s[40:48])[0]
        d['ssize'] = struct.unpack("<d",s[48:56])[0]
        d['initsize'] = struct.unpack("<d",s[56:64])[0]

    return d

def twos_comp(val, bits):
    """compute the 2's compliment of int value val"""
    if( (val&(1<<(bits-1))) != 0 ):
        val = val - (1<<bits)
    return val

#decode NTFS data runs from a MFT type 0x80 record ala: 
#http://inform.pucp.edu.pe/~inf232/Ntfs/ntfs_doc_v0.5/concepts/data_runs.html
def decodeDataRuns(dataruns):
    decodePos=0
    header=dataruns[decodePos]
    while header !='\x00':
        #print('HEADER\n' + hexdump(header))
        offset=int(binascii.hexlify(header)[0])
        runlength=int(binascii.hexlify(header)[1])
        #print('OFFSET %d LENGTH %d' %( offset,runlength))
        
        #move into the length data for the run
        decodePos+=1

        #print(decodePos,runlength)
        length=dataruns[decodePos:decodePos +int(runlength)][::-1]
        #print('LENGTH\n'+hexdump(length))
        length=int(binascii.hexlify(length),16)
            
        
        hexoffset=dataruns[decodePos +runlength:decodePos+offset+runlength][::-1]
        #print('HEXOFFSET\n' +hexdump(hexoffset))
        cluster=twos_comp(int(binascii.hexlify(hexoffset),16),offset*8)
        
        yield(length,cluster)
        decodePos=decodePos + offset+runlength
        header=dataruns[decodePos]
        #break


def debug(message):
    if options.debug:
        sys.stderr.write(message +'\n')



if __name__ == '__main__':
    
    parser = OptionParser()
    parser.add_option("-s", dest='server', default='127.0.0.1', help="name or IP address of server")
    parser.add_option("-p", dest='port', default=6666,type='int', help="port number")
    parser.add_option("-f", dest='input', default="stdin",help="input: stdin default, drive name, filename, etc")
    parser.add_option("-d", "--debug",action="store_true", dest="debug", default=False, help="turn on debugging output")    
    
    (options,args) = parser.parse_args()    
    

    ntfsdrive=file(r'%s'%options.input,'rb')
    if os.name=='nt':
        #poor win can't seek a drive to individual bytes..only 1 sector at a time..
        #convert MBR to stringio to make it seekable
        ntfs=ntfsdrive.read(512)
        ntfsfile=StringIO(ntfs)
    else:
        ntfsfile=ntfsdrive

    #parse the MBR for this drive to get the bytes per sector,sectors per cluster and MFT location. 
    #bytes per sector
    ntfsfile.seek(0x0b)
    bytesPerSector=ntfsfile.read(wordsize)
    bytesPerSector=struct.unpack('<h', binascii.unhexlify(binascii.hexlify(bytesPerSector)))[0]
    
    #sectors per cluster
    
    ntfsfile.seek(0x0d)
    sectorsPerCluster=ntfsfile.read(bytesize)
    sectorsPerCluster=struct.unpack('<b', binascii.unhexlify(binascii.hexlify(sectorsPerCluster)))[0]
    
    
    #get mftlogical cluster number
    ntfsfile.seek(0x30)
    cno=ntfsfile.read(longlongsize)
    mftClusterNumber=struct.unpack('<q', binascii.unhexlify(binascii.hexlify(cno)))[0]
    
    
    debug('%d %d %d'%(bytesPerSector,sectorsPerCluster,mftClusterNumber))

    #MFT is then at NTFS + (bytesPerSector*sectorsPerCluster*mftClusterNumber)
    mftloc=long(bytesPerSector*sectorsPerCluster*mftClusterNumber)   
    ntfsdrive.seek(0)
    ntfsdrive.seek(mftloc)
    mftraw=ntfsdrive.read(1024)
   
    
    #We've got the MFT record for the MFT itself.
    #parse it to the DATA section, decode the data runs and send the MFT over TCP
    ReadPtr=0
    mftDict={}
    mftDict['attr_off'] = struct.unpack("<H",mftraw[20:22])[0]
    ReadPtr=mftDict['attr_off']    
    debug(str(mftDict))
    while ReadPtr<len(mftraw):    
        ATRrecord = decodeATRHeader(mftraw[ReadPtr:])
        debug("Attribute type: %x Length: %d Res: %x" % (ATRrecord['type'], ATRrecord['len'], ATRrecord['res']))
        if ATRrecord['type'] == 0x80:
            debug(hexdump(mftraw[ReadPtr:ReadPtr+ATRrecord['len']]))
            debug(hexdump(mftraw[ReadPtr+ATRrecord['run_off']:ReadPtr+ATRrecord['len']]))
            dataruns=mftraw[ReadPtr+ATRrecord['run_off']:ReadPtr+ATRrecord['len']]
            prevCluster=None
            prevSeek=0
            sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
            sock.connect((options.server,options.port))            
            
            for length,cluster in decodeDataRuns(dataruns):
                debug('%d %d'%(length,cluster))
                debug('drivepos: %d'%(ntfsdrive.tell()))
                
                if prevCluster==None:    
                    ntfsdrive.seek(cluster*bytesPerSector*sectorsPerCluster)
                    prevSeek=ntfsdrive.tell()
                    sock.send(ntfsdrive.read(length*bytesPerSector*sectorsPerCluster))
                    prevCluster=cluster
                else:
                    ntfsdrive.seek(prevSeek)
                    newpos=prevSeek + (cluster*bytesPerSector*sectorsPerCluster)
                    debug('seekpos: %d'%(newpos))
                    ntfsdrive.seek(newpos)
                    prevSeek=ntfsdrive.tell()                    
                    sock.send(ntfsdrive.read(length*bytesPerSector*sectorsPerCluster))
                    prevCluster=cluster
            sock.close                    
            break
        if ATRrecord['len'] > 0:
            ReadPtr = ReadPtr + ATRrecord['len']
        