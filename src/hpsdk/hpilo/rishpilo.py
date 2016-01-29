#!/usr/bin/env python2.7
"""Base implementation for interaction with HP iLO interface"""

#---------Imports---------

import os
import sys
import time
import select
import ctypes

#---------End of imports---------

class HpIloReadError(Exception):
    """Throw when errors encountered when reading from iLO"""
    def __init__(self, descr):
        self.descr = descr

    def __str__(self):
        return repr(self.descr)

class HpIloError(Exception):
    """Throw after a successful read, but when error code is non zero"""
    pass

class HpIlo(object):
    """Base class of interaction with hpilo"""
    if os.name != 'nt':
        # Newer versions of hpilo kernel module support a configurable max_ccb
        MAX_CCB = '/sys/module/hpilo/parameters/max_ccb'
        CHANNEL = '/dev/hpilo/d0ccb'

    def __init__(self):
        if os.name == 'nt':
            fhandle = ctypes.c_void_p()

            self.libhandle = ctypes.windll.kernel32.LoadLibraryA('cpqci')
            self.dll = ctypes.WinDLL(None, handle=self.libhandle)
            self.dll.ChifInitialize(None)
            self.chifsuccess = 0

            self.dll.ChifCreate.argtypes = [ctypes.c_void_p]
            self.dll.ChifCreate.restype = ctypes.c_uint32

            try:
                status = self.dll.ChifCreate(ctypes.byref(fhandle))
                if status != self.chifsuccess:
                    print "Error %s trying to open a channel to iLO " %(status)
                    self.unload()
                    exit(1)
                self.fhandle = fhandle
                self.dll.ChifSetRecvTimeout(self.fhandle, 120000)
            except:
                print "Fail to open the driver channel"
                self.unload()
                sys.exit(0)
        else:
            if os.path.exists(HpIlo.MAX_CCB):
                fhandle = open(HpIlo.MAX_CCB, 'r')

                for line in fhandle:
                    start = int(line) - 1

                fhandle.close()
            else:
                #otherwise the default number of channels is 8
                start = 7

            self.file = HpIlo.CHANNEL + str(start)
            self.cmd = None
            self.svc = None
            self.response = None

            while True:
                try:
                    self.fhandle = os.open(self.file, os.O_NONBLOCK | os.O_EXCL\
                                            | os.O_RDWR, 0666)
                    self.len = 0
                    self.seq = 0
                    return
                except Exception:
                    start = start - 1
                    self.file = HpIlo.CHANNEL + str(start)
                    if start < 0:
                        raise HpIloReadError("iLO channel could not be allocated.")

    def write_raw(self, data):
        """Send data to iLO.  Use this if you have already pre-packed and"""\
        """ formatted data
        :param data: bytearray of data to send
        :type data: bytearray
        """
        return os.write(self.fhandle, data)

    def read_raw(self, timeout=5):
        """Read data from iLO. Use this if you need the response as is"""\
        """ (without any parse)"""
        try:
            pkt = bytearray()
            status = select.select([self.fhandle], [], [], timeout)

            if status != ([self.fhandle], [], []) and timeout > 0:
                raise HpIloReadError("Ilo is not responding")

            if status != ([self.fhandle], [], []) and timeout == 0:
                return pkt

            pkt.extend(os.read(self.fhandle, 8096))
            self.response = pkt[4] + 256*pkt[5]

            return pkt
        except Exception, excp:
            raise HpIloReadError("%s : %s" % (excp, sys.exc_info()[0]))

    def chif_packet_exchange(self, data, datarecv):
        """ Windows only function for handling chif calls """
        buff = "".join(map(chr, data))
        buff = ctypes.create_string_buffer("".join(map(chr, data)))
        error = ctypes.c_uint()
        recbuff = ctypes.create_string_buffer(datarecv)

        error = self.dll.ChifPacketExchange(self.fhandle, ctypes.byref(buff),\
                                             ctypes.byref(recbuff), datarecv)
        if error != self.chifsuccess:
            print "CpqCiRecv return an error %s" % (error)
            self.close()
            self.unload()
            exit(1)

        pkt = bytearray()

        if datarecv is None:
            pkt.extend(recbuff)
        else:
            pkt.extend(recbuff[:datarecv])

        return pkt

    def send_receive_raw(self, data, retries=3, datarecv=None):
        """ Windows only chif handler """
        tries = 0

        while tries < retries:
            try:
                if os.name == 'nt':
                    resp = self.chif_packet_exchange(data, datarecv)
                else:
                    retlen = self.write_raw(data)
                    if retlen != len(data):
                        raise ValueError()

                    resp = self.read_raw(120)

                return resp
            except:
                time.sleep(1)

                if tries == (retries - 1):
                    raise

            tries += 1

        raise HpIloError(100, "iLO not responding")

    def close(self):
        """Chif close function"""
        try:
            if os.name == 'nt':
                self.dll.ChifClose(self.fhandle)
            else:
                os.close(self.fhandle)
        except:
            pass

    def unload(self):
        """Chif unload function"""
        try:
            del self.dll
            ctypes.windll.kernel32.FreeLibrary(self.libhandle)
        except:
            pass

    def __del__(self):
        """Chif delete function"""
        self.close()

        if os.name == 'nt':
            self.unload()


