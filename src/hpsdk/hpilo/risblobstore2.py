#!/usr/bin/env python2.7
"""Base implementation for interaction with HPBLOB interface"""

VERSION = 2

#---------Imports---------
import os
import sys
import struct

from ctypes import *
from hp.hpilo.rishpilo import (HpIlo)

#---------End of imports---------

#-----------------------Error Returns----------------------

class UnexpectedResponseError(Exception):
    """Raise when we get data that we don't expect from iLO"""
    pass

class HpIloError(Exception):
    """Raised when ilo returns non-zero error code"""
    pass

class Blob2CreateError(Exception):
    """Raised when create operation fails"""
    pass

class Blob2ReadError(Exception):
    """Raised when read operation fails"""
    pass

class Blob2WriteError(Exception):
    """Raised when write operation fails"""
    pass

class Blob2DeleteError(Exception):
    """Raised when delete operation fails"""
    pass

class Blob2FinalizeError(Exception):
    """Raised when finalize operation fails"""
    pass

class BlobNotFoundError(Exception):
    """Raised when blob not found in key/namespace"""
    pass

class ChifDllMissingError(Exception):
    """Raised when unable to obtain hprest_chif dll handle"""
    pass

#----------------------------------------------------------

#-------------------Helper functions-------------------------

class BlobReturnCodes(object):
    """Blobstore return codes.

    SUCCESS           success
    ERROR             general error
    BADPARAM          bad parameter given
    BADCONFIG         bad configuration for attempted operation
    NOMEMORY          malloc fail or other internal error
    TIMEOUT           Internal timeout
    RETRY             Retry again later
    NOT_AGAIN         don't do this again

    BADNAME           problem with blob name
    TOOLARGE          problem with blob size (too large)
    READONLY          read only
    WRITEONLY         write only
    NOTFOUND          blob name not found
    BUFFERTOOSMALL    caller supplied buffer was too small
    MOREBLOBS         caller supplied buffer too small, more blobs available

    UNAVAILABLE       Unavailable currently
    DISABLED          Feature disabled by configuration
    UNINITIALIZED     not correctly initialized for this call
    UNIMPLEMENTED     We'll get to it
    UNSUPPORTED       not on this platform

    NOTMODIFIED        call did not perform the operation
    (if-none-match matched existing ETag)

    PRECONDITIONFAILED call did not perform the operation
    (if-match did not match existing ETag)
    """

    SUCCESS = 0
    ERROR = 1
    BADPARAM = 2
    BADCONFIG = 3
    NOMEMORY = 4
    TIMEOUT = 5
    RETRY = 6
    NOT_AGAIN = 7

    BADNAME = 8
    TOOLARGE = 9
    READONLY = 10
    WRITEONLY = 11
    NOTFOUND = 12
    BUFFERTOOSMALL = 13
    MOREBLOBS = 14

    UNAVAILABLE = 15
    DISABLED = 16
    UNINITIALIZED = 17
    UNIMPLEMENTED = 18
    UNSUPPORTED = 19

    NOTMODIFIED = 20
    PRECONDITIONFAILED = 21

class BlobStore2(object):
    """Blob store 2 class"""
    def __init__(self):
        self.channel = HpIlo()

    def __del__(self):
        """Blob store 2 del function"""
        self.channel.close()

    def create(self, key, namespace="perm"):
        """Create the blob

        :param key: The blob key to create.
        :type key: str.
        :param namespace: The blob namespace to create the key in.
        :type namespace: str.

        """
        lib = self.getHprestChifHandle()
        lib.create_not_blobentry.argtypes = [c_char_p, c_char_p]
        lib.create_not_blobentry.restype = POINTER(c_ubyte)

        name = create_string_buffer(key)
        namespace = create_string_buffer(namespace)
        
        ptr = lib.create_not_blobentry(name, namespace)
        data = ptr[:lib.size_of_createRequest()]
        data = bytearray(data)

        resp = self._send_receive_raw(data, lib.size_of_createResponse())

        if len(resp) > lib.size_of_createResponse(): #Size of _CreateResponse
            raise UnexpectedResponseError(100, "unexpected response from iLO")

        if len(resp) < lib.size_of_createResponse(): #Size of _CreateResponse
            raise UnexpectedResponseError(100, "unexpected response from iLO")

        errorcode = struct.unpack("<I", resp[8:12])[0]

        if not (errorcode == BlobReturnCodes.SUCCESS or \
                                    errorcode == BlobReturnCodes.NOTMODIFIED):
            raise Blob2CreateError()

        self.unloadChifHandle(lib)

        return resp

    def get_info(self, key, namespace="perm"):
        """Get blob info"""
        lib = self.getHprestChifHandle()
        lib.get_info.argtypes = [c_char_p, c_char_p]
        lib.get_info.restype = POINTER(c_ubyte)

        name = create_string_buffer(key)
        namespace = create_string_buffer(namespace)
        
        ptr = lib.get_info(name, namespace)
        data = ptr[:lib.size_of_infoRequest()]
        data = bytearray(data)

        resp = self._send_receive_raw(data, lib.size_of_infoResponse())

        if len(resp) > lib.size_of_infoResponse(): #Size of _InfoResponse
            raise UnexpectedResponseError(100, "unexpected response from iLO")

        if len(resp) < lib.size_of_infoResponse(): #Size of _InfoResponse
            raise UnexpectedResponseError(100, "unexpected response from iLO")

        errorcode = struct.unpack("<I", resp[8:12])[0]
        if errorcode == BlobReturnCodes.NOTFOUND:
            raise BlobNotFoundError(key, namespace)

        if not (errorcode == BlobReturnCodes.SUCCESS or \
                                    errorcode == BlobReturnCodes.NOTMODIFIED):
            raise HpIloError()
        
        response = resp[lib.size_of_responseHeader():]
        
        self.unloadChifHandle(lib)

        return response

    def read(self, key, namespace="perm"):
        """Blob read"""
        lib = self.getHprestChifHandle()
        maxread = lib.max_read_size()
        readsize = lib.size_of_readRequest()
        readhead = lib.size_of_responseHeader()

        self.unloadChifHandle(lib)
        
        blob_info = self.get_info(key, namespace)
        blobsize = struct.unpack("<I", blob_info[0:4])[0]

        bytes_read = 0
        data = bytearray()

        while bytes_read < blobsize:
            if (maxread - readsize) < (blobsize - bytes_read):
                count = maxread - readsize
            else:
                count = blobsize - bytes_read

            read_block_size = bytes_read
            recvpkt = self.read_fragment(key, namespace, read_block_size,\
                                                                    count)

            newreadsize = readhead + 4
            bytesread = struct.unpack("<I", recvpkt[readhead:(newreadsize)])[0]
            data.extend(recvpkt[newreadsize:newreadsize + bytesread])
            bytes_read += bytesread

        return data

    def read_fragment(self, key, namespace="perm", offset=0,\
                                                                    count=1):
        """Blob read fragment"""
        lib = self.getHprestChifHandle()
        lib.read_fragment.argtypes = [c_uint, c_uint, c_char_p, c_char_p]
        lib.read_fragment.restype = POINTER(c_ubyte)

        name = create_string_buffer(key)
        namespace = create_string_buffer(namespace)
        
        ptr = lib.read_fragment(offset, count, name, namespace)
        data = ptr[:lib.size_of_readRequest()]
        data = bytearray(data)

        resp = self._send_receive_raw(data, lib.size_of_readResponse())

        if len(resp) < lib.size_of_responseHeader():
            raise UnexpectedResponseError(100, "unexpected response from iLO")

        resp = resp + "\0" * (lib.size_of_readResponse() - len(resp))

        return resp

    def write(self, key, namespace="perm", data=None):
        """Blob write"""
        lib = self.getHprestChifHandle()
        maxwrite = lib.max_write_size()
        writesize = lib.size_of_writeRequest()

        self.unloadChifHandle(lib)

        if data:
            data_length = len(data)
            bytes_written = 0
            while bytes_written < data_length:
                if (maxwrite - writesize) < (data_length - bytes_written):
                    count = maxwrite - writesize
                else:
                    count = data_length - bytes_written

                write_blob_size = bytes_written

                self.write_fragment(key, namespace=namespace,
                            data=data[write_blob_size:write_blob_size+count], \
                            offset=write_blob_size, count=count)

                bytes_written += count

        return self.finalize(key, namespace=namespace)

    def write_fragment(self, key, namespace="perm", data=None, offset=0, \
                                                                    count=1):
        """Blob write fragment"""
        lib = self.getHprestChifHandle()
        lib.write_fragment.argtypes = [c_uint, c_uint, c_char_p, c_char_p]
        lib.write_fragment.restype = POINTER(c_ubyte)
        
        name = create_string_buffer(key)
        namespace = create_string_buffer(namespace)
        
        ptr = lib.write_fragment(offset, count, name, namespace)
        sendpacket = ptr[:lib.size_of_writeRequest()]

        dataarr = bytearray(sendpacket)
        dataarr.extend(buffer(data))

        resp = self._send_receive_raw(dataarr, lib.size_of_writeResponse())

        if len(resp) < lib.size_of_writeResponse(): #Size of _WriteResponse
            raise UnexpectedResponseError(100, "unexpected response from iLO")

        errorcode = struct.unpack("<I", resp[8:12])[0]
        if not (errorcode == BlobReturnCodes.SUCCESS or\
                                    errorcode == BlobReturnCodes.NOTMODIFIED):
            raise Blob2WriteError(errorcode)

        self.unloadChifHandle(lib)

        return resp

    def delete(self, key, namespace="perm"):
        """Blob delete"""
        lib = self.getHprestChifHandle()
        lib.delete_blob.argtypes = [c_char_p, c_char_p]
        lib.delete_blob.restype = POINTER(c_ubyte)

        name = create_string_buffer(key)
        namespace = create_string_buffer(namespace)

        ptr = lib.delete_blob(name, namespace)
        data = ptr[:lib.size_of_deleteRequest()]
        data = bytearray(data)

        resp = self._send_receive_raw(data, lib.size_of_deleteResponse())
        
        if len(resp) > lib.size_of_deleteResponse(): #Size of _DeleteResponse
            raise UnexpectedResponseError(100, "unexpected response from iLO")

        if len(resp) < lib.size_of_deleteResponse(): #Size of _DeleteResponse
            raise UnexpectedResponseError(100, "unexpected response from iLO")

        errorcode = struct.unpack("<I", resp[8:12])[0]
        if not (errorcode == BlobReturnCodes.SUCCESS or\
                                    errorcode == BlobReturnCodes.NOTMODIFIED):
            raise Blob2DeleteError(errorcode)

        self.unloadChifHandle(lib)

        return errorcode

    def list(self, namespace="perm", sep="\t"):
        lib = self.getHprestChifHandle()
        lib.list_blob.argtypes = [c_char_p]
        lib.list_blob.restype = POINTER(c_ubyte)
        
        namespace = create_string_buffer("perm")
        
        ptr = lib.list_blob(namespace)
        data = ptr[:lib.size_of_listRequest()]
        data = bytearray(data)

        resp = self._send_receive_raw(data, lib.size_of_listResponse())

        if len(resp) < lib.size_of_listResponseFixed():
            raise UnexpectedResponseError(100,"unexpected response from iLO")

        resp = resp + "\0" * (lib.size_of_listResponse() - len(resp))
        
        self.unloadChifHandle(lib)

        return resp

    def finalize(self, key, namespace="perm"):
        """Blob finalize"""
        lib = self.getHprestChifHandle()
        lib.finalize_blob.argtypes = [c_char_p, c_char_p]
        lib.finalize_blob.restype = POINTER(c_ubyte)
        
        name = create_string_buffer(key)
        namespace = create_string_buffer(namespace)
        
        ptr = lib.finalize_blob(name, namespace)
        data = ptr[:lib.size_of_finalizeRequest()]
        data = bytearray(data)

        resp = self._send_receive_raw(data, lib.size_of_finalizeResponse())

        if len(resp) > lib.size_of_finalizeResponse(): #Size of _FinalizeResponse
            raise UnexpectedResponseError(100, "unexpected response from iLO")

        if len(resp) < lib.size_of_finalizeResponse(): #Size of _FinalizeResponse
            raise UnexpectedResponseError(100, "unexpected response from iLO")

        errorcode = struct.unpack("<I", resp[8:12])[0]

        if not (errorcode == BlobReturnCodes.SUCCESS or\
                                    errorcode == BlobReturnCodes.NOTMODIFIED):
            raise Blob2FinalizeError()

        self.unloadChifHandle(lib)

        return errorcode

    def rest_immediate(self, req_data, rqt_key="RisRequest", \
                                        rsp_key="RisResponse", \
                                        rsp_namespace="volatile"):
        """Blob rest immediate"""
        lib = self.getHprestChifHandle()

        if len(req_data) < (lib.size_of_restImmediateRequest() + \
                                                        lib.max_write_size()):
            lib.rest_immediate.argtypes = [c_uint, c_char_p, c_char_p]
            lib.rest_immediate.restype = POINTER(c_ubyte)

            name = create_string_buffer(rsp_key)
            namespace = create_string_buffer(rsp_namespace)
            
            ptr = lib.rest_immediate(len(req_data), name, namespace)
            sendpacket = ptr[:lib.size_of_restImmediateRequest()]
            mode = False
        else:
            self.create(rqt_key, rsp_namespace)
            self.write(rqt_key, rsp_namespace, req_data)

            lib.rest_immediate_blobdesc.argtypes = [c_char_p, c_char_p, c_char_p]
            lib.rest_immediate_blobdesc.restype = POINTER(c_ubyte)
            
            name = create_string_buffer(rqt_key)
            namespace = create_string_buffer(rsp_namespace)
            rspname = create_string_buffer(rsp_key)
            
            ptr = lib.rest_immediate_blobdesc(name, rspname, namespace)
            sendpacket = ptr[:lib.size_of_restBlobRequest()]
            mode = True

        data = bytearray(sendpacket)

        if not mode:
            data.extend(req_data)

        resp = self._send_receive_raw(data, lib.size_of_restResponse())

        errorcode = struct.unpack("<I", resp[8:12])[0]
        recvmode = struct.unpack("<I", resp[12:16])[0]
        
        fixdlen = lib.size_of_restResponseFixed()
        response = resp[fixdlen:struct.unpack("<I", resp[16:20])[0] + fixdlen]

        if errorcode == BlobReturnCodes.NOTFOUND:
            raise BlobNotFoundError(rsp_key, rsp_namespace)

        tmpresponse = None
        if errorcode == BlobReturnCodes.SUCCESS and not mode:
            if recvmode == 0:
                tmpresponse = ''.join(map(chr, response))
        elif errorcode == BlobReturnCodes.NOTMODIFIED and not mode:
            if recvmode == 0:
                tmpresponse = ''.join(map(chr, response))
        elif recvmode == 0:
            raise HpIloError()

        self.unloadChifHandle(lib)

        if not tmpresponse and recvmode == 1:
            tmpresponse = self.read(rsp_key, rsp_namespace)
            self.delete(rsp_key, rsp_namespace)
        else:
            self.delete(rsp_key, rsp_namespace)

        return tmpresponse

    def _send_receive_raw(self, indata, datarecv=0):
        """Blob send receive raw"""
        resp = self.channel.send_receive_raw(indata, 3, datarecv)
        return resp

    def getHprestChifHandle(self):
        try:
            if os.name == 'nt':
                libhandle = cdll.LoadLibrary('hprest_chif.dll')
            else:
                libhandle = cdll.LoadLibrary('hprest_chif.so')
        except Exception as excp:
            raise ChifDllMissingError(excp)
        return libhandle

    def unloadChifHandle(self, lib):
        try:
            if os.name == 'nt':
                libHandle = lib._handle
                windll.kernel32.FreeLibrary(None, handle=libHandle)
        except:
            pass
