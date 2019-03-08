#!/usr/bin/env python

#
# MalScan, A Simple PE File Heuristics Scanner
# Written By : @Ice3man (Nizamul Rana)
#
#  MalScan is a simple PE file heuristics scanner in python that I wrote
#  as a simple learning experiment for Windows Malware Analysis.
#  It is not complete by any means, so do whatever you want with the code.
#
#  PEID Rules are from awesome PEiD project.
#
# (C) Ice3man, 2018-19 All Rights Reserved
#
#  Redistribution and use in source and binary forms, with or without
#  modification, are permitted provided that the following conditions
#  are met:
#
#   1. Redistributions of source code must retain the above copyright
#      notice, this list of conditions and the following disclaimer.
#   2. Redistributions in binary form must reproduce the above copyright
#      notice, this list of conditions and the following disclaimer in the
#      documentation and/or other materials provided with the distribution.
#
#  THIS SOFTWARE IS PROVIDED BY THE COPYRIGHT HOLDERS AND CONTRIBUTORS
#  "AS IS" AND ANY EXPRESS OR IMPLIED WARRANTIES, INCLUDING, BUT NOT LIMITED
#  TO, THE IMPLIED WARRANTIES OF MERCHANTABILITY AND FITNESS FOR A
#  PARTICULAR PURPOSE ARE DISCLAIMED. IN NO EVENT SHALL THE COPYRIGHT HOLDER
#  OR CONTRIBUTORS BE LIABLE FOR ANY DIRECT, INDIRECT, INCIDENTAL, SPECIAL,
#  EXEMPLARY, OR CONSEQUENTIAL DAMAGES (INCLUDING, BUT NOT LIMITED TO,
#  PROCUREMENT OF SUBSTITUTE GOODS OR SERVICES; LOSS OF USE, DATA, OR
#  PROFITS; OR BUSINESS INTERRUPTION) HOWEVER CAUSED AND ON ANY THEORY OF
#  LIABILITY, WHETHER IN CONTRACT, STRICT LIABILITY, OR TORT (INCLUDING
#  NEGLIGENCE OR OTHERWISE) ARISING IN ANY WAY OUT OF THE USE OF THIS
#  SOFTWARE, EVEN IF ADVISED OF THE POSSIBILITY OF SUCH DAMAGE.
#


__author__ = "@Ice3man"
__version__ = "1.0"
__contact__ = "nizamulrock@gmail.com"

yarasig = "Yara-Rules.yara"  # TODO : Change this to your own custom rules

peid = "UserDB.txt"  # peid rules

import os
import sys
import hashlib
import time
import peutils

try:
    import pefile
except ImportError:
    print 'pefile not installed, see http://code.google.com/p/pefile/'
    sys.exit()

try:
    import yara
except ImportError:
    print 'yara-python is not installed, see http://code.google.com/p/yara-project/'

high_entropy = 0  # checking for high entropy sections
has_ep_out = 0  # cheks Entry point for bad entries
has_antivm = 0  # antivm checks
has_kernelmode_imports = 0  # ntoskernel imports
has_antidbg = 0  # anti_dbg_imp

good_ep_sections = ['.text', '.code', 'CODE', 'INIT', 'PAGE']
anti_dbg_imp = ['NtQueryInformationProcess', 'NtSetInformationThread',
                'IsDebuggerPresent', 'CheckRemoteDebugger']

kernel_loads = []  # for holding kernel32 imports

sigs = peutils.SignatureDatabase(peid)


def check_antidbg(pe):
    for entry in pe.DIRECTORY_ENTRY_IMPORT:
        if (entry.dll == "ntdll.dll"):
            for imp in entry.imports:
                for i in anti_dbg_imp:
                    if(imp.name == i):
                        has_antidbg = 1


def check_kernel_mode(pe):
    for entry in pe.DIRECTORY_ENTRY_IMPORT:
        if (entry.dll == "ntoskrnl.exe"):
            has_kernelmode_imports = 1


def check_yara(file):
    rule = yara.compile(yarasig)
    result = rule.match(file)
    return result

# taken From OpenSource AnalyzePE Program


def antivm(file):
    tricks = {
        "Red Pill": "\x0f\x01\x0d\x00\x00\x00\x00\xc3",
        "VirtualPc trick": "\x0f\x3f\x07\x0b",
        "VMware trick": "VMXh",
        "VMCheck.dll": "\x45\xC7\x00\x01",
        "VMCheck.dll for VirtualPC": "\x0f\x3f\x07\x0b\xc7\x45\xfc\xff\xff\xff\xff",
        "Xen": "XenVMM",
        "Bochs & QEmu CPUID Trick": "\x44\x4d\x41\x63",
        "Torpig VMM Trick": "\xE8\xED\xFF\xFF\xFF\x25\x00\x00\x00\xFF\x33\xC9\x3D\x00\x00\x00\x80\x0F\x95\xC1\x8B\xC1\xC3",
        "Torpig (UPX) VMM Trick": "\x51\x51\x0F\x01\x27\x00\xC1\xFB\xB5\xD5\x35\x02\xE2\xC3\xD1\x66\x25\x32\xBD\x83\x7F\xB7\x4E\x3D\x06\x80\x0F\x95\xC1\x8B\xC1\xC3"
    }
    ret = []
    with open(file, "rb") as f:
        buf = f.read()
        for trick in tricks:
            pos = buf.find(tricks[trick])
            if pos > -1:
                ret.append("\t[+] 0x%x %s" % (pos, trick))
                has_antivm = 1

    if len(ret):
        resp = "Yes"
        if verb == True:
            antis = '\n'.join(ret)
            resp = resp + '\n' + antis
        return resp


def check_dynamic_loaders(pe):
    i = 0
    for entry in pe.DIRECTORY_ENTRY_IMPORT:
        if (entry.dll == "KERNEL32.DLL"):
            for imp in entry.imports:
                i += 1
    if (i <= 7):
        dynamic = 1
    elif (i == 0):
        dynamic = 1
    return dynamic

# uses peutils module to perform checking for PEiD signs


def check_packers(pe):
    packers = []
    if sigs:
        matches = sigs.match(pe, ep_only=True)
        if matches != None:
            for match in matches:
                packers.append(match)
    return packers

# thanks pescanner


def check_entry_point(pe):
    name = ''
    ep = pe.OPTIONAL_HEADER.AddressOfEntryPoint
    pos = 0
    for sec in pe.sections:
        if (ep >= sec.VirtualAddress) and \
                (ep < (sec.VirtualAddress + sec.Misc_VirtualSize)):
            name = sec.Name.replace('\x00', '')
            break
        else:
            pos += 1
    return (ep, name, pos)


def main():
    has_res = 0 # For Suspecious Resources
    print "\n[*] MalScan : A PE File Heuristics Scanner"
    print "[*] Written By : @Ice3man (Nizamul Rana)"
    print "[*] Github : https://github.com/ice3man543"

    if len(sys.argv) != 2:
        print "\nUsage: %s <file to scan>\n" % (sys.argv[0])
        sys.exit()

    file = sys.argv[1]

    pe = pefile.PE(file)  # Loading the PE file

    fp = open(file, 'rb')
    data = fp.read()

    print "\n\n[*] File Name : %s" % file

    print"[*] Size : %d bytes" % len(data)
    if pe.FILE_HEADER.Machine == 0x14C:  # IMAGE_FILE_MACHINE_I386
        print "[*] Architecture : 32 Bits Binary"
    elif pe.FILE_HEADER.Machine == 0x8664:  # IMAGE_FILE_MACHINE_AMD64
        print "[*] Architecture : 64 Bits Binary"

    print "[*] MD5 : %s" % hashlib.md5(data).hexdigest()
    print "[*] SHA1 : %s" % hashlib.sha1(data).hexdigest()
    print "[*] SHA256 : %s" % hashlib.sha256(data).hexdigest()
    print "[*] CRC Hash : 0x%x" % pe.OPTIONAL_HEADER.CheckSum
    val = pe.FILE_HEADER.TimeDateStamp
    print "[*] Timestamp : [%s UTC]" % time.asctime(time.gmtime(val))

    # packer = check_yara(file)
    print "\n[*] PEiD Signatures Check ==> %s" % check_packers(pe)
    # print "\n[*] Yara Scan ==> %s" % packer
    print "[*] Anit-VM ==> %s" % antivm(file)

    (ep, name, pos) = check_entry_point(pe)
    ep_ava = ep + pe.OPTIONAL_HEADER.ImageBase
    if (name not in good_ep_sections) or pos == len(pe.sections):
        print "\n[*] Entry-Point Check ==> %s %s %d/%d [SUSPECIOUS]" % (hex(ep_ava), name, pos, len(pe.sections))
        has_ep_out = 1
    else:
        print "\n[*] Entry-Point Check ==> %s %s %d/%d" % (hex(ep_ava), name, pos, len(pe.sections))
        has_ep_out = 0

    high_entropy = 0
    print "\n\n[Section Overview]"
    j = 1
    print "\nNo.| Section Name |  VirtualAddress   |  VirtualSize    |  SizeOfRawData  |  Entropy \n"
    for section in pe.sections:
        # check if sections has high entropy
        if section.get_entropy() >= 7.4:
            print "[%d]|  %s    |     0x%x        |     0x%x      |      0x%x     |    %d   [SUSPECIOUS]" % (j, section.Name, section.VirtualAddress, section.Misc_VirtualSize, section.SizeOfRawData, section.get_entropy())
            j += 1
            high_entropy = 1
        else:
            print "[%d]|  %s    |     0x%x        |     0x%x      |      0x%x     |    %d   " % (j, section.Name, section.VirtualAddress, section.Misc_VirtualSize, section.SizeOfRawData, section.get_entropy())
            j += 1

    print "\n\n[Imports Overview]"
    for entry in pe.DIRECTORY_ENTRY_IMPORT:
        print "\n", entry.dll
        for imp in entry.imports:
            print '\t', hex(imp.address), imp.name

    print "\n\n[Exports Overview]"
    try:
        for export in pe.DIRECTORY_ENTRY_EXPORT.symbols:
            print "\t", hex(export.address), export.name
    except AttributeError:
        print "\n[*] No Exports Found In File . . .\n"

    k = 1
    print "\n\n[Resources Overview]"
    try:
        print "\nNo.| Resource Name | OffsetToData  |  Resource Size  |  Language\n"
        for resource_type in pe.DIRECTORY_ENTRY_RESOURCE.entries:
            if resource_type.name is not None:
                name = "%s" % resource_type.name
            else:
                name = "%s" % pefile.RESOURCE_TYPE.get(resource_type.struct.Id)
            if name == None:
                name = "%d" % resource_type.struct.Id
            if hasattr(resource_type, 'directory'):
                for resource_id in resource_type.directory.entries:
                    if hasattr(resource_id, 'directory'):
                        for resource_lang in resource_id.directory.entries:
                            # filetype = get_filetype(data)
                            lang = pefile.LANG.get(
                                resource_lang.data.lang, '*unknown*')
                            if (name == "BINARY"):
                                print "[%d]|  %s    |   0x%x        |   %d      |   %s  [SUSPECIOUS]" % (k, name, resource_lang.data.struct.OffsetToData, resource_lang.data.struct.Size, lang)
                                k += 1
                                has_res = 1
                            elif (name == "RT_RCDATA"):
                                print "[%d]|  %s    |   0x%x        |   %d      |   %s  [SUSPECIOUS]" % (k, name, resource_lang.data.struct.OffsetToData, resource_lang.data.struct.Size, lang)
                                k += 1
                                has_res = 1
                            else:
                                print "[%d]|  %s    |   0x%x        |   %d      |   %s" % (k, name, resource_lang.data.struct.OffsetToData, resource_lang.data.struct.Size, lang)
                                k += 1
                                has_res = 0
    except AttributeError:
        print "\n[*] No Resources Found In File\n"

    print "\n[TLS Overview]"
    if hasattr(pe, "DIRECTORY_ENTRY_TLS"):
        print "[*] TLS callback functions array detected at 0x%x" % pe.DIRECTORY_ENTRY_TLS.struct.AddressOfCallBacks
        callback_rva = pe.DIRECTORY_ENTRY_TLS.struct.AddressOfCallBacks - \
            pe.OPTIONAL_HEADER.ImageBase
        print("\t[*] Callback Array RVA 0x%x" % callback_rva)
    else:
        print "\n[*] No TLS Callbacks Detected ..."

    # final report
    check_antidbg(pe)
    check_kernel_mode(pe)
    antivm(file)
    dynamic = check_dynamic_loaders(pe)

    print "\n[MISC. Information]\n"

    if has_res == 1:
        print "[*] Alert -> Has Some Suspecious Resources"
    if has_antivm == 1:
        print "[*] Alert -> Has Anti-VirtualMachine Tricks"
    if has_ep_out == 1:
        print "[*] Alert -> Has Entry Point Outside Known Good Sections"
    if high_entropy == 1:
        print "[*] Alert -> Has High Entropy Values. Probably Packed Or Compressed"
    if dynamic == 1:
        print "[*] Alert -> Most Likely, Executable Uses Dynamic Loading or is Packed [Very Suspecious]"
    if has_kernelmode_imports == 1:
        print "[*] Alert -> Uses Kernel Mode. Probably a system driver"
    if has_antidbg == 1:
        print "[*] Alert -> Uses Anti-Debugging Tricks"

    if has_antidbg != 1 & high_entropy != 1 & has_ep_out != 1 & has_antivm != 1 & has_res != 1:
        print "\n[*] No Known Anomalies Detected In PE File ..."

    print "\n[*] Exiting MalScan Engine ..."
    sys.exit()

main()
