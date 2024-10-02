# BandiView Vulnerability Report

# Vulnerability 1

## Vulnerability Overview

- **Summary:** A vulnerability occurs when loading crafted JXR files in BandiView (v7.05).
- **Manufacturer:** Bandisoft
- **Software:** BandiView
- **Version:** v7.05 (2024/7/15, BuildNo=26122)
- **Attack Type:** Improper input validation
- **Impact:** Denial of Service (DoS)
- **Vulnerable Target:** BandiView.exe
- **Vulnerable Function:** `sub_0x3d80fc` (Offset in BandiView.exe)

## Vulnerability Environment

**Edition**                   Windows 10 Pro

**Version**                   22H2

**Installation Date**    2023-11-17

**OS Build**                 19045.4651

**Experience**             Windows Feature Experience Pack 1000.19060.1000.0

## Details

- **Discovery Method:** Fuzz testing and debugging revealed unexpected behavior during file parsing.
- **Cause:** When inserting a file with unsupported content, BandiView fails to properly handle the input, leading to an error.
    
    ```c
    if ( v17 == 5238 )
    {
      v18 = (_DWORD *)(a1 + 66480);
      sub_7FF768E261C0(*(_QWORD *)(a1 + 88), a3, a4, a5, a1 + 66480);
      *(_WORD *)(*(_QWORD *)(a1 + 66488) + 2 * (v9 >> 1)) = 0; //Vulnerable Code
      *v18 = 31;
      return (unsigned int)v10;
    }
    goto LABEL_83;
    ```
    

---

- **Proof/Validation**
    
    When attempting to load the file in BandiView, the program shuts down.
    
    ```bash
    (4cbc.548c): Access violation - code c0000005 (first chance)
    First chance exceptions are reported before any exception handling.
    This exception may be expected and handled.
    BandiView+0x3d80fc:
    00007ff6`fbcf80fc 6644893448      mov     word ptr [rax+rcx*2],r14w ds:00000000`e5dbcde6=????
    ```
    
    ```bash
    0:019> !analyze -v
    *******************************************************************************
    *                                                                             *
    *                        Exception Analysis                                   *
    *                                                                             *
    *******************************************************************************
    
    KEY_VALUES_STRING: 1
    
        Key  : AV.Fault
        Value: Write
    
        Key  : Analysis.CPU.mSec
        Value: 484
    
        Key  : Analysis.Elapsed.mSec
        Value: 1061
    
        Key  : Analysis.IO.Other.Mb
        Value: 4
    
        Key  : Analysis.IO.Read.Mb
        Value: 1
    
        Key  : Analysis.IO.Write.Mb
        Value: 11
    
        Key  : Analysis.Init.CPU.mSec
        Value: 515
    
        Key  : Analysis.Init.Elapsed.mSec
        Value: 108867
    
        Key  : Analysis.Memory.CommitPeak.Mb
        Value: 98
    
        Key  : Analysis.Version.DbgEng
        Value: 10.0.27704.1001
    
        Key  : Analysis.Version.Description
        Value: 10.2408.27.01 amd64fre
    
        Key  : Analysis.Version.Ext
        Value: 1.2408.27.1
    
        Key  : Failure.Bucket
        Value: INVALID_POINTER_WRITE_c0000005_BandiView.exe!Unknown
    
        Key  : Failure.Hash
        Value: {bfe0ef3a-1175-0614-d858-640033fc855a}
    
        Key  : Timeline.OS.Boot.DeltaSec
        Value: 28456
    
        Key  : Timeline.Process.Start.DeltaSec
        Value: 121
    
        Key  : WER.OS.Branch
        Value: vb_release
    
        Key  : WER.OS.Version
        Value: 10.0.19041.1
    
        Key  : WER.Process.Version
        Value: 7.5.0.1
    
    NTGLOBALFLAG:  0
    
    APPLICATION_VERIFIER_FLAGS:  0
    
    EXCEPTION_RECORD:  (.exr -1)
    ExceptionAddress: 00007ff6fbcf80fc (BandiView+0x00000000003d80fc)
       ExceptionCode: c0000005 (Access violation)
      ExceptionFlags: 00000000
    NumberParameters: 2
       Parameter[0]: 0000000000000001
       Parameter[1]: 00000000e5dbcde6
    Attempt to write to address 00000000e5dbcde6
    
    FAULTING_THREAD:  0000548c
    
    PROCESS_NAME:  BandiView.exe
    
    WRITE_ADDRESS:  00000000e5dbcde6 
    
    ERROR_CODE: (NTSTATUS) 0xc0000005 - 0x%p               0x%p                        .          %s              .
    
    EXCEPTION_CODE_STR:  c0000005
    
    EXCEPTION_PARAMETER1:  0000000000000001
    
    EXCEPTION_PARAMETER2:  00000000e5dbcde6
    
    STACK_TEXT:  
    00000055`ba4fee00 00007ff6`fbcf884b     : 0000018a`2428f0d0 0000018a`2428f0d0 00000055`ba4feee0 00000000`00000001 : BandiView+0x3d80fc
    00000055`ba4feea0 00007ff6`fbcf8b04     : 0000018a`2a3c2e60 0000018a`2428f0d0 00000055`ba4f4949 00000000`000000e5 : BandiView+0x3d884b
    00000055`ba4fef20 00007ff6`fbcf8b65     : 00000000`00000049 00000000`00000002 00007ff6`fbb4d990 00000000`00000000 : BandiView+0x3d8b04
    00000055`ba4fef90 00007ff6`fbb1e95d     : 0000018a`241eee20 0000018a`241eee20 00000055`ba4ff0b0 00000000`00000068 : BandiView+0x3d8b65
    00000055`ba4fefc0 00007ff6`fbaf3a87     : 00000000`0002eb0b 00000055`ba4ff0b0 00000055`ba4ff0b0 00000000`00000000 : BandiView+0x1fe95d
    00000055`ba4ff030 00007ff6`fba50859     : 00000055`ba4ff328 00000055`ba4ff190 0000018a`241eee20 00000000`00000000 : BandiView+0x1d3a87
    00000055`ba4ff090 00007ff6`fba1aa81     : 0000018a`2428a250 00000000`0007d000 ffffffff`ffffffff 0000018a`241eef70 : BandiView+0x130859
    00000055`ba4ff300 00007ff6`fba6c699     : 0000018a`2428a250 0000018a`241eef88 0000018a`23d4ee58 0000018a`23d4ef48 : BandiView+0xfaa81
    00000055`ba4ff3a0 00007ff6`fba6784f     : 0000018a`2428a250 0000018a`2421e690 00000055`ba4ff4b8 ffffffff`ffffffff : BandiView+0x14c699
    00000055`ba4ff430 00007ff6`fba67100     : 0000018a`00000001 00000000`00000000 0000018a`163c0e88 00000000`00000000 : BandiView+0x14784f
    00000055`ba4ff520 00007ff6`fba46c1e     : 00000000`00000001 0000018a`1d81e960 00000000`00000000 0000018a`17d20000 : BandiView+0x147100
    00000055`ba4ff5f0 00007ff6`fb9ee2af     : 0000018a`1d81e960 0000018a`1d81e960 00000000`00000000 0000018a`2428a240 : BandiView+0x126c1e
    00000055`ba4ff650 00007ff6`fb9ee11c     : 00007ff6`fbf81bb0 00000000`00000000 00000000`00000000 00000000`00000000 : BandiView+0xce2af
    00000055`ba4ff6c0 00007ff6`fb9eebff     : 00000000`00000000 00000000`00000000 00000000`00000005 00000000`00000005 : BandiView+0xce11c
    00000055`ba4ff6f0 00007ff6`fbd4d6ca     : 0000018a`18307160 00000000`00000000 00000000`00000000 00000000`00000000 : BandiView+0xcebff
    00000055`ba4ff720 00007ffe`75307374     : 00000000`00000000 00000000`00000000 00000000`00000000 00000000`00000000 : BandiView+0x42d6ca
    00000055`ba4ff750 00007ffe`7569cc91     : 00000000`00000000 00000000`00000000 00000000`00000000 00000000`00000000 : kernel32!BaseThreadInitThunk+0x14
    00000055`ba4ff780 00000000`00000000     : 00000000`00000000 00000000`00000000 00000000`00000000 00000000`00000000 : ntdll!RtlUserThreadStart+0x21
    
    SYMBOL_NAME:  BandiView+3d80fc
    
    MODULE_NAME: BandiView
    
    IMAGE_NAME:  BandiView.exe
    
    STACK_COMMAND:  ~19s ; .cxr ; kb
    
    FAILURE_BUCKET_ID:  INVALID_POINTER_WRITE_c0000005_BandiView.exe!Unknown
    
    OS_VERSION:  10.0.19041.1
    
    BUILDLAB_STR:  vb_release
    
    OSPLATFORM_TYPE:  x64
    
    OSNAME:  Windows 10
    
    IMAGE_VERSION:  7.5.0.1
    
    FAILURE_ID_HASH:  {bfe0ef3a-1175-0614-d858-640033fc855a}
    
    Followup:     MachineOwner
    ---------
    ```
    
    When analyzing the file using Microsoft's Windbg program, the same results were observed.
    

---

- **Exploitation Scenario**
    
     If a user disguises the malicious file with extensions like .jpg or .png and downloads it through various means, then attempts to open it using the BandiView image viewer, the vulnerability will be triggered, causing the program to freeze. This results in the user losing access to all functions of BandiView, effectively leading to a Denial of Service (DoS) attack.
    

---

- **Mitigation:** Strengthen exception handling in the image loading function

# Vulnerability 2

## Vulnerability Overview

- **Summary:** A vulnerability occurs when loading crafted PSD files in BandiView (v7.05).
- **Manufacturer:** Bandisoft
- **Software:** BandiView
- **Version:** v7.05 (2024/7/15, BuildNo=26122)
- **Attack Type:** Improper input validation
- **Impact:** Buffer Overflow
- **Vulnerable Target:** BandiView.exe

## Vulnerability Environment

**Edition**                   Windows 11 Pro

**Version**                   23H2

**Installation Date**    2023-10-10

**OS Build**                 22631.4037

**Experience**             Windows Feature Experience Pack 1000.22700.1027.0

## Details

- **Discovery Method:** The vulnerability was discovered during a fuzz testing process targeting the file parsing functions in BandiView. Unexpected behavior was observed, and further analysis using the IDA Pro debugger revealed the presence of the vulnerability.

---

- **Cause:** A buffer overflow vulnerability occurs due to insufficient verification of PSD files. This flaw allows attackers to overflow the buffer, potentially leading to unpredictable program behavior, crashes, or the execution of arbitrary code. Proper validation of file inputs is necessary to prevent such vulnerabilities.

---

- **Proof/Validation:**
    
    When attempting to load the file in BandiView, the program shuts down.
    
    ```bash
    (7090.2734): Security check failure or stack buffer overrun - code c0000409 (!!! second chance !!!)
    Subcode: 0x2 FAST_FAIL_STACK_COOKIE_CHECK_FAILURE 
    BandiView_x64+0x410d1d:
    00007ff7`aa7b0d1d cd29            int     29h
    ```
    
    ```bash
    0:013> !analyze -v
    SOS_HOSTING: Failed to find runtime directory
    SOS_HOSTING: ICLRRuntimeHost::ExecuteInDefaultAppDomain failed 80131515
    *******************************************************************************
    *                                                                             *
    *                        Exception Analysis                                   *
    *                                                                             *
    *******************************************************************************
    
    Failed to find runtime module (coreclr.dll or clr.dll or libcoreclr.so), 0x80004005
    Extension commands need it in order to have something to do.
    For more information see https://go.microsoft.com/fwlink/?linkid=2135652
    Failed to find runtime module (coreclr.dll or clr.dll or libcoreclr.so), 0x80004005
    Extension commands need it in order to have something to do.
    For more information see https://go.microsoft.com/fwlink/?linkid=2135652
    
    KEY_VALUES_STRING: 1
    
        Key  : Analysis.CPU.mSec
        Value: 1640
    
        Key  : Analysis.Elapsed.mSec
        Value: 71243
    
        Key  : Analysis.IO.Other.Mb
        Value: 31
    
        Key  : Analysis.IO.Read.Mb
        Value: 1
    
        Key  : Analysis.IO.Write.Mb
        Value: 65
    
        Key  : Analysis.Init.CPU.mSec
        Value: 264
    
        Key  : Analysis.Init.Elapsed.mSec
        Value: 507279
    
        Key  : Analysis.Memory.CommitPeak.Mb
        Value: 167
    
        Key  : FailFast.Name
        Value: STACK_COOKIE_CHECK_FAILURE
    
        Key  : FailFast.Type
        Value: 2
    
        Key  : Failure.Bucket
        Value: FAIL_FAST_STACK_BUFFER_OVERRUN_STACK_COOKIE_CHECK_FAILURE_MISSING_GSFRAME_c0000409_BandiView.x64.exe!Unknown
    
        Key  : Failure.Hash
        Value: {d3a506d9-04ad-bfdd-58cb-04f4250ceab5}
    
        Key  : Timeline.OS.Boot.DeltaSec
        Value: 433742
    
        Key  : Timeline.Process.Start.DeltaSec
        Value: 507
    
        Key  : WER.OS.Branch
        Value: ni_release
    
        Key  : WER.OS.Version
        Value: 10.0.22621.1
    
        Key  : WER.Process.Version
        Value: 7.5.0.1
    
    NTGLOBALFLAG:  70
    
    APPLICATION_VERIFIER_FLAGS:  0
    
    EXCEPTION_RECORD:  (.exr -1)
    ExceptionAddress: 00007ff7aa7b0d1d (BandiView_x64+0x0000000000410d1d)
       ExceptionCode: c0000409 (Security check failure or stack buffer overrun)
      ExceptionFlags: 00000001
    NumberParameters: 1
       Parameter[0]: 0000000000000002
    Subcode: 0x2 FAST_FAIL_STACK_COOKIE_CHECK_FAILURE 
    
    FAULTING_THREAD:  00002734
    
    PROCESS_NAME:  BandiView.x64.exe
    
    ERROR_CODE: (NTSTATUS) 0xc0000409 -                                                                     .                                                                                       .
    
    EXCEPTION_CODE_STR:  c0000409
    
    EXCEPTION_PARAMETER1:  0000000000000002
    
    STACK_TEXT:  
    0000008d`048ff1e0 00007ff7`aa5d2fa6     : 000002d8`219f4790 00000255`00000000 00000000`00000001 00000000`00000010 : BandiView_x64+0x410d1d
    0000008d`048ff220 00000255`24ddd9a0     : 00000255`24ddddd0 00000255`24dde200 00000255`24dde630 00000255`24ddea60 : BandiView_x64+0x232fa6
    0000008d`048ff350 00000255`24ddddd0     : 00000255`24dde200 00000255`24dde630 00000255`24ddea60 00000255`24ddee90 : 0x00000255`24ddd9a0
    0000008d`048ff358 00000255`24dde200     : 00000255`24dde630 00000255`24ddea60 00000255`24ddee90 00000255`24ddf2c0 : 0x00000255`24ddddd0
    0000008d`048ff360 00000255`24dde630     : 00000255`24ddea60 00000255`24ddee90 00000255`24ddf2c0 00000255`24ddf6f0 : 0x00000255`24dde200
    0000008d`048ff368 00000255`24ddea60     : 00000255`24ddee90 00000255`24ddf2c0 00000255`24ddf6f0 00000255`24d986b0 : 0x00000255`24dde630
    0000008d`048ff370 00000255`24ddee90     : 00000255`24ddf2c0 00000255`24ddf6f0 00000255`24d986b0 00000255`24d98ae0 : 0x00000255`24ddea60
    0000008d`048ff378 00000255`24ddf2c0     : 00000255`24ddf6f0 00000255`24d986b0 00000255`24d98ae0 00000255`24d98f10 : 0x00000255`24ddee90
    0000008d`048ff380 00000255`24ddf6f0     : 00000255`24d986b0 00000255`24d98ae0 00000255`24d98f10 00000255`24d99340 : 0x00000255`24ddf2c0
    0000008d`048ff388 00000255`24d986b0     : 00000255`24d98ae0 00000255`24d98f10 00000255`24d99340 00000255`24d99770 : 0x00000255`24ddf6f0
    0000008d`048ff390 00000255`24d98ae0     : 00000255`24d98f10 00000255`24d99340 00000255`24d99770 00000255`24d99ba0 : 0x00000255`24d986b0
    0000008d`048ff398 00000255`24d98f10     : 00000255`24d99340 00000255`24d99770 00000255`24d99ba0 00000255`24d99fd0 : 0x00000255`24d98ae0
    0000008d`048ff3a0 00000255`24d99340     : 00000255`24d99770 00000255`24d99ba0 00000255`24d99fd0 00000255`24d9a400 : 0x00000255`24d98f10
    0000008d`048ff3a8 00000255`24d99770     : 00000255`24d99ba0 00000255`24d99fd0 00000255`24d9a400 00000255`24d9a830 : 0x00000255`24d99340
    0000008d`048ff3b0 00000255`24d99ba0     : 00000255`24d99fd0 00000255`24d9a400 00000255`24d9a830 00000255`24d9ac60 : 0x00000255`24d99770
    0000008d`048ff3b8 00000255`24d99fd0     : 00000255`24d9a400 00000255`24d9a830 00000255`24d9ac60 00000255`24d9b090 : 0x00000255`24d99ba0
    0000008d`048ff3c0 00000255`24d9a400     : 00000255`24d9a830 00000255`24d9ac60 00000255`24d9b090 00000255`24d9b4c0 : 0x00000255`24d99fd0
    0000008d`048ff3c8 00000255`24d9a830     : 00000255`24d9ac60 00000255`24d9b090 00000255`24d9b4c0 00000255`24d9b8f0 : 0x00000255`24d9a400
    0000008d`048ff3d0 00000255`24d9ac60     : 00000255`24d9b090 00000255`24d9b4c0 00000255`24d9b8f0 00000255`24d9bd20 : 0x00000255`24d9a830
    0000008d`048ff3d8 00000255`24d9b090     : 00000255`24d9b4c0 00000255`24d9b8f0 00000255`24d9bd20 00000255`24d9c150 : 0x00000255`24d9ac60
    0000008d`048ff3e0 00000255`24d9b4c0     : 00000255`24d9b8f0 00000255`24d9bd20 00000255`24d9c150 00000255`24d9c580 : 0x00000255`24d9b090
    0000008d`048ff3e8 00000255`24d9b8f0     : 00000255`24d9bd20 00000255`24d9c150 00000255`24d9c580 00000255`24d9c9b0 : 0x00000255`24d9b4c0
    0000008d`048ff3f0 00000255`24d9bd20     : 00000255`24d9c150 00000255`24d9c580 00000255`24d9c9b0 00000255`24d9cde0 : 0x00000255`24d9b8f0
    0000008d`048ff3f8 00000255`24d9c150     : 00000255`24d9c580 00000255`24d9c9b0 00000255`24d9cde0 00000255`24d9d210 : 0x00000255`24d9bd20
    0000008d`048ff400 00000255`24d9c580     : 00000255`24d9c9b0 00000255`24d9cde0 00000255`24d9d210 00000255`24d9d640 : 0x00000255`24d9c150
    0000008d`048ff408 00000255`24d9c9b0     : 00000255`24d9cde0 00000255`24d9d210 00000255`24d9d640 00000255`24d9da70 : 0x00000255`24d9c580
    0000008d`048ff410 00000255`24d9cde0     : 00000255`24d9d210 00000255`24d9d640 00000255`24d9da70 00000255`24d9dea0 : 0x00000255`24d9c9b0
    0000008d`048ff418 00000255`24d9d210     : 00000255`24d9d640 00000255`24d9da70 00000255`24d9dea0 00000255`24d9e2d0 : 0x00000255`24d9cde0
    0000008d`048ff420 00000255`24d9d640     : 00000255`24d9da70 00000255`24d9dea0 00000255`24d9e2d0 00000255`24d9e700 : 0x00000255`24d9d210
    0000008d`048ff428 00000255`24d9da70     : 00000255`24d9dea0 00000255`24d9e2d0 00000255`24d9e700 00000255`24d9eb30 : 0x00000255`24d9d640
    0000008d`048ff430 00000255`24d9dea0     : 00000255`24d9e2d0 00000255`24d9e700 00000255`24d9eb30 00000255`24d9ef60 : 0x00000255`24d9da70
    0000008d`048ff438 00000255`24d9e2d0     : 00000255`24d9e700 00000255`24d9eb30 00000255`24d9ef60 00000255`24d9f390 : 0x00000255`24d9dea0
    0000008d`048ff440 00000255`24d9e700     : 00000255`24d9eb30 00000255`24d9ef60 00000255`24d9f390 00000255`24d9f7c0 : 0x00000255`24d9e2d0
    0000008d`048ff448 00000255`24d9eb30     : 00000255`24d9ef60 00000255`24d9f390 00000255`24d9f7c0 00000255`24d9fbf0 : 0x00000255`24d9e700
    0000008d`048ff450 00000255`24d9ef60     : 00000255`24d9f390 00000255`24d9f7c0 00000255`24d9fbf0 00000255`24da0020 : 0x00000255`24d9eb30
    0000008d`048ff458 00000255`24d9f390     : 00000255`24d9f7c0 00000255`24d9fbf0 00000255`24da0020 00000255`24da0450 : 0x00000255`24d9ef60
    0000008d`048ff460 00000255`24d9f7c0     : 00000255`24d9fbf0 00000255`24da0020 00000255`24da0450 00000255`24da0880 : 0x00000255`24d9f390
    0000008d`048ff468 00000255`24d9fbf0     : 00000255`24da0020 00000255`24da0450 00000255`24da0880 00000255`24da0cb0 : 0x00000255`24d9f7c0
    0000008d`048ff470 00000255`24da0020     : 00000255`24da0450 00000255`24da0880 00000255`24da0cb0 00000255`24da10e0 : 0x00000255`24d9fbf0
    0000008d`048ff478 00000255`24da0450     : 00000255`24da0880 00000255`24da0cb0 00000255`24da10e0 00000255`24da1510 : 0x00000255`24da0020
    0000008d`048ff480 00000255`24da0880     : 00000255`24da0cb0 00000255`24da10e0 00000255`24da1510 00000255`24da1940 : 0x00000255`24da0450
    0000008d`048ff488 00000255`24da0cb0     : 00000255`24da10e0 00000255`24da1510 00000255`24da1940 00000255`24da1d70 : 0x00000255`24da0880
    0000008d`048ff490 00000255`24da10e0     : 00000255`24da1510 00000255`24da1940 00000255`24da1d70 00000255`24da21a0 : 0x00000255`24da0cb0
    0000008d`048ff498 00000255`24da1510     : 00000255`24da1940 00000255`24da1d70 00000255`24da21a0 00000255`24da25d0 : 0x00000255`24da10e0
    0000008d`048ff4a0 00000255`24da1940     : 00000255`24da1d70 00000255`24da21a0 00000255`24da25d0 00000255`24da2a00 : 0x00000255`24da1510
    0000008d`048ff4a8 00000255`24da1d70     : 00000255`24da21a0 00000255`24da25d0 00000255`24da2a00 00000255`24da2e30 : 0x00000255`24da1940
    0000008d`048ff4b0 00000255`24da21a0     : 00000255`24da25d0 00000255`24da2a00 00000255`24da2e30 00000255`24da3260 : 0x00000255`24da1d70
    0000008d`048ff4b8 00000255`24da25d0     : 00000255`24da2a00 00000255`24da2e30 00000255`24da3260 00000255`24da3690 : 0x00000255`24da21a0
    0000008d`048ff4c0 00000255`24da2a00     : 00000255`24da2e30 00000255`24da3260 00000255`24da3690 00000255`24da3ac0 : 0x00000255`24da25d0
    0000008d`048ff4c8 00000255`24da2e30     : 00000255`24da3260 00000255`24da3690 00000255`24da3ac0 00000255`24da3ef0 : 0x00000255`24da2a00
    0000008d`048ff4d0 00000255`24da3260     : 00000255`24da3690 00000255`24da3ac0 00000255`24da3ef0 00000255`24da4320 : 0x00000255`24da2e30
    0000008d`048ff4d8 00000255`24da3690     : 00000255`24da3ac0 00000255`24da3ef0 00000255`24da4320 00000255`24da4750 : 0x00000255`24da3260
    0000008d`048ff4e0 00000255`24da3ac0     : 00000255`24da3ef0 00000255`24da4320 00000255`24da4750 00000255`24da4b80 : 0x00000255`24da3690
    0000008d`048ff4e8 00000255`24da3ef0     : 00000255`24da4320 00000255`24da4750 00000255`24da4b80 00000255`24da4fb0 : 0x00000255`24da3ac0
    0000008d`048ff4f0 00000255`24da4320     : 00000255`24da4750 00000255`24da4b80 00000255`24da4fb0 00000255`24da53e0 : 0x00000255`24da3ef0
    0000008d`048ff4f8 00000255`24da4750     : 00000255`24da4b80 00000255`24da4fb0 00000255`24da53e0 00000255`24da5810 : 0x00000255`24da4320
    0000008d`048ff500 00000255`24da4b80     : 00000255`24da4fb0 00000255`24da53e0 00000255`24da5810 00000255`24da5c40 : 0x00000255`24da4750
    0000008d`048ff508 00000255`24da4fb0     : 00000255`24da53e0 00000255`24da5810 00000255`24da5c40 00000255`24da6070 : 0x00000255`24da4b80
    0000008d`048ff510 00000255`24da53e0     : 00000255`24da5810 00000255`24da5c40 00000255`24da6070 00000255`24da64a0 : 0x00000255`24da4fb0
    0000008d`048ff518 00000255`24da5810     : 00000255`24da5c40 00000255`24da6070 00000255`24da64a0 00000255`24da68d0 : 0x00000255`24da53e0
    0000008d`048ff520 00000255`24da5c40     : 00000255`24da6070 00000255`24da64a0 00000255`24da68d0 00000255`24da6d00 : 0x00000255`24da5810
    0000008d`048ff528 00000255`24da6070     : 00000255`24da64a0 00000255`24da68d0 00000255`24da6d00 00000255`24da7130 : 0x00000255`24da5c40
    0000008d`048ff530 00000255`24da64a0     : 00000255`24da68d0 00000255`24da6d00 00000255`24da7130 00000255`24da7560 : 0x00000255`24da6070
    0000008d`048ff538 00000255`24da68d0     : 00000255`24da6d00 00000255`24da7130 00000255`24da7560 00000255`24da7990 : 0x00000255`24da64a0
    0000008d`048ff540 00000255`24da6d00     : 00000255`24da7130 00000255`24da7560 00000255`24da7990 00000255`24da7dc0 : 0x00000255`24da68d0
    0000008d`048ff548 00000255`24da7130     : 00000255`24da7560 00000255`24da7990 00000255`24da7dc0 00000255`24da81f0 : 0x00000255`24da6d00
    0000008d`048ff550 00000255`24da7560     : 00000255`24da7990 00000255`24da7dc0 00000255`24da81f0 00000255`24da8620 : 0x00000255`24da7130
    0000008d`048ff558 00000255`24da7990     : 00000255`24da7dc0 00000255`24da81f0 00000255`24da8620 00000255`24da8a50 : 0x00000255`24da7560
    0000008d`048ff560 00000255`24da7dc0     : 00000255`24da81f0 00000255`24da8620 00000255`24da8a50 00000255`24da8e80 : 0x00000255`24da7990
    0000008d`048ff568 00000255`24da81f0     : 00000255`24da8620 00000255`24da8a50 00000255`24da8e80 00000255`24da92b0 : 0x00000255`24da7dc0
    0000008d`048ff570 00000255`24da8620     : 00000255`24da8a50 00000255`24da8e80 00000255`24da92b0 00000255`24da96e0 : 0x00000255`24da81f0
    0000008d`048ff578 00000255`24da8a50     : 00000255`24da8e80 00000255`24da92b0 00000255`24da96e0 00000255`24da9b10 : 0x00000255`24da8620
    0000008d`048ff580 00000255`24da8e80     : 00000255`24da92b0 00000255`24da96e0 00000255`24da9b10 00000255`24da9f40 : 0x00000255`24da8a50
    0000008d`048ff588 00000255`24da92b0     : 00000255`24da96e0 00000255`24da9b10 00000255`24da9f40 00000255`24daa370 : 0x00000255`24da8e80
    0000008d`048ff590 00000255`24da96e0     : 00000255`24da9b10 00000255`24da9f40 00000255`24daa370 00000255`24daa7a0 : 0x00000255`24da92b0
    0000008d`048ff598 00000255`24da9b10     : 00000255`24da9f40 00000255`24daa370 00000255`24daa7a0 00000255`24daabd0 : 0x00000255`24da96e0
    0000008d`048ff5a0 00000255`24da9f40     : 00000255`24daa370 00000255`24daa7a0 00000255`24daabd0 00000255`24dab000 : 0x00000255`24da9b10
    0000008d`048ff5a8 00000255`24daa370     : 00000255`24daa7a0 00000255`24daabd0 00000255`24dab000 00000000`00000000 : 0x00000255`24da9f40
    0000008d`048ff5b0 00000255`24daa7a0     : 00000255`24daabd0 00000255`24dab000 00000000`00000000 0000008d`048ff7f0 : 0x00000255`24daa370
    0000008d`048ff5b8 00000255`24daabd0     : 00000255`24dab000 00000000`00000000 0000008d`048ff7f0 00007ff7`aa50db67 : 0x00000255`24daa7a0
    0000008d`048ff5c0 00000255`24dab000     : 00000000`00000000 0000008d`048ff7f0 00007ff7`aa50db67 00000255`24de75b0 : 0x00000255`24daabd0
    0000008d`048ff5c8 00000000`00000000     : 0000008d`048ff7f0 00007ff7`aa50db67 00000255`24de75b0 00000255`24de8a90 : 0x00000255`24dab000
    
    SYMBOL_NAME:  BandiView_x64+410d1d
    
    MODULE_NAME: BandiView_x64
    
    IMAGE_NAME:  BandiView.x64.exe
    
    STACK_COMMAND:  ~13s ; .cxr ; kb
    
    FAILURE_BUCKET_ID:  FAIL_FAST_STACK_BUFFER_OVERRUN_STACK_COOKIE_CHECK_FAILURE_MISSING_GSFRAME_c0000409_BandiView.x64.exe!Unknown
    
    OS_VERSION:  10.0.22621.1
    
    BUILDLAB_STR:  ni_release
    
    OSPLATFORM_TYPE:  x64
    
    OSNAME:  Windows 10
    
    IMAGE_VERSION:  7.5.0.1
    
    FAILURE_ID_HASH:  {d3a506d9-04ad-bfdd-58cb-04f4250ceab5}
    
    Followup:     MachineOwner
    ---------
    ```
    
    When analyzing the file using Microsoft's Windbg program, the same results were observed.
    

---

- **Exploitation Scenario**
    
    The buffer overflow (BOF) vulnerability can lead to serious risks, such as Remote Code Execution (RCE).
    

---

- **Mitigation:** Strengthen exception handling in the image loading function

# Vulnerability 3

## Vulnerability Overview

- **Summary:** A vulnerability occurs when loading crafted PSD files in BandiView (v7.05).
- **Manufacturer:** Bandisoft
- **Software:** BandiView
- **Version:** v7.05 (2024/7/15, BuildNo=26122)
- **Attack Type:** Improper input validation
- **Impact:** Denial of Service (DoS)
- **Vulnerable Target:** BandiView.exe

## Vulnerability Environment

**Edition**                   Windows 11 Pro

**Version**                   23H2

**Installation Date**    2023-10-10

**OS Build**                 22631.4037

**Experience**             Windows Feature Experience Pack 1000.22700.1027.0

## Details

- **Discovery Method:** The vulnerability was discovered during a fuzz testing process targeting the file parsing functions in BandiView. Unexpected behavior was observed, and further analysis using the IDA Pro debugger revealed the presence of the vulnerability.
- **Cause:** Occurs due to insufficient verification of PSD files.

---

- **Proof/Validation:**
    
    When attempting to load the file in BandiView, the program shuts down.
    
    ```bash
    (6650.3260): Access violation - code c0000005 (first chance)
    First chance exceptions are reported before any exception handling.
    This exception may be expected and handled.
    BandiView_x64+0x232bd8:
    00007ff7`aa5d2bd8 498906          mov     qword ptr [r14],rax ds:000000d0`7d900000=????????????????
    ```
    
    ```bash
    0:011> !analyze -v
    *******************************************************************************
    *                                                                             *
    *                        Exception Analysis                                   *
    *                                                                             *
    *******************************************************************************
    
    KEY_VALUES_STRING: 1
    
        Key  : AV.Fault
        Value: Write
    
        Key  : Analysis.CPU.mSec
        Value: 390
    
        Key  : Analysis.Elapsed.mSec
        Value: 731
    
        Key  : Analysis.IO.Other.Mb
        Value: 0
    
        Key  : Analysis.IO.Read.Mb
        Value: 1
    
        Key  : Analysis.IO.Write.Mb
        Value: 1
    
        Key  : Analysis.Init.CPU.mSec
        Value: 218
    
        Key  : Analysis.Init.Elapsed.mSec
        Value: 45594
    
        Key  : Analysis.Memory.CommitPeak.Mb
        Value: 103
    
        Key  : Failure.Bucket
        Value: INVALID_POINTER_WRITE_c0000005_BandiView.x64.exe!Unknown
    
        Key  : Failure.Hash
        Value: {9036daf9-6f88-0a17-e1be-b4aa4be8a406}
    
        Key  : Timeline.OS.Boot.DeltaSec
        Value: 434805
    
        Key  : Timeline.Process.Start.DeltaSec
        Value: 45
    
        Key  : WER.OS.Branch
        Value: ni_release
    
        Key  : WER.OS.Version
        Value: 10.0.22621.1
    
        Key  : WER.Process.Version
        Value: 7.5.0.1
    
    NTGLOBALFLAG:  70
    
    APPLICATION_VERIFIER_FLAGS:  0
    
    EXCEPTION_RECORD:  (.exr -1)
    ExceptionAddress: 00007ff7aa5d2bd8 (BandiView_x64+0x0000000000232bd8)
       ExceptionCode: c0000005 (Access violation)
      ExceptionFlags: 00000000
    NumberParameters: 2
       Parameter[0]: 0000000000000001
       Parameter[1]: 000000d07d900000
    Attempt to write to address 000000d07d900000
    
    FAULTING_THREAD:  00003260
    
    PROCESS_NAME:  BandiView.x64.exe
    
    WRITE_ADDRESS:  000000d07d900000 
    
    ERROR_CODE: (NTSTATUS) 0xc0000005 - 0x%p               0x%p                        .          %s              .
    
    EXCEPTION_CODE_STR:  c0000005
    
    EXCEPTION_PARAMETER1:  0000000000000001
    
    EXCEPTION_PARAMETER2:  000000d07d900000
    
    IP_ON_HEAP:  000002399d673080
    The fault address in not in any loaded module, please check your build's rebase
    log at <releasedir>\bin\build_logs\timebuild\ntrebase.log for module which may
    contain the address if it were loaded.
    
    FRAME_ONE_INVALID: 1
    
    STACK_TEXT:  
    000000d0`7d8ff0d0 00000239`9d673080     : 00000239`a40e4d90 00000239`a40e51c0 00000239`a40e55f0 00000239`a40e5a20 : BandiView_x64+0x232bd8
    000000d0`7d8ff200 00000239`a40e4d90     : 00000239`a40e51c0 00000239`a40e55f0 00000239`a40e5a20 00000239`a40e5e50 : 0x00000239`9d673080
    000000d0`7d8ff208 00000239`a40e51c0     : 00000239`a40e55f0 00000239`a40e5a20 00000239`a40e5e50 00000239`a40e6280 : 0x00000239`a40e4d90
    000000d0`7d8ff210 00000239`a40e55f0     : 00000239`a40e5a20 00000239`a40e5e50 00000239`a40e6280 00000239`a40e66b0 : 0x00000239`a40e51c0
    000000d0`7d8ff218 00000239`a40e5a20     : 00000239`a40e5e50 00000239`a40e6280 00000239`a40e66b0 00000239`a40e6ae0 : 0x00000239`a40e55f0
    000000d0`7d8ff220 00000239`a40e5e50     : 00000239`a40e6280 00000239`a40e66b0 00000239`a40e6ae0 00000239`a40e6f10 : 0x00000239`a40e5a20
    000000d0`7d8ff228 00000239`a40e6280     : 00000239`a40e66b0 00000239`a40e6ae0 00000239`a40e6f10 00000239`a40e7340 : 0x00000239`a40e5e50
    000000d0`7d8ff230 00000239`a40e66b0     : 00000239`a40e6ae0 00000239`a40e6f10 00000239`a40e7340 00000239`a40e7770 : 0x00000239`a40e6280
    000000d0`7d8ff238 00000239`a40e6ae0     : 00000239`a40e6f10 00000239`a40e7340 00000239`a40e7770 00000239`a40e7ba0 : 0x00000239`a40e66b0
    000000d0`7d8ff240 00000239`a40e6f10     : 00000239`a40e7340 00000239`a40e7770 00000239`a40e7ba0 00000239`a40e7fd0 : 0x00000239`a40e6ae0
    000000d0`7d8ff248 00000239`a40e7340     : 00000239`a40e7770 00000239`a40e7ba0 00000239`a40e7fd0 00000239`a40e8400 : 0x00000239`a40e6f10
    000000d0`7d8ff250 00000239`a40e7770     : 00000239`a40e7ba0 00000239`a40e7fd0 00000239`a40e8400 00000239`a40e8830 : 0x00000239`a40e7340
    000000d0`7d8ff258 00000239`a40e7ba0     : 00000239`a40e7fd0 00000239`a40e8400 00000239`a40e8830 00000239`a40e8c60 : 0x00000239`a40e7770
    000000d0`7d8ff260 00000239`a40e7fd0     : 00000239`a40e8400 00000239`a40e8830 00000239`a40e8c60 00000239`a40e9090 : 0x00000239`a40e7ba0
    000000d0`7d8ff268 00000239`a40e8400     : 00000239`a40e8830 00000239`a40e8c60 00000239`a40e9090 00000239`a40e94c0 : 0x00000239`a40e7fd0
    000000d0`7d8ff270 00000239`a40e8830     : 00000239`a40e8c60 00000239`a40e9090 00000239`a40e94c0 00000239`a40e98f0 : 0x00000239`a40e8400
    000000d0`7d8ff278 00000239`a40e8c60     : 00000239`a40e9090 00000239`a40e94c0 00000239`a40e98f0 00000239`a40e9d20 : 0x00000239`a40e8830
    000000d0`7d8ff280 00000239`a40e9090     : 00000239`a40e94c0 00000239`a40e98f0 00000239`a40e9d20 00000239`a40ea150 : 0x00000239`a40e8c60
    000000d0`7d8ff288 00000239`a40e94c0     : 00000239`a40e98f0 00000239`a40e9d20 00000239`a40ea150 00000239`a40ea580 : 0x00000239`a40e9090
    000000d0`7d8ff290 00000239`a40e98f0     : 00000239`a40e9d20 00000239`a40ea150 00000239`a40ea580 00000239`a40ea9b0 : 0x00000239`a40e94c0
    000000d0`7d8ff298 00000239`a40e9d20     : 00000239`a40ea150 00000239`a40ea580 00000239`a40ea9b0 00000239`a40eade0 : 0x00000239`a40e98f0
    000000d0`7d8ff2a0 00000239`a40ea150     : 00000239`a40ea580 00000239`a40ea9b0 00000239`a40eade0 00000239`a40eb210 : 0x00000239`a40e9d20
    000000d0`7d8ff2a8 00000239`a40ea580     : 00000239`a40ea9b0 00000239`a40eade0 00000239`a40eb210 00000239`a40eb640 : 0x00000239`a40ea150
    000000d0`7d8ff2b0 00000239`a40ea9b0     : 00000239`a40eade0 00000239`a40eb210 00000239`a40eb640 00000239`a40eba70 : 0x00000239`a40ea580
    000000d0`7d8ff2b8 00000239`a40eade0     : 00000239`a40eb210 00000239`a40eb640 00000239`a40eba70 00000239`a40ebea0 : 0x00000239`a40ea9b0
    000000d0`7d8ff2c0 00000239`a40eb210     : 00000239`a40eb640 00000239`a40eba70 00000239`a40ebea0 00000239`a40ec2d0 : 0x00000239`a40eade0
    000000d0`7d8ff2c8 00000239`a40eb640     : 00000239`a40eba70 00000239`a40ebea0 00000239`a40ec2d0 00000239`a40ec700 : 0x00000239`a40eb210
    000000d0`7d8ff2d0 00000239`a40eba70     : 00000239`a40ebea0 00000239`a40ec2d0 00000239`a40ec700 00000239`a40ecb30 : 0x00000239`a40eb640
    000000d0`7d8ff2d8 00000239`a40ebea0     : 00000239`a40ec2d0 00000239`a40ec700 00000239`a40ecb30 00000239`a40ecf60 : 0x00000239`a40eba70
    000000d0`7d8ff2e0 00000239`a40ec2d0     : 00000239`a40ec700 00000239`a40ecb30 00000239`a40ecf60 00000239`a40ed390 : 0x00000239`a40ebea0
    000000d0`7d8ff2e8 00000239`a40ec700     : 00000239`a40ecb30 00000239`a40ecf60 00000239`a40ed390 00000239`a40ed7c0 : 0x00000239`a40ec2d0
    000000d0`7d8ff2f0 00000239`a40ecb30     : 00000239`a40ecf60 00000239`a40ed390 00000239`a40ed7c0 00000239`a40edbf0 : 0x00000239`a40ec700
    000000d0`7d8ff2f8 00000239`a40ecf60     : 00000239`a40ed390 00000239`a40ed7c0 00000239`a40edbf0 00000239`a40ee020 : 0x00000239`a40ecb30
    000000d0`7d8ff300 00000239`a40ed390     : 00000239`a40ed7c0 00000239`a40edbf0 00000239`a40ee020 00000239`a4351c00 : 0x00000239`a40ecf60
    000000d0`7d8ff308 00000239`a40ed7c0     : 00000239`a40edbf0 00000239`a40ee020 00000239`a4351c00 00000239`a4352030 : 0x00000239`a40ed390
    000000d0`7d8ff310 00000239`a40edbf0     : 00000239`a40ee020 00000239`a4351c00 00000239`a4352030 00000239`a4352460 : 0x00000239`a40ed7c0
    000000d0`7d8ff318 00000239`a40ee020     : 00000239`a4351c00 00000239`a4352030 00000239`a4352460 00000239`a4352890 : 0x00000239`a40edbf0
    000000d0`7d8ff320 00000239`a4351c00     : 00000239`a4352030 00000239`a4352460 00000239`a4352890 00000239`a4352cc0 : 0x00000239`a40ee020
    000000d0`7d8ff328 00000239`a4352030     : 00000239`a4352460 00000239`a4352890 00000239`a4352cc0 00000239`a43530f0 : 0x00000239`a4351c00
    000000d0`7d8ff330 00000239`a4352460     : 00000239`a4352890 00000239`a4352cc0 00000239`a43530f0 00000239`a4353520 : 0x00000239`a4352030
    000000d0`7d8ff338 00000239`a4352890     : 00000239`a4352cc0 00000239`a43530f0 00000239`a4353520 00000239`a4353950 : 0x00000239`a4352460
    000000d0`7d8ff340 00000239`a4352cc0     : 00000239`a43530f0 00000239`a4353520 00000239`a4353950 00000239`a4353d80 : 0x00000239`a4352890
    000000d0`7d8ff348 00000239`a43530f0     : 00000239`a4353520 00000239`a4353950 00000239`a4353d80 00000239`a43541b0 : 0x00000239`a4352cc0
    000000d0`7d8ff350 00000239`a4353520     : 00000239`a4353950 00000239`a4353d80 00000239`a43541b0 00000239`a43545e0 : 0x00000239`a43530f0
    000000d0`7d8ff358 00000239`a4353950     : 00000239`a4353d80 00000239`a43541b0 00000239`a43545e0 00000239`a4354a10 : 0x00000239`a4353520
    000000d0`7d8ff360 00000239`a4353d80     : 00000239`a43541b0 00000239`a43545e0 00000239`a4354a10 00000239`a4354e40 : 0x00000239`a4353950
    000000d0`7d8ff368 00000239`a43541b0     : 00000239`a43545e0 00000239`a4354a10 00000239`a4354e40 00000239`a4355270 : 0x00000239`a4353d80
    000000d0`7d8ff370 00000239`a43545e0     : 00000239`a4354a10 00000239`a4354e40 00000239`a4355270 00000239`a43556a0 : 0x00000239`a43541b0
    000000d0`7d8ff378 00000239`a4354a10     : 00000239`a4354e40 00000239`a4355270 00000239`a43556a0 00000239`a4355ad0 : 0x00000239`a43545e0
    000000d0`7d8ff380 00000239`a4354e40     : 00000239`a4355270 00000239`a43556a0 00000239`a4355ad0 00000239`a4355f00 : 0x00000239`a4354a10
    000000d0`7d8ff388 00000239`a4355270     : 00000239`a43556a0 00000239`a4355ad0 00000239`a4355f00 00000239`a4356330 : 0x00000239`a4354e40
    000000d0`7d8ff390 00000239`a43556a0     : 00000239`a4355ad0 00000239`a4355f00 00000239`a4356330 00000239`a4356760 : 0x00000239`a4355270
    000000d0`7d8ff398 00000239`a4355ad0     : 00000239`a4355f00 00000239`a4356330 00000239`a4356760 00000239`a4356b90 : 0x00000239`a43556a0
    000000d0`7d8ff3a0 00000239`a4355f00     : 00000239`a4356330 00000239`a4356760 00000239`a4356b90 00000239`a4356fc0 : 0x00000239`a4355ad0
    000000d0`7d8ff3a8 00000239`a4356330     : 00000239`a4356760 00000239`a4356b90 00000239`a4356fc0 00000239`a43573f0 : 0x00000239`a4355f00
    000000d0`7d8ff3b0 00000239`a4356760     : 00000239`a4356b90 00000239`a4356fc0 00000239`a43573f0 00000239`a4357820 : 0x00000239`a4356330
    000000d0`7d8ff3b8 00000239`a4356b90     : 00000239`a4356fc0 00000239`a43573f0 00000239`a4357820 00000239`a4357c50 : 0x00000239`a4356760
    000000d0`7d8ff3c0 00000239`a4356fc0     : 00000239`a43573f0 00000239`a4357820 00000239`a4357c50 00000239`a4358080 : 0x00000239`a4356b90
    000000d0`7d8ff3c8 00000239`a43573f0     : 00000239`a4357820 00000239`a4357c50 00000239`a4358080 00000239`a43584b0 : 0x00000239`a4356fc0
    000000d0`7d8ff3d0 00000239`a4357820     : 00000239`a4357c50 00000239`a4358080 00000239`a43584b0 00000239`a43588e0 : 0x00000239`a43573f0
    000000d0`7d8ff3d8 00000239`a4357c50     : 00000239`a4358080 00000239`a43584b0 00000239`a43588e0 00000239`a4358d10 : 0x00000239`a4357820
    000000d0`7d8ff3e0 00000239`a4358080     : 00000239`a43584b0 00000239`a43588e0 00000239`a4358d10 00000239`a4359140 : 0x00000239`a4357c50
    000000d0`7d8ff3e8 00000239`a43584b0     : 00000239`a43588e0 00000239`a4358d10 00000239`a4359140 00000239`a4359570 : 0x00000239`a4358080
    000000d0`7d8ff3f0 00000239`a43588e0     : 00000239`a4358d10 00000239`a4359140 00000239`a4359570 00000239`a43599a0 : 0x00000239`a43584b0
    000000d0`7d8ff3f8 00000239`a4358d10     : 00000239`a4359140 00000239`a4359570 00000239`a43599a0 00000239`a4359dd0 : 0x00000239`a43588e0
    000000d0`7d8ff400 00000239`a4359140     : 00000239`a4359570 00000239`a43599a0 00000239`a4359dd0 00000239`a435a200 : 0x00000239`a4358d10
    000000d0`7d8ff408 00000239`a4359570     : 00000239`a43599a0 00000239`a4359dd0 00000239`a435a200 00000239`a435a630 : 0x00000239`a4359140
    000000d0`7d8ff410 00000239`a43599a0     : 00000239`a4359dd0 00000239`a435a200 00000239`a435a630 00000239`a435aa60 : 0x00000239`a4359570
    000000d0`7d8ff418 00000239`a4359dd0     : 00000239`a435a200 00000239`a435a630 00000239`a435aa60 00000239`a435ae90 : 0x00000239`a43599a0
    000000d0`7d8ff420 00000239`a435a200     : 00000239`a435a630 00000239`a435aa60 00000239`a435ae90 00000239`a435b2c0 : 0x00000239`a4359dd0
    000000d0`7d8ff428 00000239`a435a630     : 00000239`a435aa60 00000239`a435ae90 00000239`a435b2c0 00000239`a435b6f0 : 0x00000239`a435a200
    000000d0`7d8ff430 00000239`a435aa60     : 00000239`a435ae90 00000239`a435b2c0 00000239`a435b6f0 00000239`a435bb20 : 0x00000239`a435a630
    000000d0`7d8ff438 00000239`a435ae90     : 00000239`a435b2c0 00000239`a435b6f0 00000239`a435bb20 00000239`a435bf50 : 0x00000239`a435aa60
    000000d0`7d8ff440 00000239`a435b2c0     : 00000239`a435b6f0 00000239`a435bb20 00000239`a435bf50 00000239`a435c380 : 0x00000239`a435ae90
    000000d0`7d8ff448 00000239`a435b6f0     : 00000239`a435bb20 00000239`a435bf50 00000239`a435c380 00000239`a435c7b0 : 0x00000239`a435b2c0
    000000d0`7d8ff450 00000239`a435bb20     : 00000239`a435bf50 00000239`a435c380 00000239`a435c7b0 00000239`a435cbe0 : 0x00000239`a435b6f0
    000000d0`7d8ff458 00000239`a435bf50     : 00000239`a435c380 00000239`a435c7b0 00000239`a435cbe0 00000239`a435d010 : 0x00000239`a435bb20
    000000d0`7d8ff460 00000239`a435c380     : 00000239`a435c7b0 00000239`a435cbe0 00000239`a435d010 00000239`a435d440 : 0x00000239`a435bf50
    000000d0`7d8ff468 00000239`a435c7b0     : 00000239`a435cbe0 00000239`a435d010 00000239`a435d440 00000239`a435d870 : 0x00000239`a435c380
    000000d0`7d8ff470 00000239`a435cbe0     : 00000239`a435d010 00000239`a435d440 00000239`a435d870 00000239`a435dca0 : 0x00000239`a435c7b0
    000000d0`7d8ff478 00000239`a435d010     : 00000239`a435d440 00000239`a435d870 00000239`a435dca0 00000239`a435e0d0 : 0x00000239`a435cbe0
    000000d0`7d8ff480 00000239`a435d440     : 00000239`a435d870 00000239`a435dca0 00000239`a435e0d0 00000239`a435e500 : 0x00000239`a435d010
    000000d0`7d8ff488 00000239`a435d870     : 00000239`a435dca0 00000239`a435e0d0 00000239`a435e500 00000239`a435e930 : 0x00000239`a435d440
    000000d0`7d8ff490 00000239`a435dca0     : 00000239`a435e0d0 00000239`a435e500 00000239`a435e930 00000239`a435ed60 : 0x00000239`a435d870
    000000d0`7d8ff498 00000239`a435e0d0     : 00000239`a435e500 00000239`a435e930 00000239`a435ed60 00000239`a435f190 : 0x00000239`a435dca0
    000000d0`7d8ff4a0 00000239`a435e500     : 00000239`a435e930 00000239`a435ed60 00000239`a435f190 00000239`a435f5c0 : 0x00000239`a435e0d0
    000000d0`7d8ff4a8 00000239`a435e930     : 00000239`a435ed60 00000239`a435f190 00000239`a435f5c0 00000239`a435f9f0 : 0x00000239`a435e500
    000000d0`7d8ff4b0 00000239`a435ed60     : 00000239`a435f190 00000239`a435f5c0 00000239`a435f9f0 00000239`a435fe20 : 0x00000239`a435e930
    000000d0`7d8ff4b8 00000239`a435f190     : 00000239`a435f5c0 00000239`a435f9f0 00000239`a435fe20 00000239`a4360250 : 0x00000239`a435ed60
    000000d0`7d8ff4c0 00000239`a435f5c0     : 00000239`a435f9f0 00000239`a435fe20 00000239`a4360250 00000239`a4360680 : 0x00000239`a435f190
    
    SYMBOL_NAME:  BandiView_x64+232bd8
    
    MODULE_NAME: BandiView_x64
    
    IMAGE_NAME:  BandiView.x64.exe
    
    STACK_COMMAND:  ~11s ; .cxr ; kb
    
    FAILURE_BUCKET_ID:  INVALID_POINTER_WRITE_c0000005_BandiView.x64.exe!Unknown
    
    OS_VERSION:  10.0.22621.1
    
    BUILDLAB_STR:  ni_release
    
    OSPLATFORM_TYPE:  x64
    
    OSNAME:  Windows 10
    
    IMAGE_VERSION:  7.5.0.1
    
    FAILURE_ID_HASH:  {9036daf9-6f88-0a17-e1be-b4aa4be8a406}
    
    Followup:     MachineOwner
    ---------
    
    ```
    
    When analyzing the file using Microsoft's Windbg program, the same results were observed.
    

---

- **Exploitation Scenario**
    
    If a user disguises the file with extensions like .psd and downloads it through various means, then attempts to open it using the BandiView image viewer, the vulnerability is triggered, causing the program to freeze. This results in the user losing access to all functions of BandiView, leading to a Denial of Service (DoS) attack.
    

---

- **Mitigation:** Strengthen exception handling in the image loading function
