.586
.model flat, stdcall
    option casemap :none
     
    include c:\masm32\include\windows.inc
    include c:\masm32\include\user32.inc
    include c:\masm32\include\kernel32.inc
    include c:\masm32\include\masm32.inc
    include c:\masm32\include\Advapi32.inc
    include macro.inc

    includelib c:\masm32\lib\user32.lib
    includelib c:\masm32\lib\kernel32.lib
    includelib c:\masm32\lib\masm32.lib
    includelib c:\masm32\lib\Advapi32.lib
    
    ALG_CLASS_HASH      equ 32768
    ALG_TYPE_ANY        equ 0
    ALG_SID_MD5         equ 3
    ALG_SID_SHA         equ 4
    ALG_SID_SHA_256     equ 12
    ALLOC_MEM           equ 250000h                 ;100000h = 1MByte

    PROV_RSA_FULL       equ 1
    PROV_RSA_AES        equ 24
    CALG_MD5            equ (ALG_CLASS_HASH or ALG_TYPE_ANY or ALG_SID_MD5)
    CALG_SHA1           equ (ALG_CLASS_HASH or ALG_TYPE_ANY or ALG_SID_SHA) 
    CALG_SHA_256        equ (ALG_CLASS_HASH or ALG_TYPE_ANY or ALG_SID_SHA_256)  
    
    HashConvert         PROTO  BufLengthP:DWORD
    ThreadProc1         PROTO  ;For SHA1
    ThreadProc2         PROTO  ;For SHA256
    


.data?
        ItemBuffer          DB 128 DUP (?)          ;Buffer for Commadline Args 
        DWRC                DD ?
        TMP                 DD ?
        CRC32Table          DB 2048 DUP (?)
        hFileCRC            DD ?
        BytesRead           DD ?
        FileLen             DD ?
        InBuffer            DB 128 DUP (?)
        FreqVal             DD ?
        MaxCompressionAsc   DB 20 DUP (?)
        hDLLKernel32        DD ?
        hDEP                DD ?
        hProv               DD ?
        hProv256            DD ?
        hHash               DD ?
        hHash256            DD ?
        HashBuffer          DB 128 DUP (?)
        HashBufferAsc       DB 128 DUP (?)    
        @rgbDigits          DB 16 DUP (?)
        hHeap               DD ?
        hBlock              DD ?
        lpFileBuf           DD ?
        ThreadID1           DD ?
        ThreadID2           DD ?
        ThreadParam1        DD ?
        ThreadParam2        DD ?
        hThread1            DD ?
        hThread2            DD ?
        
        
        

.data
        CRC32Result         DD 0FFFFFFFFh
        Conversion          DB 11 DUP (0)
        CR_LF               DB 10,13,0  
        TabSign             DB 9,0 
        FrequencyTable      DD 256 DUP (0)          ;Currently Max 4GByte but due to DD
        FileLenAsc          DB 32 DUP (0)
        Entropy             DD 00h
        Invert              DD -1.00
        Base                DD 1.00
        ByteSize            DD 8.00
        FreqAsc             DB 20 DUP (0)
        EntropyAsc          DB 20 DUP (0)
        LenBuffer           DD 128
        DQEntropy           DQ 0  
        DDMaxCompression    DD 0  
        SubString           DB "/f",0
        UserDLL             DB "kernel32",0
        strDEP              DB "SetProcessDEPPolicy",0
        BufLengthSHA1       DD 41
        BufLengthSHA256     DD 64

;-----------------------------------------------------------------------------------------------------------------------------------------------------
    
.code
start:  
        invoke LoadLibrary, ADDR UserDLL
        cmp  eax,0
        je   NoDEP
        mov  hDLLKernel32,eax

        invoke GetProcAddress,hDLLKernel32,ADDR strDEP     ;Activate DEP just to show...
        cmp  eax,0
        je   NoDEP
        mov  hDEP,eax
  
        push 01
        call dword ptr hDEP
  
NoDEP:  
  
        invoke GetCL,1,ADDR ItemBuffer                         
        cmp  eax,1
        jne  Fehler
        
        mov  eax,dword ptr [ItemBuffer]
        cmp  eax,"pleh"                                     ;crc32 help or...
        je   Help
        cmp  ax,"?/"                                        ;crc32 /? will show the help
        jne  NoHelp
Help:
        invoke StdOut,ADDR CR_LF
        print "Info: Hash, CRC32 and Shannon Entropy calculator by Marcus Roming, Windows32 Commandline. Ver. 1.05"
        invoke StdOut,ADDR CR_LF
        print "Syntax: CRC32 filename.ext [/f]"
        invoke StdOut,ADDR CR_LF
        print "CRC32 Polynom: 0EDB88320h"
        invoke StdOut,ADDR CR_LF
        print "StartValue: 0FFFFFFFFh"
        invoke StdOut,ADDR CR_LF
        jmp  Ende

NoHelp:

        invoke CryptAcquireContext,ADDR hProv256, 0, 0, PROV_RSA_AES, 0         ;SHA256
        invoke CryptCreateHash, hProv256, CALG_SHA_256, 0, 0, ADDR hHash256
    
        invoke CryptAcquireContext,ADDR hProv, 0, 0, PROV_RSA_FULL, 0           ;SHA1
        invoke CryptCreateHash, hProv, CALG_SHA1, 0, 0, ADDR hHash
            
        invoke CreateFile,ADDR ItemBuffer,GENERIC_READ,0,NULL,OPEN_EXISTING,FILE_FLAG_SEQUENTIAL_SCAN,NULL  ;Open file fom cmd line
        cmp  eax,-1
        jne  Weiter1

        invoke StdOut,ADDR CR_LF
        print "Error: Unable to open file!"
        invoke StdOut,ADDR CR_LF
        jmp  Ende

Weiter1:
        mov  hFileCRC,eax
        
        ;See: http://masm32.com/board/index.php?topic=1311.0
        
        invoke GetProcessHeap
        mov  hHeap,eax
        
        mov  ecx,ALLOC_MEM+10h
        invoke HeapAlloc,hHeap,NULL,ecx
        or   eax,eax
        jnz  AllOk
        
        invoke StdOut,ADDR CR_LF
        print "Error: Allocate Memory!"
        invoke StdOut,ADDR CR_LF
        jmp  Ende

AllOk:  mov  hBlock,eax
        add  eax,15
        and  al,-16
        mov  lpFileBuf,eax
        ;Allocating memory done!
              
        invoke ReadFile,hFileCRC,lpFileBuf,ALLOC_MEM,ADDR BytesRead,NULL
        cmp  eax,0
        jne  Weiter2

        invoke StdOut,ADDR CR_LF
        print "Error: Unable to read file!"
        invoke StdOut,ADDR CR_LF
        invoke CloseHandle,hFileCRC
        jmp  Ende
Weiter2:                                    ;File successfully opened!

        cmp  [BytesRead],0
        jne  Weiter3

        invoke StdOut,ADDR CR_LF
        print "Error: 0-Byte File (CRC32=0) read error!"
        invoke StdOut,ADDR CR_LF
        jmp  Ende

Weiter3:



        ;Create CRC32 Table
        call TableDance

;---------------------------------------------------------------CRC32 calculation---------------------------------------------------------------------

        mov  ecx,[BytesRead]
CycleCRC:
         
        pushad

        invoke  CreateThread, NULL, 0, ADDR ThreadProc1, ADDR ThreadParam1, 0, ADDR ThreadID1  ;Start Thread that calculates SHA1
        mov  hThread1,eax
        cmp  eax,0
        je   ThreadErr
        invoke  CreateThread, NULL, 0, ADDR ThreadProc2, ADDR ThreadParam2, 0, ADDR ThreadID2  ;Start Thread that calculates SHA256
        mov  hThread2,eax
        cmp  eax,0
        je   ThreadErr
        ;Now both threads work in parallel
        popad
        
        mov  esi,lpFileBuf

        CRCLoop:            
            push [CRC32Result]
            and  [CRC32Result],0FFh
            xor  eax,eax
            
            mov  al,byte ptr [esi]
            pushad
            mov  ebx,OFFSET FrequencyTable
            shl  eax,2
            add  ebx,eax
            inc  dword ptr [ebx]
            popad  
            mov  ebx,[CRC32Result]
            xor  ebx,eax
            mov  edi,ebx                ;edi statt bzw. n 
            pop  [CRC32Result]
            and  [CRC32Result],0FFFFFF00h
            mov  eax,[CRC32Result]
            shr  eax,8
            and  eax,0FFFFFFh
            mov  ebx,[OFFSET CRC32Table +EDI*4]
            xor  eax,ebx
            mov  [CRC32Result],eax
            inc  esi
        Loop CRCLoop
    
        
        invoke WaitForSingleObject,hThread1,30000      ;Wait for Thread-Results
        cmp  eax,WAIT_FAILED
        je   ThreadErr
        invoke WaitForSingleObject,hThread2,30000 
        cmp  eax,WAIT_FAILED
        je   ThreadErr
        
        invoke ReadFile,hFileCRC,lpFileBuf,ALLOC_MEM,ADDR BytesRead,NULL   ;More data available?     
        
        
        mov  ecx,[BytesRead]
        cmp  ecx,0
        
jne  CycleCRC       

        invoke CloseHandle,hFileCRC
        not  CRC32Result                                ;Important! 
        invoke dw2hex,CRC32Result,ADDR Conversion
        invoke StdOut,ADDR CR_LF
        print "CRC32 (HEX)  : "
        invoke StdOut,ADDR TabSign
        invoke StdOut,ADDR Conversion
        invoke StdOut,ADDR CR_LF
    
        invoke CryptGetHashParam, hHash,HP_HASHVAL, ADDR HashBuffer, ADDR BufLengthSHA1, 0         ;Create SHA1
        
        ;initialize array for conversion digits
        mov DWORD PTR [@rgbDigits],"3210"
        mov DWORD PTR [@rgbDigits+4],"7654"
        mov DWORD PTR [@rgbDigits+8],"ba98"
        mov DWORD PTR [@rgbDigits+12],"fedc" 
        
        print "SHA 1 (HEX)  : "
        invoke StdOut,ADDR TabSign

        invoke HashConvert,BufLengthSHA1
        invoke StdOut,ADDR HashBufferAsc
        invoke StdOut,ADDR CR_LF
        
        invoke CryptGetHashParam, hHash256,HP_HASHVAL, ADDR HashBuffer, ADDR BufLengthSHA256, 0     ;Create SHA256
        
        print "SHA256(HEX)  : "
        invoke StdOut,ADDR TabSign

        invoke HashConvert,BufLengthSHA256
        invoke StdOut,ADDR HashBufferAsc
        
        invoke CryptDestroyHash,hHash
        invoke CryptReleaseContext,hProv, NULL  

        invoke CryptDestroyHash,hHash256
        invoke CryptReleaseContext,hProv256, NULL   
        
        invoke HeapFree,hHeap,NULL,hBlock           ;Free allocated memory!   
    
; -----------------------------------------------------Determine and print file length----------------------------------------------------------------
        invoke filesize,ADDR ItemBuffer
        cmp  eax,-1
        je   Fehler
        mov  FileLen,eax
        push FileLen
  
        print "File length  : "
        invoke StdOut,ADDR TabSign
        invoke udw2str,FileLen,ADDR FileLenAsc       ;udw2str = unsigned dword to string
        invoke StdOut,ADDR FileLenAsc
        print " Byte"
        invoke StdOut,ADDR CR_LF
  
        shr  FileLen,10  
        print "File length  : "
        invoke StdOut,ADDR TabSign
        invoke dwtoa,FileLen,ADDR FileLenAsc
        invoke StdOut,ADDR FileLenAsc
        print " KByte"
        invoke StdOut,ADDR CR_LF
  
        shr  FileLen,10  
        print "File length  : "
        invoke StdOut,ADDR TabSign
        invoke dwtoa,FileLen,ADDR FileLenAsc
        invoke StdOut,ADDR FileLenAsc
        print " MByte"
        invoke StdOut,ADDR CR_LF       
    
        pop  FileLen 
  
;------------------------------------------------Print generated frequency table if /f in cmdline-----------------------------------------------------     

        print "Freq. table  : "

        invoke  GetCL,2,ADDR ItemBuffer
        mov  eax,dword ptr [ItemBuffer]
        cmp  ax,"f/"    
        jne  NoTableOut
        invoke StdOut,ADDR CR_LF
                                         
        mov  ecx,256
        xor  ebx,ebx
FTable:
        push ecx
        mov  edx,dword ptr [FrequencyTable+ebx]
        mov  [FreqVal],edx
        invoke udw2str,FreqVal,ADDR FreqAsc 
        invoke StdOut,ADDR FreqAsc
        invoke StdOut,ADDR TabSign
        add  ebx,4
        pop  ecx
        Loop FTable
        jmp  FreqOk
        
NoTableOut:
        invoke StdOut,ADDR TabSign
        print "Use /f !"
FreqOk:  

;---------------------------------------------------------Divide frequency table by file length-------------------------------------------------------
        mov  ecx,256
        xor  ebx,ebx  
LoopDiv:
        fild [FrequencyTable+ebx]
        fild [FileLen]
        fdiv
        fstp [FrequencyTable+ebx]      ;Save as floating point value!
        wait
        add  ebx,4
        Loop LoopDiv
;-----------------------------------------------------------------Entropy calculation-----------------------------------------------------------------      
;Calculate ent = ent + freq * math.log(freq, 2)  --> Shannon entropy

        mov  ecx,256
        xor  ebx,ebx  
LoopEnt:
        cmp  [FrequencyTable+ebx],0
        je   IsZero
        fld  [Base]                   ;Base 2 logarithm, not e!!
        fld  [FrequencyTable+ebx]     ;Load as floating point value!
        fyl2x                         ;Log base 2
        fld  [FrequencyTable+ebx]     ;Load as floating point value!
        fmul
        fld  [Entropy]
        fadd
        fstp [Entropy]
        wait

IsZero:
        add  ebx,4
        Loop LoopEnt

;-----------------------------------------------------------------Calculate the results !------------------------------------------------------------   
        fld  [Entropy]
        fld  [Invert]
        fmul     
        fst  [DQEntropy]
        fild  [FileLen]
        fmul  
        fld  [ByteSize]
        fdiv
        fistp [DDMaxCompression]
        wait
        
        invoke StdOut,ADDR CR_LF
        print "Entropy      : "                     
        invoke StdOut,ADDR TabSign
        invoke FloatToStr,DQEntropy,ADDR EntropyAsc
        invoke StdOut,ADDR EntropyAsc
        invoke StdOut,ADDR CR_LF
        
        print "Max compress.: "                                 ;Show theoretical maximum compression (Entropy*FileLength/8)
        invoke StdOut,ADDR TabSign
        invoke udw2str,DDMaxCompression,ADDR MaxCompressionAsc
        invoke StdOut,ADDR MaxCompressionAsc
        print " Byte"
        invoke StdOut,ADDR CR_LF
        
        
        jmp Ende  
        
ThreadErr:  
        invoke StdOut,ADDR CR_LF
        print "Error: Thread error!"
        invoke StdOut,ADDR CR_LF      
        jmp  Ende          

Fehler:
        invoke StdOut,ADDR CR_LF
        print "Error: Missing commandline, /? or help for help!"
        invoke StdOut,ADDR CR_LF
    
Ende:   invoke  ExitProcess,eax


;---------------------------------------Procedure for Table creation--------------------------------------------------------------

TableDance PROC
        mov  ecx,256
Loop1:  
        mov  [DWRC],ecx
        push ecx
        mov  ecx,8
    InnerLoop:
            mov  eax,[DWRC]
            mov  [TMP],eax
            and  [TMP],01h          ;CHK DWRC without modifiaction
            jz  ElseMarke           ;jz!
            mov  eax,[DWRC]
            and  eax,0FFFFFFFEh
            sar  eax,1
            and  eax,07FFFFFFFh
            xor  eax,0EDB88320h     ;Polynome, Standard for CRC32
            mov  [DWRC],eax
            jmp  NotElse
            ElseMarke:
            mov  eax,[DWRC]
            and  eax,0FFFFFFFEh
            sar  eax,1
            and  eax,07FFFFFFFh
            mov  [DWRC],eax
            NotElse:
    Loop InnerLoop
        pop  ecx
        mov  esi,ecx
        mov  eax,[DWRC]
        mov  [OFFSET CRC32Table + ESI*4],eax        ;Table with CRC32-Values of all possible 256 Values of a Byte
Loop Loop1
    ret
TableDance ENDP


 ;------------------------------------------------------------------Convert Hash into string----------------------------------------------------------
 ;See: http://www.masmforum.com/board/index.php?PHPSESSID=786dd40408172108b65a5a36b09c88c0&action=printpage;topic=4322.0
 ;----------------------------------------------------------------------------------------------------------------------------------------------------
 
HashConvert  PROC BufLengthP:DWORD 

        pushad
        ;convert the hash to an SHA string using a lookup table
        xor eax,eax
        xor edx,edx
        mov ebx,OFFSET HashBufferAsc
        lea edi,HashBuffer
        mov ecx,[BufLengthP]
        lea esi,@rgbDigits
LoopingP:
        mov al,[edi]
        shr al,4
        mov dl,[esi+eax]
        mov [ebx],dl
        inc ebx
        mov al,[edi]
        and al,0fh
        mov dl,[esi+eax]
        mov [ebx],dl
        inc edi
        inc ebx
        dec ecx
jnz LoopingP
        mov ax,0
        mov [ebx],ax
        popad
        
        ret

HashConvert  ENDP        

ThreadProc1  PROC

        invoke CryptHashData,hHash,lpFileBuf,BytesRead, 0
        ret
             
ThreadProc1  ENDP  

ThreadProc2  PROC

        invoke CryptHashData,hHash256,lpFileBuf,BytesRead, 0
        ret
             
ThreadProc2  ENDP                


END start