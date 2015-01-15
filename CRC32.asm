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
    LenBuffer           equ 128         

    PROV_RSA_FULL       equ 1
    PROV_RSA_AES        equ 24
    CALG_MD5            equ (ALG_CLASS_HASH or ALG_TYPE_ANY or ALG_SID_MD5)
    CALG_SHA1           equ (ALG_CLASS_HASH or ALG_TYPE_ANY or ALG_SID_SHA) 
    CALG_SHA_256        equ (ALG_CLASS_HASH or ALG_TYPE_ANY or ALG_SID_SHA_256)  
    
    HashConvert         PROTO  BufLengthP:DWORD
    ThreadProc1         PROTO  ;For SHA1
    ThreadProc2         PROTO  ;For SHA256
    ThreadProc3         PROTO  ;For MD5


.data?   
        ALIGN 2                                       ;Note: Alignment seems to have dramatic effects on                
        @rgbDigits          DB 16 DUP (?)             ;speed here. 
        Conversion          DB 12 DUP (?)             ;ToDo: Optimize further, seems to be not optimal...
        CRC32Table          DB 2048 DUP (?)
        MaxCompressionAsc   DB 20 DUP (?)
        EntropyAsc          DB 20 DUP (?)
        ItemBuffer          DB 32770 DUP (?)          ;Buffer for Commadline Args 
        FileLenAsc          DB 32 DUP (?)
        FreqAsc             DB 20 DUP (?)          
        InBuffer            DB 128 DUP (?)
        HashBuffer          DB 128 DUP (?)
        HashBufferAsc       DB 128 DUP (?)  
        ALIGN 4                                       ;Align all DD now...
        BytesRead           DD ?  
        DWRC                DD ?
        FileLen             DD ?
        FreqVal             DD ? 
        hBlock              DD ?
        hDEP                DD ?
        hDLLKernel32        DD ?
        hFileCRC            DD ?
        hHashMD5            DD ?
        hHashSHA1           DD ?
        hHash256            DD ?
        hHeap               DD ?
        hProv               DD ?
        hProv256            DD ?
        hThread1            DD ?
        hThread2            DD ?  
        hThread3            DD ?
        lpFileBuf           DD ?
        ThreadID1           DD ?
        ThreadID2           DD ?
        ThreadID3           DD ?
        ThreadParam1        DD ?
        ThreadParam2        DD ?
        ThreadParam3        DD ?
        TMP                 DD ?
        FrequencyTable      DD 256 DUP (?)
        ALIGN 8        
        DQFileLen           DQ ?
        DQFileLenMB         DQ ?

.data
        ALIGN 2
        CR_LF               DB 13,10,0
        TabSign             DB 9,0
        strDEP              DB "SetProcessDEPPolicy",0
        SubString           DB "/f",0
        UserDLL             DB "kernel32",0
        ALIGN 4        
        Base                DD 1.00
        BufLengthMD5        DD 33
        BufLengthSHA1       DD 41
        BufLengthSHA256     DD 64
        ByteSize            DD 8.00
        ConstDiv            DD 1024 
        CRC32Result         DD 0FFFFFFFFh
        DDMaxCompression    DD 0  
        Entropy             DD 00h
        HighOrderSize       DD 0
        Invert              DD -1.00
        ALIGN 8        
        DQEntropy           DQ 0  
        
;-----------------------------------------------------------------------------------------------------------------------------------------------------
    
.code
start:  
        invoke LoadLibrary, ADDR UserDLL
        cmp  eax,0
        je   NoDEP
        mov  hDLLKernel32,eax

        invoke GetProcAddress,hDLLKernel32,ADDR strDEP     ;Activate DEP just to show...
        cmp  eax,0                                         ;and maybe also needed (see below)
        je   NoDEP
        mov  hDEP,eax
  
        push 01
        call dword ptr hDEP
  
NoDEP:  
  
        invoke getcl_ex,1,ADDR ItemBuffer                  ;GetCL has problems with Buffer-overflows... thus getcl_ex!                        
        cmp  eax,1
        jne  NoCmdLn
        
        mov  eax,dword ptr [ItemBuffer]                                   
        cmp  ax,"?/"                                       ;crc32 /? will show the help
        jne  NoHelp
Help:
        invoke StdOut,ADDR CR_LF
        print "Info: Hash, CRC32 and Shannon Entropy calculator by Marcus Roming, Ver. 1.30",13,10
        print "Syntax: CRC32 filename.ext [/f]",13,10
        print "CRC32 Polynom: 0EDB88320h",13,10
        print "StartValue: 0FFFFFFFFh",13,10
        jmp  Ende

NoHelp:

        invoke CryptAcquireContext,ADDR hProv256, 0, 0, PROV_RSA_AES, 0         ;SHA256
        invoke CryptCreateHash, hProv256, CALG_SHA_256, 0, 0, ADDR hHash256
    
        invoke CryptAcquireContext,ADDR hProv, 0, 0, PROV_RSA_FULL, 0           ;SHA1
        invoke CryptCreateHash, hProv, CALG_SHA1, 0, 0, ADDR hHashSHA1
        
        invoke CryptCreateHash, hProv, CALG_MD5, 0, 0, ADDR hHashMD5            ;MD5
            
        invoke CreateFile,ADDR ItemBuffer,GENERIC_READ,0,NULL,OPEN_EXISTING,FILE_FLAG_SEQUENTIAL_SCAN,NULL  ;Open file fom cmd line
        cmp  eax,-1
        jne  NoErr1

        invoke StdOut,ADDR CR_LF
        print "Error: Unable to open file!",13,10
        jmp  Ende

NoErr1:
        mov  hFileCRC,eax
        
        ;See: http://masm32.com/board/index.php?topic=1311.0
        
        invoke GetProcessHeap
        mov  hHeap,eax
        
        mov  ecx,ALLOC_MEM+10h
        invoke HeapAlloc,hHeap,NULL,ecx
        or   eax,eax
        jnz  AllOk
        
        invoke StdOut,ADDR CR_LF
        print "Error: Unable to allocate Memory!",13,10
        jmp  Ende

AllOk:  mov  hBlock,eax
        add  eax,15
        and  al,-16
        mov  lpFileBuf,eax
        ;Allocating memory done!
              
        invoke ReadFile,hFileCRC,lpFileBuf,ALLOC_MEM,ADDR BytesRead,NULL
        cmp  eax,0
        jne  NoErr2

        invoke StdOut,ADDR CR_LF
        print "Error: Unable to read file!",13,10
        invoke CloseHandle,hFileCRC
        jmp  Ende
NoErr2:                                    ;File successfully opened!

        cmp  [BytesRead],0
        jne  NoErr3

        invoke StdOut,ADDR CR_LF
        print "Error: 0-Byte File (CRC32=0) read error!",13,10
        jmp  Ende

NoErr3:



        ;Create CRC32 Table
        call CreateCRCTable

;---------------------------------------------------------------CRC32 calculation---------------------------------------------------------------------

        mov  ecx,[BytesRead]
CycleCRC:
         
        pushad ;push  eax seems to be not enough.

        invoke  CreateThread, NULL, 0, ADDR ThreadProc1, ADDR ThreadParam1, 0, ADDR ThreadID1  ;Start Thread that calculates SHA1
        mov  hThread1,eax
        cmp  eax,0
        je   ThreadErr
        invoke  CreateThread, NULL, 0, ADDR ThreadProc2, ADDR ThreadParam2, 0, ADDR ThreadID2  ;Start Thread that calculates SHA256
        mov  hThread2,eax
        cmp  eax,0
        je   ThreadErr
        invoke  CreateThread, NULL, 0, ADDR ThreadProc3, ADDR ThreadParam3, 0, ADDR ThreadID3  ;Start Thread that calculates MD5
        mov  hThread3,eax
        cmp  eax,0
        je   ThreadErr
        ;Now all threads work in parallel
        popad
        
        mov  esi,lpFileBuf

        CRCLoop:            
            push [CRC32Result]
            and  [CRC32Result],0FFh
            xor  eax,eax
            
            mov  al,byte ptr [esi]
            push ebx
            push eax
            mov  ebx,OFFSET FrequencyTable  ;Populate the frequ. table for entropy calculation:
            shl  eax,2                      ;eax contains the byte value. Times 4 since we have dword values in the table!
            add  ebx,eax                    ;ebx now points to the correct pos. in the table
            inc  dword ptr [ebx]            ;Increment this position
            pop  eax
            pop  ebx
            mov  ebx,[CRC32Result]
            xor  ebx,eax
            mov  edi,ebx                    ;edi statt bzw. n 
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
    
        
        
        invoke WaitForSingleObject,hThread1,90000      ;Wait for Thread-Results
        cmp  eax,WAIT_FAILED
        je   ThreadErr
        invoke WaitForSingleObject,hThread2,90000 
        cmp  eax,WAIT_FAILED
        je   ThreadErr
        invoke WaitForSingleObject,hThread3,90000 
        cmp  eax,WAIT_FAILED
        je   ThreadErr
        
        invoke CloseHandle,hThread1
        invoke CloseHandle,hThread2
        invoke CloseHandle,hThread3
        
        invoke ReadFile,hFileCRC,lpFileBuf,ALLOC_MEM,ADDR BytesRead,NULL   ;More data available?     
        ;Note: We have to wait until both threads are ready otherwise we overwrite data that still in use!
        
        mov  ecx,[BytesRead]
        cmp  ecx,0
        
jne  CycleCRC       

        not  CRC32Result                                ;Important! 
        invoke dw2hex,CRC32Result,ADDR Conversion
        invoke StdOut,ADDR CR_LF
        print "CRC32 (HEX)  : "
        invoke StdOut,ADDR TabSign
        invoke StdOut,ADDR Conversion
        invoke StdOut,ADDR CR_LF
    
        
        ;initialize array for conversion digits
        mov DWORD PTR [@rgbDigits],"3210"
        mov DWORD PTR [@rgbDigits+4],"7654"
        mov DWORD PTR [@rgbDigits+8],"ba98"
        mov DWORD PTR [@rgbDigits+12],"fedc" 
        
        invoke CryptGetHashParam, hHashMD5,HP_HASHVAL, ADDR HashBuffer, ADDR BufLengthMD5, 0         ;Create MD5 
      
        print "MD5   (HEX)  : "
        invoke StdOut,ADDR TabSign

        invoke HashConvert,BufLengthMD5
        invoke StdOut,ADDR HashBufferAsc
        invoke StdOut,ADDR CR_LF
    
        invoke CryptGetHashParam, hHashSHA1,HP_HASHVAL, ADDR HashBuffer, ADDR BufLengthSHA1, 0         ;Create SHA1  
      
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
        
        invoke CryptDestroyHash,hHashMD5       
        invoke CryptDestroyHash,hHashSHA1
        invoke CryptReleaseContext,hProv, NULL  

        invoke CryptDestroyHash,hHash256
        invoke CryptReleaseContext,hProv256, NULL   
        
        invoke HeapFree,hHeap,NULL,hBlock           ;Free allocated memory!   
    
; -----------------------------------------------------Determine and print file length----------------------------------------------------------------
        invoke GetFileSize,hFileCRC,ADDR HighOrderSize            ;Limits filesize and entropy calculation, we do not get the high dword
        mov  FileLen,eax                                          ;If value is wrong we will not use it anyway
        cmp  [FileLen],7FFFFFFFh                                  ;01111111111111111111111111111111b  > 2 GByte?                               
        ja   TooLarge
        cmp  [HighOrderSize],0
        je   NoErr4
        
TooLarge:
        invoke StdOut,ADDR CR_LF
        print "Error : File too big for file size and entropy. Will skip calculations!",13,10
        jmp  Ende

NoErr4:        
        push FileLen
  
        print "File length  : "
        invoke StdOut,ADDR TabSign
        invoke udw2str,FileLen,ADDR FileLenAsc       ;udw2str = unsigned dword to string
        invoke StdOut,ADDR FileLenAsc
        print " Byte",13,10
  
        finit                                        ;Initialize FPU and calculate KByte Size
        fild  [FileLen]
        fidiv [ConstDiv]                             ;divide by 1024
        fst   [DQFileLen]                            ;Resutl still in ST(0)
        fidiv [ConstDiv]                             ;divide by 1024 --> MByte
        fstp  [DQFileLenMB]                          ;Now stack is empty!
        wait

        print "File length  : "
        invoke StdOut,ADDR TabSign
        invoke FloatToStr2,DQFileLen,ADDR FileLenAsc
        mov    byte ptr [FileLenAsc + 7],00h         ;Will allow a maximum of 6 Digits plus comma!
        invoke StdOut,ADDR FileLenAsc
        print " KByte",13,10
  
        print "File length  : "
        invoke StdOut,ADDR TabSign
        invoke FloatToStr2,DQFileLenMB,ADDR FileLenAsc
        mov    byte ptr [FileLenAsc + 7],00h         ;Will allow a maximum of 6 Digits plus comma!
        invoke StdOut,ADDR FileLenAsc
        print " MByte",13,10   
    
        pop  FileLen 
  
;------------------------------------------------Print generated frequency table if /f in cmdline-----------------------------------------------------     

        print "Freq. table  : "

        invoke  getcl_ex,2,ADDR ItemBuffer
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
        invoke dwtoa,FreqVal,ADDR FreqAsc 
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
        fidiv [FileLen]
        fstp [FrequencyTable+ebx]      ;Save as floating point value!
        wait
        add  ebx,4
        Loop LoopDiv
;-----------------------------------------------------------------Entropy calculation-----------------------------------------------------------------      
;Calculate ent = ent + freq * math.log(freq, 2)  --> Shannon entropy

        mov  ecx,256
        xor  ebx,ebx  
LoopEnt:
        cmp  dword ptr [FrequencyTable+ebx],0
        je   IsZero
        fld  [Base]                              ;Base 2 logarithm, not e!!
        fld  dword ptr [FrequencyTable+ebx]       ;Load as floating point value!
        fyl2x                                    ;Log base 2
        fld  dword ptr [FrequencyTable+ebx]       ;Load as floating point value!
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
        
        print "Approx. comp.: "                                 ;Show theoretical maximum compression (Entropy*FileLength/8)
        invoke StdOut,ADDR TabSign
        invoke udw2str,DDMaxCompression,ADDR MaxCompressionAsc
        invoke StdOut,ADDR MaxCompressionAsc
        print " Byte"
        invoke StdOut,ADDR CR_LF
        
        
        jmp Ende  
        
ThreadErr:  
        invoke StdOut,ADDR CR_LF
        print "Error: Thread error!",13,10   
        jmp  Ende          

NoCmdLn:
        invoke StdOut,ADDR CR_LF
        print "Error: Missing commandline, /? for help!",13,10
    
Ende:   invoke CloseHandle,hFileCRC
        invoke  ExitProcess,eax


;---------------------------------------Procedure for Table creation--------------------------------------------------------------

CreateCRCTable PROC
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
CreateCRCTable ENDP


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

        invoke CryptHashData,hHashSHA1,lpFileBuf,BytesRead, 0
        ret
             
ThreadProc1  ENDP  

ThreadProc2  PROC

        invoke CryptHashData,hHash256,lpFileBuf,BytesRead, 0
        ret
             
ThreadProc2  ENDP      

ThreadProc3  PROC

        invoke CryptHashData,hHashMD5,lpFileBuf,BytesRead, 0
        ret
             
ThreadProc3  ENDP               


END start