PUBLIC Encr_lilith
PUBLIC Dncr_lilith
    option casemap:none

.code
; _fastcall convention
Encr_lilith PROC
; standard entry
    push rbp
    push r10
    push r12
    push r13

    mov rbp, rsp
    sub rsp, 40h
; zero out then begin iterations after limtit
    xor r10, r10  
    xor r12, r12
    xor cl, cl

    mov r13, rcx
outer_limit:    
    inc cl

limit:
; r10 iteration counter - r11 round counter - r12 key counter 
; rcx, data | rdx, key | r8, len
; allocation unit size is 4096 / 64 = 64, so there should always be an even # of 8 byte clusters
; makes 7 rounds on the same blocks 
    
    mov r9, qword ptr [r13 + r10 * 8]
    ;add r9, 1h
    

    cmp r12, 1h
    je key_limit
    ror r9, cl
    xor r9, qword ptr [rdx + r12 * 8]
    inc r12
    jmp key_past
key_limit:
    ror r9, cl
    xor r9, qword ptr [rdx + r12 * 8]
    dec r12
    

key_past:
    mov qword ptr [r13 + r10 * 8], r9
    inc r10
    cmp r10, r8
    jne limit
    

    xor r10, r10
    cmp cl, 7
    jne outer_limit

    mov rax, r13
    add rsp, 40h

    pop r13
    pop r12
    pop r10
    pop rbp
    ret
Encr_lilith ENDP
;
;
;
;
Dncr_lilith PROC
    push rbp
    push r12
    push r13
    mov rbp, rsp
    sub rsp, 40h

    xor r10, r10
    xor r12, r12
   

    mov r13, rcx
    mov cl, 8
    
outer_limit:
    dec cl
limit:
    mov r9, qword ptr [r13 + r10 * 8]
    

    cmp r12, 1h
    je key_limit
    xor r9, qword ptr [rdx + r12 * 8]
    rol r9, cl
    inc r12 
    jmp key_past
key_limit:
    xor r9, qword ptr [rdx + r12 * 8]
    rol r9, cl
    dec r12 
key_past:
    mov qword ptr [r13 + r10 * 8], r9

    
    ;sub r9, 1h

    inc r10 
    cmp r10, r8
    jne limit
   
    xor r10, r10
    cmp cl, 1
    jne outer_limit

    mov rax, r13 
    add rsp, 40h

    pop r13
    pop r12
    pop rbp
    ret 0 

Dncr_lilith ENDP
END 


