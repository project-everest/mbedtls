.code
ALIGN 16
aes128_key_expansion proc
  movdqu xmm1, xmmword ptr [rcx + 0]
  movdqu xmmword ptr [rdx + 0], xmm1
  aeskeygenassist xmm2, xmm1, 1
  pshufd xmm2, xmm2, 255
  vpslldq xmm3, xmm1, 4
  pxor xmm1, xmm3
  vpslldq xmm3, xmm1, 4
  pxor xmm1, xmm3
  vpslldq xmm3, xmm1, 4
  pxor xmm1, xmm3
  pxor xmm1, xmm2
  movdqu xmmword ptr [rdx + 16], xmm1
  aeskeygenassist xmm2, xmm1, 2
  pshufd xmm2, xmm2, 255
  vpslldq xmm3, xmm1, 4
  pxor xmm1, xmm3
  vpslldq xmm3, xmm1, 4
  pxor xmm1, xmm3
  vpslldq xmm3, xmm1, 4
  pxor xmm1, xmm3
  pxor xmm1, xmm2
  movdqu xmmword ptr [rdx + 32], xmm1
  aeskeygenassist xmm2, xmm1, 4
  pshufd xmm2, xmm2, 255
  vpslldq xmm3, xmm1, 4
  pxor xmm1, xmm3
  vpslldq xmm3, xmm1, 4
  pxor xmm1, xmm3
  vpslldq xmm3, xmm1, 4
  pxor xmm1, xmm3
  pxor xmm1, xmm2
  movdqu xmmword ptr [rdx + 48], xmm1
  aeskeygenassist xmm2, xmm1, 8
  pshufd xmm2, xmm2, 255
  vpslldq xmm3, xmm1, 4
  pxor xmm1, xmm3
  vpslldq xmm3, xmm1, 4
  pxor xmm1, xmm3
  vpslldq xmm3, xmm1, 4
  pxor xmm1, xmm3
  pxor xmm1, xmm2
  movdqu xmmword ptr [rdx + 64], xmm1
  aeskeygenassist xmm2, xmm1, 16
  pshufd xmm2, xmm2, 255
  vpslldq xmm3, xmm1, 4
  pxor xmm1, xmm3
  vpslldq xmm3, xmm1, 4
  pxor xmm1, xmm3
  vpslldq xmm3, xmm1, 4
  pxor xmm1, xmm3
  pxor xmm1, xmm2
  movdqu xmmword ptr [rdx + 80], xmm1
  aeskeygenassist xmm2, xmm1, 32
  pshufd xmm2, xmm2, 255
  vpslldq xmm3, xmm1, 4
  pxor xmm1, xmm3
  vpslldq xmm3, xmm1, 4
  pxor xmm1, xmm3
  vpslldq xmm3, xmm1, 4
  pxor xmm1, xmm3
  pxor xmm1, xmm2
  movdqu xmmword ptr [rdx + 96], xmm1
  aeskeygenassist xmm2, xmm1, 64
  pshufd xmm2, xmm2, 255
  vpslldq xmm3, xmm1, 4
  pxor xmm1, xmm3
  vpslldq xmm3, xmm1, 4
  pxor xmm1, xmm3
  vpslldq xmm3, xmm1, 4
  pxor xmm1, xmm3
  pxor xmm1, xmm2
  movdqu xmmword ptr [rdx + 112], xmm1
  aeskeygenassist xmm2, xmm1, 128
  pshufd xmm2, xmm2, 255
  vpslldq xmm3, xmm1, 4
  pxor xmm1, xmm3
  vpslldq xmm3, xmm1, 4
  pxor xmm1, xmm3
  vpslldq xmm3, xmm1, 4
  pxor xmm1, xmm3
  pxor xmm1, xmm2
  movdqu xmmword ptr [rdx + 128], xmm1
  aeskeygenassist xmm2, xmm1, 27
  pshufd xmm2, xmm2, 255
  vpslldq xmm3, xmm1, 4
  pxor xmm1, xmm3
  vpslldq xmm3, xmm1, 4
  pxor xmm1, xmm3
  vpslldq xmm3, xmm1, 4
  pxor xmm1, xmm3
  pxor xmm1, xmm2
  movdqu xmmword ptr [rdx + 144], xmm1
  aeskeygenassist xmm2, xmm1, 54
  pshufd xmm2, xmm2, 255
  vpslldq xmm3, xmm1, 4
  pxor xmm1, xmm3
  vpslldq xmm3, xmm1, 4
  pxor xmm1, xmm3
  vpslldq xmm3, xmm1, 4
  pxor xmm1, xmm3
  pxor xmm1, xmm2
  movdqu xmmword ptr [rdx + 160], xmm1
  pxor xmm1, xmm1
  pxor xmm2, xmm2
  pxor xmm3, xmm3
  ret
aes128_key_expansion endp
ALIGN 16
aes256_key_expansion proc
  movdqu xmm1, xmmword ptr [rcx + 0]
  movdqu xmm3, xmmword ptr [rcx + 16]
  movdqu xmmword ptr [rdx + 0], xmm1
  movdqu xmmword ptr [rdx + 16], xmm3
  aeskeygenassist xmm2, xmm3, 1
  pshufd xmm2, xmm2, 255
  vpslldq xmm4, xmm1, 4
  pxor xmm1, xmm4
  vpslldq xmm4, xmm1, 4
  pxor xmm1, xmm4
  vpslldq xmm4, xmm1, 4
  pxor xmm1, xmm4
  pxor xmm1, xmm2
  movdqu xmmword ptr [rdx + 32], xmm1
  aeskeygenassist xmm2, xmm1, 0
  pshufd xmm2, xmm2, 170
  vpslldq xmm4, xmm3, 4
  pxor xmm3, xmm4
  vpslldq xmm4, xmm3, 4
  pxor xmm3, xmm4
  vpslldq xmm4, xmm3, 4
  pxor xmm3, xmm4
  pxor xmm3, xmm2
  movdqu xmmword ptr [rdx + 48], xmm3
  aeskeygenassist xmm2, xmm3, 2
  pshufd xmm2, xmm2, 255
  vpslldq xmm4, xmm1, 4
  pxor xmm1, xmm4
  vpslldq xmm4, xmm1, 4
  pxor xmm1, xmm4
  vpslldq xmm4, xmm1, 4
  pxor xmm1, xmm4
  pxor xmm1, xmm2
  movdqu xmmword ptr [rdx + 64], xmm1
  aeskeygenassist xmm2, xmm1, 0
  pshufd xmm2, xmm2, 170
  vpslldq xmm4, xmm3, 4
  pxor xmm3, xmm4
  vpslldq xmm4, xmm3, 4
  pxor xmm3, xmm4
  vpslldq xmm4, xmm3, 4
  pxor xmm3, xmm4
  pxor xmm3, xmm2
  movdqu xmmword ptr [rdx + 80], xmm3
  aeskeygenassist xmm2, xmm3, 4
  pshufd xmm2, xmm2, 255
  vpslldq xmm4, xmm1, 4
  pxor xmm1, xmm4
  vpslldq xmm4, xmm1, 4
  pxor xmm1, xmm4
  vpslldq xmm4, xmm1, 4
  pxor xmm1, xmm4
  pxor xmm1, xmm2
  movdqu xmmword ptr [rdx + 96], xmm1
  aeskeygenassist xmm2, xmm1, 0
  pshufd xmm2, xmm2, 170
  vpslldq xmm4, xmm3, 4
  pxor xmm3, xmm4
  vpslldq xmm4, xmm3, 4
  pxor xmm3, xmm4
  vpslldq xmm4, xmm3, 4
  pxor xmm3, xmm4
  pxor xmm3, xmm2
  movdqu xmmword ptr [rdx + 112], xmm3
  aeskeygenassist xmm2, xmm3, 8
  pshufd xmm2, xmm2, 255
  vpslldq xmm4, xmm1, 4
  pxor xmm1, xmm4
  vpslldq xmm4, xmm1, 4
  pxor xmm1, xmm4
  vpslldq xmm4, xmm1, 4
  pxor xmm1, xmm4
  pxor xmm1, xmm2
  movdqu xmmword ptr [rdx + 128], xmm1
  aeskeygenassist xmm2, xmm1, 0
  pshufd xmm2, xmm2, 170
  vpslldq xmm4, xmm3, 4
  pxor xmm3, xmm4
  vpslldq xmm4, xmm3, 4
  pxor xmm3, xmm4
  vpslldq xmm4, xmm3, 4
  pxor xmm3, xmm4
  pxor xmm3, xmm2
  movdqu xmmword ptr [rdx + 144], xmm3
  aeskeygenassist xmm2, xmm3, 16
  pshufd xmm2, xmm2, 255
  vpslldq xmm4, xmm1, 4
  pxor xmm1, xmm4
  vpslldq xmm4, xmm1, 4
  pxor xmm1, xmm4
  vpslldq xmm4, xmm1, 4
  pxor xmm1, xmm4
  pxor xmm1, xmm2
  movdqu xmmword ptr [rdx + 160], xmm1
  aeskeygenassist xmm2, xmm1, 0
  pshufd xmm2, xmm2, 170
  vpslldq xmm4, xmm3, 4
  pxor xmm3, xmm4
  vpslldq xmm4, xmm3, 4
  pxor xmm3, xmm4
  vpslldq xmm4, xmm3, 4
  pxor xmm3, xmm4
  pxor xmm3, xmm2
  movdqu xmmword ptr [rdx + 176], xmm3
  aeskeygenassist xmm2, xmm3, 32
  pshufd xmm2, xmm2, 255
  vpslldq xmm4, xmm1, 4
  pxor xmm1, xmm4
  vpslldq xmm4, xmm1, 4
  pxor xmm1, xmm4
  vpslldq xmm4, xmm1, 4
  pxor xmm1, xmm4
  pxor xmm1, xmm2
  movdqu xmmword ptr [rdx + 192], xmm1
  aeskeygenassist xmm2, xmm1, 0
  pshufd xmm2, xmm2, 170
  vpslldq xmm4, xmm3, 4
  pxor xmm3, xmm4
  vpslldq xmm4, xmm3, 4
  pxor xmm3, xmm4
  vpslldq xmm4, xmm3, 4
  pxor xmm3, xmm4
  pxor xmm3, xmm2
  movdqu xmmword ptr [rdx + 208], xmm3
  aeskeygenassist xmm2, xmm3, 64
  pshufd xmm2, xmm2, 255
  vpslldq xmm4, xmm1, 4
  pxor xmm1, xmm4
  vpslldq xmm4, xmm1, 4
  pxor xmm1, xmm4
  vpslldq xmm4, xmm1, 4
  pxor xmm1, xmm4
  pxor xmm1, xmm2
  movdqu xmmword ptr [rdx + 224], xmm1
  pxor xmm1, xmm1
  pxor xmm2, xmm2
  pxor xmm3, xmm3
  pxor xmm4, xmm4
  ret
aes256_key_expansion endp
ALIGN 16
gcm128_encrypt proc
  mov r9, rcx
  pextrq rax, xmm15, 0
  push rax
  pextrq rax, xmm15, 1
  push rax
  pextrq rax, xmm14, 0
  push rax
  pextrq rax, xmm14, 1
  push rax
  pextrq rax, xmm13, 0
  push rax
  pextrq rax, xmm13, 1
  push rax
  pextrq rax, xmm12, 0
  push rax
  pextrq rax, xmm12, 1
  push rax
  pextrq rax, xmm11, 0
  push rax
  pextrq rax, xmm11, 1
  push rax
  pextrq rax, xmm10, 0
  push rax
  pextrq rax, xmm10, 1
  push rax
  pextrq rax, xmm9, 0
  push rax
  pextrq rax, xmm9, 1
  push rax
  pextrq rax, xmm8, 0
  push rax
  pextrq rax, xmm8, 1
  push rax
  pextrq rax, xmm7, 0
  push rax
  pextrq rax, xmm7, 1
  push rax
  pextrq rax, xmm6, 0
  push rax
  pextrq rax, xmm6, 1
  push rax
  push r15
  push r14
  push r13
  push r12
  push rsi
  push rdi
  push rbp
  push rbx
  mov r14, qword ptr [r9 + 0]
  mov r13, qword ptr [r9 + 8]
  mov rax, qword ptr [r9 + 16]
  mov r11, qword ptr [r9 + 24]
  mov r10, qword ptr [r9 + 32]
  mov r8, qword ptr [r9 + 40]
  mov rbx, qword ptr [r9 + 48]
  mov r15, qword ptr [r9 + 56]
  movdqu xmm7, xmmword ptr [r10 + 0]
  mov r12, 579005069656919567
  pinsrq xmm8, r12, 0
  mov r12, 283686952306183
  pinsrq xmm8, r12, 1
  pxor xmm0, xmm0
  movdqu xmm2, xmmword ptr [r8 + 0]
  pxor xmm0, xmm2
  movdqu xmm2, xmmword ptr [r8 + 16]
  aesenc xmm0, xmm2
  movdqu xmm2, xmmword ptr [r8 + 32]
  aesenc xmm0, xmm2
  movdqu xmm2, xmmword ptr [r8 + 48]
  aesenc xmm0, xmm2
  movdqu xmm2, xmmword ptr [r8 + 64]
  aesenc xmm0, xmm2
  movdqu xmm2, xmmword ptr [r8 + 80]
  aesenc xmm0, xmm2
  movdqu xmm2, xmmword ptr [r8 + 96]
  aesenc xmm0, xmm2
  movdqu xmm2, xmmword ptr [r8 + 112]
  aesenc xmm0, xmm2
  movdqu xmm2, xmmword ptr [r8 + 128]
  aesenc xmm0, xmm2
  movdqu xmm2, xmmword ptr [r8 + 144]
  aesenc xmm0, xmm2
  movdqu xmm2, xmmword ptr [r8 + 160]
  aesenclast xmm0, xmm2
  pxor xmm2, xmm2
  pshufb xmm0, xmm8
  movdqu xmm11, xmm0
  pshufb xmm7, xmm8
  mov r12, 2
  pinsrd xmm7, r12d, 0
  pxor xmm1, xmm1
  cmp r11, 0
  jbe L0
  mov rcx, r11
  shr rcx, 4
  mov r9, rax
  cmp rcx, 0
  je L2
  mov rdx, 0
  jmp L5
ALIGN 16
L4:
  movdqu xmm2, xmmword ptr [r9 + 0]
  pxor xmm1, xmm2
  movdqu xmm2, xmm11
  pshufb xmm1, xmm8
  movdqu xmm5, xmm1
  pclmulqdq xmm1, xmm2, 16
  movdqu xmm3, xmm1
  movdqu xmm1, xmm5
  pclmulqdq xmm1, xmm2, 1
  movdqu xmm4, xmm1
  movdqu xmm1, xmm5
  pclmulqdq xmm1, xmm2, 0
  pclmulqdq xmm5, xmm2, 17
  movdqu xmm2, xmm5
  movdqu xmm5, xmm1
  movdqu xmm1, xmm3
  mov r12, 0
  pinsrd xmm1, r12d, 0
  pshufd xmm1, xmm1, 14
  pxor xmm2, xmm1
  movdqu xmm1, xmm4
  mov r12, 0
  pinsrd xmm1, r12d, 0
  pshufd xmm1, xmm1, 14
  pxor xmm2, xmm1
  movdqu xmm1, xmm3
  mov r12, 0
  pinsrd xmm1, r12d, 3
  pshufd xmm1, xmm1, 79
  mov r12, 0
  pinsrd xmm4, r12d, 3
  pshufd xmm4, xmm4, 79
  pxor xmm1, xmm4
  pxor xmm1, xmm5
  movdqu xmm3, xmm1
  psrld xmm3, 31
  movdqu xmm4, xmm2
  psrld xmm4, 31
  pslld xmm1, 1
  pslld xmm2, 1
  vpslldq xmm5, xmm3, 4
  vpslldq xmm4, xmm4, 4
  mov r12, 0
  pinsrd xmm3, r12d, 0
  pshufd xmm3, xmm3, 3
  pxor xmm3, xmm4
  pxor xmm1, xmm5
  pxor xmm2, xmm3
  movdqu xmm6, xmm2
  pxor xmm2, xmm2
  mov r12, 3774873600
  pinsrd xmm2, r12d, 3
  movdqu xmm5, xmm1
  pclmulqdq xmm1, xmm2, 16
  movdqu xmm3, xmm1
  movdqu xmm1, xmm5
  pclmulqdq xmm1, xmm2, 1
  movdqu xmm4, xmm1
  movdqu xmm1, xmm5
  pclmulqdq xmm1, xmm2, 0
  pclmulqdq xmm5, xmm2, 17
  movdqu xmm2, xmm5
  movdqu xmm5, xmm1
  movdqu xmm1, xmm3
  mov r12, 0
  pinsrd xmm1, r12d, 0
  pshufd xmm1, xmm1, 14
  pxor xmm2, xmm1
  movdqu xmm1, xmm4
  mov r12, 0
  pinsrd xmm1, r12d, 0
  pshufd xmm1, xmm1, 14
  pxor xmm2, xmm1
  movdqu xmm1, xmm3
  mov r12, 0
  pinsrd xmm1, r12d, 3
  pshufd xmm1, xmm1, 79
  mov r12, 0
  pinsrd xmm4, r12d, 3
  pshufd xmm4, xmm4, 79
  pxor xmm1, xmm4
  pxor xmm1, xmm5
  movdqu xmm3, xmm1
  psrld xmm3, 31
  movdqu xmm4, xmm2
  psrld xmm4, 31
  pslld xmm1, 1
  pslld xmm2, 1
  vpslldq xmm5, xmm3, 4
  vpslldq xmm4, xmm4, 4
  mov r12, 0
  pinsrd xmm3, r12d, 0
  pshufd xmm3, xmm3, 3
  pxor xmm3, xmm4
  pxor xmm1, xmm5
  pxor xmm2, xmm3
  movdqu xmm5, xmm2
  pxor xmm2, xmm2
  mov r12, 3774873600
  pinsrd xmm2, r12d, 3
  pclmulqdq xmm1, xmm2, 17
  movdqu xmm2, xmm1
  psrld xmm2, 31
  pslld xmm1, 1
  vpslldq xmm2, xmm2, 4
  pxor xmm1, xmm2
  pxor xmm1, xmm5
  pxor xmm1, xmm6
  pshufb xmm1, xmm8
  add rdx, 1
  add r9, 16
ALIGN 16
L5:
  cmp rdx, rcx
  jne L4
  jmp L3
L2:
L3:
  mov rax, r11
  and rax, 15
  cmp rax, 0
  jne L6
  jmp L7
L6:
  movdqu xmm2, xmmword ptr [r9 + 0]
  cmp rax, 8
  jae L8
  mov rcx, 0
  pinsrq xmm2, rcx, 1
  mov rcx, rax
  shl rcx, 3
  mov rdx, 1
  shl rdx, cl
  sub rdx, 1
  pextrq rcx, xmm2, 0
  and rcx, rdx
  pinsrq xmm2, rcx, 0
  jmp L9
L8:
  mov rcx, rax
  sub rcx, 8
  shl rcx, 3
  mov rdx, 1
  shl rdx, cl
  sub rdx, 1
  pextrq rcx, xmm2, 1
  and rcx, rdx
  pinsrq xmm2, rcx, 1
L9:
  pxor xmm1, xmm2
  movdqu xmm2, xmm11
  pshufb xmm1, xmm8
  movdqu xmm5, xmm1
  pclmulqdq xmm1, xmm2, 16
  movdqu xmm3, xmm1
  movdqu xmm1, xmm5
  pclmulqdq xmm1, xmm2, 1
  movdqu xmm4, xmm1
  movdqu xmm1, xmm5
  pclmulqdq xmm1, xmm2, 0
  pclmulqdq xmm5, xmm2, 17
  movdqu xmm2, xmm5
  movdqu xmm5, xmm1
  movdqu xmm1, xmm3
  mov r12, 0
  pinsrd xmm1, r12d, 0
  pshufd xmm1, xmm1, 14
  pxor xmm2, xmm1
  movdqu xmm1, xmm4
  mov r12, 0
  pinsrd xmm1, r12d, 0
  pshufd xmm1, xmm1, 14
  pxor xmm2, xmm1
  movdqu xmm1, xmm3
  mov r12, 0
  pinsrd xmm1, r12d, 3
  pshufd xmm1, xmm1, 79
  mov r12, 0
  pinsrd xmm4, r12d, 3
  pshufd xmm4, xmm4, 79
  pxor xmm1, xmm4
  pxor xmm1, xmm5
  movdqu xmm3, xmm1
  psrld xmm3, 31
  movdqu xmm4, xmm2
  psrld xmm4, 31
  pslld xmm1, 1
  pslld xmm2, 1
  vpslldq xmm5, xmm3, 4
  vpslldq xmm4, xmm4, 4
  mov r12, 0
  pinsrd xmm3, r12d, 0
  pshufd xmm3, xmm3, 3
  pxor xmm3, xmm4
  pxor xmm1, xmm5
  pxor xmm2, xmm3
  movdqu xmm6, xmm2
  pxor xmm2, xmm2
  mov r12, 3774873600
  pinsrd xmm2, r12d, 3
  movdqu xmm5, xmm1
  pclmulqdq xmm1, xmm2, 16
  movdqu xmm3, xmm1
  movdqu xmm1, xmm5
  pclmulqdq xmm1, xmm2, 1
  movdqu xmm4, xmm1
  movdqu xmm1, xmm5
  pclmulqdq xmm1, xmm2, 0
  pclmulqdq xmm5, xmm2, 17
  movdqu xmm2, xmm5
  movdqu xmm5, xmm1
  movdqu xmm1, xmm3
  mov r12, 0
  pinsrd xmm1, r12d, 0
  pshufd xmm1, xmm1, 14
  pxor xmm2, xmm1
  movdqu xmm1, xmm4
  mov r12, 0
  pinsrd xmm1, r12d, 0
  pshufd xmm1, xmm1, 14
  pxor xmm2, xmm1
  movdqu xmm1, xmm3
  mov r12, 0
  pinsrd xmm1, r12d, 3
  pshufd xmm1, xmm1, 79
  mov r12, 0
  pinsrd xmm4, r12d, 3
  pshufd xmm4, xmm4, 79
  pxor xmm1, xmm4
  pxor xmm1, xmm5
  movdqu xmm3, xmm1
  psrld xmm3, 31
  movdqu xmm4, xmm2
  psrld xmm4, 31
  pslld xmm1, 1
  pslld xmm2, 1
  vpslldq xmm5, xmm3, 4
  vpslldq xmm4, xmm4, 4
  mov r12, 0
  pinsrd xmm3, r12d, 0
  pshufd xmm3, xmm3, 3
  pxor xmm3, xmm4
  pxor xmm1, xmm5
  pxor xmm2, xmm3
  movdqu xmm5, xmm2
  pxor xmm2, xmm2
  mov r12, 3774873600
  pinsrd xmm2, r12d, 3
  pclmulqdq xmm1, xmm2, 17
  movdqu xmm2, xmm1
  psrld xmm2, 31
  pslld xmm1, 1
  vpslldq xmm2, xmm2, 4
  pxor xmm1, xmm2
  pxor xmm1, xmm5
  pxor xmm1, xmm6
  pshufb xmm1, xmm8
L7:
  jmp L1
L0:
L1:
  mov rax, r14
  mov rcx, r13
  cmp rcx, 0
  jbe L10
  mov rsi, rcx
  and rsi, 15
  shr rcx, 4
  mov rdx, rcx
  shr rdx, 2
  and rcx, 3
  cmp rdx, 0
  jbe L12
  mov r9, rax
  mov r10, rbx
  pshufb xmm7, xmm8
  movdqu xmm9, xmm7
  mov rax, 579005069656919567
  pinsrq xmm0, rax, 0
  mov rax, 579005069656919567
  pinsrq xmm0, rax, 1
  pshufb xmm9, xmm0
  movdqu xmm10, xmm9
  pxor xmm3, xmm3
  mov rax, 1
  pinsrd xmm3, eax, 2
  paddd xmm9, xmm3
  mov rax, 3
  pinsrd xmm3, eax, 2
  mov rax, 2
  pinsrd xmm3, eax, 0
  paddd xmm10, xmm3
  pshufb xmm9, xmm8
  pshufb xmm10, xmm8
  pextrq rdi, xmm7, 0
  mov rax, 283686952306183
  pinsrq xmm0, rax, 0
  mov rax, 579005069656919567
  pinsrq xmm0, rax, 1
  pxor xmm15, xmm15
  mov rax, 4
  pinsrd xmm15, eax, 0
  mov rax, 4
  pinsrd xmm15, eax, 2
  jmp L15
ALIGN 16
L14:
  pinsrq xmm2, rdi, 0
  pinsrq xmm12, rdi, 0
  pinsrq xmm13, rdi, 0
  pinsrq xmm14, rdi, 0
  shufpd xmm2, xmm9, 2
  shufpd xmm12, xmm9, 0
  shufpd xmm13, xmm10, 2
  shufpd xmm14, xmm10, 0
  pshufb xmm9, xmm0
  pshufb xmm10, xmm0
  movdqu xmm3, xmmword ptr [r8 + 0]
  movdqu xmm4, xmmword ptr [r8 + 16]
  movdqu xmm5, xmmword ptr [r8 + 32]
  movdqu xmm6, xmmword ptr [r8 + 48]
  paddd xmm9, xmm15
  paddd xmm10, xmm15
  pxor xmm2, xmm3
  pxor xmm12, xmm3
  pxor xmm13, xmm3
  pxor xmm14, xmm3
  pshufb xmm9, xmm0
  pshufb xmm10, xmm0
  aesenc xmm2, xmm4
  aesenc xmm12, xmm4
  aesenc xmm13, xmm4
  aesenc xmm14, xmm4
  aesenc xmm2, xmm5
  aesenc xmm12, xmm5
  aesenc xmm13, xmm5
  aesenc xmm14, xmm5
  aesenc xmm2, xmm6
  aesenc xmm12, xmm6
  aesenc xmm13, xmm6
  aesenc xmm14, xmm6
  movdqu xmm3, xmmword ptr [r8 + 64]
  movdqu xmm4, xmmword ptr [r8 + 80]
  movdqu xmm5, xmmword ptr [r8 + 96]
  movdqu xmm6, xmmword ptr [r8 + 112]
  aesenc xmm2, xmm3
  aesenc xmm12, xmm3
  aesenc xmm13, xmm3
  aesenc xmm14, xmm3
  aesenc xmm2, xmm4
  aesenc xmm12, xmm4
  aesenc xmm13, xmm4
  aesenc xmm14, xmm4
  aesenc xmm2, xmm5
  aesenc xmm12, xmm5
  aesenc xmm13, xmm5
  aesenc xmm14, xmm5
  aesenc xmm2, xmm6
  aesenc xmm12, xmm6
  aesenc xmm13, xmm6
  aesenc xmm14, xmm6
  movdqu xmm3, xmmword ptr [r8 + 128]
  movdqu xmm4, xmmword ptr [r8 + 144]
  movdqu xmm5, xmmword ptr [r8 + 160]
  aesenc xmm2, xmm3
  aesenc xmm12, xmm3
  aesenc xmm13, xmm3
  aesenc xmm14, xmm3
  aesenc xmm2, xmm4
  aesenc xmm12, xmm4
  aesenc xmm13, xmm4
  aesenc xmm14, xmm4
  aesenclast xmm2, xmm5
  aesenclast xmm12, xmm5
  aesenclast xmm13, xmm5
  aesenclast xmm14, xmm5
  movdqu xmm7, xmmword ptr [r9 + 0]
  pxor xmm2, xmm7
  movdqu xmm7, xmmword ptr [r9 + 16]
  pxor xmm12, xmm7
  movdqu xmm7, xmmword ptr [r9 + 32]
  pxor xmm13, xmm7
  movdqu xmm7, xmmword ptr [r9 + 48]
  pxor xmm14, xmm7
  movdqu xmmword ptr [r10 + 0], xmm2
  movdqu xmmword ptr [r10 + 16], xmm12
  movdqu xmmword ptr [r10 + 32], xmm13
  movdqu xmmword ptr [r10 + 48], xmm14
  pxor xmm1, xmm2
  movdqu xmm2, xmm11
  pshufb xmm1, xmm8
  movdqu xmm5, xmm1
  pclmulqdq xmm1, xmm2, 16
  movdqu xmm3, xmm1
  movdqu xmm1, xmm5
  pclmulqdq xmm1, xmm2, 1
  movdqu xmm4, xmm1
  movdqu xmm1, xmm5
  pclmulqdq xmm1, xmm2, 0
  pclmulqdq xmm5, xmm2, 17
  movdqu xmm2, xmm5
  movdqu xmm5, xmm1
  movdqu xmm1, xmm3
  mov r12, 0
  pinsrd xmm1, r12d, 0
  pshufd xmm1, xmm1, 14
  pxor xmm2, xmm1
  movdqu xmm1, xmm4
  mov r12, 0
  pinsrd xmm1, r12d, 0
  pshufd xmm1, xmm1, 14
  pxor xmm2, xmm1
  movdqu xmm1, xmm3
  mov r12, 0
  pinsrd xmm1, r12d, 3
  pshufd xmm1, xmm1, 79
  mov r12, 0
  pinsrd xmm4, r12d, 3
  pshufd xmm4, xmm4, 79
  pxor xmm1, xmm4
  pxor xmm1, xmm5
  movdqu xmm3, xmm1
  psrld xmm3, 31
  movdqu xmm4, xmm2
  psrld xmm4, 31
  pslld xmm1, 1
  pslld xmm2, 1
  vpslldq xmm5, xmm3, 4
  vpslldq xmm4, xmm4, 4
  mov r12, 0
  pinsrd xmm3, r12d, 0
  pshufd xmm3, xmm3, 3
  pxor xmm3, xmm4
  pxor xmm1, xmm5
  pxor xmm2, xmm3
  movdqu xmm6, xmm2
  pxor xmm2, xmm2
  mov r12, 3774873600
  pinsrd xmm2, r12d, 3
  movdqu xmm5, xmm1
  pclmulqdq xmm1, xmm2, 16
  movdqu xmm3, xmm1
  movdqu xmm1, xmm5
  pclmulqdq xmm1, xmm2, 1
  movdqu xmm4, xmm1
  movdqu xmm1, xmm5
  pclmulqdq xmm1, xmm2, 0
  pclmulqdq xmm5, xmm2, 17
  movdqu xmm2, xmm5
  movdqu xmm5, xmm1
  movdqu xmm1, xmm3
  mov r12, 0
  pinsrd xmm1, r12d, 0
  pshufd xmm1, xmm1, 14
  pxor xmm2, xmm1
  movdqu xmm1, xmm4
  mov r12, 0
  pinsrd xmm1, r12d, 0
  pshufd xmm1, xmm1, 14
  pxor xmm2, xmm1
  movdqu xmm1, xmm3
  mov r12, 0
  pinsrd xmm1, r12d, 3
  pshufd xmm1, xmm1, 79
  mov r12, 0
  pinsrd xmm4, r12d, 3
  pshufd xmm4, xmm4, 79
  pxor xmm1, xmm4
  pxor xmm1, xmm5
  movdqu xmm3, xmm1
  psrld xmm3, 31
  movdqu xmm4, xmm2
  psrld xmm4, 31
  pslld xmm1, 1
  pslld xmm2, 1
  vpslldq xmm5, xmm3, 4
  vpslldq xmm4, xmm4, 4
  mov r12, 0
  pinsrd xmm3, r12d, 0
  pshufd xmm3, xmm3, 3
  pxor xmm3, xmm4
  pxor xmm1, xmm5
  pxor xmm2, xmm3
  movdqu xmm5, xmm2
  pxor xmm2, xmm2
  mov r12, 3774873600
  pinsrd xmm2, r12d, 3
  pclmulqdq xmm1, xmm2, 17
  movdqu xmm2, xmm1
  psrld xmm2, 31
  pslld xmm1, 1
  vpslldq xmm2, xmm2, 4
  pxor xmm1, xmm2
  pxor xmm1, xmm5
  pxor xmm1, xmm6
  pshufb xmm1, xmm8
  movdqu xmm2, xmm12
  pxor xmm1, xmm2
  movdqu xmm2, xmm11
  pshufb xmm1, xmm8
  movdqu xmm5, xmm1
  pclmulqdq xmm1, xmm2, 16
  movdqu xmm3, xmm1
  movdqu xmm1, xmm5
  pclmulqdq xmm1, xmm2, 1
  movdqu xmm4, xmm1
  movdqu xmm1, xmm5
  pclmulqdq xmm1, xmm2, 0
  pclmulqdq xmm5, xmm2, 17
  movdqu xmm2, xmm5
  movdqu xmm5, xmm1
  movdqu xmm1, xmm3
  mov r12, 0
  pinsrd xmm1, r12d, 0
  pshufd xmm1, xmm1, 14
  pxor xmm2, xmm1
  movdqu xmm1, xmm4
  mov r12, 0
  pinsrd xmm1, r12d, 0
  pshufd xmm1, xmm1, 14
  pxor xmm2, xmm1
  movdqu xmm1, xmm3
  mov r12, 0
  pinsrd xmm1, r12d, 3
  pshufd xmm1, xmm1, 79
  mov r12, 0
  pinsrd xmm4, r12d, 3
  pshufd xmm4, xmm4, 79
  pxor xmm1, xmm4
  pxor xmm1, xmm5
  movdqu xmm3, xmm1
  psrld xmm3, 31
  movdqu xmm4, xmm2
  psrld xmm4, 31
  pslld xmm1, 1
  pslld xmm2, 1
  vpslldq xmm5, xmm3, 4
  vpslldq xmm4, xmm4, 4
  mov r12, 0
  pinsrd xmm3, r12d, 0
  pshufd xmm3, xmm3, 3
  pxor xmm3, xmm4
  pxor xmm1, xmm5
  pxor xmm2, xmm3
  movdqu xmm6, xmm2
  pxor xmm2, xmm2
  mov r12, 3774873600
  pinsrd xmm2, r12d, 3
  movdqu xmm5, xmm1
  pclmulqdq xmm1, xmm2, 16
  movdqu xmm3, xmm1
  movdqu xmm1, xmm5
  pclmulqdq xmm1, xmm2, 1
  movdqu xmm4, xmm1
  movdqu xmm1, xmm5
  pclmulqdq xmm1, xmm2, 0
  pclmulqdq xmm5, xmm2, 17
  movdqu xmm2, xmm5
  movdqu xmm5, xmm1
  movdqu xmm1, xmm3
  mov r12, 0
  pinsrd xmm1, r12d, 0
  pshufd xmm1, xmm1, 14
  pxor xmm2, xmm1
  movdqu xmm1, xmm4
  mov r12, 0
  pinsrd xmm1, r12d, 0
  pshufd xmm1, xmm1, 14
  pxor xmm2, xmm1
  movdqu xmm1, xmm3
  mov r12, 0
  pinsrd xmm1, r12d, 3
  pshufd xmm1, xmm1, 79
  mov r12, 0
  pinsrd xmm4, r12d, 3
  pshufd xmm4, xmm4, 79
  pxor xmm1, xmm4
  pxor xmm1, xmm5
  movdqu xmm3, xmm1
  psrld xmm3, 31
  movdqu xmm4, xmm2
  psrld xmm4, 31
  pslld xmm1, 1
  pslld xmm2, 1
  vpslldq xmm5, xmm3, 4
  vpslldq xmm4, xmm4, 4
  mov r12, 0
  pinsrd xmm3, r12d, 0
  pshufd xmm3, xmm3, 3
  pxor xmm3, xmm4
  pxor xmm1, xmm5
  pxor xmm2, xmm3
  movdqu xmm5, xmm2
  pxor xmm2, xmm2
  mov r12, 3774873600
  pinsrd xmm2, r12d, 3
  pclmulqdq xmm1, xmm2, 17
  movdqu xmm2, xmm1
  psrld xmm2, 31
  pslld xmm1, 1
  vpslldq xmm2, xmm2, 4
  pxor xmm1, xmm2
  pxor xmm1, xmm5
  pxor xmm1, xmm6
  pshufb xmm1, xmm8
  movdqu xmm2, xmm13
  pxor xmm1, xmm2
  movdqu xmm2, xmm11
  pshufb xmm1, xmm8
  movdqu xmm5, xmm1
  pclmulqdq xmm1, xmm2, 16
  movdqu xmm3, xmm1
  movdqu xmm1, xmm5
  pclmulqdq xmm1, xmm2, 1
  movdqu xmm4, xmm1
  movdqu xmm1, xmm5
  pclmulqdq xmm1, xmm2, 0
  pclmulqdq xmm5, xmm2, 17
  movdqu xmm2, xmm5
  movdqu xmm5, xmm1
  movdqu xmm1, xmm3
  mov r12, 0
  pinsrd xmm1, r12d, 0
  pshufd xmm1, xmm1, 14
  pxor xmm2, xmm1
  movdqu xmm1, xmm4
  mov r12, 0
  pinsrd xmm1, r12d, 0
  pshufd xmm1, xmm1, 14
  pxor xmm2, xmm1
  movdqu xmm1, xmm3
  mov r12, 0
  pinsrd xmm1, r12d, 3
  pshufd xmm1, xmm1, 79
  mov r12, 0
  pinsrd xmm4, r12d, 3
  pshufd xmm4, xmm4, 79
  pxor xmm1, xmm4
  pxor xmm1, xmm5
  movdqu xmm3, xmm1
  psrld xmm3, 31
  movdqu xmm4, xmm2
  psrld xmm4, 31
  pslld xmm1, 1
  pslld xmm2, 1
  vpslldq xmm5, xmm3, 4
  vpslldq xmm4, xmm4, 4
  mov r12, 0
  pinsrd xmm3, r12d, 0
  pshufd xmm3, xmm3, 3
  pxor xmm3, xmm4
  pxor xmm1, xmm5
  pxor xmm2, xmm3
  movdqu xmm6, xmm2
  pxor xmm2, xmm2
  mov r12, 3774873600
  pinsrd xmm2, r12d, 3
  movdqu xmm5, xmm1
  pclmulqdq xmm1, xmm2, 16
  movdqu xmm3, xmm1
  movdqu xmm1, xmm5
  pclmulqdq xmm1, xmm2, 1
  movdqu xmm4, xmm1
  movdqu xmm1, xmm5
  pclmulqdq xmm1, xmm2, 0
  pclmulqdq xmm5, xmm2, 17
  movdqu xmm2, xmm5
  movdqu xmm5, xmm1
  movdqu xmm1, xmm3
  mov r12, 0
  pinsrd xmm1, r12d, 0
  pshufd xmm1, xmm1, 14
  pxor xmm2, xmm1
  movdqu xmm1, xmm4
  mov r12, 0
  pinsrd xmm1, r12d, 0
  pshufd xmm1, xmm1, 14
  pxor xmm2, xmm1
  movdqu xmm1, xmm3
  mov r12, 0
  pinsrd xmm1, r12d, 3
  pshufd xmm1, xmm1, 79
  mov r12, 0
  pinsrd xmm4, r12d, 3
  pshufd xmm4, xmm4, 79
  pxor xmm1, xmm4
  pxor xmm1, xmm5
  movdqu xmm3, xmm1
  psrld xmm3, 31
  movdqu xmm4, xmm2
  psrld xmm4, 31
  pslld xmm1, 1
  pslld xmm2, 1
  vpslldq xmm5, xmm3, 4
  vpslldq xmm4, xmm4, 4
  mov r12, 0
  pinsrd xmm3, r12d, 0
  pshufd xmm3, xmm3, 3
  pxor xmm3, xmm4
  pxor xmm1, xmm5
  pxor xmm2, xmm3
  movdqu xmm5, xmm2
  pxor xmm2, xmm2
  mov r12, 3774873600
  pinsrd xmm2, r12d, 3
  pclmulqdq xmm1, xmm2, 17
  movdqu xmm2, xmm1
  psrld xmm2, 31
  pslld xmm1, 1
  vpslldq xmm2, xmm2, 4
  pxor xmm1, xmm2
  pxor xmm1, xmm5
  pxor xmm1, xmm6
  pshufb xmm1, xmm8
  movdqu xmm2, xmm14
  pxor xmm1, xmm2
  movdqu xmm2, xmm11
  pshufb xmm1, xmm8
  movdqu xmm5, xmm1
  pclmulqdq xmm1, xmm2, 16
  movdqu xmm3, xmm1
  movdqu xmm1, xmm5
  pclmulqdq xmm1, xmm2, 1
  movdqu xmm4, xmm1
  movdqu xmm1, xmm5
  pclmulqdq xmm1, xmm2, 0
  pclmulqdq xmm5, xmm2, 17
  movdqu xmm2, xmm5
  movdqu xmm5, xmm1
  movdqu xmm1, xmm3
  mov r12, 0
  pinsrd xmm1, r12d, 0
  pshufd xmm1, xmm1, 14
  pxor xmm2, xmm1
  movdqu xmm1, xmm4
  mov r12, 0
  pinsrd xmm1, r12d, 0
  pshufd xmm1, xmm1, 14
  pxor xmm2, xmm1
  movdqu xmm1, xmm3
  mov r12, 0
  pinsrd xmm1, r12d, 3
  pshufd xmm1, xmm1, 79
  mov r12, 0
  pinsrd xmm4, r12d, 3
  pshufd xmm4, xmm4, 79
  pxor xmm1, xmm4
  pxor xmm1, xmm5
  movdqu xmm3, xmm1
  psrld xmm3, 31
  movdqu xmm4, xmm2
  psrld xmm4, 31
  pslld xmm1, 1
  pslld xmm2, 1
  vpslldq xmm5, xmm3, 4
  vpslldq xmm4, xmm4, 4
  mov r12, 0
  pinsrd xmm3, r12d, 0
  pshufd xmm3, xmm3, 3
  pxor xmm3, xmm4
  pxor xmm1, xmm5
  pxor xmm2, xmm3
  movdqu xmm6, xmm2
  pxor xmm2, xmm2
  mov r12, 3774873600
  pinsrd xmm2, r12d, 3
  movdqu xmm5, xmm1
  pclmulqdq xmm1, xmm2, 16
  movdqu xmm3, xmm1
  movdqu xmm1, xmm5
  pclmulqdq xmm1, xmm2, 1
  movdqu xmm4, xmm1
  movdqu xmm1, xmm5
  pclmulqdq xmm1, xmm2, 0
  pclmulqdq xmm5, xmm2, 17
  movdqu xmm2, xmm5
  movdqu xmm5, xmm1
  movdqu xmm1, xmm3
  mov r12, 0
  pinsrd xmm1, r12d, 0
  pshufd xmm1, xmm1, 14
  pxor xmm2, xmm1
  movdqu xmm1, xmm4
  mov r12, 0
  pinsrd xmm1, r12d, 0
  pshufd xmm1, xmm1, 14
  pxor xmm2, xmm1
  movdqu xmm1, xmm3
  mov r12, 0
  pinsrd xmm1, r12d, 3
  pshufd xmm1, xmm1, 79
  mov r12, 0
  pinsrd xmm4, r12d, 3
  pshufd xmm4, xmm4, 79
  pxor xmm1, xmm4
  pxor xmm1, xmm5
  movdqu xmm3, xmm1
  psrld xmm3, 31
  movdqu xmm4, xmm2
  psrld xmm4, 31
  pslld xmm1, 1
  pslld xmm2, 1
  vpslldq xmm5, xmm3, 4
  vpslldq xmm4, xmm4, 4
  mov r12, 0
  pinsrd xmm3, r12d, 0
  pshufd xmm3, xmm3, 3
  pxor xmm3, xmm4
  pxor xmm1, xmm5
  pxor xmm2, xmm3
  movdqu xmm5, xmm2
  pxor xmm2, xmm2
  mov r12, 3774873600
  pinsrd xmm2, r12d, 3
  pclmulqdq xmm1, xmm2, 17
  movdqu xmm2, xmm1
  psrld xmm2, 31
  pslld xmm1, 1
  vpslldq xmm2, xmm2, 4
  pxor xmm1, xmm2
  pxor xmm1, xmm5
  pxor xmm1, xmm6
  pshufb xmm1, xmm8
  sub rdx, 1
  add r9, 64
  add r10, 64
ALIGN 16
L15:
  cmp rdx, 0
  ja L14
  movdqu xmm7, xmm9
  pinsrq xmm7, rdi, 0
  pshufb xmm7, xmm8
  mov rax, r9
  mov rbx, r10
  jmp L13
L12:
L13:
  mov rdx, 0
  mov r9, rax
  mov r10, rbx
  pxor xmm10, xmm10
  mov r12, 1
  pinsrd xmm10, r12d, 0
  jmp L17
ALIGN 16
L16:
  movdqu xmm0, xmm7
  pshufb xmm0, xmm8
  movdqu xmm2, xmmword ptr [r8 + 0]
  pxor xmm0, xmm2
  movdqu xmm2, xmmword ptr [r8 + 16]
  aesenc xmm0, xmm2
  movdqu xmm2, xmmword ptr [r8 + 32]
  aesenc xmm0, xmm2
  movdqu xmm2, xmmword ptr [r8 + 48]
  aesenc xmm0, xmm2
  movdqu xmm2, xmmword ptr [r8 + 64]
  aesenc xmm0, xmm2
  movdqu xmm2, xmmword ptr [r8 + 80]
  aesenc xmm0, xmm2
  movdqu xmm2, xmmword ptr [r8 + 96]
  aesenc xmm0, xmm2
  movdqu xmm2, xmmword ptr [r8 + 112]
  aesenc xmm0, xmm2
  movdqu xmm2, xmmword ptr [r8 + 128]
  aesenc xmm0, xmm2
  movdqu xmm2, xmmword ptr [r8 + 144]
  aesenc xmm0, xmm2
  movdqu xmm2, xmmword ptr [r8 + 160]
  aesenclast xmm0, xmm2
  pxor xmm2, xmm2
  movdqu xmm2, xmmword ptr [r9 + 0]
  pxor xmm2, xmm0
  movdqu xmmword ptr [r10 + 0], xmm2
  pxor xmm1, xmm2
  movdqu xmm2, xmm11
  pshufb xmm1, xmm8
  movdqu xmm5, xmm1
  pclmulqdq xmm1, xmm2, 16
  movdqu xmm3, xmm1
  movdqu xmm1, xmm5
  pclmulqdq xmm1, xmm2, 1
  movdqu xmm4, xmm1
  movdqu xmm1, xmm5
  pclmulqdq xmm1, xmm2, 0
  pclmulqdq xmm5, xmm2, 17
  movdqu xmm2, xmm5
  movdqu xmm5, xmm1
  movdqu xmm1, xmm3
  mov r12, 0
  pinsrd xmm1, r12d, 0
  pshufd xmm1, xmm1, 14
  pxor xmm2, xmm1
  movdqu xmm1, xmm4
  mov r12, 0
  pinsrd xmm1, r12d, 0
  pshufd xmm1, xmm1, 14
  pxor xmm2, xmm1
  movdqu xmm1, xmm3
  mov r12, 0
  pinsrd xmm1, r12d, 3
  pshufd xmm1, xmm1, 79
  mov r12, 0
  pinsrd xmm4, r12d, 3
  pshufd xmm4, xmm4, 79
  pxor xmm1, xmm4
  pxor xmm1, xmm5
  movdqu xmm3, xmm1
  psrld xmm3, 31
  movdqu xmm4, xmm2
  psrld xmm4, 31
  pslld xmm1, 1
  pslld xmm2, 1
  vpslldq xmm5, xmm3, 4
  vpslldq xmm4, xmm4, 4
  mov r12, 0
  pinsrd xmm3, r12d, 0
  pshufd xmm3, xmm3, 3
  pxor xmm3, xmm4
  pxor xmm1, xmm5
  pxor xmm2, xmm3
  movdqu xmm6, xmm2
  pxor xmm2, xmm2
  mov r12, 3774873600
  pinsrd xmm2, r12d, 3
  movdqu xmm5, xmm1
  pclmulqdq xmm1, xmm2, 16
  movdqu xmm3, xmm1
  movdqu xmm1, xmm5
  pclmulqdq xmm1, xmm2, 1
  movdqu xmm4, xmm1
  movdqu xmm1, xmm5
  pclmulqdq xmm1, xmm2, 0
  pclmulqdq xmm5, xmm2, 17
  movdqu xmm2, xmm5
  movdqu xmm5, xmm1
  movdqu xmm1, xmm3
  mov r12, 0
  pinsrd xmm1, r12d, 0
  pshufd xmm1, xmm1, 14
  pxor xmm2, xmm1
  movdqu xmm1, xmm4
  mov r12, 0
  pinsrd xmm1, r12d, 0
  pshufd xmm1, xmm1, 14
  pxor xmm2, xmm1
  movdqu xmm1, xmm3
  mov r12, 0
  pinsrd xmm1, r12d, 3
  pshufd xmm1, xmm1, 79
  mov r12, 0
  pinsrd xmm4, r12d, 3
  pshufd xmm4, xmm4, 79
  pxor xmm1, xmm4
  pxor xmm1, xmm5
  movdqu xmm3, xmm1
  psrld xmm3, 31
  movdqu xmm4, xmm2
  psrld xmm4, 31
  pslld xmm1, 1
  pslld xmm2, 1
  vpslldq xmm5, xmm3, 4
  vpslldq xmm4, xmm4, 4
  mov r12, 0
  pinsrd xmm3, r12d, 0
  pshufd xmm3, xmm3, 3
  pxor xmm3, xmm4
  pxor xmm1, xmm5
  pxor xmm2, xmm3
  movdqu xmm5, xmm2
  pxor xmm2, xmm2
  mov r12, 3774873600
  pinsrd xmm2, r12d, 3
  pclmulqdq xmm1, xmm2, 17
  movdqu xmm2, xmm1
  psrld xmm2, 31
  pslld xmm1, 1
  vpslldq xmm2, xmm2, 4
  pxor xmm1, xmm2
  pxor xmm1, xmm5
  pxor xmm1, xmm6
  pshufb xmm1, xmm8
  add rdx, 1
  add r9, 16
  add r10, 16
  paddd xmm7, xmm10
ALIGN 16
L17:
  cmp rdx, rcx
  jne L16
  cmp rsi, 0
  jne L18
  jmp L19
L18:
  movdqu xmm3, xmm1
  movdqu xmm2, xmmword ptr [r9 + 0]
  movdqu xmm1, xmm2
  movdqu xmm0, xmm7
  mov r12, 579005069656919567
  pinsrq xmm2, r12, 0
  mov r12, 283686952306183
  pinsrq xmm2, r12, 1
  pshufb xmm0, xmm2
  movdqu xmm2, xmmword ptr [r8 + 0]
  pxor xmm0, xmm2
  movdqu xmm2, xmmword ptr [r8 + 16]
  aesenc xmm0, xmm2
  movdqu xmm2, xmmword ptr [r8 + 32]
  aesenc xmm0, xmm2
  movdqu xmm2, xmmword ptr [r8 + 48]
  aesenc xmm0, xmm2
  movdqu xmm2, xmmword ptr [r8 + 64]
  aesenc xmm0, xmm2
  movdqu xmm2, xmmword ptr [r8 + 80]
  aesenc xmm0, xmm2
  movdqu xmm2, xmmword ptr [r8 + 96]
  aesenc xmm0, xmm2
  movdqu xmm2, xmmword ptr [r8 + 112]
  aesenc xmm0, xmm2
  movdqu xmm2, xmmword ptr [r8 + 128]
  aesenc xmm0, xmm2
  movdqu xmm2, xmmword ptr [r8 + 144]
  aesenc xmm0, xmm2
  movdqu xmm2, xmmword ptr [r8 + 160]
  aesenclast xmm0, xmm2
  pxor xmm2, xmm2
  pxor xmm1, xmm0
  movdqu xmmword ptr [r10 + 0], xmm1
  mov rax, rsi
  mov r9, r10
  movdqu xmm1, xmm3
  movdqu xmm2, xmmword ptr [r9 + 0]
  cmp rax, 8
  jae L20
  mov rcx, 0
  pinsrq xmm2, rcx, 1
  mov rcx, rax
  shl rcx, 3
  mov rdx, 1
  shl rdx, cl
  sub rdx, 1
  pextrq rcx, xmm2, 0
  and rcx, rdx
  pinsrq xmm2, rcx, 0
  jmp L21
L20:
  mov rcx, rax
  sub rcx, 8
  shl rcx, 3
  mov rdx, 1
  shl rdx, cl
  sub rdx, 1
  pextrq rcx, xmm2, 1
  and rcx, rdx
  pinsrq xmm2, rcx, 1
L21:
  pxor xmm1, xmm2
  movdqu xmm2, xmm11
  pshufb xmm1, xmm8
  movdqu xmm5, xmm1
  pclmulqdq xmm1, xmm2, 16
  movdqu xmm3, xmm1
  movdqu xmm1, xmm5
  pclmulqdq xmm1, xmm2, 1
  movdqu xmm4, xmm1
  movdqu xmm1, xmm5
  pclmulqdq xmm1, xmm2, 0
  pclmulqdq xmm5, xmm2, 17
  movdqu xmm2, xmm5
  movdqu xmm5, xmm1
  movdqu xmm1, xmm3
  mov r12, 0
  pinsrd xmm1, r12d, 0
  pshufd xmm1, xmm1, 14
  pxor xmm2, xmm1
  movdqu xmm1, xmm4
  mov r12, 0
  pinsrd xmm1, r12d, 0
  pshufd xmm1, xmm1, 14
  pxor xmm2, xmm1
  movdqu xmm1, xmm3
  mov r12, 0
  pinsrd xmm1, r12d, 3
  pshufd xmm1, xmm1, 79
  mov r12, 0
  pinsrd xmm4, r12d, 3
  pshufd xmm4, xmm4, 79
  pxor xmm1, xmm4
  pxor xmm1, xmm5
  movdqu xmm3, xmm1
  psrld xmm3, 31
  movdqu xmm4, xmm2
  psrld xmm4, 31
  pslld xmm1, 1
  pslld xmm2, 1
  vpslldq xmm5, xmm3, 4
  vpslldq xmm4, xmm4, 4
  mov r12, 0
  pinsrd xmm3, r12d, 0
  pshufd xmm3, xmm3, 3
  pxor xmm3, xmm4
  pxor xmm1, xmm5
  pxor xmm2, xmm3
  movdqu xmm6, xmm2
  pxor xmm2, xmm2
  mov r12, 3774873600
  pinsrd xmm2, r12d, 3
  movdqu xmm5, xmm1
  pclmulqdq xmm1, xmm2, 16
  movdqu xmm3, xmm1
  movdqu xmm1, xmm5
  pclmulqdq xmm1, xmm2, 1
  movdqu xmm4, xmm1
  movdqu xmm1, xmm5
  pclmulqdq xmm1, xmm2, 0
  pclmulqdq xmm5, xmm2, 17
  movdqu xmm2, xmm5
  movdqu xmm5, xmm1
  movdqu xmm1, xmm3
  mov r12, 0
  pinsrd xmm1, r12d, 0
  pshufd xmm1, xmm1, 14
  pxor xmm2, xmm1
  movdqu xmm1, xmm4
  mov r12, 0
  pinsrd xmm1, r12d, 0
  pshufd xmm1, xmm1, 14
  pxor xmm2, xmm1
  movdqu xmm1, xmm3
  mov r12, 0
  pinsrd xmm1, r12d, 3
  pshufd xmm1, xmm1, 79
  mov r12, 0
  pinsrd xmm4, r12d, 3
  pshufd xmm4, xmm4, 79
  pxor xmm1, xmm4
  pxor xmm1, xmm5
  movdqu xmm3, xmm1
  psrld xmm3, 31
  movdqu xmm4, xmm2
  psrld xmm4, 31
  pslld xmm1, 1
  pslld xmm2, 1
  vpslldq xmm5, xmm3, 4
  vpslldq xmm4, xmm4, 4
  mov r12, 0
  pinsrd xmm3, r12d, 0
  pshufd xmm3, xmm3, 3
  pxor xmm3, xmm4
  pxor xmm1, xmm5
  pxor xmm2, xmm3
  movdqu xmm5, xmm2
  pxor xmm2, xmm2
  mov r12, 3774873600
  pinsrd xmm2, r12d, 3
  pclmulqdq xmm1, xmm2, 17
  movdqu xmm2, xmm1
  psrld xmm2, 31
  pslld xmm1, 1
  vpslldq xmm2, xmm2, 4
  pxor xmm1, xmm2
  pxor xmm1, xmm5
  pxor xmm1, xmm6
  pshufb xmm1, xmm8
L19:
  jmp L11
L10:
L11:
  pxor xmm2, xmm2
  mov rax, r13
  imul rax, 8
  pinsrd xmm2, eax, 0
  mov rax, r11
  imul rax, 8
  pinsrd xmm2, eax, 2
  pshufb xmm2, xmm8
  pxor xmm1, xmm2
  movdqu xmm2, xmm11
  pshufb xmm1, xmm8
  movdqu xmm5, xmm1
  pclmulqdq xmm1, xmm2, 16
  movdqu xmm3, xmm1
  movdqu xmm1, xmm5
  pclmulqdq xmm1, xmm2, 1
  movdqu xmm4, xmm1
  movdqu xmm1, xmm5
  pclmulqdq xmm1, xmm2, 0
  pclmulqdq xmm5, xmm2, 17
  movdqu xmm2, xmm5
  movdqu xmm5, xmm1
  movdqu xmm1, xmm3
  mov r12, 0
  pinsrd xmm1, r12d, 0
  pshufd xmm1, xmm1, 14
  pxor xmm2, xmm1
  movdqu xmm1, xmm4
  mov r12, 0
  pinsrd xmm1, r12d, 0
  pshufd xmm1, xmm1, 14
  pxor xmm2, xmm1
  movdqu xmm1, xmm3
  mov r12, 0
  pinsrd xmm1, r12d, 3
  pshufd xmm1, xmm1, 79
  mov r12, 0
  pinsrd xmm4, r12d, 3
  pshufd xmm4, xmm4, 79
  pxor xmm1, xmm4
  pxor xmm1, xmm5
  movdqu xmm3, xmm1
  psrld xmm3, 31
  movdqu xmm4, xmm2
  psrld xmm4, 31
  pslld xmm1, 1
  pslld xmm2, 1
  vpslldq xmm5, xmm3, 4
  vpslldq xmm4, xmm4, 4
  mov r12, 0
  pinsrd xmm3, r12d, 0
  pshufd xmm3, xmm3, 3
  pxor xmm3, xmm4
  pxor xmm1, xmm5
  pxor xmm2, xmm3
  movdqu xmm6, xmm2
  pxor xmm2, xmm2
  mov r12, 3774873600
  pinsrd xmm2, r12d, 3
  movdqu xmm5, xmm1
  pclmulqdq xmm1, xmm2, 16
  movdqu xmm3, xmm1
  movdqu xmm1, xmm5
  pclmulqdq xmm1, xmm2, 1
  movdqu xmm4, xmm1
  movdqu xmm1, xmm5
  pclmulqdq xmm1, xmm2, 0
  pclmulqdq xmm5, xmm2, 17
  movdqu xmm2, xmm5
  movdqu xmm5, xmm1
  movdqu xmm1, xmm3
  mov r12, 0
  pinsrd xmm1, r12d, 0
  pshufd xmm1, xmm1, 14
  pxor xmm2, xmm1
  movdqu xmm1, xmm4
  mov r12, 0
  pinsrd xmm1, r12d, 0
  pshufd xmm1, xmm1, 14
  pxor xmm2, xmm1
  movdqu xmm1, xmm3
  mov r12, 0
  pinsrd xmm1, r12d, 3
  pshufd xmm1, xmm1, 79
  mov r12, 0
  pinsrd xmm4, r12d, 3
  pshufd xmm4, xmm4, 79
  pxor xmm1, xmm4
  pxor xmm1, xmm5
  movdqu xmm3, xmm1
  psrld xmm3, 31
  movdqu xmm4, xmm2
  psrld xmm4, 31
  pslld xmm1, 1
  pslld xmm2, 1
  vpslldq xmm5, xmm3, 4
  vpslldq xmm4, xmm4, 4
  mov r12, 0
  pinsrd xmm3, r12d, 0
  pshufd xmm3, xmm3, 3
  pxor xmm3, xmm4
  pxor xmm1, xmm5
  pxor xmm2, xmm3
  movdqu xmm5, xmm2
  pxor xmm2, xmm2
  mov r12, 3774873600
  pinsrd xmm2, r12d, 3
  pclmulqdq xmm1, xmm2, 17
  movdqu xmm2, xmm1
  psrld xmm2, 31
  pslld xmm1, 1
  vpslldq xmm2, xmm2, 4
  pxor xmm1, xmm2
  pxor xmm1, xmm5
  pxor xmm1, xmm6
  pshufb xmm1, xmm8
  mov r12, 1
  pinsrd xmm7, r12d, 0
  movdqu xmm0, xmm7
  mov r12, 579005069656919567
  pinsrq xmm2, r12, 0
  mov r12, 283686952306183
  pinsrq xmm2, r12, 1
  pshufb xmm0, xmm2
  movdqu xmm2, xmmword ptr [r8 + 0]
  pxor xmm0, xmm2
  movdqu xmm2, xmmword ptr [r8 + 16]
  aesenc xmm0, xmm2
  movdqu xmm2, xmmword ptr [r8 + 32]
  aesenc xmm0, xmm2
  movdqu xmm2, xmmword ptr [r8 + 48]
  aesenc xmm0, xmm2
  movdqu xmm2, xmmword ptr [r8 + 64]
  aesenc xmm0, xmm2
  movdqu xmm2, xmmword ptr [r8 + 80]
  aesenc xmm0, xmm2
  movdqu xmm2, xmmword ptr [r8 + 96]
  aesenc xmm0, xmm2
  movdqu xmm2, xmmword ptr [r8 + 112]
  aesenc xmm0, xmm2
  movdqu xmm2, xmmword ptr [r8 + 128]
  aesenc xmm0, xmm2
  movdqu xmm2, xmmword ptr [r8 + 144]
  aesenc xmm0, xmm2
  movdqu xmm2, xmmword ptr [r8 + 160]
  aesenclast xmm0, xmm2
  pxor xmm2, xmm2
  pxor xmm1, xmm0
  movdqu xmmword ptr [r15 + 0], xmm1
  pop rbx
  pop rbp
  pop rdi
  pop rsi
  pop r12
  pop r13
  pop r14
  pop r15
  pop rax
  pinsrq xmm6, rax, 1
  pop rax
  pinsrq xmm6, rax, 0
  pop rax
  pinsrq xmm7, rax, 1
  pop rax
  pinsrq xmm7, rax, 0
  pop rax
  pinsrq xmm8, rax, 1
  pop rax
  pinsrq xmm8, rax, 0
  pop rax
  pinsrq xmm9, rax, 1
  pop rax
  pinsrq xmm9, rax, 0
  pop rax
  pinsrq xmm10, rax, 1
  pop rax
  pinsrq xmm10, rax, 0
  pop rax
  pinsrq xmm11, rax, 1
  pop rax
  pinsrq xmm11, rax, 0
  pop rax
  pinsrq xmm12, rax, 1
  pop rax
  pinsrq xmm12, rax, 0
  pop rax
  pinsrq xmm13, rax, 1
  pop rax
  pinsrq xmm13, rax, 0
  pop rax
  pinsrq xmm14, rax, 1
  pop rax
  pinsrq xmm14, rax, 0
  pop rax
  pinsrq xmm15, rax, 1
  pop rax
  pinsrq xmm15, rax, 0
  ret
gcm128_encrypt endp
ALIGN 16
gcm128_decrypt proc
  mov r9, rcx
  pextrq rax, xmm15, 0
  push rax
  pextrq rax, xmm15, 1
  push rax
  pextrq rax, xmm14, 0
  push rax
  pextrq rax, xmm14, 1
  push rax
  pextrq rax, xmm13, 0
  push rax
  pextrq rax, xmm13, 1
  push rax
  pextrq rax, xmm12, 0
  push rax
  pextrq rax, xmm12, 1
  push rax
  pextrq rax, xmm11, 0
  push rax
  pextrq rax, xmm11, 1
  push rax
  pextrq rax, xmm10, 0
  push rax
  pextrq rax, xmm10, 1
  push rax
  pextrq rax, xmm9, 0
  push rax
  pextrq rax, xmm9, 1
  push rax
  pextrq rax, xmm8, 0
  push rax
  pextrq rax, xmm8, 1
  push rax
  pextrq rax, xmm7, 0
  push rax
  pextrq rax, xmm7, 1
  push rax
  pextrq rax, xmm6, 0
  push rax
  pextrq rax, xmm6, 1
  push rax
  push r15
  push r14
  push r13
  push r12
  push rsi
  push rdi
  push rbp
  push rbx
  mov r14, qword ptr [r9 + 0]
  mov r13, qword ptr [r9 + 8]
  mov rax, qword ptr [r9 + 16]
  mov r11, qword ptr [r9 + 24]
  mov r10, qword ptr [r9 + 32]
  mov r8, qword ptr [r9 + 40]
  mov rbx, qword ptr [r9 + 48]
  mov r15, qword ptr [r9 + 56]
  movdqu xmm7, xmmword ptr [r10 + 0]
  mov r12, 579005069656919567
  pinsrq xmm8, r12, 0
  mov r12, 283686952306183
  pinsrq xmm8, r12, 1
  pxor xmm0, xmm0
  movdqu xmm2, xmmword ptr [r8 + 0]
  pxor xmm0, xmm2
  movdqu xmm2, xmmword ptr [r8 + 16]
  aesenc xmm0, xmm2
  movdqu xmm2, xmmword ptr [r8 + 32]
  aesenc xmm0, xmm2
  movdqu xmm2, xmmword ptr [r8 + 48]
  aesenc xmm0, xmm2
  movdqu xmm2, xmmword ptr [r8 + 64]
  aesenc xmm0, xmm2
  movdqu xmm2, xmmword ptr [r8 + 80]
  aesenc xmm0, xmm2
  movdqu xmm2, xmmword ptr [r8 + 96]
  aesenc xmm0, xmm2
  movdqu xmm2, xmmword ptr [r8 + 112]
  aesenc xmm0, xmm2
  movdqu xmm2, xmmword ptr [r8 + 128]
  aesenc xmm0, xmm2
  movdqu xmm2, xmmword ptr [r8 + 144]
  aesenc xmm0, xmm2
  movdqu xmm2, xmmword ptr [r8 + 160]
  aesenclast xmm0, xmm2
  pxor xmm2, xmm2
  pshufb xmm0, xmm8
  movdqu xmm11, xmm0
  pshufb xmm7, xmm8
  mov r12, 2
  pinsrd xmm7, r12d, 0
  pxor xmm1, xmm1
  cmp r11, 0
  jbe L22
  mov rcx, r11
  shr rcx, 4
  mov r9, rax
  cmp rcx, 0
  je L24
  mov rdx, 0
  jmp L27
ALIGN 16
L26:
  movdqu xmm2, xmmword ptr [r9 + 0]
  pxor xmm1, xmm2
  movdqu xmm2, xmm11
  pshufb xmm1, xmm8
  movdqu xmm5, xmm1
  pclmulqdq xmm1, xmm2, 16
  movdqu xmm3, xmm1
  movdqu xmm1, xmm5
  pclmulqdq xmm1, xmm2, 1
  movdqu xmm4, xmm1
  movdqu xmm1, xmm5
  pclmulqdq xmm1, xmm2, 0
  pclmulqdq xmm5, xmm2, 17
  movdqu xmm2, xmm5
  movdqu xmm5, xmm1
  movdqu xmm1, xmm3
  mov r12, 0
  pinsrd xmm1, r12d, 0
  pshufd xmm1, xmm1, 14
  pxor xmm2, xmm1
  movdqu xmm1, xmm4
  mov r12, 0
  pinsrd xmm1, r12d, 0
  pshufd xmm1, xmm1, 14
  pxor xmm2, xmm1
  movdqu xmm1, xmm3
  mov r12, 0
  pinsrd xmm1, r12d, 3
  pshufd xmm1, xmm1, 79
  mov r12, 0
  pinsrd xmm4, r12d, 3
  pshufd xmm4, xmm4, 79
  pxor xmm1, xmm4
  pxor xmm1, xmm5
  movdqu xmm3, xmm1
  psrld xmm3, 31
  movdqu xmm4, xmm2
  psrld xmm4, 31
  pslld xmm1, 1
  pslld xmm2, 1
  vpslldq xmm5, xmm3, 4
  vpslldq xmm4, xmm4, 4
  mov r12, 0
  pinsrd xmm3, r12d, 0
  pshufd xmm3, xmm3, 3
  pxor xmm3, xmm4
  pxor xmm1, xmm5
  pxor xmm2, xmm3
  movdqu xmm6, xmm2
  pxor xmm2, xmm2
  mov r12, 3774873600
  pinsrd xmm2, r12d, 3
  movdqu xmm5, xmm1
  pclmulqdq xmm1, xmm2, 16
  movdqu xmm3, xmm1
  movdqu xmm1, xmm5
  pclmulqdq xmm1, xmm2, 1
  movdqu xmm4, xmm1
  movdqu xmm1, xmm5
  pclmulqdq xmm1, xmm2, 0
  pclmulqdq xmm5, xmm2, 17
  movdqu xmm2, xmm5
  movdqu xmm5, xmm1
  movdqu xmm1, xmm3
  mov r12, 0
  pinsrd xmm1, r12d, 0
  pshufd xmm1, xmm1, 14
  pxor xmm2, xmm1
  movdqu xmm1, xmm4
  mov r12, 0
  pinsrd xmm1, r12d, 0
  pshufd xmm1, xmm1, 14
  pxor xmm2, xmm1
  movdqu xmm1, xmm3
  mov r12, 0
  pinsrd xmm1, r12d, 3
  pshufd xmm1, xmm1, 79
  mov r12, 0
  pinsrd xmm4, r12d, 3
  pshufd xmm4, xmm4, 79
  pxor xmm1, xmm4
  pxor xmm1, xmm5
  movdqu xmm3, xmm1
  psrld xmm3, 31
  movdqu xmm4, xmm2
  psrld xmm4, 31
  pslld xmm1, 1
  pslld xmm2, 1
  vpslldq xmm5, xmm3, 4
  vpslldq xmm4, xmm4, 4
  mov r12, 0
  pinsrd xmm3, r12d, 0
  pshufd xmm3, xmm3, 3
  pxor xmm3, xmm4
  pxor xmm1, xmm5
  pxor xmm2, xmm3
  movdqu xmm5, xmm2
  pxor xmm2, xmm2
  mov r12, 3774873600
  pinsrd xmm2, r12d, 3
  pclmulqdq xmm1, xmm2, 17
  movdqu xmm2, xmm1
  psrld xmm2, 31
  pslld xmm1, 1
  vpslldq xmm2, xmm2, 4
  pxor xmm1, xmm2
  pxor xmm1, xmm5
  pxor xmm1, xmm6
  pshufb xmm1, xmm8
  add rdx, 1
  add r9, 16
ALIGN 16
L27:
  cmp rdx, rcx
  jne L26
  jmp L25
L24:
L25:
  mov rax, r11
  and rax, 15
  cmp rax, 0
  jne L28
  jmp L29
L28:
  movdqu xmm2, xmmword ptr [r9 + 0]
  cmp rax, 8
  jae L30
  mov rcx, 0
  pinsrq xmm2, rcx, 1
  mov rcx, rax
  shl rcx, 3
  mov rdx, 1
  shl rdx, cl
  sub rdx, 1
  pextrq rcx, xmm2, 0
  and rcx, rdx
  pinsrq xmm2, rcx, 0
  jmp L31
L30:
  mov rcx, rax
  sub rcx, 8
  shl rcx, 3
  mov rdx, 1
  shl rdx, cl
  sub rdx, 1
  pextrq rcx, xmm2, 1
  and rcx, rdx
  pinsrq xmm2, rcx, 1
L31:
  pxor xmm1, xmm2
  movdqu xmm2, xmm11
  pshufb xmm1, xmm8
  movdqu xmm5, xmm1
  pclmulqdq xmm1, xmm2, 16
  movdqu xmm3, xmm1
  movdqu xmm1, xmm5
  pclmulqdq xmm1, xmm2, 1
  movdqu xmm4, xmm1
  movdqu xmm1, xmm5
  pclmulqdq xmm1, xmm2, 0
  pclmulqdq xmm5, xmm2, 17
  movdqu xmm2, xmm5
  movdqu xmm5, xmm1
  movdqu xmm1, xmm3
  mov r12, 0
  pinsrd xmm1, r12d, 0
  pshufd xmm1, xmm1, 14
  pxor xmm2, xmm1
  movdqu xmm1, xmm4
  mov r12, 0
  pinsrd xmm1, r12d, 0
  pshufd xmm1, xmm1, 14
  pxor xmm2, xmm1
  movdqu xmm1, xmm3
  mov r12, 0
  pinsrd xmm1, r12d, 3
  pshufd xmm1, xmm1, 79
  mov r12, 0
  pinsrd xmm4, r12d, 3
  pshufd xmm4, xmm4, 79
  pxor xmm1, xmm4
  pxor xmm1, xmm5
  movdqu xmm3, xmm1
  psrld xmm3, 31
  movdqu xmm4, xmm2
  psrld xmm4, 31
  pslld xmm1, 1
  pslld xmm2, 1
  vpslldq xmm5, xmm3, 4
  vpslldq xmm4, xmm4, 4
  mov r12, 0
  pinsrd xmm3, r12d, 0
  pshufd xmm3, xmm3, 3
  pxor xmm3, xmm4
  pxor xmm1, xmm5
  pxor xmm2, xmm3
  movdqu xmm6, xmm2
  pxor xmm2, xmm2
  mov r12, 3774873600
  pinsrd xmm2, r12d, 3
  movdqu xmm5, xmm1
  pclmulqdq xmm1, xmm2, 16
  movdqu xmm3, xmm1
  movdqu xmm1, xmm5
  pclmulqdq xmm1, xmm2, 1
  movdqu xmm4, xmm1
  movdqu xmm1, xmm5
  pclmulqdq xmm1, xmm2, 0
  pclmulqdq xmm5, xmm2, 17
  movdqu xmm2, xmm5
  movdqu xmm5, xmm1
  movdqu xmm1, xmm3
  mov r12, 0
  pinsrd xmm1, r12d, 0
  pshufd xmm1, xmm1, 14
  pxor xmm2, xmm1
  movdqu xmm1, xmm4
  mov r12, 0
  pinsrd xmm1, r12d, 0
  pshufd xmm1, xmm1, 14
  pxor xmm2, xmm1
  movdqu xmm1, xmm3
  mov r12, 0
  pinsrd xmm1, r12d, 3
  pshufd xmm1, xmm1, 79
  mov r12, 0
  pinsrd xmm4, r12d, 3
  pshufd xmm4, xmm4, 79
  pxor xmm1, xmm4
  pxor xmm1, xmm5
  movdqu xmm3, xmm1
  psrld xmm3, 31
  movdqu xmm4, xmm2
  psrld xmm4, 31
  pslld xmm1, 1
  pslld xmm2, 1
  vpslldq xmm5, xmm3, 4
  vpslldq xmm4, xmm4, 4
  mov r12, 0
  pinsrd xmm3, r12d, 0
  pshufd xmm3, xmm3, 3
  pxor xmm3, xmm4
  pxor xmm1, xmm5
  pxor xmm2, xmm3
  movdqu xmm5, xmm2
  pxor xmm2, xmm2
  mov r12, 3774873600
  pinsrd xmm2, r12d, 3
  pclmulqdq xmm1, xmm2, 17
  movdqu xmm2, xmm1
  psrld xmm2, 31
  pslld xmm1, 1
  vpslldq xmm2, xmm2, 4
  pxor xmm1, xmm2
  pxor xmm1, xmm5
  pxor xmm1, xmm6
  pshufb xmm1, xmm8
L29:
  jmp L23
L22:
L23:
  mov rax, r14
  mov rcx, r13
  cmp rcx, 0
  jbe L32
  mov rsi, rcx
  and rsi, 15
  shr rcx, 4
  mov rdx, 0
  mov r9, rax
  mov r10, rbx
  pxor xmm10, xmm10
  mov r12, 1
  pinsrd xmm10, r12d, 0
  jmp L35
ALIGN 16
L34:
  movdqu xmm0, xmmword ptr [r9 + 0]
  movdqu xmm2, xmm0
  pxor xmm1, xmm2
  movdqu xmm2, xmm11
  pshufb xmm1, xmm8
  movdqu xmm5, xmm1
  pclmulqdq xmm1, xmm2, 16
  movdqu xmm3, xmm1
  movdqu xmm1, xmm5
  pclmulqdq xmm1, xmm2, 1
  movdqu xmm4, xmm1
  movdqu xmm1, xmm5
  pclmulqdq xmm1, xmm2, 0
  pclmulqdq xmm5, xmm2, 17
  movdqu xmm2, xmm5
  movdqu xmm5, xmm1
  movdqu xmm1, xmm3
  mov r12, 0
  pinsrd xmm1, r12d, 0
  pshufd xmm1, xmm1, 14
  pxor xmm2, xmm1
  movdqu xmm1, xmm4
  mov r12, 0
  pinsrd xmm1, r12d, 0
  pshufd xmm1, xmm1, 14
  pxor xmm2, xmm1
  movdqu xmm1, xmm3
  mov r12, 0
  pinsrd xmm1, r12d, 3
  pshufd xmm1, xmm1, 79
  mov r12, 0
  pinsrd xmm4, r12d, 3
  pshufd xmm4, xmm4, 79
  pxor xmm1, xmm4
  pxor xmm1, xmm5
  movdqu xmm3, xmm1
  psrld xmm3, 31
  movdqu xmm4, xmm2
  psrld xmm4, 31
  pslld xmm1, 1
  pslld xmm2, 1
  vpslldq xmm5, xmm3, 4
  vpslldq xmm4, xmm4, 4
  mov r12, 0
  pinsrd xmm3, r12d, 0
  pshufd xmm3, xmm3, 3
  pxor xmm3, xmm4
  pxor xmm1, xmm5
  pxor xmm2, xmm3
  movdqu xmm6, xmm2
  pxor xmm2, xmm2
  mov r12, 3774873600
  pinsrd xmm2, r12d, 3
  movdqu xmm5, xmm1
  pclmulqdq xmm1, xmm2, 16
  movdqu xmm3, xmm1
  movdqu xmm1, xmm5
  pclmulqdq xmm1, xmm2, 1
  movdqu xmm4, xmm1
  movdqu xmm1, xmm5
  pclmulqdq xmm1, xmm2, 0
  pclmulqdq xmm5, xmm2, 17
  movdqu xmm2, xmm5
  movdqu xmm5, xmm1
  movdqu xmm1, xmm3
  mov r12, 0
  pinsrd xmm1, r12d, 0
  pshufd xmm1, xmm1, 14
  pxor xmm2, xmm1
  movdqu xmm1, xmm4
  mov r12, 0
  pinsrd xmm1, r12d, 0
  pshufd xmm1, xmm1, 14
  pxor xmm2, xmm1
  movdqu xmm1, xmm3
  mov r12, 0
  pinsrd xmm1, r12d, 3
  pshufd xmm1, xmm1, 79
  mov r12, 0
  pinsrd xmm4, r12d, 3
  pshufd xmm4, xmm4, 79
  pxor xmm1, xmm4
  pxor xmm1, xmm5
  movdqu xmm3, xmm1
  psrld xmm3, 31
  movdqu xmm4, xmm2
  psrld xmm4, 31
  pslld xmm1, 1
  pslld xmm2, 1
  vpslldq xmm5, xmm3, 4
  vpslldq xmm4, xmm4, 4
  mov r12, 0
  pinsrd xmm3, r12d, 0
  pshufd xmm3, xmm3, 3
  pxor xmm3, xmm4
  pxor xmm1, xmm5
  pxor xmm2, xmm3
  movdqu xmm5, xmm2
  pxor xmm2, xmm2
  mov r12, 3774873600
  pinsrd xmm2, r12d, 3
  pclmulqdq xmm1, xmm2, 17
  movdqu xmm2, xmm1
  psrld xmm2, 31
  pslld xmm1, 1
  vpslldq xmm2, xmm2, 4
  pxor xmm1, xmm2
  pxor xmm1, xmm5
  pxor xmm1, xmm6
  pshufb xmm1, xmm8
  movdqu xmm3, xmm0
  movdqu xmm0, xmm7
  pshufb xmm0, xmm8
  movdqu xmm2, xmmword ptr [r8 + 0]
  pxor xmm0, xmm2
  movdqu xmm2, xmmword ptr [r8 + 16]
  aesenc xmm0, xmm2
  movdqu xmm2, xmmword ptr [r8 + 32]
  aesenc xmm0, xmm2
  movdqu xmm2, xmmword ptr [r8 + 48]
  aesenc xmm0, xmm2
  movdqu xmm2, xmmword ptr [r8 + 64]
  aesenc xmm0, xmm2
  movdqu xmm2, xmmword ptr [r8 + 80]
  aesenc xmm0, xmm2
  movdqu xmm2, xmmword ptr [r8 + 96]
  aesenc xmm0, xmm2
  movdqu xmm2, xmmword ptr [r8 + 112]
  aesenc xmm0, xmm2
  movdqu xmm2, xmmword ptr [r8 + 128]
  aesenc xmm0, xmm2
  movdqu xmm2, xmmword ptr [r8 + 144]
  aesenc xmm0, xmm2
  movdqu xmm2, xmmword ptr [r8 + 160]
  aesenclast xmm0, xmm2
  pxor xmm2, xmm2
  pxor xmm3, xmm0
  movdqu xmmword ptr [r10 + 0], xmm3
  add rdx, 1
  add r9, 16
  add r10, 16
  paddd xmm7, xmm10
ALIGN 16
L35:
  cmp rdx, rcx
  jne L34
  cmp rsi, 0
  jne L36
  jmp L37
L36:
  movdqu xmm3, xmm1
  movdqu xmm2, xmmword ptr [r9 + 0]
  movdqu xmm1, xmm2
  movdqu xmm0, xmm7
  mov r12, 579005069656919567
  pinsrq xmm2, r12, 0
  mov r12, 283686952306183
  pinsrq xmm2, r12, 1
  pshufb xmm0, xmm2
  movdqu xmm2, xmmword ptr [r8 + 0]
  pxor xmm0, xmm2
  movdqu xmm2, xmmword ptr [r8 + 16]
  aesenc xmm0, xmm2
  movdqu xmm2, xmmword ptr [r8 + 32]
  aesenc xmm0, xmm2
  movdqu xmm2, xmmword ptr [r8 + 48]
  aesenc xmm0, xmm2
  movdqu xmm2, xmmword ptr [r8 + 64]
  aesenc xmm0, xmm2
  movdqu xmm2, xmmword ptr [r8 + 80]
  aesenc xmm0, xmm2
  movdqu xmm2, xmmword ptr [r8 + 96]
  aesenc xmm0, xmm2
  movdqu xmm2, xmmword ptr [r8 + 112]
  aesenc xmm0, xmm2
  movdqu xmm2, xmmword ptr [r8 + 128]
  aesenc xmm0, xmm2
  movdqu xmm2, xmmword ptr [r8 + 144]
  aesenc xmm0, xmm2
  movdqu xmm2, xmmword ptr [r8 + 160]
  aesenclast xmm0, xmm2
  pxor xmm2, xmm2
  pxor xmm1, xmm0
  movdqu xmmword ptr [r10 + 0], xmm1
  mov rax, rsi
  movdqu xmm1, xmm3
  movdqu xmm2, xmmword ptr [r9 + 0]
  cmp rax, 8
  jae L38
  mov rcx, 0
  pinsrq xmm2, rcx, 1
  mov rcx, rax
  shl rcx, 3
  mov rdx, 1
  shl rdx, cl
  sub rdx, 1
  pextrq rcx, xmm2, 0
  and rcx, rdx
  pinsrq xmm2, rcx, 0
  jmp L39
L38:
  mov rcx, rax
  sub rcx, 8
  shl rcx, 3
  mov rdx, 1
  shl rdx, cl
  sub rdx, 1
  pextrq rcx, xmm2, 1
  and rcx, rdx
  pinsrq xmm2, rcx, 1
L39:
  pxor xmm1, xmm2
  movdqu xmm2, xmm11
  pshufb xmm1, xmm8
  movdqu xmm5, xmm1
  pclmulqdq xmm1, xmm2, 16
  movdqu xmm3, xmm1
  movdqu xmm1, xmm5
  pclmulqdq xmm1, xmm2, 1
  movdqu xmm4, xmm1
  movdqu xmm1, xmm5
  pclmulqdq xmm1, xmm2, 0
  pclmulqdq xmm5, xmm2, 17
  movdqu xmm2, xmm5
  movdqu xmm5, xmm1
  movdqu xmm1, xmm3
  mov r12, 0
  pinsrd xmm1, r12d, 0
  pshufd xmm1, xmm1, 14
  pxor xmm2, xmm1
  movdqu xmm1, xmm4
  mov r12, 0
  pinsrd xmm1, r12d, 0
  pshufd xmm1, xmm1, 14
  pxor xmm2, xmm1
  movdqu xmm1, xmm3
  mov r12, 0
  pinsrd xmm1, r12d, 3
  pshufd xmm1, xmm1, 79
  mov r12, 0
  pinsrd xmm4, r12d, 3
  pshufd xmm4, xmm4, 79
  pxor xmm1, xmm4
  pxor xmm1, xmm5
  movdqu xmm3, xmm1
  psrld xmm3, 31
  movdqu xmm4, xmm2
  psrld xmm4, 31
  pslld xmm1, 1
  pslld xmm2, 1
  vpslldq xmm5, xmm3, 4
  vpslldq xmm4, xmm4, 4
  mov r12, 0
  pinsrd xmm3, r12d, 0
  pshufd xmm3, xmm3, 3
  pxor xmm3, xmm4
  pxor xmm1, xmm5
  pxor xmm2, xmm3
  movdqu xmm6, xmm2
  pxor xmm2, xmm2
  mov r12, 3774873600
  pinsrd xmm2, r12d, 3
  movdqu xmm5, xmm1
  pclmulqdq xmm1, xmm2, 16
  movdqu xmm3, xmm1
  movdqu xmm1, xmm5
  pclmulqdq xmm1, xmm2, 1
  movdqu xmm4, xmm1
  movdqu xmm1, xmm5
  pclmulqdq xmm1, xmm2, 0
  pclmulqdq xmm5, xmm2, 17
  movdqu xmm2, xmm5
  movdqu xmm5, xmm1
  movdqu xmm1, xmm3
  mov r12, 0
  pinsrd xmm1, r12d, 0
  pshufd xmm1, xmm1, 14
  pxor xmm2, xmm1
  movdqu xmm1, xmm4
  mov r12, 0
  pinsrd xmm1, r12d, 0
  pshufd xmm1, xmm1, 14
  pxor xmm2, xmm1
  movdqu xmm1, xmm3
  mov r12, 0
  pinsrd xmm1, r12d, 3
  pshufd xmm1, xmm1, 79
  mov r12, 0
  pinsrd xmm4, r12d, 3
  pshufd xmm4, xmm4, 79
  pxor xmm1, xmm4
  pxor xmm1, xmm5
  movdqu xmm3, xmm1
  psrld xmm3, 31
  movdqu xmm4, xmm2
  psrld xmm4, 31
  pslld xmm1, 1
  pslld xmm2, 1
  vpslldq xmm5, xmm3, 4
  vpslldq xmm4, xmm4, 4
  mov r12, 0
  pinsrd xmm3, r12d, 0
  pshufd xmm3, xmm3, 3
  pxor xmm3, xmm4
  pxor xmm1, xmm5
  pxor xmm2, xmm3
  movdqu xmm5, xmm2
  pxor xmm2, xmm2
  mov r12, 3774873600
  pinsrd xmm2, r12d, 3
  pclmulqdq xmm1, xmm2, 17
  movdqu xmm2, xmm1
  psrld xmm2, 31
  pslld xmm1, 1
  vpslldq xmm2, xmm2, 4
  pxor xmm1, xmm2
  pxor xmm1, xmm5
  pxor xmm1, xmm6
  pshufb xmm1, xmm8
L37:
  jmp L33
L32:
L33:
  pxor xmm2, xmm2
  mov rax, r13
  imul rax, 8
  pinsrd xmm2, eax, 0
  mov rax, r11
  imul rax, 8
  pinsrd xmm2, eax, 2
  pshufb xmm2, xmm8
  pxor xmm1, xmm2
  movdqu xmm2, xmm11
  pshufb xmm1, xmm8
  movdqu xmm5, xmm1
  pclmulqdq xmm1, xmm2, 16
  movdqu xmm3, xmm1
  movdqu xmm1, xmm5
  pclmulqdq xmm1, xmm2, 1
  movdqu xmm4, xmm1
  movdqu xmm1, xmm5
  pclmulqdq xmm1, xmm2, 0
  pclmulqdq xmm5, xmm2, 17
  movdqu xmm2, xmm5
  movdqu xmm5, xmm1
  movdqu xmm1, xmm3
  mov r12, 0
  pinsrd xmm1, r12d, 0
  pshufd xmm1, xmm1, 14
  pxor xmm2, xmm1
  movdqu xmm1, xmm4
  mov r12, 0
  pinsrd xmm1, r12d, 0
  pshufd xmm1, xmm1, 14
  pxor xmm2, xmm1
  movdqu xmm1, xmm3
  mov r12, 0
  pinsrd xmm1, r12d, 3
  pshufd xmm1, xmm1, 79
  mov r12, 0
  pinsrd xmm4, r12d, 3
  pshufd xmm4, xmm4, 79
  pxor xmm1, xmm4
  pxor xmm1, xmm5
  movdqu xmm3, xmm1
  psrld xmm3, 31
  movdqu xmm4, xmm2
  psrld xmm4, 31
  pslld xmm1, 1
  pslld xmm2, 1
  vpslldq xmm5, xmm3, 4
  vpslldq xmm4, xmm4, 4
  mov r12, 0
  pinsrd xmm3, r12d, 0
  pshufd xmm3, xmm3, 3
  pxor xmm3, xmm4
  pxor xmm1, xmm5
  pxor xmm2, xmm3
  movdqu xmm6, xmm2
  pxor xmm2, xmm2
  mov r12, 3774873600
  pinsrd xmm2, r12d, 3
  movdqu xmm5, xmm1
  pclmulqdq xmm1, xmm2, 16
  movdqu xmm3, xmm1
  movdqu xmm1, xmm5
  pclmulqdq xmm1, xmm2, 1
  movdqu xmm4, xmm1
  movdqu xmm1, xmm5
  pclmulqdq xmm1, xmm2, 0
  pclmulqdq xmm5, xmm2, 17
  movdqu xmm2, xmm5
  movdqu xmm5, xmm1
  movdqu xmm1, xmm3
  mov r12, 0
  pinsrd xmm1, r12d, 0
  pshufd xmm1, xmm1, 14
  pxor xmm2, xmm1
  movdqu xmm1, xmm4
  mov r12, 0
  pinsrd xmm1, r12d, 0
  pshufd xmm1, xmm1, 14
  pxor xmm2, xmm1
  movdqu xmm1, xmm3
  mov r12, 0
  pinsrd xmm1, r12d, 3
  pshufd xmm1, xmm1, 79
  mov r12, 0
  pinsrd xmm4, r12d, 3
  pshufd xmm4, xmm4, 79
  pxor xmm1, xmm4
  pxor xmm1, xmm5
  movdqu xmm3, xmm1
  psrld xmm3, 31
  movdqu xmm4, xmm2
  psrld xmm4, 31
  pslld xmm1, 1
  pslld xmm2, 1
  vpslldq xmm5, xmm3, 4
  vpslldq xmm4, xmm4, 4
  mov r12, 0
  pinsrd xmm3, r12d, 0
  pshufd xmm3, xmm3, 3
  pxor xmm3, xmm4
  pxor xmm1, xmm5
  pxor xmm2, xmm3
  movdqu xmm5, xmm2
  pxor xmm2, xmm2
  mov r12, 3774873600
  pinsrd xmm2, r12d, 3
  pclmulqdq xmm1, xmm2, 17
  movdqu xmm2, xmm1
  psrld xmm2, 31
  pslld xmm1, 1
  vpslldq xmm2, xmm2, 4
  pxor xmm1, xmm2
  pxor xmm1, xmm5
  pxor xmm1, xmm6
  pshufb xmm1, xmm8
  mov r12, 1
  pinsrd xmm7, r12d, 0
  movdqu xmm0, xmm7
  mov r12, 579005069656919567
  pinsrq xmm2, r12, 0
  mov r12, 283686952306183
  pinsrq xmm2, r12, 1
  pshufb xmm0, xmm2
  movdqu xmm2, xmmword ptr [r8 + 0]
  pxor xmm0, xmm2
  movdqu xmm2, xmmword ptr [r8 + 16]
  aesenc xmm0, xmm2
  movdqu xmm2, xmmword ptr [r8 + 32]
  aesenc xmm0, xmm2
  movdqu xmm2, xmmword ptr [r8 + 48]
  aesenc xmm0, xmm2
  movdqu xmm2, xmmword ptr [r8 + 64]
  aesenc xmm0, xmm2
  movdqu xmm2, xmmword ptr [r8 + 80]
  aesenc xmm0, xmm2
  movdqu xmm2, xmmword ptr [r8 + 96]
  aesenc xmm0, xmm2
  movdqu xmm2, xmmword ptr [r8 + 112]
  aesenc xmm0, xmm2
  movdqu xmm2, xmmword ptr [r8 + 128]
  aesenc xmm0, xmm2
  movdqu xmm2, xmmword ptr [r8 + 144]
  aesenc xmm0, xmm2
  movdqu xmm2, xmmword ptr [r8 + 160]
  aesenclast xmm0, xmm2
  pxor xmm2, xmm2
  pxor xmm1, xmm0
  movdqu xmm0, xmmword ptr [r15 + 0]
  pcmpeqd xmm0, xmm1
  pextrq rdx, xmm0, 0
  cmp rdx, 18446744073709551615
  jne L40
  mov rax, 0
  jmp L41
L40:
  mov rax, 1
L41:
  pextrq rdx, xmm0, 1
  cmp rdx, 18446744073709551615
  jne L42
  mov rdx, 0
  jmp L43
L42:
  mov rdx, 1
L43:
  add rax, rdx
  mov rdx, rax
  pop rbx
  pop rbp
  pop rdi
  pop rsi
  pop r12
  pop r13
  pop r14
  pop r15
  pop rax
  pinsrq xmm6, rax, 1
  pop rax
  pinsrq xmm6, rax, 0
  pop rax
  pinsrq xmm7, rax, 1
  pop rax
  pinsrq xmm7, rax, 0
  pop rax
  pinsrq xmm8, rax, 1
  pop rax
  pinsrq xmm8, rax, 0
  pop rax
  pinsrq xmm9, rax, 1
  pop rax
  pinsrq xmm9, rax, 0
  pop rax
  pinsrq xmm10, rax, 1
  pop rax
  pinsrq xmm10, rax, 0
  pop rax
  pinsrq xmm11, rax, 1
  pop rax
  pinsrq xmm11, rax, 0
  pop rax
  pinsrq xmm12, rax, 1
  pop rax
  pinsrq xmm12, rax, 0
  pop rax
  pinsrq xmm13, rax, 1
  pop rax
  pinsrq xmm13, rax, 0
  pop rax
  pinsrq xmm14, rax, 1
  pop rax
  pinsrq xmm14, rax, 0
  pop rax
  pinsrq xmm15, rax, 1
  pop rax
  pinsrq xmm15, rax, 0
  mov rax, rdx
  ret
gcm128_decrypt endp
ALIGN 16
gcm256_encrypt proc
  mov r9, rcx
  pextrq rax, xmm15, 0
  push rax
  pextrq rax, xmm15, 1
  push rax
  pextrq rax, xmm14, 0
  push rax
  pextrq rax, xmm14, 1
  push rax
  pextrq rax, xmm13, 0
  push rax
  pextrq rax, xmm13, 1
  push rax
  pextrq rax, xmm12, 0
  push rax
  pextrq rax, xmm12, 1
  push rax
  pextrq rax, xmm11, 0
  push rax
  pextrq rax, xmm11, 1
  push rax
  pextrq rax, xmm10, 0
  push rax
  pextrq rax, xmm10, 1
  push rax
  pextrq rax, xmm9, 0
  push rax
  pextrq rax, xmm9, 1
  push rax
  pextrq rax, xmm8, 0
  push rax
  pextrq rax, xmm8, 1
  push rax
  pextrq rax, xmm7, 0
  push rax
  pextrq rax, xmm7, 1
  push rax
  pextrq rax, xmm6, 0
  push rax
  pextrq rax, xmm6, 1
  push rax
  push r15
  push r14
  push r13
  push r12
  push rsi
  push rdi
  push rbp
  push rbx
  mov r14, qword ptr [r9 + 0]
  mov r13, qword ptr [r9 + 8]
  mov rax, qword ptr [r9 + 16]
  mov r11, qword ptr [r9 + 24]
  mov r10, qword ptr [r9 + 32]
  mov r8, qword ptr [r9 + 40]
  mov rbx, qword ptr [r9 + 48]
  mov r15, qword ptr [r9 + 56]
  movdqu xmm7, xmmword ptr [r10 + 0]
  mov r12, 579005069656919567
  pinsrq xmm8, r12, 0
  mov r12, 283686952306183
  pinsrq xmm8, r12, 1
  pxor xmm0, xmm0
  movdqu xmm2, xmmword ptr [r8 + 0]
  pxor xmm0, xmm2
  movdqu xmm2, xmmword ptr [r8 + 16]
  aesenc xmm0, xmm2
  movdqu xmm2, xmmword ptr [r8 + 32]
  aesenc xmm0, xmm2
  movdqu xmm2, xmmword ptr [r8 + 48]
  aesenc xmm0, xmm2
  movdqu xmm2, xmmword ptr [r8 + 64]
  aesenc xmm0, xmm2
  movdqu xmm2, xmmword ptr [r8 + 80]
  aesenc xmm0, xmm2
  movdqu xmm2, xmmword ptr [r8 + 96]
  aesenc xmm0, xmm2
  movdqu xmm2, xmmword ptr [r8 + 112]
  aesenc xmm0, xmm2
  movdqu xmm2, xmmword ptr [r8 + 128]
  aesenc xmm0, xmm2
  movdqu xmm2, xmmword ptr [r8 + 144]
  aesenc xmm0, xmm2
  movdqu xmm2, xmmword ptr [r8 + 160]
  aesenc xmm0, xmm2
  movdqu xmm2, xmmword ptr [r8 + 176]
  aesenc xmm0, xmm2
  movdqu xmm2, xmmword ptr [r8 + 192]
  aesenc xmm0, xmm2
  movdqu xmm2, xmmword ptr [r8 + 208]
  aesenc xmm0, xmm2
  movdqu xmm2, xmmword ptr [r8 + 224]
  aesenclast xmm0, xmm2
  pxor xmm2, xmm2
  pshufb xmm0, xmm8
  movdqu xmm11, xmm0
  pshufb xmm7, xmm8
  mov r12, 2
  pinsrd xmm7, r12d, 0
  pxor xmm1, xmm1
  cmp r11, 0
  jbe L44
  mov rcx, r11
  shr rcx, 4
  mov r9, rax
  cmp rcx, 0
  je L46
  mov rdx, 0
  jmp L49
ALIGN 16
L48:
  movdqu xmm2, xmmword ptr [r9 + 0]
  pxor xmm1, xmm2
  movdqu xmm2, xmm11
  pshufb xmm1, xmm8
  movdqu xmm5, xmm1
  pclmulqdq xmm1, xmm2, 16
  movdqu xmm3, xmm1
  movdqu xmm1, xmm5
  pclmulqdq xmm1, xmm2, 1
  movdqu xmm4, xmm1
  movdqu xmm1, xmm5
  pclmulqdq xmm1, xmm2, 0
  pclmulqdq xmm5, xmm2, 17
  movdqu xmm2, xmm5
  movdqu xmm5, xmm1
  movdqu xmm1, xmm3
  mov r12, 0
  pinsrd xmm1, r12d, 0
  pshufd xmm1, xmm1, 14
  pxor xmm2, xmm1
  movdqu xmm1, xmm4
  mov r12, 0
  pinsrd xmm1, r12d, 0
  pshufd xmm1, xmm1, 14
  pxor xmm2, xmm1
  movdqu xmm1, xmm3
  mov r12, 0
  pinsrd xmm1, r12d, 3
  pshufd xmm1, xmm1, 79
  mov r12, 0
  pinsrd xmm4, r12d, 3
  pshufd xmm4, xmm4, 79
  pxor xmm1, xmm4
  pxor xmm1, xmm5
  movdqu xmm3, xmm1
  psrld xmm3, 31
  movdqu xmm4, xmm2
  psrld xmm4, 31
  pslld xmm1, 1
  pslld xmm2, 1
  vpslldq xmm5, xmm3, 4
  vpslldq xmm4, xmm4, 4
  mov r12, 0
  pinsrd xmm3, r12d, 0
  pshufd xmm3, xmm3, 3
  pxor xmm3, xmm4
  pxor xmm1, xmm5
  pxor xmm2, xmm3
  movdqu xmm6, xmm2
  pxor xmm2, xmm2
  mov r12, 3774873600
  pinsrd xmm2, r12d, 3
  movdqu xmm5, xmm1
  pclmulqdq xmm1, xmm2, 16
  movdqu xmm3, xmm1
  movdqu xmm1, xmm5
  pclmulqdq xmm1, xmm2, 1
  movdqu xmm4, xmm1
  movdqu xmm1, xmm5
  pclmulqdq xmm1, xmm2, 0
  pclmulqdq xmm5, xmm2, 17
  movdqu xmm2, xmm5
  movdqu xmm5, xmm1
  movdqu xmm1, xmm3
  mov r12, 0
  pinsrd xmm1, r12d, 0
  pshufd xmm1, xmm1, 14
  pxor xmm2, xmm1
  movdqu xmm1, xmm4
  mov r12, 0
  pinsrd xmm1, r12d, 0
  pshufd xmm1, xmm1, 14
  pxor xmm2, xmm1
  movdqu xmm1, xmm3
  mov r12, 0
  pinsrd xmm1, r12d, 3
  pshufd xmm1, xmm1, 79
  mov r12, 0
  pinsrd xmm4, r12d, 3
  pshufd xmm4, xmm4, 79
  pxor xmm1, xmm4
  pxor xmm1, xmm5
  movdqu xmm3, xmm1
  psrld xmm3, 31
  movdqu xmm4, xmm2
  psrld xmm4, 31
  pslld xmm1, 1
  pslld xmm2, 1
  vpslldq xmm5, xmm3, 4
  vpslldq xmm4, xmm4, 4
  mov r12, 0
  pinsrd xmm3, r12d, 0
  pshufd xmm3, xmm3, 3
  pxor xmm3, xmm4
  pxor xmm1, xmm5
  pxor xmm2, xmm3
  movdqu xmm5, xmm2
  pxor xmm2, xmm2
  mov r12, 3774873600
  pinsrd xmm2, r12d, 3
  pclmulqdq xmm1, xmm2, 17
  movdqu xmm2, xmm1
  psrld xmm2, 31
  pslld xmm1, 1
  vpslldq xmm2, xmm2, 4
  pxor xmm1, xmm2
  pxor xmm1, xmm5
  pxor xmm1, xmm6
  pshufb xmm1, xmm8
  add rdx, 1
  add r9, 16
ALIGN 16
L49:
  cmp rdx, rcx
  jne L48
  jmp L47
L46:
L47:
  mov rax, r11
  and rax, 15
  cmp rax, 0
  jne L50
  jmp L51
L50:
  movdqu xmm2, xmmword ptr [r9 + 0]
  cmp rax, 8
  jae L52
  mov rcx, 0
  pinsrq xmm2, rcx, 1
  mov rcx, rax
  shl rcx, 3
  mov rdx, 1
  shl rdx, cl
  sub rdx, 1
  pextrq rcx, xmm2, 0
  and rcx, rdx
  pinsrq xmm2, rcx, 0
  jmp L53
L52:
  mov rcx, rax
  sub rcx, 8
  shl rcx, 3
  mov rdx, 1
  shl rdx, cl
  sub rdx, 1
  pextrq rcx, xmm2, 1
  and rcx, rdx
  pinsrq xmm2, rcx, 1
L53:
  pxor xmm1, xmm2
  movdqu xmm2, xmm11
  pshufb xmm1, xmm8
  movdqu xmm5, xmm1
  pclmulqdq xmm1, xmm2, 16
  movdqu xmm3, xmm1
  movdqu xmm1, xmm5
  pclmulqdq xmm1, xmm2, 1
  movdqu xmm4, xmm1
  movdqu xmm1, xmm5
  pclmulqdq xmm1, xmm2, 0
  pclmulqdq xmm5, xmm2, 17
  movdqu xmm2, xmm5
  movdqu xmm5, xmm1
  movdqu xmm1, xmm3
  mov r12, 0
  pinsrd xmm1, r12d, 0
  pshufd xmm1, xmm1, 14
  pxor xmm2, xmm1
  movdqu xmm1, xmm4
  mov r12, 0
  pinsrd xmm1, r12d, 0
  pshufd xmm1, xmm1, 14
  pxor xmm2, xmm1
  movdqu xmm1, xmm3
  mov r12, 0
  pinsrd xmm1, r12d, 3
  pshufd xmm1, xmm1, 79
  mov r12, 0
  pinsrd xmm4, r12d, 3
  pshufd xmm4, xmm4, 79
  pxor xmm1, xmm4
  pxor xmm1, xmm5
  movdqu xmm3, xmm1
  psrld xmm3, 31
  movdqu xmm4, xmm2
  psrld xmm4, 31
  pslld xmm1, 1
  pslld xmm2, 1
  vpslldq xmm5, xmm3, 4
  vpslldq xmm4, xmm4, 4
  mov r12, 0
  pinsrd xmm3, r12d, 0
  pshufd xmm3, xmm3, 3
  pxor xmm3, xmm4
  pxor xmm1, xmm5
  pxor xmm2, xmm3
  movdqu xmm6, xmm2
  pxor xmm2, xmm2
  mov r12, 3774873600
  pinsrd xmm2, r12d, 3
  movdqu xmm5, xmm1
  pclmulqdq xmm1, xmm2, 16
  movdqu xmm3, xmm1
  movdqu xmm1, xmm5
  pclmulqdq xmm1, xmm2, 1
  movdqu xmm4, xmm1
  movdqu xmm1, xmm5
  pclmulqdq xmm1, xmm2, 0
  pclmulqdq xmm5, xmm2, 17
  movdqu xmm2, xmm5
  movdqu xmm5, xmm1
  movdqu xmm1, xmm3
  mov r12, 0
  pinsrd xmm1, r12d, 0
  pshufd xmm1, xmm1, 14
  pxor xmm2, xmm1
  movdqu xmm1, xmm4
  mov r12, 0
  pinsrd xmm1, r12d, 0
  pshufd xmm1, xmm1, 14
  pxor xmm2, xmm1
  movdqu xmm1, xmm3
  mov r12, 0
  pinsrd xmm1, r12d, 3
  pshufd xmm1, xmm1, 79
  mov r12, 0
  pinsrd xmm4, r12d, 3
  pshufd xmm4, xmm4, 79
  pxor xmm1, xmm4
  pxor xmm1, xmm5
  movdqu xmm3, xmm1
  psrld xmm3, 31
  movdqu xmm4, xmm2
  psrld xmm4, 31
  pslld xmm1, 1
  pslld xmm2, 1
  vpslldq xmm5, xmm3, 4
  vpslldq xmm4, xmm4, 4
  mov r12, 0
  pinsrd xmm3, r12d, 0
  pshufd xmm3, xmm3, 3
  pxor xmm3, xmm4
  pxor xmm1, xmm5
  pxor xmm2, xmm3
  movdqu xmm5, xmm2
  pxor xmm2, xmm2
  mov r12, 3774873600
  pinsrd xmm2, r12d, 3
  pclmulqdq xmm1, xmm2, 17
  movdqu xmm2, xmm1
  psrld xmm2, 31
  pslld xmm1, 1
  vpslldq xmm2, xmm2, 4
  pxor xmm1, xmm2
  pxor xmm1, xmm5
  pxor xmm1, xmm6
  pshufb xmm1, xmm8
L51:
  jmp L45
L44:
L45:
  mov rax, r14
  mov rcx, r13
  cmp rcx, 0
  jbe L54
  mov rsi, rcx
  and rsi, 15
  shr rcx, 4
  mov rdx, rcx
  shr rdx, 2
  and rcx, 3
  cmp rdx, 0
  jbe L56
  mov r9, rax
  mov r10, rbx
  pshufb xmm7, xmm8
  movdqu xmm9, xmm7
  mov rax, 579005069656919567
  pinsrq xmm0, rax, 0
  mov rax, 579005069656919567
  pinsrq xmm0, rax, 1
  pshufb xmm9, xmm0
  movdqu xmm10, xmm9
  pxor xmm3, xmm3
  mov rax, 1
  pinsrd xmm3, eax, 2
  paddd xmm9, xmm3
  mov rax, 3
  pinsrd xmm3, eax, 2
  mov rax, 2
  pinsrd xmm3, eax, 0
  paddd xmm10, xmm3
  pshufb xmm9, xmm8
  pshufb xmm10, xmm8
  pextrq rdi, xmm7, 0
  mov rax, 283686952306183
  pinsrq xmm0, rax, 0
  mov rax, 579005069656919567
  pinsrq xmm0, rax, 1
  pxor xmm15, xmm15
  mov rax, 4
  pinsrd xmm15, eax, 0
  mov rax, 4
  pinsrd xmm15, eax, 2
  jmp L59
ALIGN 16
L58:
  pinsrq xmm2, rdi, 0
  pinsrq xmm12, rdi, 0
  pinsrq xmm13, rdi, 0
  pinsrq xmm14, rdi, 0
  shufpd xmm2, xmm9, 2
  shufpd xmm12, xmm9, 0
  shufpd xmm13, xmm10, 2
  shufpd xmm14, xmm10, 0
  pshufb xmm9, xmm0
  pshufb xmm10, xmm0
  movdqu xmm3, xmmword ptr [r8 + 0]
  movdqu xmm4, xmmword ptr [r8 + 16]
  movdqu xmm5, xmmword ptr [r8 + 32]
  movdqu xmm6, xmmword ptr [r8 + 48]
  paddd xmm9, xmm15
  paddd xmm10, xmm15
  pxor xmm2, xmm3
  pxor xmm12, xmm3
  pxor xmm13, xmm3
  pxor xmm14, xmm3
  pshufb xmm9, xmm0
  pshufb xmm10, xmm0
  aesenc xmm2, xmm4
  aesenc xmm12, xmm4
  aesenc xmm13, xmm4
  aesenc xmm14, xmm4
  aesenc xmm2, xmm5
  aesenc xmm12, xmm5
  aesenc xmm13, xmm5
  aesenc xmm14, xmm5
  aesenc xmm2, xmm6
  aesenc xmm12, xmm6
  aesenc xmm13, xmm6
  aesenc xmm14, xmm6
  movdqu xmm3, xmmword ptr [r8 + 64]
  movdqu xmm4, xmmword ptr [r8 + 80]
  movdqu xmm5, xmmword ptr [r8 + 96]
  movdqu xmm6, xmmword ptr [r8 + 112]
  aesenc xmm2, xmm3
  aesenc xmm12, xmm3
  aesenc xmm13, xmm3
  aesenc xmm14, xmm3
  aesenc xmm2, xmm4
  aesenc xmm12, xmm4
  aesenc xmm13, xmm4
  aesenc xmm14, xmm4
  aesenc xmm2, xmm5
  aesenc xmm12, xmm5
  aesenc xmm13, xmm5
  aesenc xmm14, xmm5
  aesenc xmm2, xmm6
  aesenc xmm12, xmm6
  aesenc xmm13, xmm6
  aesenc xmm14, xmm6
  movdqu xmm3, xmmword ptr [r8 + 128]
  movdqu xmm4, xmmword ptr [r8 + 144]
  movdqu xmm5, xmmword ptr [r8 + 160]
  aesenc xmm2, xmm3
  aesenc xmm12, xmm3
  aesenc xmm13, xmm3
  aesenc xmm14, xmm3
  aesenc xmm2, xmm4
  aesenc xmm12, xmm4
  aesenc xmm13, xmm4
  aesenc xmm14, xmm4
  movdqu xmm3, xmm5
  movdqu xmm4, xmmword ptr [r8 + 176]
  movdqu xmm5, xmmword ptr [r8 + 192]
  movdqu xmm6, xmmword ptr [r8 + 208]
  aesenc xmm2, xmm3
  aesenc xmm12, xmm3
  aesenc xmm13, xmm3
  aesenc xmm14, xmm3
  aesenc xmm2, xmm4
  aesenc xmm12, xmm4
  aesenc xmm13, xmm4
  aesenc xmm14, xmm4
  aesenc xmm2, xmm5
  aesenc xmm12, xmm5
  aesenc xmm13, xmm5
  aesenc xmm14, xmm5
  aesenc xmm2, xmm6
  aesenc xmm12, xmm6
  aesenc xmm13, xmm6
  aesenc xmm14, xmm6
  movdqu xmm5, xmmword ptr [r8 + 224]
  aesenclast xmm2, xmm5
  aesenclast xmm12, xmm5
  aesenclast xmm13, xmm5
  aesenclast xmm14, xmm5
  movdqu xmm7, xmmword ptr [r9 + 0]
  pxor xmm2, xmm7
  movdqu xmm7, xmmword ptr [r9 + 16]
  pxor xmm12, xmm7
  movdqu xmm7, xmmword ptr [r9 + 32]
  pxor xmm13, xmm7
  movdqu xmm7, xmmword ptr [r9 + 48]
  pxor xmm14, xmm7
  movdqu xmmword ptr [r10 + 0], xmm2
  movdqu xmmword ptr [r10 + 16], xmm12
  movdqu xmmword ptr [r10 + 32], xmm13
  movdqu xmmword ptr [r10 + 48], xmm14
  pxor xmm1, xmm2
  movdqu xmm2, xmm11
  pshufb xmm1, xmm8
  movdqu xmm5, xmm1
  pclmulqdq xmm1, xmm2, 16
  movdqu xmm3, xmm1
  movdqu xmm1, xmm5
  pclmulqdq xmm1, xmm2, 1
  movdqu xmm4, xmm1
  movdqu xmm1, xmm5
  pclmulqdq xmm1, xmm2, 0
  pclmulqdq xmm5, xmm2, 17
  movdqu xmm2, xmm5
  movdqu xmm5, xmm1
  movdqu xmm1, xmm3
  mov r12, 0
  pinsrd xmm1, r12d, 0
  pshufd xmm1, xmm1, 14
  pxor xmm2, xmm1
  movdqu xmm1, xmm4
  mov r12, 0
  pinsrd xmm1, r12d, 0
  pshufd xmm1, xmm1, 14
  pxor xmm2, xmm1
  movdqu xmm1, xmm3
  mov r12, 0
  pinsrd xmm1, r12d, 3
  pshufd xmm1, xmm1, 79
  mov r12, 0
  pinsrd xmm4, r12d, 3
  pshufd xmm4, xmm4, 79
  pxor xmm1, xmm4
  pxor xmm1, xmm5
  movdqu xmm3, xmm1
  psrld xmm3, 31
  movdqu xmm4, xmm2
  psrld xmm4, 31
  pslld xmm1, 1
  pslld xmm2, 1
  vpslldq xmm5, xmm3, 4
  vpslldq xmm4, xmm4, 4
  mov r12, 0
  pinsrd xmm3, r12d, 0
  pshufd xmm3, xmm3, 3
  pxor xmm3, xmm4
  pxor xmm1, xmm5
  pxor xmm2, xmm3
  movdqu xmm6, xmm2
  pxor xmm2, xmm2
  mov r12, 3774873600
  pinsrd xmm2, r12d, 3
  movdqu xmm5, xmm1
  pclmulqdq xmm1, xmm2, 16
  movdqu xmm3, xmm1
  movdqu xmm1, xmm5
  pclmulqdq xmm1, xmm2, 1
  movdqu xmm4, xmm1
  movdqu xmm1, xmm5
  pclmulqdq xmm1, xmm2, 0
  pclmulqdq xmm5, xmm2, 17
  movdqu xmm2, xmm5
  movdqu xmm5, xmm1
  movdqu xmm1, xmm3
  mov r12, 0
  pinsrd xmm1, r12d, 0
  pshufd xmm1, xmm1, 14
  pxor xmm2, xmm1
  movdqu xmm1, xmm4
  mov r12, 0
  pinsrd xmm1, r12d, 0
  pshufd xmm1, xmm1, 14
  pxor xmm2, xmm1
  movdqu xmm1, xmm3
  mov r12, 0
  pinsrd xmm1, r12d, 3
  pshufd xmm1, xmm1, 79
  mov r12, 0
  pinsrd xmm4, r12d, 3
  pshufd xmm4, xmm4, 79
  pxor xmm1, xmm4
  pxor xmm1, xmm5
  movdqu xmm3, xmm1
  psrld xmm3, 31
  movdqu xmm4, xmm2
  psrld xmm4, 31
  pslld xmm1, 1
  pslld xmm2, 1
  vpslldq xmm5, xmm3, 4
  vpslldq xmm4, xmm4, 4
  mov r12, 0
  pinsrd xmm3, r12d, 0
  pshufd xmm3, xmm3, 3
  pxor xmm3, xmm4
  pxor xmm1, xmm5
  pxor xmm2, xmm3
  movdqu xmm5, xmm2
  pxor xmm2, xmm2
  mov r12, 3774873600
  pinsrd xmm2, r12d, 3
  pclmulqdq xmm1, xmm2, 17
  movdqu xmm2, xmm1
  psrld xmm2, 31
  pslld xmm1, 1
  vpslldq xmm2, xmm2, 4
  pxor xmm1, xmm2
  pxor xmm1, xmm5
  pxor xmm1, xmm6
  pshufb xmm1, xmm8
  movdqu xmm2, xmm12
  pxor xmm1, xmm2
  movdqu xmm2, xmm11
  pshufb xmm1, xmm8
  movdqu xmm5, xmm1
  pclmulqdq xmm1, xmm2, 16
  movdqu xmm3, xmm1
  movdqu xmm1, xmm5
  pclmulqdq xmm1, xmm2, 1
  movdqu xmm4, xmm1
  movdqu xmm1, xmm5
  pclmulqdq xmm1, xmm2, 0
  pclmulqdq xmm5, xmm2, 17
  movdqu xmm2, xmm5
  movdqu xmm5, xmm1
  movdqu xmm1, xmm3
  mov r12, 0
  pinsrd xmm1, r12d, 0
  pshufd xmm1, xmm1, 14
  pxor xmm2, xmm1
  movdqu xmm1, xmm4
  mov r12, 0
  pinsrd xmm1, r12d, 0
  pshufd xmm1, xmm1, 14
  pxor xmm2, xmm1
  movdqu xmm1, xmm3
  mov r12, 0
  pinsrd xmm1, r12d, 3
  pshufd xmm1, xmm1, 79
  mov r12, 0
  pinsrd xmm4, r12d, 3
  pshufd xmm4, xmm4, 79
  pxor xmm1, xmm4
  pxor xmm1, xmm5
  movdqu xmm3, xmm1
  psrld xmm3, 31
  movdqu xmm4, xmm2
  psrld xmm4, 31
  pslld xmm1, 1
  pslld xmm2, 1
  vpslldq xmm5, xmm3, 4
  vpslldq xmm4, xmm4, 4
  mov r12, 0
  pinsrd xmm3, r12d, 0
  pshufd xmm3, xmm3, 3
  pxor xmm3, xmm4
  pxor xmm1, xmm5
  pxor xmm2, xmm3
  movdqu xmm6, xmm2
  pxor xmm2, xmm2
  mov r12, 3774873600
  pinsrd xmm2, r12d, 3
  movdqu xmm5, xmm1
  pclmulqdq xmm1, xmm2, 16
  movdqu xmm3, xmm1
  movdqu xmm1, xmm5
  pclmulqdq xmm1, xmm2, 1
  movdqu xmm4, xmm1
  movdqu xmm1, xmm5
  pclmulqdq xmm1, xmm2, 0
  pclmulqdq xmm5, xmm2, 17
  movdqu xmm2, xmm5
  movdqu xmm5, xmm1
  movdqu xmm1, xmm3
  mov r12, 0
  pinsrd xmm1, r12d, 0
  pshufd xmm1, xmm1, 14
  pxor xmm2, xmm1
  movdqu xmm1, xmm4
  mov r12, 0
  pinsrd xmm1, r12d, 0
  pshufd xmm1, xmm1, 14
  pxor xmm2, xmm1
  movdqu xmm1, xmm3
  mov r12, 0
  pinsrd xmm1, r12d, 3
  pshufd xmm1, xmm1, 79
  mov r12, 0
  pinsrd xmm4, r12d, 3
  pshufd xmm4, xmm4, 79
  pxor xmm1, xmm4
  pxor xmm1, xmm5
  movdqu xmm3, xmm1
  psrld xmm3, 31
  movdqu xmm4, xmm2
  psrld xmm4, 31
  pslld xmm1, 1
  pslld xmm2, 1
  vpslldq xmm5, xmm3, 4
  vpslldq xmm4, xmm4, 4
  mov r12, 0
  pinsrd xmm3, r12d, 0
  pshufd xmm3, xmm3, 3
  pxor xmm3, xmm4
  pxor xmm1, xmm5
  pxor xmm2, xmm3
  movdqu xmm5, xmm2
  pxor xmm2, xmm2
  mov r12, 3774873600
  pinsrd xmm2, r12d, 3
  pclmulqdq xmm1, xmm2, 17
  movdqu xmm2, xmm1
  psrld xmm2, 31
  pslld xmm1, 1
  vpslldq xmm2, xmm2, 4
  pxor xmm1, xmm2
  pxor xmm1, xmm5
  pxor xmm1, xmm6
  pshufb xmm1, xmm8
  movdqu xmm2, xmm13
  pxor xmm1, xmm2
  movdqu xmm2, xmm11
  pshufb xmm1, xmm8
  movdqu xmm5, xmm1
  pclmulqdq xmm1, xmm2, 16
  movdqu xmm3, xmm1
  movdqu xmm1, xmm5
  pclmulqdq xmm1, xmm2, 1
  movdqu xmm4, xmm1
  movdqu xmm1, xmm5
  pclmulqdq xmm1, xmm2, 0
  pclmulqdq xmm5, xmm2, 17
  movdqu xmm2, xmm5
  movdqu xmm5, xmm1
  movdqu xmm1, xmm3
  mov r12, 0
  pinsrd xmm1, r12d, 0
  pshufd xmm1, xmm1, 14
  pxor xmm2, xmm1
  movdqu xmm1, xmm4
  mov r12, 0
  pinsrd xmm1, r12d, 0
  pshufd xmm1, xmm1, 14
  pxor xmm2, xmm1
  movdqu xmm1, xmm3
  mov r12, 0
  pinsrd xmm1, r12d, 3
  pshufd xmm1, xmm1, 79
  mov r12, 0
  pinsrd xmm4, r12d, 3
  pshufd xmm4, xmm4, 79
  pxor xmm1, xmm4
  pxor xmm1, xmm5
  movdqu xmm3, xmm1
  psrld xmm3, 31
  movdqu xmm4, xmm2
  psrld xmm4, 31
  pslld xmm1, 1
  pslld xmm2, 1
  vpslldq xmm5, xmm3, 4
  vpslldq xmm4, xmm4, 4
  mov r12, 0
  pinsrd xmm3, r12d, 0
  pshufd xmm3, xmm3, 3
  pxor xmm3, xmm4
  pxor xmm1, xmm5
  pxor xmm2, xmm3
  movdqu xmm6, xmm2
  pxor xmm2, xmm2
  mov r12, 3774873600
  pinsrd xmm2, r12d, 3
  movdqu xmm5, xmm1
  pclmulqdq xmm1, xmm2, 16
  movdqu xmm3, xmm1
  movdqu xmm1, xmm5
  pclmulqdq xmm1, xmm2, 1
  movdqu xmm4, xmm1
  movdqu xmm1, xmm5
  pclmulqdq xmm1, xmm2, 0
  pclmulqdq xmm5, xmm2, 17
  movdqu xmm2, xmm5
  movdqu xmm5, xmm1
  movdqu xmm1, xmm3
  mov r12, 0
  pinsrd xmm1, r12d, 0
  pshufd xmm1, xmm1, 14
  pxor xmm2, xmm1
  movdqu xmm1, xmm4
  mov r12, 0
  pinsrd xmm1, r12d, 0
  pshufd xmm1, xmm1, 14
  pxor xmm2, xmm1
  movdqu xmm1, xmm3
  mov r12, 0
  pinsrd xmm1, r12d, 3
  pshufd xmm1, xmm1, 79
  mov r12, 0
  pinsrd xmm4, r12d, 3
  pshufd xmm4, xmm4, 79
  pxor xmm1, xmm4
  pxor xmm1, xmm5
  movdqu xmm3, xmm1
  psrld xmm3, 31
  movdqu xmm4, xmm2
  psrld xmm4, 31
  pslld xmm1, 1
  pslld xmm2, 1
  vpslldq xmm5, xmm3, 4
  vpslldq xmm4, xmm4, 4
  mov r12, 0
  pinsrd xmm3, r12d, 0
  pshufd xmm3, xmm3, 3
  pxor xmm3, xmm4
  pxor xmm1, xmm5
  pxor xmm2, xmm3
  movdqu xmm5, xmm2
  pxor xmm2, xmm2
  mov r12, 3774873600
  pinsrd xmm2, r12d, 3
  pclmulqdq xmm1, xmm2, 17
  movdqu xmm2, xmm1
  psrld xmm2, 31
  pslld xmm1, 1
  vpslldq xmm2, xmm2, 4
  pxor xmm1, xmm2
  pxor xmm1, xmm5
  pxor xmm1, xmm6
  pshufb xmm1, xmm8
  movdqu xmm2, xmm14
  pxor xmm1, xmm2
  movdqu xmm2, xmm11
  pshufb xmm1, xmm8
  movdqu xmm5, xmm1
  pclmulqdq xmm1, xmm2, 16
  movdqu xmm3, xmm1
  movdqu xmm1, xmm5
  pclmulqdq xmm1, xmm2, 1
  movdqu xmm4, xmm1
  movdqu xmm1, xmm5
  pclmulqdq xmm1, xmm2, 0
  pclmulqdq xmm5, xmm2, 17
  movdqu xmm2, xmm5
  movdqu xmm5, xmm1
  movdqu xmm1, xmm3
  mov r12, 0
  pinsrd xmm1, r12d, 0
  pshufd xmm1, xmm1, 14
  pxor xmm2, xmm1
  movdqu xmm1, xmm4
  mov r12, 0
  pinsrd xmm1, r12d, 0
  pshufd xmm1, xmm1, 14
  pxor xmm2, xmm1
  movdqu xmm1, xmm3
  mov r12, 0
  pinsrd xmm1, r12d, 3
  pshufd xmm1, xmm1, 79
  mov r12, 0
  pinsrd xmm4, r12d, 3
  pshufd xmm4, xmm4, 79
  pxor xmm1, xmm4
  pxor xmm1, xmm5
  movdqu xmm3, xmm1
  psrld xmm3, 31
  movdqu xmm4, xmm2
  psrld xmm4, 31
  pslld xmm1, 1
  pslld xmm2, 1
  vpslldq xmm5, xmm3, 4
  vpslldq xmm4, xmm4, 4
  mov r12, 0
  pinsrd xmm3, r12d, 0
  pshufd xmm3, xmm3, 3
  pxor xmm3, xmm4
  pxor xmm1, xmm5
  pxor xmm2, xmm3
  movdqu xmm6, xmm2
  pxor xmm2, xmm2
  mov r12, 3774873600
  pinsrd xmm2, r12d, 3
  movdqu xmm5, xmm1
  pclmulqdq xmm1, xmm2, 16
  movdqu xmm3, xmm1
  movdqu xmm1, xmm5
  pclmulqdq xmm1, xmm2, 1
  movdqu xmm4, xmm1
  movdqu xmm1, xmm5
  pclmulqdq xmm1, xmm2, 0
  pclmulqdq xmm5, xmm2, 17
  movdqu xmm2, xmm5
  movdqu xmm5, xmm1
  movdqu xmm1, xmm3
  mov r12, 0
  pinsrd xmm1, r12d, 0
  pshufd xmm1, xmm1, 14
  pxor xmm2, xmm1
  movdqu xmm1, xmm4
  mov r12, 0
  pinsrd xmm1, r12d, 0
  pshufd xmm1, xmm1, 14
  pxor xmm2, xmm1
  movdqu xmm1, xmm3
  mov r12, 0
  pinsrd xmm1, r12d, 3
  pshufd xmm1, xmm1, 79
  mov r12, 0
  pinsrd xmm4, r12d, 3
  pshufd xmm4, xmm4, 79
  pxor xmm1, xmm4
  pxor xmm1, xmm5
  movdqu xmm3, xmm1
  psrld xmm3, 31
  movdqu xmm4, xmm2
  psrld xmm4, 31
  pslld xmm1, 1
  pslld xmm2, 1
  vpslldq xmm5, xmm3, 4
  vpslldq xmm4, xmm4, 4
  mov r12, 0
  pinsrd xmm3, r12d, 0
  pshufd xmm3, xmm3, 3
  pxor xmm3, xmm4
  pxor xmm1, xmm5
  pxor xmm2, xmm3
  movdqu xmm5, xmm2
  pxor xmm2, xmm2
  mov r12, 3774873600
  pinsrd xmm2, r12d, 3
  pclmulqdq xmm1, xmm2, 17
  movdqu xmm2, xmm1
  psrld xmm2, 31
  pslld xmm1, 1
  vpslldq xmm2, xmm2, 4
  pxor xmm1, xmm2
  pxor xmm1, xmm5
  pxor xmm1, xmm6
  pshufb xmm1, xmm8
  sub rdx, 1
  add r9, 64
  add r10, 64
ALIGN 16
L59:
  cmp rdx, 0
  ja L58
  movdqu xmm7, xmm9
  pinsrq xmm7, rdi, 0
  pshufb xmm7, xmm8
  mov rax, r9
  mov rbx, r10
  jmp L57
L56:
L57:
  mov rdx, 0
  mov r9, rax
  mov r10, rbx
  pxor xmm10, xmm10
  mov r12, 1
  pinsrd xmm10, r12d, 0
  jmp L61
ALIGN 16
L60:
  movdqu xmm0, xmm7
  pshufb xmm0, xmm8
  movdqu xmm2, xmmword ptr [r8 + 0]
  pxor xmm0, xmm2
  movdqu xmm2, xmmword ptr [r8 + 16]
  aesenc xmm0, xmm2
  movdqu xmm2, xmmword ptr [r8 + 32]
  aesenc xmm0, xmm2
  movdqu xmm2, xmmword ptr [r8 + 48]
  aesenc xmm0, xmm2
  movdqu xmm2, xmmword ptr [r8 + 64]
  aesenc xmm0, xmm2
  movdqu xmm2, xmmword ptr [r8 + 80]
  aesenc xmm0, xmm2
  movdqu xmm2, xmmword ptr [r8 + 96]
  aesenc xmm0, xmm2
  movdqu xmm2, xmmword ptr [r8 + 112]
  aesenc xmm0, xmm2
  movdqu xmm2, xmmword ptr [r8 + 128]
  aesenc xmm0, xmm2
  movdqu xmm2, xmmword ptr [r8 + 144]
  aesenc xmm0, xmm2
  movdqu xmm2, xmmword ptr [r8 + 160]
  aesenc xmm0, xmm2
  movdqu xmm2, xmmword ptr [r8 + 176]
  aesenc xmm0, xmm2
  movdqu xmm2, xmmword ptr [r8 + 192]
  aesenc xmm0, xmm2
  movdqu xmm2, xmmword ptr [r8 + 208]
  aesenc xmm0, xmm2
  movdqu xmm2, xmmword ptr [r8 + 224]
  aesenclast xmm0, xmm2
  pxor xmm2, xmm2
  movdqu xmm2, xmmword ptr [r9 + 0]
  pxor xmm2, xmm0
  movdqu xmmword ptr [r10 + 0], xmm2
  pxor xmm1, xmm2
  movdqu xmm2, xmm11
  pshufb xmm1, xmm8
  movdqu xmm5, xmm1
  pclmulqdq xmm1, xmm2, 16
  movdqu xmm3, xmm1
  movdqu xmm1, xmm5
  pclmulqdq xmm1, xmm2, 1
  movdqu xmm4, xmm1
  movdqu xmm1, xmm5
  pclmulqdq xmm1, xmm2, 0
  pclmulqdq xmm5, xmm2, 17
  movdqu xmm2, xmm5
  movdqu xmm5, xmm1
  movdqu xmm1, xmm3
  mov r12, 0
  pinsrd xmm1, r12d, 0
  pshufd xmm1, xmm1, 14
  pxor xmm2, xmm1
  movdqu xmm1, xmm4
  mov r12, 0
  pinsrd xmm1, r12d, 0
  pshufd xmm1, xmm1, 14
  pxor xmm2, xmm1
  movdqu xmm1, xmm3
  mov r12, 0
  pinsrd xmm1, r12d, 3
  pshufd xmm1, xmm1, 79
  mov r12, 0
  pinsrd xmm4, r12d, 3
  pshufd xmm4, xmm4, 79
  pxor xmm1, xmm4
  pxor xmm1, xmm5
  movdqu xmm3, xmm1
  psrld xmm3, 31
  movdqu xmm4, xmm2
  psrld xmm4, 31
  pslld xmm1, 1
  pslld xmm2, 1
  vpslldq xmm5, xmm3, 4
  vpslldq xmm4, xmm4, 4
  mov r12, 0
  pinsrd xmm3, r12d, 0
  pshufd xmm3, xmm3, 3
  pxor xmm3, xmm4
  pxor xmm1, xmm5
  pxor xmm2, xmm3
  movdqu xmm6, xmm2
  pxor xmm2, xmm2
  mov r12, 3774873600
  pinsrd xmm2, r12d, 3
  movdqu xmm5, xmm1
  pclmulqdq xmm1, xmm2, 16
  movdqu xmm3, xmm1
  movdqu xmm1, xmm5
  pclmulqdq xmm1, xmm2, 1
  movdqu xmm4, xmm1
  movdqu xmm1, xmm5
  pclmulqdq xmm1, xmm2, 0
  pclmulqdq xmm5, xmm2, 17
  movdqu xmm2, xmm5
  movdqu xmm5, xmm1
  movdqu xmm1, xmm3
  mov r12, 0
  pinsrd xmm1, r12d, 0
  pshufd xmm1, xmm1, 14
  pxor xmm2, xmm1
  movdqu xmm1, xmm4
  mov r12, 0
  pinsrd xmm1, r12d, 0
  pshufd xmm1, xmm1, 14
  pxor xmm2, xmm1
  movdqu xmm1, xmm3
  mov r12, 0
  pinsrd xmm1, r12d, 3
  pshufd xmm1, xmm1, 79
  mov r12, 0
  pinsrd xmm4, r12d, 3
  pshufd xmm4, xmm4, 79
  pxor xmm1, xmm4
  pxor xmm1, xmm5
  movdqu xmm3, xmm1
  psrld xmm3, 31
  movdqu xmm4, xmm2
  psrld xmm4, 31
  pslld xmm1, 1
  pslld xmm2, 1
  vpslldq xmm5, xmm3, 4
  vpslldq xmm4, xmm4, 4
  mov r12, 0
  pinsrd xmm3, r12d, 0
  pshufd xmm3, xmm3, 3
  pxor xmm3, xmm4
  pxor xmm1, xmm5
  pxor xmm2, xmm3
  movdqu xmm5, xmm2
  pxor xmm2, xmm2
  mov r12, 3774873600
  pinsrd xmm2, r12d, 3
  pclmulqdq xmm1, xmm2, 17
  movdqu xmm2, xmm1
  psrld xmm2, 31
  pslld xmm1, 1
  vpslldq xmm2, xmm2, 4
  pxor xmm1, xmm2
  pxor xmm1, xmm5
  pxor xmm1, xmm6
  pshufb xmm1, xmm8
  add rdx, 1
  add r9, 16
  add r10, 16
  paddd xmm7, xmm10
ALIGN 16
L61:
  cmp rdx, rcx
  jne L60
  cmp rsi, 0
  jne L62
  jmp L63
L62:
  movdqu xmm3, xmm1
  movdqu xmm2, xmmword ptr [r9 + 0]
  movdqu xmm1, xmm2
  movdqu xmm0, xmm7
  mov r12, 579005069656919567
  pinsrq xmm2, r12, 0
  mov r12, 283686952306183
  pinsrq xmm2, r12, 1
  pshufb xmm0, xmm2
  movdqu xmm2, xmmword ptr [r8 + 0]
  pxor xmm0, xmm2
  movdqu xmm2, xmmword ptr [r8 + 16]
  aesenc xmm0, xmm2
  movdqu xmm2, xmmword ptr [r8 + 32]
  aesenc xmm0, xmm2
  movdqu xmm2, xmmword ptr [r8 + 48]
  aesenc xmm0, xmm2
  movdqu xmm2, xmmword ptr [r8 + 64]
  aesenc xmm0, xmm2
  movdqu xmm2, xmmword ptr [r8 + 80]
  aesenc xmm0, xmm2
  movdqu xmm2, xmmword ptr [r8 + 96]
  aesenc xmm0, xmm2
  movdqu xmm2, xmmword ptr [r8 + 112]
  aesenc xmm0, xmm2
  movdqu xmm2, xmmword ptr [r8 + 128]
  aesenc xmm0, xmm2
  movdqu xmm2, xmmword ptr [r8 + 144]
  aesenc xmm0, xmm2
  movdqu xmm2, xmmword ptr [r8 + 160]
  aesenc xmm0, xmm2
  movdqu xmm2, xmmword ptr [r8 + 176]
  aesenc xmm0, xmm2
  movdqu xmm2, xmmword ptr [r8 + 192]
  aesenc xmm0, xmm2
  movdqu xmm2, xmmword ptr [r8 + 208]
  aesenc xmm0, xmm2
  movdqu xmm2, xmmword ptr [r8 + 224]
  aesenclast xmm0, xmm2
  pxor xmm2, xmm2
  pxor xmm1, xmm0
  movdqu xmmword ptr [r10 + 0], xmm1
  mov rax, rsi
  mov r9, r10
  movdqu xmm1, xmm3
  movdqu xmm2, xmmword ptr [r9 + 0]
  cmp rax, 8
  jae L64
  mov rcx, 0
  pinsrq xmm2, rcx, 1
  mov rcx, rax
  shl rcx, 3
  mov rdx, 1
  shl rdx, cl
  sub rdx, 1
  pextrq rcx, xmm2, 0
  and rcx, rdx
  pinsrq xmm2, rcx, 0
  jmp L65
L64:
  mov rcx, rax
  sub rcx, 8
  shl rcx, 3
  mov rdx, 1
  shl rdx, cl
  sub rdx, 1
  pextrq rcx, xmm2, 1
  and rcx, rdx
  pinsrq xmm2, rcx, 1
L65:
  pxor xmm1, xmm2
  movdqu xmm2, xmm11
  pshufb xmm1, xmm8
  movdqu xmm5, xmm1
  pclmulqdq xmm1, xmm2, 16
  movdqu xmm3, xmm1
  movdqu xmm1, xmm5
  pclmulqdq xmm1, xmm2, 1
  movdqu xmm4, xmm1
  movdqu xmm1, xmm5
  pclmulqdq xmm1, xmm2, 0
  pclmulqdq xmm5, xmm2, 17
  movdqu xmm2, xmm5
  movdqu xmm5, xmm1
  movdqu xmm1, xmm3
  mov r12, 0
  pinsrd xmm1, r12d, 0
  pshufd xmm1, xmm1, 14
  pxor xmm2, xmm1
  movdqu xmm1, xmm4
  mov r12, 0
  pinsrd xmm1, r12d, 0
  pshufd xmm1, xmm1, 14
  pxor xmm2, xmm1
  movdqu xmm1, xmm3
  mov r12, 0
  pinsrd xmm1, r12d, 3
  pshufd xmm1, xmm1, 79
  mov r12, 0
  pinsrd xmm4, r12d, 3
  pshufd xmm4, xmm4, 79
  pxor xmm1, xmm4
  pxor xmm1, xmm5
  movdqu xmm3, xmm1
  psrld xmm3, 31
  movdqu xmm4, xmm2
  psrld xmm4, 31
  pslld xmm1, 1
  pslld xmm2, 1
  vpslldq xmm5, xmm3, 4
  vpslldq xmm4, xmm4, 4
  mov r12, 0
  pinsrd xmm3, r12d, 0
  pshufd xmm3, xmm3, 3
  pxor xmm3, xmm4
  pxor xmm1, xmm5
  pxor xmm2, xmm3
  movdqu xmm6, xmm2
  pxor xmm2, xmm2
  mov r12, 3774873600
  pinsrd xmm2, r12d, 3
  movdqu xmm5, xmm1
  pclmulqdq xmm1, xmm2, 16
  movdqu xmm3, xmm1
  movdqu xmm1, xmm5
  pclmulqdq xmm1, xmm2, 1
  movdqu xmm4, xmm1
  movdqu xmm1, xmm5
  pclmulqdq xmm1, xmm2, 0
  pclmulqdq xmm5, xmm2, 17
  movdqu xmm2, xmm5
  movdqu xmm5, xmm1
  movdqu xmm1, xmm3
  mov r12, 0
  pinsrd xmm1, r12d, 0
  pshufd xmm1, xmm1, 14
  pxor xmm2, xmm1
  movdqu xmm1, xmm4
  mov r12, 0
  pinsrd xmm1, r12d, 0
  pshufd xmm1, xmm1, 14
  pxor xmm2, xmm1
  movdqu xmm1, xmm3
  mov r12, 0
  pinsrd xmm1, r12d, 3
  pshufd xmm1, xmm1, 79
  mov r12, 0
  pinsrd xmm4, r12d, 3
  pshufd xmm4, xmm4, 79
  pxor xmm1, xmm4
  pxor xmm1, xmm5
  movdqu xmm3, xmm1
  psrld xmm3, 31
  movdqu xmm4, xmm2
  psrld xmm4, 31
  pslld xmm1, 1
  pslld xmm2, 1
  vpslldq xmm5, xmm3, 4
  vpslldq xmm4, xmm4, 4
  mov r12, 0
  pinsrd xmm3, r12d, 0
  pshufd xmm3, xmm3, 3
  pxor xmm3, xmm4
  pxor xmm1, xmm5
  pxor xmm2, xmm3
  movdqu xmm5, xmm2
  pxor xmm2, xmm2
  mov r12, 3774873600
  pinsrd xmm2, r12d, 3
  pclmulqdq xmm1, xmm2, 17
  movdqu xmm2, xmm1
  psrld xmm2, 31
  pslld xmm1, 1
  vpslldq xmm2, xmm2, 4
  pxor xmm1, xmm2
  pxor xmm1, xmm5
  pxor xmm1, xmm6
  pshufb xmm1, xmm8
L63:
  jmp L55
L54:
L55:
  pxor xmm2, xmm2
  mov rax, r13
  imul rax, 8
  pinsrd xmm2, eax, 0
  mov rax, r11
  imul rax, 8
  pinsrd xmm2, eax, 2
  pshufb xmm2, xmm8
  pxor xmm1, xmm2
  movdqu xmm2, xmm11
  pshufb xmm1, xmm8
  movdqu xmm5, xmm1
  pclmulqdq xmm1, xmm2, 16
  movdqu xmm3, xmm1
  movdqu xmm1, xmm5
  pclmulqdq xmm1, xmm2, 1
  movdqu xmm4, xmm1
  movdqu xmm1, xmm5
  pclmulqdq xmm1, xmm2, 0
  pclmulqdq xmm5, xmm2, 17
  movdqu xmm2, xmm5
  movdqu xmm5, xmm1
  movdqu xmm1, xmm3
  mov r12, 0
  pinsrd xmm1, r12d, 0
  pshufd xmm1, xmm1, 14
  pxor xmm2, xmm1
  movdqu xmm1, xmm4
  mov r12, 0
  pinsrd xmm1, r12d, 0
  pshufd xmm1, xmm1, 14
  pxor xmm2, xmm1
  movdqu xmm1, xmm3
  mov r12, 0
  pinsrd xmm1, r12d, 3
  pshufd xmm1, xmm1, 79
  mov r12, 0
  pinsrd xmm4, r12d, 3
  pshufd xmm4, xmm4, 79
  pxor xmm1, xmm4
  pxor xmm1, xmm5
  movdqu xmm3, xmm1
  psrld xmm3, 31
  movdqu xmm4, xmm2
  psrld xmm4, 31
  pslld xmm1, 1
  pslld xmm2, 1
  vpslldq xmm5, xmm3, 4
  vpslldq xmm4, xmm4, 4
  mov r12, 0
  pinsrd xmm3, r12d, 0
  pshufd xmm3, xmm3, 3
  pxor xmm3, xmm4
  pxor xmm1, xmm5
  pxor xmm2, xmm3
  movdqu xmm6, xmm2
  pxor xmm2, xmm2
  mov r12, 3774873600
  pinsrd xmm2, r12d, 3
  movdqu xmm5, xmm1
  pclmulqdq xmm1, xmm2, 16
  movdqu xmm3, xmm1
  movdqu xmm1, xmm5
  pclmulqdq xmm1, xmm2, 1
  movdqu xmm4, xmm1
  movdqu xmm1, xmm5
  pclmulqdq xmm1, xmm2, 0
  pclmulqdq xmm5, xmm2, 17
  movdqu xmm2, xmm5
  movdqu xmm5, xmm1
  movdqu xmm1, xmm3
  mov r12, 0
  pinsrd xmm1, r12d, 0
  pshufd xmm1, xmm1, 14
  pxor xmm2, xmm1
  movdqu xmm1, xmm4
  mov r12, 0
  pinsrd xmm1, r12d, 0
  pshufd xmm1, xmm1, 14
  pxor xmm2, xmm1
  movdqu xmm1, xmm3
  mov r12, 0
  pinsrd xmm1, r12d, 3
  pshufd xmm1, xmm1, 79
  mov r12, 0
  pinsrd xmm4, r12d, 3
  pshufd xmm4, xmm4, 79
  pxor xmm1, xmm4
  pxor xmm1, xmm5
  movdqu xmm3, xmm1
  psrld xmm3, 31
  movdqu xmm4, xmm2
  psrld xmm4, 31
  pslld xmm1, 1
  pslld xmm2, 1
  vpslldq xmm5, xmm3, 4
  vpslldq xmm4, xmm4, 4
  mov r12, 0
  pinsrd xmm3, r12d, 0
  pshufd xmm3, xmm3, 3
  pxor xmm3, xmm4
  pxor xmm1, xmm5
  pxor xmm2, xmm3
  movdqu xmm5, xmm2
  pxor xmm2, xmm2
  mov r12, 3774873600
  pinsrd xmm2, r12d, 3
  pclmulqdq xmm1, xmm2, 17
  movdqu xmm2, xmm1
  psrld xmm2, 31
  pslld xmm1, 1
  vpslldq xmm2, xmm2, 4
  pxor xmm1, xmm2
  pxor xmm1, xmm5
  pxor xmm1, xmm6
  pshufb xmm1, xmm8
  mov r12, 1
  pinsrd xmm7, r12d, 0
  movdqu xmm0, xmm7
  mov r12, 579005069656919567
  pinsrq xmm2, r12, 0
  mov r12, 283686952306183
  pinsrq xmm2, r12, 1
  pshufb xmm0, xmm2
  movdqu xmm2, xmmword ptr [r8 + 0]
  pxor xmm0, xmm2
  movdqu xmm2, xmmword ptr [r8 + 16]
  aesenc xmm0, xmm2
  movdqu xmm2, xmmword ptr [r8 + 32]
  aesenc xmm0, xmm2
  movdqu xmm2, xmmword ptr [r8 + 48]
  aesenc xmm0, xmm2
  movdqu xmm2, xmmword ptr [r8 + 64]
  aesenc xmm0, xmm2
  movdqu xmm2, xmmword ptr [r8 + 80]
  aesenc xmm0, xmm2
  movdqu xmm2, xmmword ptr [r8 + 96]
  aesenc xmm0, xmm2
  movdqu xmm2, xmmword ptr [r8 + 112]
  aesenc xmm0, xmm2
  movdqu xmm2, xmmword ptr [r8 + 128]
  aesenc xmm0, xmm2
  movdqu xmm2, xmmword ptr [r8 + 144]
  aesenc xmm0, xmm2
  movdqu xmm2, xmmword ptr [r8 + 160]
  aesenc xmm0, xmm2
  movdqu xmm2, xmmword ptr [r8 + 176]
  aesenc xmm0, xmm2
  movdqu xmm2, xmmword ptr [r8 + 192]
  aesenc xmm0, xmm2
  movdqu xmm2, xmmword ptr [r8 + 208]
  aesenc xmm0, xmm2
  movdqu xmm2, xmmword ptr [r8 + 224]
  aesenclast xmm0, xmm2
  pxor xmm2, xmm2
  pxor xmm1, xmm0
  movdqu xmmword ptr [r15 + 0], xmm1
  pop rbx
  pop rbp
  pop rdi
  pop rsi
  pop r12
  pop r13
  pop r14
  pop r15
  pop rax
  pinsrq xmm6, rax, 1
  pop rax
  pinsrq xmm6, rax, 0
  pop rax
  pinsrq xmm7, rax, 1
  pop rax
  pinsrq xmm7, rax, 0
  pop rax
  pinsrq xmm8, rax, 1
  pop rax
  pinsrq xmm8, rax, 0
  pop rax
  pinsrq xmm9, rax, 1
  pop rax
  pinsrq xmm9, rax, 0
  pop rax
  pinsrq xmm10, rax, 1
  pop rax
  pinsrq xmm10, rax, 0
  pop rax
  pinsrq xmm11, rax, 1
  pop rax
  pinsrq xmm11, rax, 0
  pop rax
  pinsrq xmm12, rax, 1
  pop rax
  pinsrq xmm12, rax, 0
  pop rax
  pinsrq xmm13, rax, 1
  pop rax
  pinsrq xmm13, rax, 0
  pop rax
  pinsrq xmm14, rax, 1
  pop rax
  pinsrq xmm14, rax, 0
  pop rax
  pinsrq xmm15, rax, 1
  pop rax
  pinsrq xmm15, rax, 0
  ret
gcm256_encrypt endp
ALIGN 16
gcm256_decrypt proc
  mov r9, rcx
  pextrq rax, xmm15, 0
  push rax
  pextrq rax, xmm15, 1
  push rax
  pextrq rax, xmm14, 0
  push rax
  pextrq rax, xmm14, 1
  push rax
  pextrq rax, xmm13, 0
  push rax
  pextrq rax, xmm13, 1
  push rax
  pextrq rax, xmm12, 0
  push rax
  pextrq rax, xmm12, 1
  push rax
  pextrq rax, xmm11, 0
  push rax
  pextrq rax, xmm11, 1
  push rax
  pextrq rax, xmm10, 0
  push rax
  pextrq rax, xmm10, 1
  push rax
  pextrq rax, xmm9, 0
  push rax
  pextrq rax, xmm9, 1
  push rax
  pextrq rax, xmm8, 0
  push rax
  pextrq rax, xmm8, 1
  push rax
  pextrq rax, xmm7, 0
  push rax
  pextrq rax, xmm7, 1
  push rax
  pextrq rax, xmm6, 0
  push rax
  pextrq rax, xmm6, 1
  push rax
  push r15
  push r14
  push r13
  push r12
  push rsi
  push rdi
  push rbp
  push rbx
  mov r14, qword ptr [r9 + 0]
  mov r13, qword ptr [r9 + 8]
  mov rax, qword ptr [r9 + 16]
  mov r11, qword ptr [r9 + 24]
  mov r10, qword ptr [r9 + 32]
  mov r8, qword ptr [r9 + 40]
  mov rbx, qword ptr [r9 + 48]
  mov r15, qword ptr [r9 + 56]
  movdqu xmm7, xmmword ptr [r10 + 0]
  mov r12, 579005069656919567
  pinsrq xmm8, r12, 0
  mov r12, 283686952306183
  pinsrq xmm8, r12, 1
  pxor xmm0, xmm0
  movdqu xmm2, xmmword ptr [r8 + 0]
  pxor xmm0, xmm2
  movdqu xmm2, xmmword ptr [r8 + 16]
  aesenc xmm0, xmm2
  movdqu xmm2, xmmword ptr [r8 + 32]
  aesenc xmm0, xmm2
  movdqu xmm2, xmmword ptr [r8 + 48]
  aesenc xmm0, xmm2
  movdqu xmm2, xmmword ptr [r8 + 64]
  aesenc xmm0, xmm2
  movdqu xmm2, xmmword ptr [r8 + 80]
  aesenc xmm0, xmm2
  movdqu xmm2, xmmword ptr [r8 + 96]
  aesenc xmm0, xmm2
  movdqu xmm2, xmmword ptr [r8 + 112]
  aesenc xmm0, xmm2
  movdqu xmm2, xmmword ptr [r8 + 128]
  aesenc xmm0, xmm2
  movdqu xmm2, xmmword ptr [r8 + 144]
  aesenc xmm0, xmm2
  movdqu xmm2, xmmword ptr [r8 + 160]
  aesenc xmm0, xmm2
  movdqu xmm2, xmmword ptr [r8 + 176]
  aesenc xmm0, xmm2
  movdqu xmm2, xmmword ptr [r8 + 192]
  aesenc xmm0, xmm2
  movdqu xmm2, xmmword ptr [r8 + 208]
  aesenc xmm0, xmm2
  movdqu xmm2, xmmword ptr [r8 + 224]
  aesenclast xmm0, xmm2
  pxor xmm2, xmm2
  pshufb xmm0, xmm8
  movdqu xmm11, xmm0
  pshufb xmm7, xmm8
  mov r12, 2
  pinsrd xmm7, r12d, 0
  pxor xmm1, xmm1
  cmp r11, 0
  jbe L66
  mov rcx, r11
  shr rcx, 4
  mov r9, rax
  cmp rcx, 0
  je L68
  mov rdx, 0
  jmp L71
ALIGN 16
L70:
  movdqu xmm2, xmmword ptr [r9 + 0]
  pxor xmm1, xmm2
  movdqu xmm2, xmm11
  pshufb xmm1, xmm8
  movdqu xmm5, xmm1
  pclmulqdq xmm1, xmm2, 16
  movdqu xmm3, xmm1
  movdqu xmm1, xmm5
  pclmulqdq xmm1, xmm2, 1
  movdqu xmm4, xmm1
  movdqu xmm1, xmm5
  pclmulqdq xmm1, xmm2, 0
  pclmulqdq xmm5, xmm2, 17
  movdqu xmm2, xmm5
  movdqu xmm5, xmm1
  movdqu xmm1, xmm3
  mov r12, 0
  pinsrd xmm1, r12d, 0
  pshufd xmm1, xmm1, 14
  pxor xmm2, xmm1
  movdqu xmm1, xmm4
  mov r12, 0
  pinsrd xmm1, r12d, 0
  pshufd xmm1, xmm1, 14
  pxor xmm2, xmm1
  movdqu xmm1, xmm3
  mov r12, 0
  pinsrd xmm1, r12d, 3
  pshufd xmm1, xmm1, 79
  mov r12, 0
  pinsrd xmm4, r12d, 3
  pshufd xmm4, xmm4, 79
  pxor xmm1, xmm4
  pxor xmm1, xmm5
  movdqu xmm3, xmm1
  psrld xmm3, 31
  movdqu xmm4, xmm2
  psrld xmm4, 31
  pslld xmm1, 1
  pslld xmm2, 1
  vpslldq xmm5, xmm3, 4
  vpslldq xmm4, xmm4, 4
  mov r12, 0
  pinsrd xmm3, r12d, 0
  pshufd xmm3, xmm3, 3
  pxor xmm3, xmm4
  pxor xmm1, xmm5
  pxor xmm2, xmm3
  movdqu xmm6, xmm2
  pxor xmm2, xmm2
  mov r12, 3774873600
  pinsrd xmm2, r12d, 3
  movdqu xmm5, xmm1
  pclmulqdq xmm1, xmm2, 16
  movdqu xmm3, xmm1
  movdqu xmm1, xmm5
  pclmulqdq xmm1, xmm2, 1
  movdqu xmm4, xmm1
  movdqu xmm1, xmm5
  pclmulqdq xmm1, xmm2, 0
  pclmulqdq xmm5, xmm2, 17
  movdqu xmm2, xmm5
  movdqu xmm5, xmm1
  movdqu xmm1, xmm3
  mov r12, 0
  pinsrd xmm1, r12d, 0
  pshufd xmm1, xmm1, 14
  pxor xmm2, xmm1
  movdqu xmm1, xmm4
  mov r12, 0
  pinsrd xmm1, r12d, 0
  pshufd xmm1, xmm1, 14
  pxor xmm2, xmm1
  movdqu xmm1, xmm3
  mov r12, 0
  pinsrd xmm1, r12d, 3
  pshufd xmm1, xmm1, 79
  mov r12, 0
  pinsrd xmm4, r12d, 3
  pshufd xmm4, xmm4, 79
  pxor xmm1, xmm4
  pxor xmm1, xmm5
  movdqu xmm3, xmm1
  psrld xmm3, 31
  movdqu xmm4, xmm2
  psrld xmm4, 31
  pslld xmm1, 1
  pslld xmm2, 1
  vpslldq xmm5, xmm3, 4
  vpslldq xmm4, xmm4, 4
  mov r12, 0
  pinsrd xmm3, r12d, 0
  pshufd xmm3, xmm3, 3
  pxor xmm3, xmm4
  pxor xmm1, xmm5
  pxor xmm2, xmm3
  movdqu xmm5, xmm2
  pxor xmm2, xmm2
  mov r12, 3774873600
  pinsrd xmm2, r12d, 3
  pclmulqdq xmm1, xmm2, 17
  movdqu xmm2, xmm1
  psrld xmm2, 31
  pslld xmm1, 1
  vpslldq xmm2, xmm2, 4
  pxor xmm1, xmm2
  pxor xmm1, xmm5
  pxor xmm1, xmm6
  pshufb xmm1, xmm8
  add rdx, 1
  add r9, 16
ALIGN 16
L71:
  cmp rdx, rcx
  jne L70
  jmp L69
L68:
L69:
  mov rax, r11
  and rax, 15
  cmp rax, 0
  jne L72
  jmp L73
L72:
  movdqu xmm2, xmmword ptr [r9 + 0]
  cmp rax, 8
  jae L74
  mov rcx, 0
  pinsrq xmm2, rcx, 1
  mov rcx, rax
  shl rcx, 3
  mov rdx, 1
  shl rdx, cl
  sub rdx, 1
  pextrq rcx, xmm2, 0
  and rcx, rdx
  pinsrq xmm2, rcx, 0
  jmp L75
L74:
  mov rcx, rax
  sub rcx, 8
  shl rcx, 3
  mov rdx, 1
  shl rdx, cl
  sub rdx, 1
  pextrq rcx, xmm2, 1
  and rcx, rdx
  pinsrq xmm2, rcx, 1
L75:
  pxor xmm1, xmm2
  movdqu xmm2, xmm11
  pshufb xmm1, xmm8
  movdqu xmm5, xmm1
  pclmulqdq xmm1, xmm2, 16
  movdqu xmm3, xmm1
  movdqu xmm1, xmm5
  pclmulqdq xmm1, xmm2, 1
  movdqu xmm4, xmm1
  movdqu xmm1, xmm5
  pclmulqdq xmm1, xmm2, 0
  pclmulqdq xmm5, xmm2, 17
  movdqu xmm2, xmm5
  movdqu xmm5, xmm1
  movdqu xmm1, xmm3
  mov r12, 0
  pinsrd xmm1, r12d, 0
  pshufd xmm1, xmm1, 14
  pxor xmm2, xmm1
  movdqu xmm1, xmm4
  mov r12, 0
  pinsrd xmm1, r12d, 0
  pshufd xmm1, xmm1, 14
  pxor xmm2, xmm1
  movdqu xmm1, xmm3
  mov r12, 0
  pinsrd xmm1, r12d, 3
  pshufd xmm1, xmm1, 79
  mov r12, 0
  pinsrd xmm4, r12d, 3
  pshufd xmm4, xmm4, 79
  pxor xmm1, xmm4
  pxor xmm1, xmm5
  movdqu xmm3, xmm1
  psrld xmm3, 31
  movdqu xmm4, xmm2
  psrld xmm4, 31
  pslld xmm1, 1
  pslld xmm2, 1
  vpslldq xmm5, xmm3, 4
  vpslldq xmm4, xmm4, 4
  mov r12, 0
  pinsrd xmm3, r12d, 0
  pshufd xmm3, xmm3, 3
  pxor xmm3, xmm4
  pxor xmm1, xmm5
  pxor xmm2, xmm3
  movdqu xmm6, xmm2
  pxor xmm2, xmm2
  mov r12, 3774873600
  pinsrd xmm2, r12d, 3
  movdqu xmm5, xmm1
  pclmulqdq xmm1, xmm2, 16
  movdqu xmm3, xmm1
  movdqu xmm1, xmm5
  pclmulqdq xmm1, xmm2, 1
  movdqu xmm4, xmm1
  movdqu xmm1, xmm5
  pclmulqdq xmm1, xmm2, 0
  pclmulqdq xmm5, xmm2, 17
  movdqu xmm2, xmm5
  movdqu xmm5, xmm1
  movdqu xmm1, xmm3
  mov r12, 0
  pinsrd xmm1, r12d, 0
  pshufd xmm1, xmm1, 14
  pxor xmm2, xmm1
  movdqu xmm1, xmm4
  mov r12, 0
  pinsrd xmm1, r12d, 0
  pshufd xmm1, xmm1, 14
  pxor xmm2, xmm1
  movdqu xmm1, xmm3
  mov r12, 0
  pinsrd xmm1, r12d, 3
  pshufd xmm1, xmm1, 79
  mov r12, 0
  pinsrd xmm4, r12d, 3
  pshufd xmm4, xmm4, 79
  pxor xmm1, xmm4
  pxor xmm1, xmm5
  movdqu xmm3, xmm1
  psrld xmm3, 31
  movdqu xmm4, xmm2
  psrld xmm4, 31
  pslld xmm1, 1
  pslld xmm2, 1
  vpslldq xmm5, xmm3, 4
  vpslldq xmm4, xmm4, 4
  mov r12, 0
  pinsrd xmm3, r12d, 0
  pshufd xmm3, xmm3, 3
  pxor xmm3, xmm4
  pxor xmm1, xmm5
  pxor xmm2, xmm3
  movdqu xmm5, xmm2
  pxor xmm2, xmm2
  mov r12, 3774873600
  pinsrd xmm2, r12d, 3
  pclmulqdq xmm1, xmm2, 17
  movdqu xmm2, xmm1
  psrld xmm2, 31
  pslld xmm1, 1
  vpslldq xmm2, xmm2, 4
  pxor xmm1, xmm2
  pxor xmm1, xmm5
  pxor xmm1, xmm6
  pshufb xmm1, xmm8
L73:
  jmp L67
L66:
L67:
  mov rax, r14
  mov rcx, r13
  cmp rcx, 0
  jbe L76
  mov rsi, rcx
  and rsi, 15
  shr rcx, 4
  mov rdx, 0
  mov r9, rax
  mov r10, rbx
  pxor xmm10, xmm10
  mov r12, 1
  pinsrd xmm10, r12d, 0
  jmp L79
ALIGN 16
L78:
  movdqu xmm0, xmmword ptr [r9 + 0]
  movdqu xmm2, xmm0
  pxor xmm1, xmm2
  movdqu xmm2, xmm11
  pshufb xmm1, xmm8
  movdqu xmm5, xmm1
  pclmulqdq xmm1, xmm2, 16
  movdqu xmm3, xmm1
  movdqu xmm1, xmm5
  pclmulqdq xmm1, xmm2, 1
  movdqu xmm4, xmm1
  movdqu xmm1, xmm5
  pclmulqdq xmm1, xmm2, 0
  pclmulqdq xmm5, xmm2, 17
  movdqu xmm2, xmm5
  movdqu xmm5, xmm1
  movdqu xmm1, xmm3
  mov r12, 0
  pinsrd xmm1, r12d, 0
  pshufd xmm1, xmm1, 14
  pxor xmm2, xmm1
  movdqu xmm1, xmm4
  mov r12, 0
  pinsrd xmm1, r12d, 0
  pshufd xmm1, xmm1, 14
  pxor xmm2, xmm1
  movdqu xmm1, xmm3
  mov r12, 0
  pinsrd xmm1, r12d, 3
  pshufd xmm1, xmm1, 79
  mov r12, 0
  pinsrd xmm4, r12d, 3
  pshufd xmm4, xmm4, 79
  pxor xmm1, xmm4
  pxor xmm1, xmm5
  movdqu xmm3, xmm1
  psrld xmm3, 31
  movdqu xmm4, xmm2
  psrld xmm4, 31
  pslld xmm1, 1
  pslld xmm2, 1
  vpslldq xmm5, xmm3, 4
  vpslldq xmm4, xmm4, 4
  mov r12, 0
  pinsrd xmm3, r12d, 0
  pshufd xmm3, xmm3, 3
  pxor xmm3, xmm4
  pxor xmm1, xmm5
  pxor xmm2, xmm3
  movdqu xmm6, xmm2
  pxor xmm2, xmm2
  mov r12, 3774873600
  pinsrd xmm2, r12d, 3
  movdqu xmm5, xmm1
  pclmulqdq xmm1, xmm2, 16
  movdqu xmm3, xmm1
  movdqu xmm1, xmm5
  pclmulqdq xmm1, xmm2, 1
  movdqu xmm4, xmm1
  movdqu xmm1, xmm5
  pclmulqdq xmm1, xmm2, 0
  pclmulqdq xmm5, xmm2, 17
  movdqu xmm2, xmm5
  movdqu xmm5, xmm1
  movdqu xmm1, xmm3
  mov r12, 0
  pinsrd xmm1, r12d, 0
  pshufd xmm1, xmm1, 14
  pxor xmm2, xmm1
  movdqu xmm1, xmm4
  mov r12, 0
  pinsrd xmm1, r12d, 0
  pshufd xmm1, xmm1, 14
  pxor xmm2, xmm1
  movdqu xmm1, xmm3
  mov r12, 0
  pinsrd xmm1, r12d, 3
  pshufd xmm1, xmm1, 79
  mov r12, 0
  pinsrd xmm4, r12d, 3
  pshufd xmm4, xmm4, 79
  pxor xmm1, xmm4
  pxor xmm1, xmm5
  movdqu xmm3, xmm1
  psrld xmm3, 31
  movdqu xmm4, xmm2
  psrld xmm4, 31
  pslld xmm1, 1
  pslld xmm2, 1
  vpslldq xmm5, xmm3, 4
  vpslldq xmm4, xmm4, 4
  mov r12, 0
  pinsrd xmm3, r12d, 0
  pshufd xmm3, xmm3, 3
  pxor xmm3, xmm4
  pxor xmm1, xmm5
  pxor xmm2, xmm3
  movdqu xmm5, xmm2
  pxor xmm2, xmm2
  mov r12, 3774873600
  pinsrd xmm2, r12d, 3
  pclmulqdq xmm1, xmm2, 17
  movdqu xmm2, xmm1
  psrld xmm2, 31
  pslld xmm1, 1
  vpslldq xmm2, xmm2, 4
  pxor xmm1, xmm2
  pxor xmm1, xmm5
  pxor xmm1, xmm6
  pshufb xmm1, xmm8
  movdqu xmm3, xmm0
  movdqu xmm0, xmm7
  pshufb xmm0, xmm8
  movdqu xmm2, xmmword ptr [r8 + 0]
  pxor xmm0, xmm2
  movdqu xmm2, xmmword ptr [r8 + 16]
  aesenc xmm0, xmm2
  movdqu xmm2, xmmword ptr [r8 + 32]
  aesenc xmm0, xmm2
  movdqu xmm2, xmmword ptr [r8 + 48]
  aesenc xmm0, xmm2
  movdqu xmm2, xmmword ptr [r8 + 64]
  aesenc xmm0, xmm2
  movdqu xmm2, xmmword ptr [r8 + 80]
  aesenc xmm0, xmm2
  movdqu xmm2, xmmword ptr [r8 + 96]
  aesenc xmm0, xmm2
  movdqu xmm2, xmmword ptr [r8 + 112]
  aesenc xmm0, xmm2
  movdqu xmm2, xmmword ptr [r8 + 128]
  aesenc xmm0, xmm2
  movdqu xmm2, xmmword ptr [r8 + 144]
  aesenc xmm0, xmm2
  movdqu xmm2, xmmword ptr [r8 + 160]
  aesenc xmm0, xmm2
  movdqu xmm2, xmmword ptr [r8 + 176]
  aesenc xmm0, xmm2
  movdqu xmm2, xmmword ptr [r8 + 192]
  aesenc xmm0, xmm2
  movdqu xmm2, xmmword ptr [r8 + 208]
  aesenc xmm0, xmm2
  movdqu xmm2, xmmword ptr [r8 + 224]
  aesenclast xmm0, xmm2
  pxor xmm2, xmm2
  pxor xmm3, xmm0
  movdqu xmmword ptr [r10 + 0], xmm3
  add rdx, 1
  add r9, 16
  add r10, 16
  paddd xmm7, xmm10
ALIGN 16
L79:
  cmp rdx, rcx
  jne L78
  cmp rsi, 0
  jne L80
  jmp L81
L80:
  movdqu xmm3, xmm1
  movdqu xmm2, xmmword ptr [r9 + 0]
  movdqu xmm1, xmm2
  movdqu xmm0, xmm7
  mov r12, 579005069656919567
  pinsrq xmm2, r12, 0
  mov r12, 283686952306183
  pinsrq xmm2, r12, 1
  pshufb xmm0, xmm2
  movdqu xmm2, xmmword ptr [r8 + 0]
  pxor xmm0, xmm2
  movdqu xmm2, xmmword ptr [r8 + 16]
  aesenc xmm0, xmm2
  movdqu xmm2, xmmword ptr [r8 + 32]
  aesenc xmm0, xmm2
  movdqu xmm2, xmmword ptr [r8 + 48]
  aesenc xmm0, xmm2
  movdqu xmm2, xmmword ptr [r8 + 64]
  aesenc xmm0, xmm2
  movdqu xmm2, xmmword ptr [r8 + 80]
  aesenc xmm0, xmm2
  movdqu xmm2, xmmword ptr [r8 + 96]
  aesenc xmm0, xmm2
  movdqu xmm2, xmmword ptr [r8 + 112]
  aesenc xmm0, xmm2
  movdqu xmm2, xmmword ptr [r8 + 128]
  aesenc xmm0, xmm2
  movdqu xmm2, xmmword ptr [r8 + 144]
  aesenc xmm0, xmm2
  movdqu xmm2, xmmword ptr [r8 + 160]
  aesenc xmm0, xmm2
  movdqu xmm2, xmmword ptr [r8 + 176]
  aesenc xmm0, xmm2
  movdqu xmm2, xmmword ptr [r8 + 192]
  aesenc xmm0, xmm2
  movdqu xmm2, xmmword ptr [r8 + 208]
  aesenc xmm0, xmm2
  movdqu xmm2, xmmword ptr [r8 + 224]
  aesenclast xmm0, xmm2
  pxor xmm2, xmm2
  pxor xmm1, xmm0
  movdqu xmmword ptr [r10 + 0], xmm1
  mov rax, rsi
  movdqu xmm1, xmm3
  movdqu xmm2, xmmword ptr [r9 + 0]
  cmp rax, 8
  jae L82
  mov rcx, 0
  pinsrq xmm2, rcx, 1
  mov rcx, rax
  shl rcx, 3
  mov rdx, 1
  shl rdx, cl
  sub rdx, 1
  pextrq rcx, xmm2, 0
  and rcx, rdx
  pinsrq xmm2, rcx, 0
  jmp L83
L82:
  mov rcx, rax
  sub rcx, 8
  shl rcx, 3
  mov rdx, 1
  shl rdx, cl
  sub rdx, 1
  pextrq rcx, xmm2, 1
  and rcx, rdx
  pinsrq xmm2, rcx, 1
L83:
  pxor xmm1, xmm2
  movdqu xmm2, xmm11
  pshufb xmm1, xmm8
  movdqu xmm5, xmm1
  pclmulqdq xmm1, xmm2, 16
  movdqu xmm3, xmm1
  movdqu xmm1, xmm5
  pclmulqdq xmm1, xmm2, 1
  movdqu xmm4, xmm1
  movdqu xmm1, xmm5
  pclmulqdq xmm1, xmm2, 0
  pclmulqdq xmm5, xmm2, 17
  movdqu xmm2, xmm5
  movdqu xmm5, xmm1
  movdqu xmm1, xmm3
  mov r12, 0
  pinsrd xmm1, r12d, 0
  pshufd xmm1, xmm1, 14
  pxor xmm2, xmm1
  movdqu xmm1, xmm4
  mov r12, 0
  pinsrd xmm1, r12d, 0
  pshufd xmm1, xmm1, 14
  pxor xmm2, xmm1
  movdqu xmm1, xmm3
  mov r12, 0
  pinsrd xmm1, r12d, 3
  pshufd xmm1, xmm1, 79
  mov r12, 0
  pinsrd xmm4, r12d, 3
  pshufd xmm4, xmm4, 79
  pxor xmm1, xmm4
  pxor xmm1, xmm5
  movdqu xmm3, xmm1
  psrld xmm3, 31
  movdqu xmm4, xmm2
  psrld xmm4, 31
  pslld xmm1, 1
  pslld xmm2, 1
  vpslldq xmm5, xmm3, 4
  vpslldq xmm4, xmm4, 4
  mov r12, 0
  pinsrd xmm3, r12d, 0
  pshufd xmm3, xmm3, 3
  pxor xmm3, xmm4
  pxor xmm1, xmm5
  pxor xmm2, xmm3
  movdqu xmm6, xmm2
  pxor xmm2, xmm2
  mov r12, 3774873600
  pinsrd xmm2, r12d, 3
  movdqu xmm5, xmm1
  pclmulqdq xmm1, xmm2, 16
  movdqu xmm3, xmm1
  movdqu xmm1, xmm5
  pclmulqdq xmm1, xmm2, 1
  movdqu xmm4, xmm1
  movdqu xmm1, xmm5
  pclmulqdq xmm1, xmm2, 0
  pclmulqdq xmm5, xmm2, 17
  movdqu xmm2, xmm5
  movdqu xmm5, xmm1
  movdqu xmm1, xmm3
  mov r12, 0
  pinsrd xmm1, r12d, 0
  pshufd xmm1, xmm1, 14
  pxor xmm2, xmm1
  movdqu xmm1, xmm4
  mov r12, 0
  pinsrd xmm1, r12d, 0
  pshufd xmm1, xmm1, 14
  pxor xmm2, xmm1
  movdqu xmm1, xmm3
  mov r12, 0
  pinsrd xmm1, r12d, 3
  pshufd xmm1, xmm1, 79
  mov r12, 0
  pinsrd xmm4, r12d, 3
  pshufd xmm4, xmm4, 79
  pxor xmm1, xmm4
  pxor xmm1, xmm5
  movdqu xmm3, xmm1
  psrld xmm3, 31
  movdqu xmm4, xmm2
  psrld xmm4, 31
  pslld xmm1, 1
  pslld xmm2, 1
  vpslldq xmm5, xmm3, 4
  vpslldq xmm4, xmm4, 4
  mov r12, 0
  pinsrd xmm3, r12d, 0
  pshufd xmm3, xmm3, 3
  pxor xmm3, xmm4
  pxor xmm1, xmm5
  pxor xmm2, xmm3
  movdqu xmm5, xmm2
  pxor xmm2, xmm2
  mov r12, 3774873600
  pinsrd xmm2, r12d, 3
  pclmulqdq xmm1, xmm2, 17
  movdqu xmm2, xmm1
  psrld xmm2, 31
  pslld xmm1, 1
  vpslldq xmm2, xmm2, 4
  pxor xmm1, xmm2
  pxor xmm1, xmm5
  pxor xmm1, xmm6
  pshufb xmm1, xmm8
L81:
  jmp L77
L76:
L77:
  pxor xmm2, xmm2
  mov rax, r13
  imul rax, 8
  pinsrd xmm2, eax, 0
  mov rax, r11
  imul rax, 8
  pinsrd xmm2, eax, 2
  pshufb xmm2, xmm8
  pxor xmm1, xmm2
  movdqu xmm2, xmm11
  pshufb xmm1, xmm8
  movdqu xmm5, xmm1
  pclmulqdq xmm1, xmm2, 16
  movdqu xmm3, xmm1
  movdqu xmm1, xmm5
  pclmulqdq xmm1, xmm2, 1
  movdqu xmm4, xmm1
  movdqu xmm1, xmm5
  pclmulqdq xmm1, xmm2, 0
  pclmulqdq xmm5, xmm2, 17
  movdqu xmm2, xmm5
  movdqu xmm5, xmm1
  movdqu xmm1, xmm3
  mov r12, 0
  pinsrd xmm1, r12d, 0
  pshufd xmm1, xmm1, 14
  pxor xmm2, xmm1
  movdqu xmm1, xmm4
  mov r12, 0
  pinsrd xmm1, r12d, 0
  pshufd xmm1, xmm1, 14
  pxor xmm2, xmm1
  movdqu xmm1, xmm3
  mov r12, 0
  pinsrd xmm1, r12d, 3
  pshufd xmm1, xmm1, 79
  mov r12, 0
  pinsrd xmm4, r12d, 3
  pshufd xmm4, xmm4, 79
  pxor xmm1, xmm4
  pxor xmm1, xmm5
  movdqu xmm3, xmm1
  psrld xmm3, 31
  movdqu xmm4, xmm2
  psrld xmm4, 31
  pslld xmm1, 1
  pslld xmm2, 1
  vpslldq xmm5, xmm3, 4
  vpslldq xmm4, xmm4, 4
  mov r12, 0
  pinsrd xmm3, r12d, 0
  pshufd xmm3, xmm3, 3
  pxor xmm3, xmm4
  pxor xmm1, xmm5
  pxor xmm2, xmm3
  movdqu xmm6, xmm2
  pxor xmm2, xmm2
  mov r12, 3774873600
  pinsrd xmm2, r12d, 3
  movdqu xmm5, xmm1
  pclmulqdq xmm1, xmm2, 16
  movdqu xmm3, xmm1
  movdqu xmm1, xmm5
  pclmulqdq xmm1, xmm2, 1
  movdqu xmm4, xmm1
  movdqu xmm1, xmm5
  pclmulqdq xmm1, xmm2, 0
  pclmulqdq xmm5, xmm2, 17
  movdqu xmm2, xmm5
  movdqu xmm5, xmm1
  movdqu xmm1, xmm3
  mov r12, 0
  pinsrd xmm1, r12d, 0
  pshufd xmm1, xmm1, 14
  pxor xmm2, xmm1
  movdqu xmm1, xmm4
  mov r12, 0
  pinsrd xmm1, r12d, 0
  pshufd xmm1, xmm1, 14
  pxor xmm2, xmm1
  movdqu xmm1, xmm3
  mov r12, 0
  pinsrd xmm1, r12d, 3
  pshufd xmm1, xmm1, 79
  mov r12, 0
  pinsrd xmm4, r12d, 3
  pshufd xmm4, xmm4, 79
  pxor xmm1, xmm4
  pxor xmm1, xmm5
  movdqu xmm3, xmm1
  psrld xmm3, 31
  movdqu xmm4, xmm2
  psrld xmm4, 31
  pslld xmm1, 1
  pslld xmm2, 1
  vpslldq xmm5, xmm3, 4
  vpslldq xmm4, xmm4, 4
  mov r12, 0
  pinsrd xmm3, r12d, 0
  pshufd xmm3, xmm3, 3
  pxor xmm3, xmm4
  pxor xmm1, xmm5
  pxor xmm2, xmm3
  movdqu xmm5, xmm2
  pxor xmm2, xmm2
  mov r12, 3774873600
  pinsrd xmm2, r12d, 3
  pclmulqdq xmm1, xmm2, 17
  movdqu xmm2, xmm1
  psrld xmm2, 31
  pslld xmm1, 1
  vpslldq xmm2, xmm2, 4
  pxor xmm1, xmm2
  pxor xmm1, xmm5
  pxor xmm1, xmm6
  pshufb xmm1, xmm8
  mov r12, 1
  pinsrd xmm7, r12d, 0
  movdqu xmm0, xmm7
  mov r12, 579005069656919567
  pinsrq xmm2, r12, 0
  mov r12, 283686952306183
  pinsrq xmm2, r12, 1
  pshufb xmm0, xmm2
  movdqu xmm2, xmmword ptr [r8 + 0]
  pxor xmm0, xmm2
  movdqu xmm2, xmmword ptr [r8 + 16]
  aesenc xmm0, xmm2
  movdqu xmm2, xmmword ptr [r8 + 32]
  aesenc xmm0, xmm2
  movdqu xmm2, xmmword ptr [r8 + 48]
  aesenc xmm0, xmm2
  movdqu xmm2, xmmword ptr [r8 + 64]
  aesenc xmm0, xmm2
  movdqu xmm2, xmmword ptr [r8 + 80]
  aesenc xmm0, xmm2
  movdqu xmm2, xmmword ptr [r8 + 96]
  aesenc xmm0, xmm2
  movdqu xmm2, xmmword ptr [r8 + 112]
  aesenc xmm0, xmm2
  movdqu xmm2, xmmword ptr [r8 + 128]
  aesenc xmm0, xmm2
  movdqu xmm2, xmmword ptr [r8 + 144]
  aesenc xmm0, xmm2
  movdqu xmm2, xmmword ptr [r8 + 160]
  aesenc xmm0, xmm2
  movdqu xmm2, xmmword ptr [r8 + 176]
  aesenc xmm0, xmm2
  movdqu xmm2, xmmword ptr [r8 + 192]
  aesenc xmm0, xmm2
  movdqu xmm2, xmmword ptr [r8 + 208]
  aesenc xmm0, xmm2
  movdqu xmm2, xmmword ptr [r8 + 224]
  aesenclast xmm0, xmm2
  pxor xmm2, xmm2
  pxor xmm1, xmm0
  movdqu xmm0, xmmword ptr [r15 + 0]
  pcmpeqd xmm0, xmm1
  pextrq rdx, xmm0, 0
  cmp rdx, 18446744073709551615
  jne L84
  mov rax, 0
  jmp L85
L84:
  mov rax, 1
L85:
  pextrq rdx, xmm0, 1
  cmp rdx, 18446744073709551615
  jne L86
  mov rdx, 0
  jmp L87
L86:
  mov rdx, 1
L87:
  add rax, rdx
  mov rdx, rax
  pop rbx
  pop rbp
  pop rdi
  pop rsi
  pop r12
  pop r13
  pop r14
  pop r15
  pop rax
  pinsrq xmm6, rax, 1
  pop rax
  pinsrq xmm6, rax, 0
  pop rax
  pinsrq xmm7, rax, 1
  pop rax
  pinsrq xmm7, rax, 0
  pop rax
  pinsrq xmm8, rax, 1
  pop rax
  pinsrq xmm8, rax, 0
  pop rax
  pinsrq xmm9, rax, 1
  pop rax
  pinsrq xmm9, rax, 0
  pop rax
  pinsrq xmm10, rax, 1
  pop rax
  pinsrq xmm10, rax, 0
  pop rax
  pinsrq xmm11, rax, 1
  pop rax
  pinsrq xmm11, rax, 0
  pop rax
  pinsrq xmm12, rax, 1
  pop rax
  pinsrq xmm12, rax, 0
  pop rax
  pinsrq xmm13, rax, 1
  pop rax
  pinsrq xmm13, rax, 0
  pop rax
  pinsrq xmm14, rax, 1
  pop rax
  pinsrq xmm14, rax, 0
  pop rax
  pinsrq xmm15, rax, 1
  pop rax
  pinsrq xmm15, rax, 0
  mov rax, rdx
  ret
gcm256_decrypt endp
ALIGN 16
AESEncryptBlock_win_aes128_encrypt_block_win proc
  movdqu xmm0, xmmword ptr [rdx + 0]
  movdqu xmm2, xmmword ptr [r8 + 0]
  pxor xmm0, xmm2
  movdqu xmm2, xmmword ptr [r8 + 16]
  aesenc xmm0, xmm2
  movdqu xmm2, xmmword ptr [r8 + 32]
  aesenc xmm0, xmm2
  movdqu xmm2, xmmword ptr [r8 + 48]
  aesenc xmm0, xmm2
  movdqu xmm2, xmmword ptr [r8 + 64]
  aesenc xmm0, xmm2
  movdqu xmm2, xmmword ptr [r8 + 80]
  aesenc xmm0, xmm2
  movdqu xmm2, xmmword ptr [r8 + 96]
  aesenc xmm0, xmm2
  movdqu xmm2, xmmword ptr [r8 + 112]
  aesenc xmm0, xmm2
  movdqu xmm2, xmmword ptr [r8 + 128]
  aesenc xmm0, xmm2
  movdqu xmm2, xmmword ptr [r8 + 144]
  aesenc xmm0, xmm2
  movdqu xmm2, xmmword ptr [r8 + 160]
  aesenclast xmm0, xmm2
  pxor xmm2, xmm2
  movdqu xmmword ptr [rcx + 0], xmm0
  ret
AESEncryptBlock_win_aes128_encrypt_block_win endp
ALIGN 16
AESEncryptBE_win_aes128_encrypt_block_be_win proc
  mov rax, 579005069656919567
  pinsrq xmm2, rax, 0
  mov rax, 283686952306183
  pinsrq xmm2, rax, 1
  movdqu xmm0, xmmword ptr [rdx + 0]
  pshufb xmm0, xmm2
  movdqu xmm2, xmmword ptr [r8 + 0]
  pxor xmm0, xmm2
  movdqu xmm2, xmmword ptr [r8 + 16]
  aesenc xmm0, xmm2
  movdqu xmm2, xmmword ptr [r8 + 32]
  aesenc xmm0, xmm2
  movdqu xmm2, xmmword ptr [r8 + 48]
  aesenc xmm0, xmm2
  movdqu xmm2, xmmword ptr [r8 + 64]
  aesenc xmm0, xmm2
  movdqu xmm2, xmmword ptr [r8 + 80]
  aesenc xmm0, xmm2
  movdqu xmm2, xmmword ptr [r8 + 96]
  aesenc xmm0, xmm2
  movdqu xmm2, xmmword ptr [r8 + 112]
  aesenc xmm0, xmm2
  movdqu xmm2, xmmword ptr [r8 + 128]
  aesenc xmm0, xmm2
  movdqu xmm2, xmmword ptr [r8 + 144]
  aesenc xmm0, xmm2
  movdqu xmm2, xmmword ptr [r8 + 160]
  aesenclast xmm0, xmm2
  pxor xmm2, xmm2
  movdqu xmmword ptr [rcx + 0], xmm0
  ret
AESEncryptBE_win_aes128_encrypt_block_be_win endp
ALIGN 16
GCTR_win_gctr_bytes_extra_buffer_win proc
  mov rax, r9
  mov r11, r8
  mov r9, rcx
  mov r10, qword ptr [rsp + 40]
  shr rdx, 4
  imul rdx, 16
  add r9, rdx
  add r10, rdx
  mov r8, rax
  movdqu xmm3, xmm7
  movdqu xmm7, xmmword ptr [r11 + 0]
  mov r11, r12
  movdqu xmm2, xmmword ptr [r9 + 0]
  movdqu xmm1, xmm2
  movdqu xmm0, xmm7
  mov r12, 579005069656919567
  pinsrq xmm2, r12, 0
  mov r12, 283686952306183
  pinsrq xmm2, r12, 1
  pshufb xmm0, xmm2
  movdqu xmm2, xmmword ptr [r8 + 0]
  pxor xmm0, xmm2
  movdqu xmm2, xmmword ptr [r8 + 16]
  aesenc xmm0, xmm2
  movdqu xmm2, xmmword ptr [r8 + 32]
  aesenc xmm0, xmm2
  movdqu xmm2, xmmword ptr [r8 + 48]
  aesenc xmm0, xmm2
  movdqu xmm2, xmmword ptr [r8 + 64]
  aesenc xmm0, xmm2
  movdqu xmm2, xmmword ptr [r8 + 80]
  aesenc xmm0, xmm2
  movdqu xmm2, xmmword ptr [r8 + 96]
  aesenc xmm0, xmm2
  movdqu xmm2, xmmword ptr [r8 + 112]
  aesenc xmm0, xmm2
  movdqu xmm2, xmmword ptr [r8 + 128]
  aesenc xmm0, xmm2
  movdqu xmm2, xmmword ptr [r8 + 144]
  aesenc xmm0, xmm2
  movdqu xmm2, xmmword ptr [r8 + 160]
  aesenclast xmm0, xmm2
  pxor xmm2, xmm2
  pxor xmm1, xmm0
  movdqu xmmword ptr [r10 + 0], xmm1
  mov r12, r11
  movdqu xmm7, xmm3
  ret
GCTR_win_gctr_bytes_extra_buffer_win endp
ALIGN 16
GHash_stdcall_win_ghash_incremental_bytes_stdcall_win proc
  mov r10, r12
  movdqu xmm0, xmm8
  pextrq rax, xmm11, 0
  push rax
  pextrq rax, xmm11, 1
  push rax
  pextrq rax, xmm6, 0
  push rax
  pextrq rax, xmm6, 1
  push rax
  push rdx
  mov r11, 579005069656919567
  pinsrq xmm8, r11, 0
  mov r11, 283686952306183
  pinsrq xmm8, r11, 1
  mov r11, r9
  movdqu xmm1, xmmword ptr [rdx + 0]
  movdqu xmm11, xmmword ptr [rcx + 0]
  mov rax, r8
  pshufb xmm11, xmm8
  cmp r11, 0
  jbe L88
  mov rcx, r11
  shr rcx, 4
  mov r9, rax
  cmp rcx, 0
  je L90
  mov rdx, 0
  jmp L93
ALIGN 16
L92:
  movdqu xmm2, xmmword ptr [r9 + 0]
  pxor xmm1, xmm2
  movdqu xmm2, xmm11
  pshufb xmm1, xmm8
  movdqu xmm5, xmm1
  pclmulqdq xmm1, xmm2, 16
  movdqu xmm3, xmm1
  movdqu xmm1, xmm5
  pclmulqdq xmm1, xmm2, 1
  movdqu xmm4, xmm1
  movdqu xmm1, xmm5
  pclmulqdq xmm1, xmm2, 0
  pclmulqdq xmm5, xmm2, 17
  movdqu xmm2, xmm5
  movdqu xmm5, xmm1
  movdqu xmm1, xmm3
  mov r12, 0
  pinsrd xmm1, r12d, 0
  pshufd xmm1, xmm1, 14
  pxor xmm2, xmm1
  movdqu xmm1, xmm4
  mov r12, 0
  pinsrd xmm1, r12d, 0
  pshufd xmm1, xmm1, 14
  pxor xmm2, xmm1
  movdqu xmm1, xmm3
  mov r12, 0
  pinsrd xmm1, r12d, 3
  pshufd xmm1, xmm1, 79
  mov r12, 0
  pinsrd xmm4, r12d, 3
  pshufd xmm4, xmm4, 79
  pxor xmm1, xmm4
  pxor xmm1, xmm5
  movdqu xmm3, xmm1
  psrld xmm3, 31
  movdqu xmm4, xmm2
  psrld xmm4, 31
  pslld xmm1, 1
  pslld xmm2, 1
  vpslldq xmm5, xmm3, 4
  vpslldq xmm4, xmm4, 4
  mov r12, 0
  pinsrd xmm3, r12d, 0
  pshufd xmm3, xmm3, 3
  pxor xmm3, xmm4
  pxor xmm1, xmm5
  pxor xmm2, xmm3
  movdqu xmm6, xmm2
  pxor xmm2, xmm2
  mov r12, 3774873600
  pinsrd xmm2, r12d, 3
  movdqu xmm5, xmm1
  pclmulqdq xmm1, xmm2, 16
  movdqu xmm3, xmm1
  movdqu xmm1, xmm5
  pclmulqdq xmm1, xmm2, 1
  movdqu xmm4, xmm1
  movdqu xmm1, xmm5
  pclmulqdq xmm1, xmm2, 0
  pclmulqdq xmm5, xmm2, 17
  movdqu xmm2, xmm5
  movdqu xmm5, xmm1
  movdqu xmm1, xmm3
  mov r12, 0
  pinsrd xmm1, r12d, 0
  pshufd xmm1, xmm1, 14
  pxor xmm2, xmm1
  movdqu xmm1, xmm4
  mov r12, 0
  pinsrd xmm1, r12d, 0
  pshufd xmm1, xmm1, 14
  pxor xmm2, xmm1
  movdqu xmm1, xmm3
  mov r12, 0
  pinsrd xmm1, r12d, 3
  pshufd xmm1, xmm1, 79
  mov r12, 0
  pinsrd xmm4, r12d, 3
  pshufd xmm4, xmm4, 79
  pxor xmm1, xmm4
  pxor xmm1, xmm5
  movdqu xmm3, xmm1
  psrld xmm3, 31
  movdqu xmm4, xmm2
  psrld xmm4, 31
  pslld xmm1, 1
  pslld xmm2, 1
  vpslldq xmm5, xmm3, 4
  vpslldq xmm4, xmm4, 4
  mov r12, 0
  pinsrd xmm3, r12d, 0
  pshufd xmm3, xmm3, 3
  pxor xmm3, xmm4
  pxor xmm1, xmm5
  pxor xmm2, xmm3
  movdqu xmm5, xmm2
  pxor xmm2, xmm2
  mov r12, 3774873600
  pinsrd xmm2, r12d, 3
  pclmulqdq xmm1, xmm2, 17
  movdqu xmm2, xmm1
  psrld xmm2, 31
  pslld xmm1, 1
  vpslldq xmm2, xmm2, 4
  pxor xmm1, xmm2
  pxor xmm1, xmm5
  pxor xmm1, xmm6
  pshufb xmm1, xmm8
  add rdx, 1
  add r9, 16
ALIGN 16
L93:
  cmp rdx, rcx
  jne L92
  jmp L91
L90:
L91:
  mov rax, r11
  and rax, 15
  cmp rax, 0
  jne L94
  jmp L95
L94:
  movdqu xmm2, xmmword ptr [r9 + 0]
  cmp rax, 8
  jae L96
  mov rcx, 0
  pinsrq xmm2, rcx, 1
  mov rcx, rax
  shl rcx, 3
  mov rdx, 1
  shl rdx, cl
  sub rdx, 1
  pextrq rcx, xmm2, 0
  and rcx, rdx
  pinsrq xmm2, rcx, 0
  jmp L97
L96:
  mov rcx, rax
  sub rcx, 8
  shl rcx, 3
  mov rdx, 1
  shl rdx, cl
  sub rdx, 1
  pextrq rcx, xmm2, 1
  and rcx, rdx
  pinsrq xmm2, rcx, 1
L97:
  pxor xmm1, xmm2
  movdqu xmm2, xmm11
  pshufb xmm1, xmm8
  movdqu xmm5, xmm1
  pclmulqdq xmm1, xmm2, 16
  movdqu xmm3, xmm1
  movdqu xmm1, xmm5
  pclmulqdq xmm1, xmm2, 1
  movdqu xmm4, xmm1
  movdqu xmm1, xmm5
  pclmulqdq xmm1, xmm2, 0
  pclmulqdq xmm5, xmm2, 17
  movdqu xmm2, xmm5
  movdqu xmm5, xmm1
  movdqu xmm1, xmm3
  mov r12, 0
  pinsrd xmm1, r12d, 0
  pshufd xmm1, xmm1, 14
  pxor xmm2, xmm1
  movdqu xmm1, xmm4
  mov r12, 0
  pinsrd xmm1, r12d, 0
  pshufd xmm1, xmm1, 14
  pxor xmm2, xmm1
  movdqu xmm1, xmm3
  mov r12, 0
  pinsrd xmm1, r12d, 3
  pshufd xmm1, xmm1, 79
  mov r12, 0
  pinsrd xmm4, r12d, 3
  pshufd xmm4, xmm4, 79
  pxor xmm1, xmm4
  pxor xmm1, xmm5
  movdqu xmm3, xmm1
  psrld xmm3, 31
  movdqu xmm4, xmm2
  psrld xmm4, 31
  pslld xmm1, 1
  pslld xmm2, 1
  vpslldq xmm5, xmm3, 4
  vpslldq xmm4, xmm4, 4
  mov r12, 0
  pinsrd xmm3, r12d, 0
  pshufd xmm3, xmm3, 3
  pxor xmm3, xmm4
  pxor xmm1, xmm5
  pxor xmm2, xmm3
  movdqu xmm6, xmm2
  pxor xmm2, xmm2
  mov r12, 3774873600
  pinsrd xmm2, r12d, 3
  movdqu xmm5, xmm1
  pclmulqdq xmm1, xmm2, 16
  movdqu xmm3, xmm1
  movdqu xmm1, xmm5
  pclmulqdq xmm1, xmm2, 1
  movdqu xmm4, xmm1
  movdqu xmm1, xmm5
  pclmulqdq xmm1, xmm2, 0
  pclmulqdq xmm5, xmm2, 17
  movdqu xmm2, xmm5
  movdqu xmm5, xmm1
  movdqu xmm1, xmm3
  mov r12, 0
  pinsrd xmm1, r12d, 0
  pshufd xmm1, xmm1, 14
  pxor xmm2, xmm1
  movdqu xmm1, xmm4
  mov r12, 0
  pinsrd xmm1, r12d, 0
  pshufd xmm1, xmm1, 14
  pxor xmm2, xmm1
  movdqu xmm1, xmm3
  mov r12, 0
  pinsrd xmm1, r12d, 3
  pshufd xmm1, xmm1, 79
  mov r12, 0
  pinsrd xmm4, r12d, 3
  pshufd xmm4, xmm4, 79
  pxor xmm1, xmm4
  pxor xmm1, xmm5
  movdqu xmm3, xmm1
  psrld xmm3, 31
  movdqu xmm4, xmm2
  psrld xmm4, 31
  pslld xmm1, 1
  pslld xmm2, 1
  vpslldq xmm5, xmm3, 4
  vpslldq xmm4, xmm4, 4
  mov r12, 0
  pinsrd xmm3, r12d, 0
  pshufd xmm3, xmm3, 3
  pxor xmm3, xmm4
  pxor xmm1, xmm5
  pxor xmm2, xmm3
  movdqu xmm5, xmm2
  pxor xmm2, xmm2
  mov r12, 3774873600
  pinsrd xmm2, r12d, 3
  pclmulqdq xmm1, xmm2, 17
  movdqu xmm2, xmm1
  psrld xmm2, 31
  pslld xmm1, 1
  vpslldq xmm2, xmm2, 4
  pxor xmm1, xmm2
  pxor xmm1, xmm5
  pxor xmm1, xmm6
  pshufb xmm1, xmm8
L95:
  jmp L89
L88:
L89:
  pop rdx
  movdqu xmmword ptr [rdx + 0], xmm1
  mov r12, r10
  pop rax
  pinsrq xmm6, rax, 1
  pop rax
  pinsrq xmm6, rax, 0
  pop rax
  pinsrq xmm11, rax, 1
  pop rax
  pinsrq xmm11, rax, 0
  movdqu xmm8, xmm0
  ret
GHash_stdcall_win_ghash_incremental_bytes_stdcall_win endp
ALIGN 16
GHash_one_block_win_ghash_incremental_one_block_buffer_win proc
  pextrq rax, xmm11, 0
  push rax
  pextrq rax, xmm11, 1
  push rax
  pextrq rax, xmm6, 0
  push rax
  pextrq rax, xmm6, 1
  push rax
  mov rax, r12
  imul r9, 16
  add r9, r8
  movdqu xmm2, xmmword ptr [r9 + 0]
  movdqu xmm0, xmm8
  mov r11, 579005069656919567
  pinsrq xmm8, r11, 0
  mov r11, 283686952306183
  pinsrq xmm8, r11, 1
  movdqu xmm1, xmmword ptr [rdx + 0]
  movdqu xmm11, xmmword ptr [rcx + 0]
  pshufb xmm11, xmm8
  pxor xmm1, xmm2
  movdqu xmm2, xmm11
  pshufb xmm1, xmm8
  movdqu xmm5, xmm1
  pclmulqdq xmm1, xmm2, 16
  movdqu xmm3, xmm1
  movdqu xmm1, xmm5
  pclmulqdq xmm1, xmm2, 1
  movdqu xmm4, xmm1
  movdqu xmm1, xmm5
  pclmulqdq xmm1, xmm2, 0
  pclmulqdq xmm5, xmm2, 17
  movdqu xmm2, xmm5
  movdqu xmm5, xmm1
  movdqu xmm1, xmm3
  mov r12, 0
  pinsrd xmm1, r12d, 0
  pshufd xmm1, xmm1, 14
  pxor xmm2, xmm1
  movdqu xmm1, xmm4
  mov r12, 0
  pinsrd xmm1, r12d, 0
  pshufd xmm1, xmm1, 14
  pxor xmm2, xmm1
  movdqu xmm1, xmm3
  mov r12, 0
  pinsrd xmm1, r12d, 3
  pshufd xmm1, xmm1, 79
  mov r12, 0
  pinsrd xmm4, r12d, 3
  pshufd xmm4, xmm4, 79
  pxor xmm1, xmm4
  pxor xmm1, xmm5
  movdqu xmm3, xmm1
  psrld xmm3, 31
  movdqu xmm4, xmm2
  psrld xmm4, 31
  pslld xmm1, 1
  pslld xmm2, 1
  vpslldq xmm5, xmm3, 4
  vpslldq xmm4, xmm4, 4
  mov r12, 0
  pinsrd xmm3, r12d, 0
  pshufd xmm3, xmm3, 3
  pxor xmm3, xmm4
  pxor xmm1, xmm5
  pxor xmm2, xmm3
  movdqu xmm6, xmm2
  pxor xmm2, xmm2
  mov r12, 3774873600
  pinsrd xmm2, r12d, 3
  movdqu xmm5, xmm1
  pclmulqdq xmm1, xmm2, 16
  movdqu xmm3, xmm1
  movdqu xmm1, xmm5
  pclmulqdq xmm1, xmm2, 1
  movdqu xmm4, xmm1
  movdqu xmm1, xmm5
  pclmulqdq xmm1, xmm2, 0
  pclmulqdq xmm5, xmm2, 17
  movdqu xmm2, xmm5
  movdqu xmm5, xmm1
  movdqu xmm1, xmm3
  mov r12, 0
  pinsrd xmm1, r12d, 0
  pshufd xmm1, xmm1, 14
  pxor xmm2, xmm1
  movdqu xmm1, xmm4
  mov r12, 0
  pinsrd xmm1, r12d, 0
  pshufd xmm1, xmm1, 14
  pxor xmm2, xmm1
  movdqu xmm1, xmm3
  mov r12, 0
  pinsrd xmm1, r12d, 3
  pshufd xmm1, xmm1, 79
  mov r12, 0
  pinsrd xmm4, r12d, 3
  pshufd xmm4, xmm4, 79
  pxor xmm1, xmm4
  pxor xmm1, xmm5
  movdqu xmm3, xmm1
  psrld xmm3, 31
  movdqu xmm4, xmm2
  psrld xmm4, 31
  pslld xmm1, 1
  pslld xmm2, 1
  vpslldq xmm5, xmm3, 4
  vpslldq xmm4, xmm4, 4
  mov r12, 0
  pinsrd xmm3, r12d, 0
  pshufd xmm3, xmm3, 3
  pxor xmm3, xmm4
  pxor xmm1, xmm5
  pxor xmm2, xmm3
  movdqu xmm5, xmm2
  pxor xmm2, xmm2
  mov r12, 3774873600
  pinsrd xmm2, r12d, 3
  pclmulqdq xmm1, xmm2, 17
  movdqu xmm2, xmm1
  psrld xmm2, 31
  pslld xmm1, 1
  vpslldq xmm2, xmm2, 4
  pxor xmm1, xmm2
  pxor xmm1, xmm5
  pxor xmm1, xmm6
  pshufb xmm1, xmm8
  movdqu xmmword ptr [rdx + 0], xmm1
  movdqu xmm8, xmm0
  mov r12, rax
  pop rax
  pinsrq xmm6, rax, 1
  pop rax
  pinsrq xmm6, rax, 0
  pop rax
  pinsrq xmm11, rax, 1
  pop rax
  pinsrq xmm11, rax, 0
  ret
GHash_one_block_win_ghash_incremental_one_block_buffer_win endp
ALIGN 16
GHash_extra_win_ghash_incremental_extra_stdcall_win proc
  mov r10, r12
  pextrq rax, xmm11, 0
  push rax
  pextrq rax, xmm11, 1
  push rax
  pextrq rax, xmm6, 0
  push rax
  pextrq rax, xmm6, 1
  push rax
  movdqu xmm0, xmm8
  mov rax, r9
  and rax, 15
  shr r9, 4
  imul r9, 16
  add rcx, r9
  mov r9, rcx
  mov r11, 579005069656919567
  pinsrq xmm8, r11, 0
  mov r11, 283686952306183
  pinsrq xmm8, r11, 1
  movdqu xmm1, xmmword ptr [rdx + 0]
  movdqu xmm11, xmmword ptr [r8 + 0]
  pshufb xmm11, xmm8
  mov r8, rdx
  movdqu xmm2, xmmword ptr [r9 + 0]
  cmp rax, 8
  jae L98
  mov rcx, 0
  pinsrq xmm2, rcx, 1
  mov rcx, rax
  shl rcx, 3
  mov rdx, 1
  shl rdx, cl
  sub rdx, 1
  pextrq rcx, xmm2, 0
  and rcx, rdx
  pinsrq xmm2, rcx, 0
  jmp L99
L98:
  mov rcx, rax
  sub rcx, 8
  shl rcx, 3
  mov rdx, 1
  shl rdx, cl
  sub rdx, 1
  pextrq rcx, xmm2, 1
  and rcx, rdx
  pinsrq xmm2, rcx, 1
L99:
  pxor xmm1, xmm2
  movdqu xmm2, xmm11
  pshufb xmm1, xmm8
  movdqu xmm5, xmm1
  pclmulqdq xmm1, xmm2, 16
  movdqu xmm3, xmm1
  movdqu xmm1, xmm5
  pclmulqdq xmm1, xmm2, 1
  movdqu xmm4, xmm1
  movdqu xmm1, xmm5
  pclmulqdq xmm1, xmm2, 0
  pclmulqdq xmm5, xmm2, 17
  movdqu xmm2, xmm5
  movdqu xmm5, xmm1
  movdqu xmm1, xmm3
  mov r12, 0
  pinsrd xmm1, r12d, 0
  pshufd xmm1, xmm1, 14
  pxor xmm2, xmm1
  movdqu xmm1, xmm4
  mov r12, 0
  pinsrd xmm1, r12d, 0
  pshufd xmm1, xmm1, 14
  pxor xmm2, xmm1
  movdqu xmm1, xmm3
  mov r12, 0
  pinsrd xmm1, r12d, 3
  pshufd xmm1, xmm1, 79
  mov r12, 0
  pinsrd xmm4, r12d, 3
  pshufd xmm4, xmm4, 79
  pxor xmm1, xmm4
  pxor xmm1, xmm5
  movdqu xmm3, xmm1
  psrld xmm3, 31
  movdqu xmm4, xmm2
  psrld xmm4, 31
  pslld xmm1, 1
  pslld xmm2, 1
  vpslldq xmm5, xmm3, 4
  vpslldq xmm4, xmm4, 4
  mov r12, 0
  pinsrd xmm3, r12d, 0
  pshufd xmm3, xmm3, 3
  pxor xmm3, xmm4
  pxor xmm1, xmm5
  pxor xmm2, xmm3
  movdqu xmm6, xmm2
  pxor xmm2, xmm2
  mov r12, 3774873600
  pinsrd xmm2, r12d, 3
  movdqu xmm5, xmm1
  pclmulqdq xmm1, xmm2, 16
  movdqu xmm3, xmm1
  movdqu xmm1, xmm5
  pclmulqdq xmm1, xmm2, 1
  movdqu xmm4, xmm1
  movdqu xmm1, xmm5
  pclmulqdq xmm1, xmm2, 0
  pclmulqdq xmm5, xmm2, 17
  movdqu xmm2, xmm5
  movdqu xmm5, xmm1
  movdqu xmm1, xmm3
  mov r12, 0
  pinsrd xmm1, r12d, 0
  pshufd xmm1, xmm1, 14
  pxor xmm2, xmm1
  movdqu xmm1, xmm4
  mov r12, 0
  pinsrd xmm1, r12d, 0
  pshufd xmm1, xmm1, 14
  pxor xmm2, xmm1
  movdqu xmm1, xmm3
  mov r12, 0
  pinsrd xmm1, r12d, 3
  pshufd xmm1, xmm1, 79
  mov r12, 0
  pinsrd xmm4, r12d, 3
  pshufd xmm4, xmm4, 79
  pxor xmm1, xmm4
  pxor xmm1, xmm5
  movdqu xmm3, xmm1
  psrld xmm3, 31
  movdqu xmm4, xmm2
  psrld xmm4, 31
  pslld xmm1, 1
  pslld xmm2, 1
  vpslldq xmm5, xmm3, 4
  vpslldq xmm4, xmm4, 4
  mov r12, 0
  pinsrd xmm3, r12d, 0
  pshufd xmm3, xmm3, 3
  pxor xmm3, xmm4
  pxor xmm1, xmm5
  pxor xmm2, xmm3
  movdqu xmm5, xmm2
  pxor xmm2, xmm2
  mov r12, 3774873600
  pinsrd xmm2, r12d, 3
  pclmulqdq xmm1, xmm2, 17
  movdqu xmm2, xmm1
  psrld xmm2, 31
  pslld xmm1, 1
  vpslldq xmm2, xmm2, 4
  pxor xmm1, xmm2
  pxor xmm1, xmm5
  pxor xmm1, xmm6
  pshufb xmm1, xmm8
  movdqu xmmword ptr [r8 + 0], xmm1
  mov r12, r10
  movdqu xmm8, xmm0
  pop rax
  pinsrq xmm6, rax, 1
  pop rax
  pinsrq xmm6, rax, 0
  pop rax
  pinsrq xmm11, rax, 1
  pop rax
  pinsrq xmm11, rax, 0
  ret
GHash_extra_win_ghash_incremental_extra_stdcall_win endp
ALIGN 16
Gcm_load_xor_win_gcm_load_xor_store_buffer_win proc
  imul r9, 16
  add rcx, r9
  movdqu xmm2, xmmword ptr [rcx + 0]
  movdqu xmm0, xmmword ptr [rdx + 0]
  pxor xmm2, xmm0
  add r8, r9
  movdqu xmmword ptr [r8 + 0], xmm2
  ret
Gcm_load_xor_win_gcm_load_xor_store_buffer_win endp
ALIGN 16
Inc32_win_inc32_buffer_win proc
  movdqu xmm1, xmmword ptr [rcx + 0]
  pxor xmm2, xmm2
  mov rax, 1
  pinsrd xmm2, eax, 0
  paddd xmm1, xmm2
  movdqu xmmword ptr [rcx + 0], xmm1
  ret
Inc32_win_inc32_buffer_win endp
ALIGN 16
Zero_quad32_win_zero_quad32_buffer proc
  pxor xmm1, xmm1
  movdqu xmmword ptr [rcx + 0], xmm1
  ret
Zero_quad32_win_zero_quad32_buffer endp
ALIGN 16
Mk_quad32_1_win_mk_quad32_lo0_be_1_buffer_win proc
  movdqu xmm1, xmmword ptr [rcx + 0]
  mov rax, 1
  pinsrd xmm1, eax, 0
  movdqu xmmword ptr [rcx + 0], xmm1
  ret
Mk_quad32_1_win_mk_quad32_lo0_be_1_buffer_win endp
ALIGN 16
Gcm_make_length_win_gcm_make_length_quad_buffer_win proc
  mov rax, 579005069656919567
  pinsrq xmm0, rax, 0
  mov rax, 283686952306183
  pinsrq xmm0, rax, 1
  pxor xmm2, xmm2
  mov rax, rcx
  imul rax, 8
  pinsrd xmm2, eax, 0
  mov rax, rdx
  imul rax, 8
  pinsrd xmm2, eax, 2
  pshufb xmm2, xmm0
  movdqu xmmword ptr [r8 + 0], xmm2
  ret
Gcm_make_length_win_gcm_make_length_quad_buffer_win endp
ALIGN 16
Quad32_xor_win_quad32_xor_buffer_win proc
  movdqu xmm1, xmmword ptr [rcx + 0]
  movdqu xmm2, xmmword ptr [rdx + 0]
  pxor xmm1, xmm2
  movdqu xmmword ptr [r8 + 0], xmm1
  ret
Quad32_xor_win_quad32_xor_buffer_win endp
ALIGN 16
Reverse_quad32_win_reverse_bytes_quad32_buffer_win proc
  movdqu xmm0, xmmword ptr [rcx + 0]
  mov rax, 579005069656919567
  pinsrq xmm1, rax, 0
  mov rax, 283686952306183
  pinsrq xmm1, rax, 1
  pshufb xmm0, xmm1
  movdqu xmmword ptr [rcx + 0], xmm0
  ret
Reverse_quad32_win_reverse_bytes_quad32_buffer_win endp
end
