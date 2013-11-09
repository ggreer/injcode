#if defined(__linux__) && defined(__x86_64)
/** injcode/shellcode-test-linux-x86_64.S
 *   
 *  Copyright(c) Thomas Habets 2009
 */
#include "asm-constants.h"

        .equ    teststr,        0
        
.globl shellcodeTest
shellcodeTest:
        mov   $SYS_write, %rax
        mov   $2, %rbx    # stderr
        lea   teststr(%rbp), %rcx
        mov   $10, %rdx   # len
        int    $0x80
        xor    %rax, %rax
.globl shellcodeTestEnd
shellcodeTestEnd:   nop
#endif
