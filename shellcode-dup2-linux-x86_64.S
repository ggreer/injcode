#if defined(__linux__) && defined(__x86_64)
/** injcode/shellcode-dup2-linux-x86_64.S
 *   
 *  Copyright(c) Thomas Habets 2009
 */
#include "asm-constants.h"

.globl shellcodeDup2
shellcodeDup2:
        # open()
        mov    $SYS_open, %rax
        lea    12(%rbp), %rbx
        mov    4(%rbp), %rcx
        mov    8(%rbp), %rdx
        int     $0x80
        cmp    $0, %rax
        jl      .Lerrout_open
        mov    %rax, %rbx

        # dup2()
        mov    $SYS_dup2, %rax
        mov    (%rbp), %rcx
        int     $0x80
        cmp    $0, %rax
        jl      .Lerrout_dup2

        # close()
        mov    $SYS_close, %rax
        int     $0x80
        cmp    $0, %rax
        jl      .Lerrout_close

        # all done
        xor    %rax, %rax
        jmp     shellcodeDup2End

.Lerrout_close:
.Lerrout_dup2:
        mov    $SYS_close, %rax
        int     $0x80
.Lerrout_open:
        
.globl shellcodeDup2End
shellcodeDup2End:   nop
#endif
