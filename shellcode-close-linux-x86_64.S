#if defined(__linux__) && defined(__x86_64)
/** injcode/shellcode-close-linux-x86_64.S
 *   
 *  Copyright(c) Thomas Habets 2009
 */
#include "asm-constants.h"

.globl shellcodeClose
shellcodeClose:
        mov   $SYS_close, %rax
        mov   (%rbp), %rbx
        int    $0x80
        xor    %rax, %rax
.globl shellcodeCloseEnd
shellcodeCloseEnd:   nop
#endif
