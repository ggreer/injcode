#if defined(__linux__) && defined(__x86_64)
/** injcode/shellcode-retty-linux-x86_64.S
 *   
 *  Copyright(c) Thomas Habets 2009
 */
        
#include "asm-constants.h"
        /* data map */
        .equ    teststr,        0   /* 10 */
        .equ    socketstruct,   12  /* 12 */
        .equ    connectstruct,  24  /* 12 + 110 */
        .equ    recvstruct,     144 /* 12 */
        .equ    msghdr,         160 /* 28 */
        .equ    iovec,          188 /* 8 */
        .equ    cmsg,           196 /* 24 */
        .equ    scratchdata,    220 /* 4 */
        .equ    childfunc,      224 /* 4 */
        .equ    childpid,       228 /* 4 */
        .equ    oldtio,         232 /* 60 */

        /* variables (can be inside structs) */
        .equ    socketfd,       24  /* permanent location of fd */
        .equ    fd0,            208 /* 4 */
        .equ    fd1,            212 /* 4 */
        .equ    fd2,            216 /* 4 */
        
        .text
        
.globl shellcodeRetty
shellcodeRetty:

        # Debug print
        #mov   $SYS_write, %rax
        #mov   $2, %rbx    # stderr
        #lea   teststr(%rbp), %rcx
        #mov   $10, %rdx   # len
        #int    $0x80
        #mov    $10, %rbx       # step 10 - debug print
        #cmp    $0, %rax
        #jl      errout

        # ioctl(0, TCGETS, &oldtio)
        mov    $SYS_ioctl, %rax
        mov    $0, %rbx
        mov    $TCGETS, %rcx
        lea    oldtio(%rbp), %rdx
        int     $0x80
        mov    $12, %rbx       # step 12
        cmp    $0, %rax
        jl      errout
        
        # fork()
        mov    $SYS_fork, %rax
        int     $0x80
        cmp    $0, %rax
        jne     parent
        jl      errout
        mov    childfunc(%rbp), %rax
        jmp     *%rax
parent:
        mov    %rax, childpid(%rbp)

        # setpgid()
setpgid:        
        mov    %rax, %rcx
        mov    $SYS_setpgid, %rax
        mov    $0, %rbx
        int     $0x80
        mov    $15, %rbx       # step 15
        cmp    $0, %rax
        jl      setpgid

        # setsid()
        mov    $SYS_setsid, %rax
        int     $0x80
        mov    $73, %rbx       # step 73
        cmp    $0, %rax
        jl      erroutclose

        # kill()
        mov    $SYS_kill, %rax
        mov    childpid(%rbp), %rbx
        mov    $SIGKILL, %rcx
        int     $0x80
                
        # waitpid()
        mov    $SYS_waitpid, %rax
        mov    childpid(%rbp), %rbx
        mov    $0, %rcx
        mov    $0, %rdx
        int     $0x80
                
        # FIXME:        do three open(/dev/null)s, just in case
        
        # socket()
        mov    $SYS_socketcall, %rax
        mov    $SC_socket, %rbx
        lea    socketstruct(%rbp), %rcx      # socket struct
        int     $0x80
        mov    %rax, socketfd(%rbp)
        mov    $20, %rbx       # step 20 - socket
        cmp    $0, %rax
        jl      errout
        # FIXME:        error handling

        # connect()
        mov    $SYS_socketcall, %rax
        mov    $SC_connect, %rbx
        lea    connectstruct(%rbp), %rcx
        int     $0x80
        mov    $30, %rbx       # step 30 - connect
        cmp    $0, %rax
        jl      erroutclose

        # recvmsg()
        mov    socketfd(%rbp), %rax
        mov    %rax, recvstruct(%rbp)
        mov    $SYS_socketcall, %rax
        mov    $SC_recvmsg, %rbx
        lea    recvstruct(%rbp), %rcx
        int     $0x80
        mov    $40, %rbx       # step 40 - recvmsg
        cmp    $1, %rax
        jne      errout

        # ioctl(fd, TIOCNOTTY, .) -- not needed. setsid() does it for us
        #mov    $SYS_ioctl, %rax
        #mov    $0, %rbx         # fd
        #mov    $TIOCNOTTY, %rcx
        #mov    $0, %rdx
        #int     $0x80
        #mov    $45, %rbx       # step 45
        #cmp    $0, %rax
        #jl      erroutclose

        # dup2(n, 0)
        mov    $SYS_dup2, %rax
        mov    fd0(%rbp), %rbx
        mov    $0, %rcx
        int     $0x80
        mov    $50, %rbx       # step 50 - dup2(n, 0)
        cmp    $0, %rax
        jl      erroutclose

        # dup2(n, 1)
        mov    $SYS_dup2, %rax
        mov    fd1(%rbp), %rbx
        mov    $1, %rcx
        int     $0x80
        mov    $60, %rbx       # step 60 - dup2(n, 1)
        cmp    $0, %rax
        jl      erroutclose

        # dup2(n, 2)
        mov    $SYS_dup2, %rax
        mov    fd2(%rbp), %rbx
        mov    $2, %rcx
        int     $0x80
        mov    $70, %rbx       # step 70 - dup2(n, 2)
        cmp    $0, %rax
        jl      erroutclose

        # ioctl(fd, TIOCTTY, 1)
        mov    $SYS_ioctl, %rax
        mov    $0, %rbx         # fd
        mov    $TIOCSCTTY, %rcx
        mov    $1, %rdx
        int     $0x80
        mov    $75, %rbx       # step 75
        cmp    $0, %rax
        jne      erroutclose

        # ioctl(0, TCSETS, &oldtio)
        mov    $SYS_ioctl, %rax
        mov    $0, %rbx
        mov    $TCSETS, %rcx
        lea    oldtio(%rbp), %rdx
        int     $0x80
        mov    $77, %rbx       # step 77
        cmp    $0, %rax
        jl      errout

        # kill()
        mov    $SYS_kill, %rax
        mov    $0, %rbx
        mov    $SIGWINCH, %rcx
        int     $0x80

        # close(socket)
        mov    $SYS_close, %rax
        mov    socketfd(%rbp), %rbx
        int     $0x80
        mov    $80, %rbx       # step 80
        cmp    $0, %rax
        jl      erroutclose

        # close(fd0)
        mov    $SYS_close, %rax
        mov    fd0(%rbp), %rbx
        int     $0x80
        mov    $90, %rbx       # step 90
        cmp    $0, %rax
        jl      erroutclose

        # close(fd1)
        mov    $SYS_close, %rax
        mov    fd1(%rbp), %rbx
        int     $0x80
        mov    $100, %rbx       # step 100
        cmp    $0, %rax
        jl      erroutclose

        # close(fd2)
        mov    $SYS_close, %rax
        mov    fd2(%rbp), %rbx
        int     $0x80
        mov    $110, %rbx       # step 110
        cmp    $0, %rax
        jl      erroutclose
        
        mov    $255, %rbx
        # all done
        jmp     okout

.globl  shellcodeRettyChild
shellcodeRettyChild:
        # setpgid()
        mov    $SYS_setpgid, %rax
        mov    $0, %rbx
        mov    $0, %rcx
        int     $0x80

        # FIXME sleep(10)
        jmp     shellcodeRettyChild
        # exit(0)
        
erroutclose:
        #FIXME:  close socket
errout: 
okout:  
.globl shellcodeRettyEnd
shellcodeRettyEnd:   nop

#endif
