#include <cstdio>
#include <sys/types.h>
#include <signal.h>
#include <sys/ptrace.h>
#include <sys/types.h>
#include <sys/wait.h>
#include <unistd.h>


#include "inject.h"

#ifndef WIFCONTINUED
#define WIFCONTINUED(a) 0
#endif

Inject::Inject(pid_t pid, int verbose, const char *argv0)
        :pid(pid),attached(false),verbose(verbose),argv0(argv0)
{
}


Inject::~Inject()
{
        try {
                detach();
        } catch(...) {
                // FIXME: the code should handle this better than just
                // ignoring failure
        }
}


void
Inject::detach()
{
        uninject();
        if (attached) {
                if (ptrace(PTRACE_DETACH, pid, NULL, NULL)) {
                        throw ErrSysPtrace("Inject::detach",
                                           PTRACE_DETACH,
                                           "");
                }
                attached = false;
        }
}
void
Inject::attach()
{
        if (!attached) {
                attached = true;
                if (ptrace(PTRACE_ATTACH, pid, NULL, NULL)) {
                        attached = false;
                        throw ErrSysPtrace("Inject::attach",
                                           PTRACE_ATTACH,
                                           "attach");
                }

                pagesize = getpagesize();
                
                // FIXME: needed?
                if (0 > kill(pid, SIGCONT)) {
                        throw ErrSys("Inject::attach", "kill");
                }
                
                if (0 > waitpid(pid, NULL, 0)) {
                        throw ErrSys("Inject::attach", "waitpid");
                }
                
                if (ptrace(PTRACE_GETREGS, pid, NULL, &oldregs)) {
                        throw ErrSysPtrace("Inject::attach",
                                           PTRACE_GETREGS,
                                           "getregs");
                }
                olddatapage.resize(pagesize);
                oldcodepage.resize(pagesize);
                peek(&olddatapage[0], dataBase(), pagesize);
                peek(&oldcodepage[0], codeBase(), pagesize);
        }
}


void
Inject::peekpoke(const char *data, unsigned long addr, size_t len, bool poke)
{
        unsigned long them;
        const char *us;

        us = data;
        them = addr;

        for(;
            len >= wordSize();
            len -= wordSize(), them += wordSize(), us += wordSize()) {
                if (poke) {
                        if (ptrace(PTRACE_POKEDATA,
                                   pid,
                                   them,
                                   *(ptr_t*)us)) {
                                throw ErrSysPtrace("Inject::peekpoke",
                                                   PTRACE_POKEDATA,
                                                   "");
                        }
                } else {
                        *(ptr_t*)us = ptrace(PTRACE_PEEKDATA,
                                               pid,
                                               them,
                                               NULL);
                }
        }
        // FIXME: handle non word-aligned peekpokes
}

Inject::ptr_t
Inject::codeBase()
{
        attach();
        return oldregs.rip & ~(pagesize-1);
}

Inject::ptr_t
Inject::dataBase()
{
        attach();
        return oldregs.rsp & ~(pagesize-1);
}


/**
 * FIXME: error handling
 */
void
Inject::inject(void *code, void *data)
{
        //printf("Injecting...\n");
        uninject();

        injected = true;
        poke((char*)code, codeBase(), pageSize());
        poke((char*)data, dataBase(), pageSize());

        struct user_regs_struct newregs;
        if (ptrace(PTRACE_GETREGS, pid, NULL, &newregs)) {
                throw ErrSysPtrace("Inject::inject",
                                   PTRACE_GETREGS,
                                   "");
        }
        newregs.rip = codeBase();
        newregs.rax = codeBase();
        newregs.rbp = dataBase();
        newregs.rsp = dataBase() + pageSize() - wordSize();

        if (ptrace(PTRACE_SETREGS, pid, NULL, &newregs)) {
                throw ErrSysPtrace("Inject::inject",
                                   PTRACE_SETREGS,
                                   "Setting new registers");
        }

}


void
Inject::run()
{
        if (!injected) {
                throw ErrBase("Inject::run", "not injected yet");
        }

        time_t last = 0;
        struct user_regs_struct regs;
        do {
                if (ptrace(PTRACE_CONT, pid, NULL, NULL)) {
                        perror("PTRACE_CONT");
                }
                int status;
                waitpid(pid, &status, 0);
                if (verbose && last != time(0)) {
                        last = time(0);
                        printf("waitpid status: %d %d %d %d\n",
                               WIFEXITED(status),
                               WIFSIGNALED(status),
                               WIFSTOPPED(status),
                               WIFCONTINUED(status));
                        if (WIFSTOPPED(status)) {
                                // FIXME: save signal and deliver later
                                printf("Stopping signal: %d\n",
                                        WSTOPSIG(status));
                        }

                        if (ptrace(PTRACE_GETREGS, pid, NULL,
                                          &regs)) {
                                perror("getregs");
                        }
                        //dumpregs(&newregs);
                        if (0) {
                                printf("%lx .. %p .. %lx\n",
                                       codeBase(),
                                       (void*)regs.rip,
                                       codeBase() + pageSize());
                        }
                }

                if (ptrace(PTRACE_GETREGS, pid, NULL, &regs)) {
                        perror("getregs");
                }
        } while(regs.rip != (long)(codeBase()  + pageSize()));
        if (regs.rax) {
                printf("Shellcode returned non-null: %lld\n", regs.rax);
                dumpregs();
        }
}

void
Inject::uninject()
{
        if (injected) {
                //printf("UnInjecting...\n");
                poke(&olddatapage[0], dataBase(), pageSize());
                poke(&oldcodepage[0], codeBase(), pageSize());
                if (ptrace(PTRACE_SETREGS, pid, NULL, &oldregs)) {
                        throw ErrSysPtrace("Inject::uninject",
                                           PTRACE_SETREGS,
                                           "Resetting original registers");
                }
                injected = false;
        }
}

void
Inject::dumpregs(bool onlyIfrax)
{
        struct user_regs_struct regs;
        if (ptrace(PTRACE_GETREGS, pid, NULL, &regs)) {
                perror("getregs");
        }
        if (onlyIfrax && !regs.rax) {
                return;
        }
        printf("----------------------------\n");
        printf("%%rip : 0x%.8llx\n", regs.rip);
        printf("%%rax : 0x%.8llx  %lld %s\n", regs.rax, regs.rax,
               strerror(-regs.rax));
        printf("%%rbx : 0x%.8llx  %lld\n", regs.rbx, regs.rbx);
        printf("%%rcx : 0x%.8llx\n", regs.rcx);
        printf("%%rdx : 0x%.8llx\n", regs.rdx);
        printf("%%rsi : 0x%.8llx\n", regs.rsi);
        printf("%%rdi : 0x%.8llx\n", regs.rdi);
        printf("%%rbp : 0x%.8llx\n", regs.rbp);
        printf("%%orig_rax : 0x%.8llx\n", regs.orig_rax);
        printf("%%rsp : 0x%.8llx\n", regs.rsp);
}
