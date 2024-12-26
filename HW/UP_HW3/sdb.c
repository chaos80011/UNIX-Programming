#include <sys/ptrace.h>
#include <sys/types.h>
#include <sys/wait.h>
#include <unistd.h>
#include <sys/user.h>
#include <sys/reg.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <errno.h>
#include <elf.h>
#include <fcntl.h>
#include <sys/stat.h>
#include <sys/mman.h>
#include <stdint.h>
#include "/home/corange/Downloads/capstone-next/include/capstone/capstone.h"
#include <stdbool.h>
#define MAX_BREAKPOINTS 100



typedef struct {
    uint64_t addr;
    char orig_data;
    bool valid;
} Breakpoint;

Breakpoint breakpoints[MAX_BREAKPOINTS] = {0};
int breakpoint_count = 0;
pid_t child_pid;
int wait_status;
bool loaded = false;
bool bp_touched = false;
int bs_flag = 0;


void set_breakpoint(uint64_t addr);
void delete_breakpoint(int bp_index);
void continue_execution();
void single_step();
void print_registers(pid_t child_pid);
void run_target(const char* programname);
void disassemble_instructions(uint64_t rip);
void patch (uint64_t addr, uint64_t value, uint64_t len);
void break_syscall();

Elf64_Addr get_entry_point(const char *program_name) {
    int fd = open(program_name, O_RDONLY);
    if (fd < 0) {
        perror("open");
        return 0;
    }

    Elf64_Ehdr elf_header;
    if (read(fd, &elf_header, sizeof(Elf64_Ehdr)) != sizeof(Elf64_Ehdr)) {
        perror("read");
        close(fd);
        return 0;
    }

    if (memcmp(elf_header.e_ident, ELFMAG, SELFMAG) != 0) {
        fprintf(stderr, "Not a valid ELF file\n");
        close(fd);
        return 0;
    }

    Elf64_Addr entry_point = elf_header.e_entry;
    close(fd);
    return entry_point;
}

void enable_bp() {
    char cc = 0xcc;
    for(int i = 0; i < breakpoint_count; i++) {
        if(breakpoints[i].valid) {
            long data = ptrace(PTRACE_PEEKDATA, child_pid, breakpoints[i].addr, 0);
            memcpy(&data, &cc, sizeof(char));
            ptrace(PTRACE_POKEDATA, child_pid, breakpoints[i].addr, data);
        }
    }
}

void disable_bp() {
    for (int i = 0; i < breakpoint_count; i++) {
        if (breakpoints[i].valid) {
            long data = ptrace(PTRACE_PEEKDATA, child_pid, breakpoints[i].addr, 0);
            memcpy(&data, &breakpoints[i].orig_data, sizeof(char));
            ptrace(PTRACE_POKEDATA, child_pid, breakpoints[i].addr, data);
        }
    }
}

void run_debugger() {
    char command[256];
    printf("(sdb) ");
    while (fgets(command, sizeof(command), stdin) != NULL) {
        if (strncmp(command, "load", 4) == 0) {
            char* program = strtok(command + 5, "\n");
            Elf64_Addr entry_point = get_entry_point(program);
            run_target(program);
        } else if (strncmp(command, "break", 5) == 0) {
            if(!loaded) {
                printf("** please load a program first.\n");
                printf("(sdb) ");
                continue;
            }
            uint64_t addr = strtoul(command + 6, NULL, 16);
            set_breakpoint(addr);
        } else if (strncmp(command, "delete", 6) == 0) {
            if(!loaded) {
                printf("** please load a program first.\n");
                printf("(sdb) ");
                continue;
            }
            int bp_index = atoi(command + 7);
            delete_breakpoint(bp_index);
        } else if (strncmp(command, "cont", 4) == 0) {
            bs_flag = 0;
            if(!loaded) {
                printf("** please load a program first.\n");
                printf("(sdb) ");
                continue;
            }
            continue_execution();
        } else if (strncmp(command, "si", 2) == 0) {
            bs_flag = 0;
            if(!loaded) {
                printf("** please load a program first.\n");
                printf("(sdb) ");
                continue;
            }
            single_step(child_pid);
        } else if (strncmp(command, "info reg", 8) == 0) {
            if(!loaded) {
                printf("** please load a program first.\n");
                printf("(sdb) ");
                continue;
            }
            print_registers(child_pid);
        } else if (strncmp(command, "info break", 10) == 0) {
            if(!loaded) {
                printf("** please load a program first.\n");
                printf("(sdb) ");
                continue;
            }
            printf("Num\tAddress\n");
            for (int i = 0; i < breakpoint_count; ++i) {
                if(breakpoints[i].valid) {
                    printf("%-3d\t0x%lx\n", i, breakpoints[i].addr);
                }
            }
        } else if (strncmp(command, "patch", 5) == 0) {
            if(!loaded) {
                printf("** please load a program first.\n");
                printf("(sdb) ");
                continue;
            }
            uint64_t addr;
            uint64_t value;
            uint64_t len;
            char *token = strtok(command, " ");

            token = strtok(NULL, " ");
            if (token == NULL) {
                fprintf(stderr, "Invalid hex address\n");
                exit(EXIT_FAILURE);
            }
            addr = strtoul(token, NULL, 16);

            token = strtok(NULL, " ");
            if (token == NULL) {
                fprintf(stderr, "Invalid hex value\n");
                exit(EXIT_FAILURE);
            }
            value = strtoul(token, NULL, 16);

            token = strtok(NULL, " ");
            if (token == NULL) {
                fprintf(stderr, "Invalid length\n");
                exit(EXIT_FAILURE);
            }
            len = strtoul(token, NULL, 16);
            patch(addr, value, len);
        } else if (strncmp(command, "syscall", 7) == 0) {
            if(!loaded) {
                printf("** please load a program first.\n");
                printf("(sdb) ");
                continue;
            }
            break_syscall();
        } else {
            printf("Unknown command: %s", command);
        }
        printf("(sdb) ");
    }
}

void run_target(const char* programname) {
    loaded = true;
    child_pid = fork();

    if (child_pid == 0) {
        if (ptrace(PTRACE_TRACEME, 0, 0, 0) < 0) {
            perror("ptrace");
            exit(1);
        }
        execl(programname, programname, NULL); // send signal (SIGCHILD) to parent 
    } else if (child_pid > 0) {
        waitpid(child_pid, &wait_status, 0);
        struct user_regs_struct regs;
        if (ptrace(PTRACE_GETREGS, child_pid, NULL, &regs) == -1) {
            perror("ptrace GETREGS");
            return;
        }
        uint64_t rip = regs.rip;
        printf("** program '%s' loaded. entry point 0x%lx.\n", programname, rip);
        disassemble_instructions(rip);
    } else {
        perror("fork");
        return;
    }
}


void set_breakpoint(uint64_t addr) {
    if (breakpoint_count >= MAX_BREAKPOINTS) {
        fprintf(stderr, "Breakpoint limit reached.\n");
        return;
    }
    long data = ptrace(PTRACE_PEEKDATA, child_pid, addr, 0);
    Breakpoint bp = {addr, ((char *)&data)[0], true};
    breakpoints[breakpoint_count++] = bp;
    long int3 = (data & ~0xff) | 0xcc; // modify the least significant byte to 0xcc
    ptrace(PTRACE_POKEDATA, child_pid, addr, int3);
    printf("** set a breakpoint at 0x%lx.\n", addr);
}

void delete_breakpoint(int bp_index) {
    // if (bp_index < 0 || bp_index >= breakpoint_count) {
    //     fprintf(stderr, "Invalid breakpoint index.\n");
    //     return;
    // }
    if(breakpoints[bp_index].valid) {
        breakpoints[bp_index].valid = false;
        printf("** delete breakpoint %d.\n", bp_index);
        long data = ptrace(PTRACE_PEEKDATA, child_pid, breakpoints[bp_index].addr, 0);
        memcpy(&data, &breakpoints[bp_index].orig_data, sizeof(char));
        ptrace(PTRACE_POKEDATA, child_pid, breakpoints[bp_index].addr, data);
    } else {
        printf("** breakpoint %d does not exist.\n", bp_index);
    }
}

void continue_execution() {
    // 停在breakpoint下一個
    if(bp_touched) {
        disable_bp();
        if (ptrace(PTRACE_SINGLESTEP, child_pid, 0, 0) == -1) {
            perror("ptrace PTRACE_SINGLESTEP");
            exit(EXIT_FAILURE);
        }
        if (waitpid(child_pid, &wait_status, 0) == -1) {
            perror("waitpid");
            exit(EXIT_FAILURE);
        }
        enable_bp();
        bp_touched = false;
    }
    if (ptrace(PTRACE_CONT, child_pid, 0, 0) == -1) {
        perror("ptrace PTRACE_CONT");
        exit(EXIT_FAILURE);
    }
    if (waitpid(child_pid, &wait_status, 0) == -1) {
        perror("waitpid");
        exit(EXIT_FAILURE);
    }

    if (WIFEXITED(wait_status)) {
        printf("** the target program terminated.\n");
        return;
    }

    struct user_regs_struct regs;
    if (ptrace(PTRACE_GETREGS, child_pid, 0, &regs) == -1) {
        perror("ptrace PTRACE_GETREGS");
        exit(EXIT_FAILURE);
    }
    uint64_t rip = regs.rip;
    bool is_bp = false;
    int i;
    for(i = 0; i < breakpoint_count; i++) {
        if(breakpoints[i].valid && rip == breakpoints[i].addr + 1) {
            is_bp = true;
            break;
        }
    }
    if(is_bp) {
        bp_touched = true;
        rip--;
        printf("** hit a breakpoint at 0x%lx.\n", rip);
        disassemble_instructions(rip);
        //回到breakpoint指令(0xcc)
        regs.rip = rip;
        if (ptrace(PTRACE_SETREGS, child_pid, 0, &regs) == -1) {
            perror("ptrace PTRACE_SETREGS");
            exit(EXIT_FAILURE);
        }

    } else {
        continue_execution();
    }  

}

void single_step() {
    bp_touched = false;
    disable_bp();
    if (ptrace(PTRACE_SINGLESTEP, child_pid, 0, 0) == -1) { //401004
        perror("ptrace PTRACE_SINGLESTEP");
        exit(EXIT_FAILURE);
    }

    if (waitpid(child_pid, &wait_status, 0) == -1) {
        perror("waitpid");
        exit(EXIT_FAILURE);
    }
    enable_bp();

    struct user_regs_struct regs;
    if (ptrace(PTRACE_GETREGS, child_pid, 0, &regs) == -1) {
        perror("ptrace PTRACE_GETREGS");
        exit(EXIT_FAILURE);
    }
    uint64_t rip = regs.rip;

    for (int i = 0; i < breakpoint_count; i++) {
        if (breakpoints[i].addr == rip) {
            printf("** hit a breakpoint at 0x%lx.\n", rip);
            bp_touched = true;
            break;
        }
    }
    disassemble_instructions(rip);

    if (WIFEXITED(wait_status)) {
        printf("** the target program terminated.\n");
    }
}

void disassemble_instructions(uint64_t rip) {
    int empty = 1;
    int total_count = 0;
    while (total_count < 5) {
        long instruction = ptrace(PTRACE_PEEKTEXT, child_pid, rip, NULL);
        if (instruction == -1) {
            perror("ptrace PEEKTEXT");
            return;
        }

        uint64_t p = rip;
        for (int i = 0; i < breakpoint_count; i++) {
            if (breakpoints[i].valid && breakpoints[i].addr >= rip && breakpoints[i].addr < rip + 8) {
                memcpy(((char *)&instruction) + breakpoints[i].addr - rip, &breakpoints[i].orig_data, 1);
            }
        }

        csh handle;
        cs_insn *insn;
        size_t count;

        if (cs_open(CS_ARCH_X86, CS_MODE_64, &handle) != CS_ERR_OK)
            return;

        count = cs_disasm(handle, (uint8_t *)&instruction, sizeof(instruction), rip, 0, &insn);
        if (count > 0) {
            size_t j;
            for (j = 0; j < count && total_count < 5; j++, total_count++) {
                empty = 1;
                for(int i = 0; i < insn[j].size; i++) {
                    if(insn[j].bytes[i] != 0x00) {
                        empty = 0;
                        break;
                    }
                }
                if(empty) {
                    break;
                }
                printf("%"PRIx64": ", insn[j].address);
                int k;
                for (k = 0; k < insn[j].size; k++) {
                    printf("%02x ", insn[j].bytes[k]);
                }
                printf("%*s%s\t%s\n", (12 - k) * 3, " ", insn[j].mnemonic, insn[j].op_str);
            }
            rip = insn[j - 1].address + insn[j - 1].size;
            cs_free(insn, count);
        } else {
            printf("ERROR: Failed to disassemble given code!\n");
        }
        cs_close(&handle);
        if(empty) {
            break;
        }
    }

    if (total_count < 5) {
        printf("** the address is out of the range of the text section.\n");
    }
}


void print_registers(pid_t child_pid) {
    struct user_regs_struct regs;
    ptrace(PTRACE_GETREGS, child_pid, 0, &regs);
    printf("$rax 0x%016llx ", regs.rax);
    printf("$rbx 0x%016llx ", regs.rbx);
    printf("$rcx 0x%016llx\n", regs.rcx);
    printf("$rdx 0x%016llx ", regs.rdx);
    printf("$rsi 0x%016llx ", regs.rsi);
    printf("$rdi 0x%016llx\n", regs.rdi);
    printf("$rbp 0x%016llx ", regs.rbp);
    printf("$rsp 0x%016llx ", regs.rsp);
    printf("$r8 0x%016llx\n", regs.r8);
    printf("$r9 0x%016llx ", regs.r9);
    printf("$r10 0x%016llx ", regs.r10);
    printf("$r11 0x%016llx\n", regs.r11);
    printf("$r12 0x%016llx ", regs.r12);
    printf("$r13 0x%016llx ", regs.r13);
    printf("$r14 0x%016llx\n", regs.r14);
    printf("$r15 0x%016llx ", regs.r15);
    printf("$rip 0x%016llx ", regs.rip);
    printf("$eflags 0x%016llx\n", regs.eflags);
}

void patch (uint64_t addr, uint64_t value, uint64_t len) {
    printf("** patch memory at address 0x%lx.\n", addr);
    long data = ptrace(PTRACE_PEEKDATA, child_pid, addr, 0);
    uint64_t temp = value;
    memcpy(&data, &temp, sizeof(char) * len);
    ptrace(PTRACE_POKEDATA, child_pid, addr, data);
}

void break_syscall() {
    static uint64_t bs_rip = 0;
    static uint64_t bs_orig_rax = 0;
    static uint64_t bs_rax = 0;
    struct user_regs_struct regs;

    if (bs_flag == 0) {
        if(bp_touched) {
            disable_bp();
            if (ptrace(PTRACE_SINGLESTEP, child_pid, 0, 0) == -1) { //401004
                perror("ptrace PTRACE_SINGLESTEP");
                exit(EXIT_FAILURE);
            }
            if (waitpid(child_pid, &wait_status, 0) == -1) {
                perror("waitpid");
                exit(EXIT_FAILURE);
            }
            enable_bp();
            bp_touched = false;
        }
        if (ptrace(PTRACE_SETOPTIONS, child_pid, 0, PTRACE_O_TRACESYSGOOD) == -1) {
            perror("ptrace SETOPTIONS");
            return;
        }

        if (ptrace(PTRACE_SYSCALL, child_pid, 0, 0) == -1) {
            perror("ptrace SYSCALL");
            return;
        }
        waitpid(child_pid, &wait_status, 0);
        if(WSTOPSIG(wait_status) & 0x80) {
            if (ptrace(PTRACE_GETREGS, child_pid, NULL, &regs) == -1) {
                perror("ptrace GETREGS");
                return;
            }
            bs_rip = regs.rip - 2;
            bs_orig_rax = regs.orig_rax;
            printf("** enter a syscall(%lld) at 0x%lx.\n", regs.orig_rax, bs_rip);
            bs_flag = true;
        } else {
            bp_touched = true;
            if (ptrace(PTRACE_GETREGS, child_pid, 0, &regs) == -1) {
                perror("ptrace PTRACE_GETREGS");
                exit(EXIT_FAILURE);
            }
            uint64_t rip = regs.rip - 1;
            printf("** hit a breakpoint at 0x%lx.\n", rip);
            disassemble_instructions(rip);
            //回到breakpoint指令(0xcc)
            regs.rip = rip;
            if (ptrace(PTRACE_SETREGS, child_pid, 0, &regs) == -1) {
                perror("ptrace PTRACE_SETREGS");
                exit(EXIT_FAILURE);
            }
            return;
        }

    } else {
        if (ptrace(PTRACE_SYSCALL, child_pid, 0, 0) == -1) {
            perror("ptrace SYSCALL");
            return;
        }
        waitpid(child_pid, &wait_status, 0);

        if (WIFEXITED(wait_status)) {
            printf("** the target program terminated.\n");
            return;
        }

        // if(WSTOPSIG(wait_status) & 0x80 == 0) {
        //     if (ptrace(PTRACE_GETREGS, child_pid, 0, &regs) == -1) {
        //         perror("ptrace PTRACE_GETREGS");
        //         exit(EXIT_FAILURE);
        //     }
        //     uint64_t rip = regs.rip;
        //     printf("** hit a breakpoint at 0x%lx.\n", rip);
        //     bp_touched = true;
        //     disassemble_instructions(rip);
        //     return;
        // }

        if (ptrace(PTRACE_GETREGS, child_pid, NULL, &regs) == -1) {
            perror("ptrace GETREGS");
            return;
        }
        bs_rax = regs.rax;
        printf("** leave a syscall(%ld) = %ld at 0x%lx.\n", bs_orig_rax, bs_rax, bs_rip);
        bs_flag = false;
    }
    disassemble_instructions(bs_rip);
}

int main(int argc, char* argv[]) {

    if(argc == 2) {
        run_target(argv[1]);
    } 
    run_debugger();


    return 0;
}
