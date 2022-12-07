#ifndef _ELFCORE_TYPES_H_
#define _ELFCORE_TYPES_H_

#include <stdint.h>

/* Process identifier */
typedef int32_t elf32_pid_t;

/* Time value with microsecond resolution */
typedef struct elf32_timeval_s
{
  int32_t tv_sec;   /* Seconds      */
  int32_t tv_usec;  /* Microseconds */
} elf32_timeval_t;

/* Information about signal */
typedef struct elf32_siginfo_s
{
  int32_t si_signo;  /* Signal number */
  int32_t si_code;   /* Extra code    */
  int32_t si_errno;  /* Errno         */
} elf32_siginfo_t;

/* CPU registers (ARM specific) */
typedef struct elf32_arm_regs_s
{
  union {
    uint32_t reg[18];
    struct {
      uint32_t r0;
      uint32_t r1;
      uint32_t r2;
      uint32_t r3;
      uint32_t r4;
      uint32_t r5;
      uint32_t r6;
      uint32_t r7;
      uint32_t r8;
      uint32_t r9;
      uint32_t r10;
      uint32_t r11;  /* Frame Pointer   (FP) */
      uint32_t r12;  /* Intra Procedure call scratch Register (IP) */
      uint32_t r13;  /* Stack Pointer   (SP) */
      uint32_t r14;  /* Link Register   (LR) */
      uint32_t r15;  /* Program Counter (PC) */
      uint32_t xPSR; /* Program Status Register (PSR) */
      uint32_t reserved;
    };
  };
} __attribute__((packed)) elf32_arm_regs_t;

/* FPU registers (ARM specific) */
typedef struct elf32_arm_fpregs_s
{
  union {
    uint64_t freg[32];
    struct {
      uint64_t D0;
      uint64_t D1;
      uint64_t D2;
      uint64_t D3;
      uint64_t D4;
      uint64_t D5;
      uint64_t D6;
      uint64_t D7;
      uint64_t D8;
      uint64_t D9;
      uint64_t D10;
      uint64_t D11;
      uint64_t D12;
      uint64_t D13;
      uint64_t D14;
      uint64_t D15;
      uint64_t D16;
      uint64_t D17;
      uint64_t D18;
      uint64_t D19;
      uint64_t D20;
      uint64_t D21;
      uint64_t D22;
      uint64_t D23;
      uint64_t D24;
      uint64_t D25;
      uint64_t D26;
      uint64_t D27;
      uint64_t D28;
      uint64_t D29;
      uint64_t D30;
      uint64_t D31;
    };
  };
  uint32_t fpscr;
} __attribute__((packed)) elf32_arm_fpregs_t;

/* Information about thread, includes CPU reg */
typedef struct elf32_prstatus_s
{
  elf32_siginfo_t  pr_info;     /* Info associated with signal    */
  uint16_t         pr_cursig;   /* Current signal                 */
  uint32_t         pr_sigpend;  /* Set of pending signals         */
  uint32_t         pr_sighold;  /* Set of held signals            */
  elf32_pid_t      pr_pid;      /* Process ID                     */
  elf32_pid_t      pr_ppid;     /* Parent's process ID            */
  elf32_pid_t      pr_pgrp;     /* Group ID                       */
  elf32_pid_t      pr_sid;      /* Session ID                     */
  elf32_timeval_t  pr_utime;    /* User time                      */
  elf32_timeval_t  pr_stime;    /* System time                    */
  elf32_timeval_t  pr_cutime;   /* Cumulative user time           */
  elf32_timeval_t  pr_cstime;   /* Cumulative system time         */
  /* ARM specific register definition */
  elf32_arm_regs_t pr_reg;      /* CPU registers                  */
  uint32_t         pr_fpvalid;  /* True if math co-processor used */
} elf32_prstatus_t;

/* Information about process */
typedef struct elf32_prpsinfo_s
{
  uint8_t     pr_state;       /* Numeric process state    */
  char        pr_sname;       /* Char for pr_state        */
  uint8_t     pr_zomb;        /* Zombie                   */
  int8_t      pr_nice;        /* Nice val                 */
  uint32_t    pr_flag;        /* Flags                    */
  uint16_t    pr_uid;         /* User ID                  */
  uint16_t    pr_gid;         /* Group ID                 */
  elf32_pid_t pr_pid;         /* Process ID               */
  elf32_pid_t pr_ppid;        /* Parent's process ID      */
  elf32_pid_t pr_pgrp;        /* Group ID                 */
  elf32_pid_t pr_sid;         /* Session ID               */
  char        pr_fname[16];   /* Filename of executable   */
  char        pr_psargs[80];  /* Initial part of arg list */
} elf32_prpsinfo_t;

#endif /* _ELFCORE_TYPES_H_ */
