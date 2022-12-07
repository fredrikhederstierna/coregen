#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <stdint.h>
#include <stdbool.h>

#include <assert.h>
#include <errno.h>
#include <fcntl.h>
#include <unistd.h>

#include <sys/types.h>
#include <sys/mman.h>
#include <sys/stat.h>
#include <sys/signal.h>

#include <elf.h>
#include <elfcore_types.h>
#include <elfcore_file_writer.h>

/**
 * ELF corefile writer.
 *
 * Uses memory mapped file to also being able to handle large files.
 *
 * Fredrik Hederstierna 2021
 *
 * This file is in the public domain.
 * You can do whatever you want with it.
 *
 * This program is distributed in the hope that it will be useful,
 * but WITHOUT ANY WARRANTY; without even the implied warranty of
 * MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.
 */

//----------------------------------------
/* Cortex-M descriptor from GDB */

// include xml-descriptor for Cortex-M target core
// info from GDB sources at /gdb/features/arm/
// also read under 'org.gnu.gdb.arm.m-profile' in /gdb/doc/gdb.texinfo
static const char ARM_M_PROFILE_WITH_VFP_XML[] =
#include "arm-m-profile-with-vfp.xml"
;

//----------------------------------------
/* Elfcore object */

// Limit max size of resulting elfcore file.
static const size_t ELFCORE_MAX_SIZE = (256*1024*1024);
// Pagesize
static const size_t ELFCORE_PAGESIZE = (4*1024);

typedef struct elfcore_file_s
{
  elfcore_target_arch_t arch;
  void *elf;
  int fd;
  size_t size;
} elfcore_file_t;

static elfcore_file_t *elfcore_file_obj = NULL;

//----------------------------------------
/* Memory region */

struct mem_region_s
{
  uint32_t addr;
  uint32_t size;
  void    *data;
};

// number of regions in list
static uint32_t mem_region_count = 0;
// list of regions
static struct mem_region_s **mem_regions = NULL;

// add memory load section to file
void elfcore_file_load_section_info_add(uint32_t address, uint32_t size, void *data)
{
  // allocate new entry
  struct mem_region_s *newreg = malloc(sizeof(struct mem_region_s));
  if (newreg == NULL) {
    assert(0);
  }
  newreg->addr = address;
  newreg->size = size;
  // data is a pointer to the memory mapped file data
  newreg->data = data;
  // add one more region to list..
  mem_region_count++;
  // extend vector of pointers to fit new entry,
  // re-allocate space every time, not very optimal, but simple..
  mem_regions = realloc(mem_regions, mem_region_count * sizeof(mem_regions[0]));
  if (mem_regions == NULL) {
    assert(0);
  }
  // store new region into the list last
  mem_regions[mem_region_count - 1] = newreg;
}

//----------------------------------------
/* Threads and registers */

// thread info
typedef struct elf32_thread_s
{
  uint32_t pid;
  void *regs;
  void *fpregs;
} elf32_thread_t;

// array of threads
static elf32_thread_t *thread_info = NULL;
// number of threads added
static uint32_t thread_count = 0;

// add thread info and registers
int32_t elfcore_file_thread_info_add(uint32_t pid,
                                     void *regs,
                                     void *fpregs)
{
  // increase thread counter
  thread_count++;
  // make space for new entry
  thread_info = (elf32_thread_t*)realloc(thread_info,
                                         thread_count * sizeof(elf32_thread_t));
  if (thread_info == NULL) {
    assert(0);
  }
  // write last in new entry
  thread_info[thread_count - 1].pid    = pid;
  thread_info[thread_count - 1].regs   = regs;
  thread_info[thread_count - 1].fpregs = fpregs;
  return thread_count;
}

//-------------------------------------------
/* Implementation */

// simple align function (alignment should be power of 2)
static void* align_ptr(void *ptr, size_t alignment)
{
  return (void *)((((size_t)ptr) + (alignment - 1)) & ~(alignment - 1));
}

//-------------------------------------------
static void* write_elf_file_header(void *ptr_start, elfcore_target_arch_t arch)
{
  void *ptr_end = ptr_start;

  // write the ELF header
  Elf32_Ehdr *ehdr;
  ehdr = ptr_start;
  ptr_end += sizeof(Elf32_Ehdr);

  // check arch
  switch (arch) {
  case ELFCORE_TARGET_ARCH_CORTEX_M: {
    break;
  }
  default:
    // currently only ARM header supported.
    assert(0);
    break;
  }

  // write magic ID
  memcpy(ehdr->e_ident, ELFMAG, SELFMAG);
  // write ELF header (content decoding info) 32bit, little endian
  ehdr->e_ident[EI_CLASS]      = ELFCLASS32;
  ehdr->e_ident[EI_DATA]       = ELFDATA2LSB;
  ehdr->e_ident[EI_VERSION]    = EV_CURRENT;
  //
  // This is the magic choice: SYSV, Linux or EABI?
  // (Doesn't seem to matter though?)
  // TODO: Why not set to ELFOSABI_ARM_AEABI and version?
  ehdr->e_ident[EI_OSABI]      = ELFOSABI_ARM;
  ehdr->e_ident[EI_ABIVERSION] = 0;
  ehdr->e_type                 = ET_CORE;
  ehdr->e_machine              = EM_ARM;
  ehdr->e_version              = EV_CURRENT;
  // execute entry point, no entry point so set to 0.
  ehdr->e_entry = 0;
  // program header table offset.
  ehdr->e_phoff = (ptr_end - ptr_start);
  // section header table, since no SH, the value is 0.
  ehdr->e_shoff = 0;
  /* Leave it as "auto". Strictly speaking this case
     means FPA, but almost nobody uses that now, and
     many toolchains fail to set the appropriate bits
     for the floating-point model they use. */
  // Processor-specific flags
  // (32-bit and 64-bit Intel architectures do not define flags,
  // so the EFLAGS value is 0 for Intel)
  // TODO: Set to EF_ARM_EABI_VER5, but "private flags = 0: [APCS-32] [FPA float format]" ?
  ehdr->e_flags     = 0;
  // ELF header size, 32-bit ELF is 52 bytes, 64 bytes.
  ehdr->e_ehsize    = sizeof(Elf32_Ehdr);
  // The size of each entry in the program header table.
  ehdr->e_phentsize = sizeof(Elf32_Phdr);
  // If the file does not have a program header table, the value of e_phnum is 0.
  // e_phentsize Multiply e_phnum.
  // The size of the whole program header table is obtained.
  ehdr->e_phnum     = mem_region_count + 1; //add note as well
  // The size of entry in section header table, that is,
  // how many bytes each section header occupies.
  ehdr->e_shentsize = sizeof(Elf32_Shdr);
  // The number of headers in section header table.
  // If the file does not have section header table, the value of e_shnum is 0.
  // e_shentsize Multiply e_shnum.
  // And you get the size of the section header table.
  ehdr->e_shnum     = 0;
  // Section header string table index.
  // Contains section name string table in section header table.
  // If there is no section name string table, e_shstrndx The value is SHN_UNDEF.
  ehdr->e_shstrndx  = 0;

  return ptr_end;
}

//----------------------------------------
static void* write_prpsinfo_section(void *ptr_start)
{
  void *ptr_end = ptr_start;

  // add Note for PRPSINFO
  Elf32_Nhdr *nhdr = ptr_end;
  memset(nhdr, 0, sizeof(Elf32_Nhdr));
  nhdr->n_type   = NT_PRPSINFO;
  nhdr->n_namesz = 5;
  nhdr->n_descsz = sizeof(struct elf32_prpsinfo_s);
  ptr_end += sizeof(Elf32_Nhdr);
  //
  memcpy(ptr_end, "CORE\0\0\0\0", 8);
  ptr_end += 8; // align
  //
  struct elf32_prpsinfo_s *prpsinfo = ptr_end;
  // build the PRPSINFO data structure
  memset(prpsinfo, 0, sizeof(struct elf32_prpsinfo_s));
  prpsinfo->pr_sname = 'R';
  prpsinfo->pr_nice  = 0;
  prpsinfo->pr_uid   = 0;
  prpsinfo->pr_gid   = 0;
  prpsinfo->pr_pid   = 0;
  prpsinfo->pr_ppid  = 0;
  prpsinfo->pr_pgrp  = 0;
  prpsinfo->pr_sid   = 0;
  ptr_end += sizeof(struct elf32_prpsinfo_s);

  return ptr_end;
}

//----------------------------------------
static void* write_arm_gdb_section(void *ptr_start)
{
  void *ptr_end = ptr_start;

  // This XML-file is based om Cortem-M4 ARMv7m arch with VFP.
  // For other corefiles with other Cortex cores, other XML profile might apply.
  size_t xml_file_size = sizeof(ARM_M_PROFILE_WITH_VFP_XML);
  Elf32_Nhdr *nhdr = ptr_end;
  nhdr->n_type   = EF_ARM_EABIMASK; //(NT_GDB_TDESC)
  nhdr->n_namesz = 4;
  nhdr->n_descsz = xml_file_size;
  ptr_end += sizeof(Elf32_Nhdr);
  //
  memcpy(ptr_end, "GDB\0", 4);
  ptr_end += 4; // align
  // write XML file describing Cortex-M profile with VFP
  memcpy(ptr_end, &(ARM_M_PROFILE_WITH_VFP_XML[0]), xml_file_size);
  ptr_end += xml_file_size;

  // align
  if ((xml_file_size % 4) > 0) {
    int32_t pad = (4 - (xml_file_size % 4));
    memset(ptr_end, 0, pad);
    ptr_end += pad;
  }

  return ptr_end;
}

//----------------------------------------
static void* write_arm_vfp_section(int32_t thread_index, void *ptr_start)
{
  void *ptr_end = ptr_start;

  // FPU registers
  // check if fp info was added to thread before try adding
  if (thread_info[thread_index].fpregs != NULL) {
    // write vfp section
    Elf32_Nhdr *nhdr = ptr_end;
    // TODO: non-arm with float: NT_FPREGSET ?
    nhdr->n_type   = NT_ARM_VFP;
    nhdr->n_namesz = 6;
    nhdr->n_descsz = sizeof(elf32_arm_fpregs_t);
    ptr_end += sizeof(Elf32_Nhdr);
    //
    // TODO: Why does arm-none-eabi-gdb gcore set this to OWNER=LINUX, not CORE?
    memcpy(ptr_end, "LINUX\0\0\0", 8);
    ptr_end += 8; // align
    // FPU float registers are ARM specific
    void *fpregs = thread_info[thread_index].fpregs;
    elf32_arm_fpregs_t *arm_fpregs = (elf32_arm_fpregs_t*)fpregs;
    memcpy(ptr_end, arm_fpregs, sizeof(elf32_arm_fpregs_t));

    ptr_end += sizeof(elf32_arm_fpregs_t);
  }

  return ptr_end;
}

//----------------------------------------
static void* write_prstatus_section(int32_t thread_index,
                                    void *ptr_start,
                                    elfcore_target_arch_t arch)
{
  void *ptr_end = ptr_start;

  Elf32_Nhdr *nhdr = ptr_end;
  nhdr->n_type   = NT_PRSTATUS;
  nhdr->n_namesz = 5;
  nhdr->n_descsz = sizeof(struct elf32_prstatus_s);
  ptr_end += sizeof(Elf32_Nhdr);
  //
  memcpy(ptr_end, "CORE\0\0\0\0", 8);
  ptr_end += 8; // align
  //
  // process status
  struct elf32_prstatus_s *prs = ptr_end;
  // TODO: we could differentiate here (fault/buserr/abort) <signal.h>
  prs->pr_info.si_signo = SIGABRT; // Segmentation fault (11).
  prs->pr_cursig        = SIGABRT;
  prs->pr_pid  = (elf32_pid_t)thread_info[thread_index].pid;
  prs->pr_pgrp = 0;
  prs->pr_sid  = 0;
  //prs->pr_fpvalid = ??;  << if RIFF contains VPF?

  // CPU registers
  void *cpu_regs = thread_info[thread_index].regs;
  switch (arch) {
  case ELFCORE_TARGET_ARCH_CORTEX_M: {
    // ARM specific CPU registers
    elf32_arm_regs_t *arm_regs = (elf32_arm_regs_t*)cpu_regs;
    uint32_t ri;
    for (ri = 0; ri < (sizeof(elf32_arm_regs_t) / sizeof(uint32_t)); ri++) {
      prs->pr_reg.reg[ri] = arm_regs->reg[ri];
    }
    ptr_end += sizeof(struct elf32_prstatus_s);
    break;
  }
  default:
    break;
  }

  // FPU registers
  void *fpu_regs = thread_info[thread_index].fpregs;
  // if floating point registers submitted
  if (fpu_regs != NULL) {
    switch (arch) {
    case ELFCORE_TARGET_ARCH_CORTEX_M: {
      ptr_end = write_arm_vfp_section(thread_index, ptr_end);
      break;
    }
    default:
      break;
    }
  }

  return ptr_end;
}

//----------------------------------------
static void* write_load_section(Elf32_Phdr *phdr, uint32_t hix,
                                uint32_t mix,
                                void *ptr_start, void *ptr_end)
{
  uint32_t alignment = ELFCORE_PAGESIZE;
  
  // lower alignment to words if address is not page-aligned
  if (mem_regions[mix]->addr & (alignment - 1)) {
    alignment = 0x4;
  }

  // alignment in file should be congruent with alignment in memory
  ptr_end = align_ptr(ptr_end, alignment);

  phdr[hix].p_type   = PT_LOAD;
  phdr[hix].p_offset = (ptr_end - ptr_start);
  phdr[hix].p_vaddr  = mem_regions[mix]->addr;
  phdr[hix].p_paddr  = mem_regions[mix]->addr;
  phdr[hix].p_filesz = mem_regions[mix]->size;
  phdr[hix].p_memsz  = mem_regions[mix]->size;
  phdr[hix].p_flags  = (PF_W | PF_R); //RAM read and write permissions, not exe
  phdr[hix].p_align  = alignment;

  memcpy(ptr_end,
         mem_regions[mix]->data,
         mem_regions[mix]->size);

  ptr_end += phdr[hix].p_filesz;

  return ptr_end;
}

//----------------------------------------
static void* write_note_section(Elf32_Phdr *phdr, uint32_t hix,
                                void *ptr_start, void *ptr_end,
                                void *note_start)
{
  // fill in NOTE size etc
  phdr[hix].p_type   = PT_NOTE;
  phdr[hix].p_offset = (note_start - ptr_start);
  phdr[hix].p_vaddr  = 0;
  phdr[hix].p_paddr  = 0;
  phdr[hix].p_filesz = (ptr_end - note_start);
  phdr[hix].p_memsz  = 0;
  phdr[hix].p_flags  = 0;
  phdr[hix].p_align  = 0;

  // just filling in the note header already previously made space for,
  // not moving the ptr_end forward
  return ptr_end;
}

//----------------------------------------
static size_t write_elfcore_sections(void *ptr_start, elfcore_target_arch_t arch)
{
  void *ptr_end = ptr_start;

  ptr_end = write_elf_file_header(ptr_end, arch);

  // write program headers, starting with the PT_NOTE entry.
  Elf32_Phdr *phdr;
  phdr = ptr_end;
  ptr_end += (sizeof(Elf32_Phdr) * (mem_region_count + 1));

  // make notes, fill in phdr afterwards later.
  void *note_start = ptr_end;

  // write process info
  ptr_end = write_prpsinfo_section(ptr_end);

  // The order of threads in the output matters.
  // GDB assumes that the first thread is the one that crashed.
  // Make it easier for the end-user to find the crashing
  // thread by dumping it first.
  uint32_t tix;
  for (tix = 0; tix < thread_count; tix++) {
    // write thread status and regs
    ptr_end = write_prstatus_section(tix, ptr_end, arch);
  } //thread

  // GDB note section
  switch (arch) {
  case ELFCORE_TARGET_ARCH_CORTEX_M: {
    // write xml-file with Cortex-M target core description
    ptr_end = write_arm_gdb_section(ptr_end);
    break;
  }
  default:
    break;
  }

  // write note (using already setup header section index 0)
  uint32_t hix = 0;
  ptr_end = write_note_section(phdr, hix,
                               ptr_start, ptr_end,
                               note_start);

  // write load sections for all added memory regions
  uint32_t mix;
  for (mix = 0; mix < mem_region_count; mix++) {
    // program headers for each of the memory segments
    ptr_end = write_load_section(phdr, (mix + 1),
                                 mix,
                                 ptr_start, ptr_end);
  }

  // return number of bytes written to ptr_end
  return (ptr_end - ptr_start);
}

//--------------------------------------
int32_t elfcore_file_write(elfcore_file_h elf_file_h)
{
  elfcore_file_t *elfcore_file = (elfcore_file_t *)elf_file_h;

  // write all file sections
  void *elf_file_ptr = elfcore_file->elf;
  elfcore_target_arch_t arch = elfcore_file->arch;
  size_t size = write_elfcore_sections(elf_file_ptr, arch);

  // write total file size
  elfcore_file->size = size;

  return 0;
}

//--------------------------------
elfcore_file_h elfcore_file_open(const char *filename,
                                 elfcore_target_arch_t target_arch)
{
  int fd;
  // open file to write
  fd = open(filename, (O_RDWR | O_CREAT | O_TRUNC), 0666);
  if (fd < 0) {
    perror("failed creating new elfcore file");
    return NULL;
  }

  // max core file size
  if (ftruncate(fd, ELFCORE_MAX_SIZE) < 0) {
    perror("file size ftruncate failed");
    return NULL;
  }

  // memory map file
  void *elf = mmap(0,
                   ELFCORE_MAX_SIZE,
                   (PROT_READ | PROT_WRITE),
                   MAP_SHARED,
                   fd,
                   0);
  if (elf == MAP_FAILED) {
    perror("failed mapping new file");
    return NULL;
  }

  // create handle
  elfcore_file_obj = (elfcore_file_t *)malloc(sizeof(*elfcore_file_obj));
  elfcore_file_obj->arch = target_arch;
  elfcore_file_obj->elf  = elf;
  elfcore_file_obj->fd   = fd;

  return (void*)elfcore_file_obj;
}

//---------------------------------------------------
// Close elfcore file, adjusting file size
int32_t elfcore_file_close(elfcore_file_h elf_file_h)
{
  elfcore_file_t *elfcore_file = (elfcore_file_t *)elf_file_h;

  void *elf_file_ptr = elfcore_file->elf;
  int fd             = elfcore_file->fd;
  size_t size        = elfcore_file->size;

  // adjust the file length
  msync(elf_file_ptr, (size_t)align_ptr((void*)size, ELFCORE_PAGESIZE), MS_SYNC);
  munmap(elf_file_ptr, ELFCORE_MAX_SIZE);
  if (ftruncate(fd, size) < 0) {
    fprintf(stderr, "elfcore file size too large: %lu max %lu", size, ELFCORE_MAX_SIZE);
    perror("elfcore file size too large");
  }
  // close
  close(fd);
  // free handle obj
  free(elfcore_file_obj);
  elfcore_file_obj = NULL;

  // free allocated mem for sections and info
  uint32_t mix;
  for (mix = 0; mix < mem_region_count; mix++) {
    free(mem_regions[mix]);
    mem_regions[mix] = NULL;
  }
  mem_region_count = 0;
  if (mem_regions != NULL) {
    free(mem_regions);
    mem_regions = NULL;
  }
  thread_count = 0;
  if (thread_info != NULL) {
    free(thread_info);
    thread_info = NULL;
  }

  return 0;
}
