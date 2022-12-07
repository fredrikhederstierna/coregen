#ifndef _ELFCORE_FILE_WRITER_H_
#define _ELFCORE_FILE_WRITER_H_

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

#include <stdint.h>

/* Defined elfcore target architecture */
typedef enum elfcore_target_arch_e
{
  ELFCORE_TARGET_ARCH_CORTEX_M = 1,
  /* more tagets can be added here */
} elfcore_target_arch_t;

/* Handle to reference elfcore file. */
typedef void* elfcore_file_h;

/* Open file to write elfcore to. */
elfcore_file_h elfcore_file_open(const char *filename,
                                 elfcore_target_arch_t target_arch);

/* Add memory load section to elfcore file. */
void elfcore_file_load_section_info_add(uint32_t address,
                                        uint32_t size,
                                        void *data);
/* Add thread info and registers to elfcore file.
   Copy of the registers argument is shallow, only copies pointer, not data. */
int32_t elfcore_file_thread_info_add(uint32_t pid,
                                     void *regs,
                                     void *fpregs);

/* Write elfcore file based on info given of contents. */
int32_t elfcore_file_write(elfcore_file_h elf_file_h);

/* Close file written elfcore to.
   Will also free any allocated memory from all added sections. */
int32_t elfcore_file_close(elfcore_file_h elf_file_h);

#endif
