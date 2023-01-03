#ifndef _ELFCORE_FILE_WRITER_H_
#define _ELFCORE_FILE_WRITER_H_

/**
 * ELF corefile writer.
 *
 * Uses memory mapped file to also being able to handle large files.
 *
 * Copyright (C) 2021/2022 Fredrik Hederstierna
 * (https://github.com/fredrikhederstierna)
 *
 * Licensed under the Apache License, Version 2.0 (the "License");
 * you may not use this file except in compliance with the License.
 * You may obtain a copy of the License at
 *
 *      http://www.apache.org/licenses/LICENSE-2.0
 *
 *  Unless required by applicable law or agreed to in writing, software
 *  distributed under the License is distributed on an "AS IS" BASIS,
 *  WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
 *  See the License for the specific language governing permissions and
 *  limitations under the License.
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
