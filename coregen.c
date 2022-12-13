/**
 * Coregen
 * - simple GUMP corefile to ELFCORE file converter
 * 
 * Consists of:
 *   RIFF file reader
 *   GUMP format conversion
 *   ELF core file writer
 *
 * Fredrik Hederstierna 2021/2022
 */

#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <stdint.h>
#include <stdbool.h>

#include <riff_file_reader.h>
#include <gump_corefile_format.h>
#include <elfcore_types.h>
#include <elfcore_file_writer.h>

static bool verbose = true;

//--------------------------------------------------
static void indent(int32_t level)
{
  int i;
  for (i = 0; i < level; i++) {
    printf("||");
  }
}

static void riff_file_list_chunk_start_fn(riff_file_data_chunk_iterator_h iter_h,
                                          int level,
                                          const char type[4],
                                          size_t size,
                                          const char format[4])
{
  indent(level); printf(" p--LIST.START[%d]: TYPE <%c%c%c%c> SIZE(%d) FORMAT <%c%c%c%c>\n",
                        level,
                        type[0], type[1], type[2], type[3],
                        (int)size,
                        format[0], format[1], format[2], format[3]);
}
static void riff_file_list_chunk_end_fn(riff_file_data_chunk_iterator_h iter_h,
                                        int level)
{
  indent(level); printf(" b--LIST.END[%d].\n", level);
}

//--------------------------------------------------
int main(int argc, char **argv)
{
  int32_t res;
  printf("Coregen tool for converting GUMP to ELFCORE files\n");

  if (argc < 3) {
    printf("Usage: %s gump_filename elfcore_filename\n", argv[0]);
    return 0;
  }

  char *gump_filename    = argv[1];
  char *elfcore_filename = argv[2];
  char type[4] = GUMP_COREFILE_MAGIC_FORMAT;

  printf("GUMP Filename %s Type %c%c%c%c Elfcore Filename %s\n",
         gump_filename, type[0], type[1], type[2], type[3], elfcore_filename);

  // open gump riff file
  riff_file_h rf = riff_file_open(gump_filename, type);
  if (rf == NULL) {
    perror("RIFF file could not be opened, exit.\n");
    return EXIT_FAILURE;
  }

  // create elf core file
  elf32_pid_t pid = 0;
  elfcore_file_h ef = elfcore_file_open(elfcore_filename,
                                        ELFCORE_TARGET_ARCH_CORTEX_M);
  if (ef == NULL) {
    perror("ELFCORE file could not be created, exit.\n");
    return EXIT_FAILURE;
  }

  riff_file_data_chunk_iterator_h iter_h = riff_file_data_chunk_iterator_new(rf,
                                                                             riff_file_list_chunk_start_fn,
                                                                             riff_file_list_chunk_end_fn);
  if (iter_h != NULL) {
    struct riff_file_data_subchunk_s* chunk;
    printf("---------------------------------------\n");
    do {
      chunk = riff_file_data_chunk_iterator_next(iter_h);
      if (chunk != NULL) {
        int32_t level = riff_file_data_chunk_iterator_get_list_level(iter_h);
        indent(level+1); printf("....CHUNK: ID <%c%c%c%c> SIZE(%d) OBJ(0x%016lx)\n",
                                chunk->id[0], chunk->id[1], chunk->id[2], chunk->id[3],
                                chunk->size,
                                (intptr_t)chunk);
        // parse GUMP file
        char sec_id[5];
        sec_id[0] = chunk->id[0];
        sec_id[1] = chunk->id[1];
        sec_id[2] = chunk->id[2];
        sec_id[3] = chunk->id[3];
        sec_id[4] = '\0';
        // check section id
        if (strncmp(sec_id, GUMP_COREFILE_MAGIC_META, 4) == 0) {
          printf("Section META\n");
        }
        else if (strncmp(sec_id, GUMP_COREFILE_MAGIC_REGS, 4) == 0) {
          printf("Section REGS\n");

          struct gump_corefile_section_registers_s *reg_sec = (struct gump_corefile_section_registers_s *)chunk->data;
          uint32_t version = reg_sec->version;

          // write threads with regs
          // Data extracted from dump
          static const elf32_arm_regs_t arm_registers =
            {
              .reg = {
                // 0
                0x0,
                0x80000000,
                0x80000000,
                0x15121,
                // 4
                0x40,
                0x0,
                0x0,
                0x2000ffb8,
                // 8
                0x0,
                0x0,
                0x0,
                0x0,
                // 12
                0x2000ff84,
                0x2000ffa8,
                0x34cfd,
                0x34d44,
                // 16
                0x61000000,
                0x80000010 }
            };
          // TODO: HAVE SPECIAL RIFF 'udump' (ARM) 'FREG' for float regs... 256+4 = 260 byte
          // True if math co-processor used, float regs, check Cortex-M0/M0+
          static elf32_arm_fpregs_t arm_fpregs = { .freg = { 0,1,2,3,4,5,6,7,
                                                             8,9,10,11,12,13,14,15,
                                                             16,17,18,19,20,21,22,23,
                                                             24,25,26,27,28,29,30,31 },
                                                   .fpscr = 0xDEADBEEF };
          // add thread section
          printf("THREAD SECTION: verions 0x%08x\n", version);
          (void)elfcore_file_thread_info_add(pid,
                                             (void*)&arm_registers,
                                             (void*)&arm_fpregs);
        }
        else if (strncmp(sec_id, GUMP_COREFILE_MAGIC_MEM, 4) == 0) {
          printf("Section MEM\n");

          struct gump_corefile_section_memory_s *mem_sec = (struct gump_corefile_section_memory_s *)chunk->data;
          uint32_t version       = mem_sec->version;
          uint32_t start_address = mem_sec->start_address;
          uint32_t end_address   = mem_sec->end_address;
          uint8_t *data          = (uint8_t*)&(chunk->data[sizeof(struct gump_corefile_section_memory_s)]);

          // add load section
          printf("LOAD SECTION: verions 0x%08x start 0x%08x end 0x%08x data %p\n", version, start_address, end_address, data);
          elfcore_file_load_section_info_add(start_address, chunk->size, (void *)data);
        }
        else {
          printf("unknown ID: \"%s\"\n", sec_id);
        }

        // extra debug
        if (verbose) {
          // dump data
          uint32_t i;
          uint32_t len = chunk->size;
          if (len > 16) {
            len = 16;
          }
          indent(level+1); printf("....DATA : [");
          for (i = 0; i < len; i++) {
            if (i > 0) {
              printf(" ");
            }
            printf("%02x", chunk->data[i]);
          }
          if (chunk->size > len) {
            printf("...");
          }
          printf("]\n");
        }

      }
      else {
        printf("EOF.\n");
        printf("---------------------------------------\n");
      }
    } while (chunk != NULL);

    // write ELF corefile
    printf("Writing ELFCORE...\n");
    res = elfcore_file_write(ef);
    if (res != 0) {
      perror("Wrote ELFCORE\n");
    }
    res = elfcore_file_close(ef);
    if (res != 0) {
      perror("Closed file\n");
    }

    // tear down and close GUMP RIFF file
    // must be done AFTER write ELF file, since ELF file
    // refer to in-place data pointers in mmapped RIFF file.
    res = riff_file_data_chunk_iterator_delete(iter_h);
    if (res != 0) {
      perror("iterator delete fail");
    }
    res = riff_file_close(rf);
    if (res != 0) {
      perror("file close fail");
    }
  }

  // done
  return EXIT_SUCCESS;
}
