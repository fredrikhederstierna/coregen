/**
 * Simple RIFF file reader.
 * Uses memory mapped file to also being able to handle large files.
 *
 * Fredrik Hederstierna 2021
 *
 * More info on RIFF at
 * https://en.wikipedia.org/wiki/Resource_Interchange_File_Format
 *
 * This file is in the public domain.
 * You can do whatever you want with it.
 *
 * This program is distributed in the hope that it will be useful,
 * but WITHOUT ANY WARRANTY; without even the implied warranty of
 * MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.
 */

#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <stdbool.h>
#include <stdint.h>

#include <assert.h>
#include <errno.h>
#include <fcntl.h>
#include <unistd.h>

#include <sys/types.h>
#include <sys/mman.h>
#include <sys/stat.h>

#include <riff_file_reader.h>

//------------------------------------------------------------------

// File and chunk header magic ID
#define RIFF_FILE_TYPE_FILE_MAGIC     "RIFF"
#define RIFF_FILE_TYPE_LIST_MAGIC     "LIST"
#define RIFF_FILE_TYPE_INFO_MAGIC     "INFO"
// (just for testing, added AVI movi ID)
#define RIFF_FILE_TYPE_AVI_MOVI_MAGIC "movi"

// Max allowed nested LIST chunks
#define RIFF_FILE_NESTED_LIST_MAX_LEVELS (10)

//------------------------------------------------------------------

// Struct describing RIFF file
struct riff_file_s
{
  int fd;
  size_t size;
  void *vaddr;
};

// Struct describing RIFF file data chunk iterator
struct riff_file_iterator_s
{
  struct riff_file_s *file;
  char *addr;
  int    list_level;
  size_t list_size[RIFF_FILE_NESTED_LIST_MAX_LEVELS];
  riff_file_list_chunk_start_fn_t list_start_cb;
  riff_file_list_chunk_end_fn_t   list_end_cb;
};

//------------------------------------------------------------------
riff_file_h riff_file_open(const char *filename, const char type[4])
{
  struct riff_file_s *f = (struct riff_file_s *)malloc(sizeof(struct riff_file_s));
  if (f == NULL) {
    perror("malloc file failed");
    return NULL;
  }

  // try open file
  int fd = open(filename, O_RDONLY);
  if (fd < 0) {
    perror("file open failed");
    free(f);
    return NULL;
  }

  // get file size
  struct stat fst;
  if (fstat(fd, &fst) != 0) {
    perror("file stat failed");
    free(f);
    return NULL;
  }
  f->size = fst.st_size;

  // memory map file
  void *file_addr = mmap(0,           //addr
                         f->size,     //length
                         PROT_READ,   //prot
                         MAP_PRIVATE, //flags
                         fd,          //fd
                         0            //offset 
                         );
  if (file_addr == MAP_FAILED) {
    perror("mmap file failed");
    close(fd);
    free(f);
    return NULL;
  }
  else {
    close(fd);
  }

  // check headers and sizes
  void *file_end = file_addr + f->size;
  if ((file_end - file_addr) < (int)sizeof(struct riff_file_header_chunk_s)) {
    fprintf(stderr, "riff header too short\n");
    int res = munmap(0, f->size);
    if (res != 0) {
      perror("munmap file failed");
    }
    free(f);
    return NULL;
  }
  f->vaddr = file_addr;

  // check header
  struct riff_file_header_chunk_s *header = (struct riff_file_header_chunk_s *)f->vaddr;

  // check type and format
  if ((memcmp(header->id, RIFF_FILE_TYPE_FILE_MAGIC, 4) != 0) ||
      (memcmp(header->format, type, 4) != 0)) {
    fprintf(stderr, "no valid riff header\n");
    fprintf(stderr, "id 0x%02x:0x%02x:0x%02x:0x%02x \"%c%c%c%c\"\n",
            header->id[0], header->id[1], header->id[2], header->id[3],
            header->id[0], header->id[1], header->id[2], header->id[3]);
    fprintf(stderr, "format 0x%02x:0x%02x:0x%02x:0x%02x \"%c%c%c%c\"\n",
            header->format[0], header->format[1], header->format[2], header->format[3],
            header->format[0], header->format[1], header->format[2], header->format[3]);
    int res = munmap(0, f->size);
    if (res != 0) {
      perror("file munmap failed");
    }
    free(f);
    return NULL;
  }

  // success
  return (void*)f;
}

//------------------------------------------------------------------
riff_file_data_chunk_iterator_h riff_file_data_chunk_iterator_new(riff_file_h file_h,
                                                                  riff_file_list_chunk_start_fn_t list_start_cb,
                                                                  riff_file_list_chunk_end_fn_t   list_end_cb)
{
  struct riff_file_s *f = (struct riff_file_s *)file_h;
  if (f != NULL) {
    struct riff_file_iterator_s *it = (struct riff_file_iterator_s *)malloc(sizeof(struct riff_file_iterator_s));
    if (it == NULL) {
      perror("malloc file iterator failed");
      return NULL;
    }
    it->file = f;
    it->addr = ((char*)f->vaddr) + sizeof(struct riff_file_header_chunk_s);
    it->list_level    = 0;
    it->list_size[0]  = f->size - sizeof(struct riff_file_header_chunk_s);
    it->list_start_cb = list_start_cb;
    it->list_end_cb   = list_end_cb;
    return it;
  }
  else {
    perror("invalid file handle");
    return NULL;
  }
}

//---------------------------------------------
int32_t riff_file_data_chunk_iterator_get_list_level(riff_file_data_chunk_iterator_h iter_h)
{
  struct riff_file_iterator_s *it = (struct riff_file_iterator_s *)iter_h;
  return it->list_level;
}

//---------------------------------------------
static void sub_all_lists(struct riff_file_iterator_s *it, int len)
{
  int i;
  for (i = 0; i <= it->list_level; i++) {
    if (it->list_size[i] >= (size_t)len) {
      it->list_size[i] -= len;
    }
    else {
      // @see https://www.recordingblogs.com/wiki/list-chunk-of-a-wave-file
      perror("LIST chunk size underflow error");
      printf("!!! SUBLIST[%d] UNDERFLOW ERROR !!! LEFT %d LEN %d\n", i, (int)it->list_size[i], len);
      it->list_size[i] = 0;
    }
  }
}

//------------------------------------------------------------------
struct riff_file_data_subchunk_s* riff_file_data_chunk_iterator_next(riff_file_data_chunk_iterator_h iter_h)
{
  struct riff_file_iterator_s *it = (struct riff_file_iterator_s *)iter_h;
  char *cur_addr = it->addr;

  while ((it->list_level > 0) && (it->list_size[it->list_level] == 0)) {
    // list done
    if (it->list_end_cb != NULL) {
      it->list_end_cb(iter_h, it->list_level);
    }
    it->list_level--;
  }

  // check if all file done
  if ((it->list_level == 0) && (it->list_size[0] == 0)) {
    // end of file, no more data to read
    return NULL;
  }

  // check if list chunk
  if (memcmp(cur_addr, RIFF_FILE_TYPE_LIST_MAGIC, 4) == 0) {
    // list
    struct riff_file_list_chunk_s *list = (struct riff_file_list_chunk_s *)cur_addr;

    // skip list header and list size
    it->addr += 8;
    sub_all_lists(it, 8);

    it->list_level++;
    assert(it->list_level < RIFF_FILE_NESTED_LIST_MAX_LEVELS);
    // store length of 'payload'
    it->list_size[ it->list_level ] = list->size;

    // if AVI movi tag, just skip data
    if (memcmp(list->type, RIFF_FILE_TYPE_AVI_MOVI_MAGIC, 4) == 0) {
      it->addr += list->size;
      sub_all_lists(it, list->size);
    }
    else {
      // skip list type
      it->addr += 4;
      sub_all_lists(it, 4);
    }

    if (it->list_start_cb != NULL) {
      it->list_start_cb(iter_h, it->list_level, list->id, list->size, list->type);
    }

    return riff_file_data_chunk_iterator_next(iter_h);
  }
  else if (memcmp(cur_addr, RIFF_FILE_TYPE_INFO_MAGIC, 4) == 0) {
    it->addr += 4;
    sub_all_lists(it, 4);
    return riff_file_data_chunk_iterator_next(iter_h);
  }
  else {
    // All chunks are aligned?
    struct riff_file_data_subchunk_s *subchunk = (struct riff_file_data_subchunk_s *)cur_addr;    

    it->addr += 8;
    sub_all_lists(it, 8);
    it->addr += subchunk->size;
    sub_all_lists(it, subchunk->size);

    return subchunk;
  }
}

//------------------------------------------------------------------
int32_t riff_file_data_chunk_iterator_delete(riff_file_data_chunk_iterator_h iter_h)
{
  free(iter_h);
  return 0;
}

//------------------------------------------------------------------
int32_t riff_file_close(riff_file_h file_h)
{
  struct riff_file_s *f = (struct riff_file_s *)file_h;
  int res = munmap(f->vaddr, f->size);
  if (res != 0) {
    perror("file munmap failed");
  }
  free(file_h);
  return 0;
}
