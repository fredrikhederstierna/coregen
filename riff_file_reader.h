#ifndef _RIFF_FILE_READER_H_
#define _RIFF_FILE_READER_H_

/**
 * Simple RIFF file reader.
 * Uses memory mapped file to also being able to handle large files.
 *
 * Fredrik Hederstierna 2021
 *
 * RIFF format is used in several popular formats as WAV, AVI, WEBP.
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

#include <stdint.h>

struct riff_file_data_subchunk_s
{
  // ascii identifier
  char id[4];
  // unsigned little endian, might need host conversion
  uint32_t size;
  // variable size field
  uint8_t data[];

  // possibly add a pad byte, if the chunk's length is not even
};

struct riff_file_list_chunk_s
{
  // ascii identifier
  char id[4];
  // unsigned little endian, might need host conversion
  uint32_t size;
  // list type
  char type[4];
  // subchunks
  struct riff_file_data_subchunk_s subchunk[];
};

struct riff_file_header_chunk_s
{
  // ascii identifier
  char id[4];
  // unsigned little endian, might need host conversion
  uint32_t size;
  // format type
  char format[4];
};

// handles to RIFF file and iterator
typedef void* riff_file_h;
typedef void* riff_file_data_chunk_iterator_h;

// callbacks for LIST chunk starting and ending
typedef void (*riff_file_list_chunk_start_fn_t)(riff_file_data_chunk_iterator_h iter_h, int level,
                                                const char type[4], size_t size, const char format[4]);
typedef void (*riff_file_list_chunk_end_fn_t)(riff_file_data_chunk_iterator_h iter_h, int level);

// open file
riff_file_h riff_file_open(const char *filename, const char type[4]);

// create new chunk iterator
riff_file_data_chunk_iterator_h riff_file_data_chunk_iterator_new(riff_file_h file_h,
                                                                  riff_file_list_chunk_start_fn_t list_start_cb,
                                                                  riff_file_list_chunk_end_fn_t   list_end_cb);

// iterate over file gettting next chunk
//@return NULL is EOF
struct riff_file_data_subchunk_s* riff_file_data_chunk_iterator_next(riff_file_data_chunk_iterator_h iter_h);

// return current nested list level
int32_t riff_file_data_chunk_iterator_get_list_level(riff_file_data_chunk_iterator_h iter_h);

// delete iterator
int32_t riff_file_data_chunk_iterator_delete(riff_file_data_chunk_iterator_h iter_h);

// close file
int32_t riff_file_close(riff_file_h file_h);

#endif
