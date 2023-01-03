#ifndef _RIFF_FILE_READER_H_
#define _RIFF_FILE_READER_H_

/**
 * Simple RIFF file reader.
 * Uses memory mapped file to also being able to handle large files.
 *
 * RIFF format is used in several popular formats as WAV, AVI, WEBP.
 * More info on RIFF at
 * https://en.wikipedia.org/wiki/Resource_Interchange_File_Format
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

/**
   RIFF files consist entirely of "chunks".
   (from https://en.wikipedia.org/wiki/Resource_Interchange_File_Format)

   All chunks have the following format:

   4 bytes         : ASCII identifier for this chunk.
   4 bytes         : unsigned, little-endian 32-bit integer with the length
   Var-sized field : chunk data itself, of the size given in the previous field
   Pad byte        : if the chunk's length is not even

   Two chunk identifiers, "RIFF" and "LIST", introduce a chunk that can contain
   subchunks.  The RIFF and LIST chunk data (appearing after the identifier and
   length) have the following format:

   4 bytes: an ASCII identifier for this particular RIFF or LIST chunk.
   rest of data: subchunks.

   The file itself consists of one RIFF chunk, which then can contain further subchunks.
*/
struct riff_file_data_subchunk_s
{
  // ascii identifier
  char id[4];
  // unsigned little endian, might need host conversion
  uint32_t size;
  // variable size field
  uint8_t data[];

  // possibly parsed data have an added pad byte, if the chunk length not even
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
