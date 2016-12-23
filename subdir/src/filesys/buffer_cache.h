#ifndef _BUFFER_CACHE_H_
#define _BUFFER_CACHE_H_

#include "threads/synch.h"
#include "devices/block.h"
#include "filesys/off_t.h"

struct buffer_head{
  bool dirty;
  bool valid;
  
  block_sector_t address;
  
  bool clock;
  char *buffer;

  struct lock buffer_lock;
  
};

bool bc_read(block_sector_t sector_idx, void *buffer, off_t bytes_read, int chunk_size, int sector_ofs);
bool bc_write(block_sector_t sector_idx, void *buffer, off_t bytes_written, int chink_size, int sector_ofs);

void bc_init(void);
void bc_term(void);
struct buffer_head* bc_select_victim (void);
struct buffer_head* bc_lookup (block_sector_t sector);
void bc_flush_entry (struct buffer_head *p_flush_entry);
void bc_flush_all_entries (void);
#endif
