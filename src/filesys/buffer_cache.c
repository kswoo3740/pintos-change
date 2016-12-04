#include "filesys/buffer_cache.h"
#include "threads/palloc.h"
#include "threads/malloc.h"
#include <string.h>
#include <debug.h>

#define BUFFER_CACHE_ENTRIES 64

struct buffer_head *buffer_head;  // store cache info
char *p_buffer_cache;  // buffer which store real data
struct buffer_head *clock_hand;  // for clock algorithm
struct lock bc_lock;  // lock for modify buffer head

void
bc_init (void)
{
  buffer_head = (struct buffer_head*) malloc (sizeof (struct buffer_head) * BUFFER_CACHE_ENTRIES);  // Initailize buffer head
  memset (buffer_head, 0, sizeof (struct buffer_head) * BUFFER_CACHE_ENTRIES);

  p_buffer_cache = (char*) malloc (sizeof(char) * (BUFFER_CACHE_ENTRIES * BLOCK_SECTOR_SIZE));  // Allocate buffer cache
  memset (p_buffer_cache, 0, sizeof(char) * (BUFFER_CACHE_ENTRIES * BLOCK_SECTOR_SIZE));

  struct buffer_head *head;
  void *cache = p_buffer_cache;

  for (head = buffer_head; head != buffer_head + BUFFER_CACHE_ENTRIES;)
  {
    /* Initialize every struct not dirty and not valid */
    memset (head, 0, sizeof (struct buffer_head));
    lock_init (&head->lock);
    head->buffer = cache;

    head++;
    cache += BLOCK_SECTOR_SIZE;
  }

  clock_hand = buffer_head;

  lock_init (&bc_lock);
}

void
bc_term (void)
{
  bc_flush_all_entries(); // Flush all entreis

  free (p_buffer_cache);
  free (buffer_head);
}

bool
bc_read (block_sector_t sector_idx, void *buffer, off_t bytes_read, int chunk_size, int sector_ofs)
{
  struct buffer_head *head = bc_lookup (sector_idx);

  if (!head)
  {
    head = bc_select_victim();

    bc_flush_entry (head);

    head->valid = true;
    head->dirty = false;
    head->address = sector_idx;

    lock_release (&bc_lock);
    block_read (fs_device, sector_idx, head->buffer);  // Read from block
  }

  head->clock = true;

  memcpy (buffer + bytes_read, head->buffer + sector_ofs, chunk_size);  // Read from buffer

  lock_release (&head->lock);

  return true;
}

bool
bc_write (block_sector_t sector_idx, void *buffer, off_t bytes_written, int chunk_size, int sector_ofs)
{
  struct buffer_head *head = bc_lookup (sector_idx);

  if (!head)
  {
    head = bc_select_victim();

    bc_flush_entry (head);

    head->valid = true;
    head->address = sector_idx;

    lock_release (&bc_lock);
    block_read (fs_device, sector_idx, head->buffer);  // Read from block
  }

  head->clock = true;
  head->dirty = true;

  memcpy (head->buffer + sector_ofs, buffer + bytes_written, chunk_size);  // Write to buffer

  lock_release (&head->lock);
  
  return true;
}

struct buffer_head*
bc_select_victim (void)
{
  bool check = false;
  struct buffer_head *res = NULL;

  while (!check)
  {
    /* Loop until find victim */
    for (; clock_hand != buffer_head + BUFFER_CACHE_ENTRIES; clock_hand++)
    {
      lock_acquire (&clock_hand->lock);

      if (!clock_hand->valid || !clock_hand->clock)
      {
        res = clock_hand;
        clock_hand++;

        check = true;
        break;
      }
      
      clock_hand->clock = false;
      lock_release (&clock_hand->lock);
    }

    clock_hand = buffer_head;
  }

  return res;
}

struct buffer_head*
bc_lookup (block_sector_t sector)
{
  lock_acquire (&bc_lock);
  struct buffer_head *head;

  for (head = buffer_head; head != buffer_head + BUFFER_CACHE_ENTRIES; head++)
  {
    /* Find matching value and return */
    if (head->valid && head->address == sector)
    {
      lock_acquire (&head->lock);
      lock_release (&bc_lock);

      return head;
    }
  }

  return NULL;
}

void
bc_flush_entry (struct buffer_head *p_flush_entry)
{
  if (!p_flush_entry->valid || !p_flush_entry->dirty)
    return;

  p_flush_entry->dirty = false;  // Not dirty any more

  block_write (fs_device, p_flush_entry->address, p_flush_entry->buffer);  // Transfer data to disk
}

void
bc_flush_all_entries (void)
{
  struct buffer_head *head;

  for (head = buffer_head; head != buffer_head + BUFFER_CACHE_ENTRIES; head++)
  {
    /* Remove all dirty entry */
    lock_acquire (&head->lock);
    bc_flush_entry (head);
    lock_release (&head->lock);
  }
}
