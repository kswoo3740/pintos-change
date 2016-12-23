#include "filesys/inode.h"
#include <list.h>
#include <debug.h>
#include <round.h>
#include <string.h>
#include "filesys/filesys.h"
#include "filesys/free-map.h"
#include "threads/malloc.h"
#include "filesys/buffer_cache.h"

/* Identifies an inode. */
#define INODE_MAGIC 0x494e4f44

#define DIRECT_BLOCK_ENTRIES 124
#define INDIRECT_BLOCK_ENTRIES (BLOCK_SECTOR_SIZE/sizeof(block_sector_t))

/* On-disk inode.
   Must be exactly BLOCK_SECTOR_SIZE bytes long. */
struct inode_disk
  {
    off_t length;                       /* File size in bytes. */
    unsigned magic;                     /* Magic number. */
    uint32_t is_dir;  //If is directory this is 1, if not it sets to be 0
    block_sector_t direct_map_table[DIRECT_BLOCK_ENTRIES];
    block_sector_t indirect_block_sec;
    block_sector_t double_indirect_block_sec;
  };

enum direct_t{
  NORMAL_DIRECT,
  INDIRECT,
  DOUBLE_INDIRECT,
  OUT_LIMIT
};

struct sector_location{
  int directness;
  int index1;
  int index2;
};

struct index_block{
  block_sector_t map_table[INDIRECT_BLOCK_ENTRIES];
};

static bool get_disk_inode(const struct inode *inode, struct inode_disk *inode_disk);

static void locate_byte(off_t pos, struct sector_location *sec_loc){
  off_t pos_sector = pos/BLOCK_SECTOR_SIZE;

  if (pos_sector < DIRECT_BLOCK_ENTRIES){
    sec_loc->directness = NORMAL_DIRECT;
    sec_loc->index1 = pos_sector;
  }else if (pos_sector < (off_t) (DIRECT_BLOCK_ENTRIES + INDIRECT_BLOCK_ENTRIES)){
    sec_loc->directness = INDIRECT;
    sec_loc->index1 = pos_sector - (off_t)DIRECT_BLOCK_ENTRIES;
  }else if (pos_sector < (off_t) (DIRECT_BLOCK_ENTRIES + INDIRECT_BLOCK_ENTRIES * (INDIRECT_BLOCK_ENTRIES + 1))){
    sec_loc->directness = DOUBLE_INDIRECT;
    sec_loc->index1 = (pos_sector - (off_t)DIRECT_BLOCK_ENTRIES) / INDIRECT_BLOCK_ENTRIES;
    sec_loc->index2 = (pos_sector - (off_t)DIRECT_BLOCK_ENTRIES) % INDIRECT_BLOCK_ENTRIES;
  }else {
    sec_loc->directness = OUT_LIMIT;
  }
}

static inline off_t map_table_offset (int index){
  return index * 4;
}

static bool register_sector (struct inode_disk *inode_disk, 
                             block_sector_t new_sector, 
                             struct sector_location sec_loc){
  block_sector_t *new_block;
  switch (sec_loc.directness){
    case NORMAL_DIRECT:
      inode_disk->direct_map_table[sec_loc.index1] = new_sector;
      break;
    case INDIRECT :
      new_block = malloc(BLOCK_SECTOR_SIZE);
      if (new_block == NULL) return false;
      
      if (sec_loc.index1 == 0){//아직 indirect table이 없는 경우
        block_sector_t ind_block_sec;
        if (free_map_allocate(1, &ind_block_sec)){
          inode_disk->indirect_block_sec = ind_block_sec;
        }
        else {
          free(new_block);
          return false;
        }
      }
      
      new_block[sec_loc.index1] = new_sector;
      bc_write(inode_disk->indirect_block_sec, new_block, 
               map_table_offset(sec_loc.index1), sizeof(block_sector_t), 
               map_table_offset(sec_loc.index1));

      free(new_block);
      break;
    
    case DOUBLE_INDIRECT :
      new_block = malloc(BLOCK_SECTOR_SIZE);
      if (new_block == NULL) return false;

      if (sec_loc.index1 == 0 && sec_loc.index2 == 0){//아직 double_indrect_table이 없는 경우
        block_sector_t dbl_ind_block_sec;
        if (free_map_allocate(1, &dbl_ind_block_sec)){
          inode_disk->double_indirect_block_sec = dbl_ind_block_sec;
        }
        else {
          free(new_block);
          return false;
        }
      }
      bc_read(inode_disk->double_indirect_block_sec, new_block, 0, sizeof(struct index_block), 0);
      
      new_block[sec_loc.index2] = new_sector;
      bc_write(new_block[sec_loc.index1], new_block, 
               map_table_offset(sec_loc.index2), sizeof(block_sector_t), 
               map_table_offset(sec_loc.index2));

      free(new_block);
      break;
    default :
      return false;
  }
  return true;
}

static block_sector_t byte_to_sector (const struct inode_disk *inode_disk, off_t pos){
  block_sector_t result_sec = -1;

  if (pos < inode_disk->length){
    struct index_block *ind_block = malloc(sizeof(struct index_block));
    struct sector_location sec_loc;
    locate_byte (pos, &sec_loc);

    switch (sec_loc.directness){
      case NORMAL_DIRECT :
        result_sec = inode_disk->direct_map_table[sec_loc.index1];
        break;
      case INDIRECT :
        bc_read(inode_disk->indirect_block_sec, ind_block->map_table, 0, sizeof(struct index_block), 0);
        result_sec = ind_block->map_table[sec_loc.index1];
        break;
      case DOUBLE_INDIRECT :
        bc_read(inode_disk->double_indirect_block_sec, ind_block, 0, sizeof(struct index_block), 0);
        block_sector_t sector_index = ind_block->map_table[sec_loc.index1];
        bc_read(sector_index, ind_block->map_table, 0, sizeof(struct index_block), 0);
        result_sec = ind_block->map_table[sec_loc.index2];
        break;
      default :
        printf("OUT_LIMIT\n");
        free(ind_block);
        return -1;;
    }
    free(ind_block);
    return result_sec;
  }else {
    return -1;
  }
}

bool inode_update_file_length (struct inode_disk *inode_disk, off_t start_pos, off_t end_pos){
  off_t size = end_pos - start_pos + 1;
  off_t offset = start_pos;
  block_sector_t sector_idx;
  inode_disk->length = end_pos + 1;
  unsigned chunk_size = 0;
  struct sector_location sec_loc;

  void *zeroes = malloc(BLOCK_SECTOR_SIZE);
  memset(zeroes, 0, BLOCK_SECTOR_SIZE);

  while (size > 0){
    off_t sector_ofs = offset % BLOCK_SECTOR_SIZE;
    chunk_size = BLOCK_SECTOR_SIZE - sector_ofs;
    if (size < BLOCK_SECTOR_SIZE)
      if (sector_ofs + size <= BLOCK_SECTOR_SIZE) chunk_size = size;


    if (sector_ofs > 0){
      sector_idx = byte_to_sector(inode_disk, offset);
      if (sector_idx == 0){ //for sparse
        if (free_map_allocate(1, &sector_idx)){
          locate_byte(offset, &sec_loc);
          register_sector(inode_disk, sector_idx, sec_loc);
        }else {
          free(zeroes);
          return false;
        }
        bc_write(sector_idx, zeroes, 0, BLOCK_SECTOR_SIZE, 0);   
      }
    }else {
      if (free_map_allocate(1, &sector_idx)){
        locate_byte(offset, &sec_loc);
        register_sector(inode_disk, sector_idx, sec_loc);
      }else {
        free(zeroes);
        return false;
      }
      bc_write(sector_idx, zeroes, 0, BLOCK_SECTOR_SIZE, 0);   
    }
    size -= chunk_size;
    offset += chunk_size;

  }
  free(zeroes);
  return true;
}

static void free_inode_sectors (struct inode_disk *inode_disk){
  int i, j;
  struct index_block *ind_block_1 = malloc(sizeof(struct index_block));
  struct index_block *ind_block_2 = malloc(sizeof(struct index_block));

  if (inode_disk->double_indirect_block_sec > 0){//if exists
    bc_read(inode_disk->double_indirect_block_sec, ind_block_1->map_table, 0, sizeof(struct index_block), 0);
    i = 0;
    while (ind_block_1->map_table[i] > 0){
      bc_read(ind_block_1->map_table[i], ind_block_2->map_table, 0, sizeof(struct index_block), 0);
      j = 0;
      while (ind_block_2->map_table[j] > 0){
        struct buffer_head *cache_entry = bc_lookup(ind_block_2->map_table[j]);
        if (cache_entry != NULL){
          bc_flush_entry(cache_entry);
        }
        free_map_release(ind_block_2->map_table[j], 1);
        j ++;
      }

      struct buffer_head *cache_entry = bc_lookup(ind_block_1->map_table[i]);
      if (cache_entry != NULL){
        bc_flush_entry(cache_entry);
      }
      free_map_release(ind_block_1->map_table[i], 1);
      i ++;
    }

    struct buffer_head *cache_entry = bc_lookup(inode_disk->double_indirect_block_sec);
    if (cache_entry != NULL){
      bc_flush_entry(cache_entry);
    }
    free_map_release(inode_disk->double_indirect_block_sec, 1);
  }
  

  if (inode_disk->indirect_block_sec > 0){
    bc_read(inode_disk->indirect_block_sec, ind_block_1->map_table, 0, sizeof(struct index_block), 0);
    i = 0;
    while (ind_block_1->map_table[i] > 0){
      struct buffer_head *cache_entry = bc_lookup(ind_block_1->map_table[i]);
      if (cache_entry != NULL){
        bc_flush_entry(cache_entry);
      }
      free_map_release(ind_block_1->map_table[i], 1);
      i ++;
    }
    
    struct buffer_head *cache_entry = bc_lookup(inode_disk->indirect_block_sec);
    if (cache_entry != NULL){
      bc_flush_entry(cache_entry);
    }
    free_map_release(inode_disk->indirect_block_sec, 1);
  }

  i = 0;
  while (inode_disk->direct_map_table[i] > 0){
    struct buffer_head *cache_entry = bc_lookup(inode_disk->direct_map_table[i]);
    if (cache_entry != NULL){
      bc_flush_entry(cache_entry);
    }
    free_map_release(inode_disk->direct_map_table[i], 1);
    i ++;
  }


  free(ind_block_1);
  free(ind_block_2);
}

/* Returns the number of sectors to allocate for an inode SIZE
   bytes long. */
static inline size_t
bytes_to_sectors (off_t size)
{
  return DIV_ROUND_UP (size, BLOCK_SECTOR_SIZE);
}

/* In-memory inode. */
struct inode 
  {
    struct list_elem elem;              /* Element in inode list. */
    block_sector_t sector;              /* Sector number of disk location. */
    int open_cnt;                       /* Number of openers. */
    bool removed;                       /* True if deleted, false otherwise. */
    int deny_write_cnt;                 /* 0: writes ok, >0: deny writes. */
    struct lock extend_lock;
  };

/* List of open inodes, so that opening a single inode twice
   returns the same `struct inode'. */
static struct list open_inodes;

/* Initializes the inode module. */
void
inode_init (void) 
{
  list_init (&open_inodes);
}

/* Initializes an inode with LENGTH bytes of data and
   writes the new inode to sector SECTOR on the file system
   device.
   Returns true if successful.
   Returns false if memory or disk allocation fails. */
bool
inode_create (block_sector_t sector, off_t length, uint32_t is_dir)
{
  struct inode_disk *disk_inode = NULL;
  bool success = false;

  ASSERT (length >= 0);

  /* If this assertion fails, the inode structure is not exactly
     one sector in size, and you should fix that. */
  ASSERT (sizeof *disk_inode == BLOCK_SECTOR_SIZE);

  disk_inode = calloc (1, sizeof *disk_inode);
  if (disk_inode != NULL)
    {
      disk_inode->length = length;
      disk_inode->magic = INODE_MAGIC;

      if (length > 0){
        inode_update_file_length(disk_inode, 0, (length-1));
      }

      disk_inode->is_dir = is_dir;

      success = bc_write(sector, disk_inode, 0, BLOCK_SECTOR_SIZE, 0);
      free(disk_inode);
    }
  return success;
}

/* Reads an inode from SECTOR
   and returns a `struct inode' that contains it.
   Returns a null pointer if memory allocation fails. */
struct inode *
inode_open (block_sector_t sector)
{
  struct list_elem *e;
  struct inode *inode;

  /* Check whether this inode is already open. */
  for (e = list_begin (&open_inodes); e != list_end (&open_inodes);
       e = list_next (e)) 
    {
      inode = list_entry (e, struct inode, elem);
      if (inode->sector == sector) 
        {
          inode_reopen (inode);
          return inode; 
        }
    }

  /* Allocate memory. */
  inode = malloc (sizeof *inode);
  if (inode == NULL)
    return NULL;

  /* Initialize. */
  list_push_front (&open_inodes, &inode->elem);
  inode->sector = sector;
  inode->open_cnt = 1;
  inode->deny_write_cnt = 0;
  inode->removed = false;

  lock_init(&inode->extend_lock);
  return inode;
}

/* Reopens and returns INODE. */
struct inode *
inode_reopen (struct inode *inode)
{
  if (inode != NULL)
    inode->open_cnt++;
  return inode;
}

/* Returns INODE's inode number. */
block_sector_t
inode_get_inumber (const struct inode *inode)
{
  return inode->sector;
}

/* Closes INODE and writes it to disk.
   If this was the last reference to INODE, frees its memory.
   If INODE was also a removed inode, frees its blocks. */
void
inode_close (struct inode *inode) 
{
  /* Ignore null pointer. */
  if (inode == NULL)
    return;

  /* Release resources if this was the last opener. */
  if (--inode->open_cnt == 0)
    {
      /* Remove from inode list and release lock. */
      list_remove (&inode->elem);
 
      /* Deallocate blocks if removed. */
      if (inode->removed) 
        {
          struct inode_disk inode_disk;
          get_disk_inode(inode, &inode_disk);
          free_inode_sectors(&inode_disk);
          free_map_release(inode->sector, 1);   
        }

      free (inode); 
    }
}

/* Marks INODE to be deleted when it is closed by the last caller who
   has it open. */
void
inode_remove (struct inode *inode) 
{
  ASSERT (inode != NULL);
  inode->removed = true;
}

/* Reads SIZE bytes from INODE into BUFFER, starting at position OFFSET.
   Returns the number of bytes actually read, which may be less
   than SIZE if an error occurs or end of file is reached. */
off_t
inode_read_at (struct inode *inode, void *buffer_, off_t size, off_t offset) 
{
  uint8_t *buffer = buffer_;
  off_t bytes_read = 0;
  static bool sec_0 = true;
  struct inode_disk *disk_inode = malloc(sizeof(struct inode_disk));
  if (disk_inode == NULL) return 0;

  lock_acquire(&inode->extend_lock);
  get_disk_inode(inode,disk_inode);
  lock_release(&inode->extend_lock);
  
  off_t length = disk_inode->length;
  
  while (size > 0) 
    {
      /* Disk sector to read, starting byte offset within sector. */
      block_sector_t sector_idx = byte_to_sector (disk_inode, offset);
//????????????????????????????????????????????????????????
      if(sector_idx == 0 & sec_0){
        void *zero = malloc(BLOCK_SECTOR_SIZE);
        memset(zero, 0, BLOCK_SECTOR_SIZE);
        bc_write(sector_idx, zero, 0, BLOCK_SECTOR_SIZE, 0);
        free(zero);
        sec_0 = false;
      }

      int sector_ofs = offset % BLOCK_SECTOR_SIZE;

      /* Bytes left in inode, bytes left in sector, lesser of the two. */
      off_t inode_left = inode_length (inode) - offset;
      int sector_left = BLOCK_SECTOR_SIZE - sector_ofs;
      int min_left = inode_left < sector_left ? inode_left : sector_left;

      /* Number of bytes to actually copy out of this sector. */
      int chunk_size = size < min_left ? size : min_left;
      if (chunk_size <= 0)
        break;

      bc_read (sector_idx, buffer, bytes_read, chunk_size, sector_ofs);
      
      /* Advance. */
      size -= chunk_size;
      offset += chunk_size;
      bytes_read += chunk_size;
    }

  free(disk_inode);
  return bytes_read;
}

/* Writes SIZE bytes from BUFFER into INODE, starting at OFFSET.
   Returns the number of bytes actually written, which may be
   less than SIZE if end of file is reached or an error occurs.
   (Normally a write at end of file would extend the inode, but
   growth is not yet implemented.) */
off_t
inode_write_at (struct inode *inode, const void *buffer_, off_t size,
                off_t offset) 
{
  const uint8_t *buffer = buffer_;
  off_t bytes_written = 0;

  if (inode->deny_write_cnt)
    return 0;
  
  lock_acquire(&inode->extend_lock);
  struct inode_disk *disk_inode = malloc(sizeof(struct inode_disk));
  if (disk_inode == NULL) return -1;
  get_disk_inode(inode, disk_inode);

  int length = disk_inode->length;
  int write_end = offset + size - 1;

  if (write_end > length - 1){
    inode_update_file_length(disk_inode, offset, write_end);
    bc_write(inode->sector, disk_inode, 0, sizeof(struct inode_disk), 0);
  }

  lock_release(&inode->extend_lock);


  while (size > 0) 
    {
      /* Sector to write, starting byte offset within sector. */
      lock_acquire(&inode->extend_lock);
      block_sector_t sector_idx = byte_to_sector (disk_inode, offset);
      int sector_ofs = offset % BLOCK_SECTOR_SIZE;

      /* Bytes left in inode, bytes left in sector, lesser of the two. */
      off_t inode_left = inode_length (inode) - offset;
      int sector_left = BLOCK_SECTOR_SIZE - sector_ofs;
      int min_left = inode_left < sector_left ? inode_left : sector_left;

      /* Number of bytes to actually write into this sector. */
      int chunk_size = size < min_left ? size : min_left;
      if (chunk_size <= 0)
        break;

      bc_write (sector_idx, (void*)buffer, bytes_written, chunk_size, sector_ofs);
      lock_release(&inode->extend_lock);
      /* Advance. */
      size -= chunk_size;
      offset += chunk_size;
      bytes_written += chunk_size;
    }

  return bytes_written;
}

/* Disables writes to INODE.
   May be called at most once per inode opener. */
void
inode_deny_write (struct inode *inode) 
{
  inode->deny_write_cnt++;
  ASSERT (inode->deny_write_cnt <= inode->open_cnt);
}

/* Re-enables writes to INODE.
   Must be called once by each inode opener who has called
   inode_deny_write() on the inode, before closing the inode. */
void
inode_allow_write (struct inode *inode) 
{
  ASSERT (inode->deny_write_cnt > 0);
  ASSERT (inode->deny_write_cnt <= inode->open_cnt);
  inode->deny_write_cnt--;
}

/* Returns the length, in bytes, of INODE's data. */
off_t
inode_length (const struct inode *inode)
{
  struct inode_disk *disk_inode = (struct inode_disk *)malloc(BLOCK_SECTOR_SIZE);
  get_disk_inode(inode, disk_inode);

  off_t length = disk_inode->length;
  free(disk_inode);
  return length;
}
static bool get_disk_inode(const struct inode *inode, struct inode_disk *inode_disk){
  return bc_read (inode->sector, inode_disk, 0, sizeof(struct inode_disk), 0);
}

bool
inode_is_dir (const struct inode *inode)
{
  struct inode_disk inode_disk;
  
  if (inode->removed)  //If inode is removed
      return false;
  if (!get_disk_inode (inode, &inode_disk))
      return false;
  return inode_disk.is_dir;
}
