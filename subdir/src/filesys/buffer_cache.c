#include "buffer_cache.h"
#include "filesys/filesys.h"
#include "userprog/process.h"

#define BUFFER_CACHE_ENTRY_NB 64

char p_buffer_cache[BUFFER_CACHE_ENTRY_NB * BLOCK_SECTOR_SIZE]; // 32kb
struct buffer_head buffer_cache[BUFFER_CACHE_ENTRY_NB];
int clock_now = 0;

struct lock bc_lock;

void bc_init(void){
  /*  Allocation buffer cache in Memory
   *  p_buffer_cache가 buffer cache 영역 포인팅
   *  전역변수 buffer_head 자료구조 초기화
   * */
  memset(p_buffer_cache, 0, BUFFER_CACHE_ENTRY_NB * BLOCK_SECTOR_SIZE);
  int i = 0;
  for (i = 0 ; i < BUFFER_CACHE_ENTRY_NB ; i ++){
    //buffer_cache[i];
    memset(buffer_cache + i, 0, sizeof(struct buffer_head));
    buffer_cache[i].buffer = p_buffer_cache + i * BLOCK_SECTOR_SIZE;
    lock_init(&buffer_cache[i].buffer_lock);
  }
  clock_now = 0;
  lock_init(&bc_lock);
}

void bc_term(void){
  /*  bc_flush_all_entries 함수를 호출하여 모든 buffer cache entry를 디스크로 flush
   *  buffer cache영역 할당 해제
   * */
  bc_flush_all_entries();
}

void bc_flush_all_entries (void){
  /*  전역변수 buffer_head를 순회하며, dirty인 entry는 block_write함수를 호출하여 디스크로 flush
   *  디스크로 flush한 후, buffer_head의 dirty값 update
   * */
  struct buffer_head *bc_entry = NULL;
  int i = 0;
  for (i = 0 ; i < BUFFER_CACHE_ENTRY_NB ; i ++){
    bc_entry = &buffer_cache[i];
    //lock_acquire(&bc_entry->buffer_lock);


    bc_flush_entry(bc_entry);

    //lock_release(&bc_entry->buffer_lock);
  }
}

void bc_flush_entry (struct buffer_head *p_flush_entry){
  /*  block_write을 호출하여, 인자로 전달받은 buffer cache entry의 데이터를 디스크로 flush
   *  buffer_head의 dirty 값 update
   * */
  //ASSERT(lock_held_by_current_thread (&p_flush_entry->buffer_lock));
  //printf("p_flush_entry = %x\n", p_flush_entry);
  //printf("address = %x, buffer = %x\n",p_flush_entry->address , p_flush_entry->buffer);
  if (!p_flush_entry->valid || !p_flush_entry->dirty){
    return;
  }
  p_flush_entry->dirty = false;
  block_write(fs_device, p_flush_entry->address, p_flush_entry->buffer);//512bytes
}

bool bc_read(block_sector_t sector_idx, void *buffer, off_t bytes_read, int chunk_size, int sector_ofs){
  /*  sector_idx를 buffer_head에서 검색 (bc_lookup 사용)
   *  검색해서 없을 경우, 디스크 블록을 캐싱할 buffer entry의 buffer_head를 구함
   *  (bc_select_victim이용)
   *  block_read함수를 이용해, 디스크 블록 데이터를 buffer cache로 read
   *  memcpy 함수를 통해, buffer 에 디스크 블록 데이터를 복사
   *  buffer_head의 clock_bit 을 setting
   * */
  struct buffer_head *buf = bc_lookup(sector_idx);
  if (buf == NULL){
    buf = bc_select_victim();
    bc_flush_entry(buf);
    buf->valid = true;
    buf->dirty = false;
    buf->address = sector_idx;

    lock_release(&bc_lock);
    block_read(fs_device, sector_idx, buf->buffer);
  }
  buf->clock = true;

  memcpy(buffer + bytes_read, buf->buffer + sector_ofs , chunk_size);
  lock_release(&buf->buffer_lock);
  return true;
}

bool bc_write(block_sector_t sector_idx, void *buffer, off_t bytes_written, int chunk_size, int sector_ofs){
  /*  sector_idx를 buffer_head에서 검색하여 buffer에 복사(구현)
   *  update buffer head구현
   * */
  struct buffer_head *buf = bc_lookup(sector_idx);
  if (buf == NULL){
    buf = bc_select_victim();
    bc_flush_entry(buf);
    buf->valid = true;
    buf->address = sector_idx;

    lock_release(&bc_lock);
    block_read(fs_device, sector_idx, buf->buffer);
  }
  buf->clock = true;
  buf->dirty = true;
  memcpy(buf->buffer + sector_ofs, buffer + bytes_written, chunk_size);
  lock_release(&buf->buffer_lock);
  return true;
}



struct buffer_head* bc_select_victim (void){
  /*  clock 알고리즘을 사용하여 victim entry를 선택
   *  buffer_head 전역변수를 순회하며 clock_bit 변수를 검사
   *  선택된 victim entry가 dirty일 경우, 디스크로 flush
   *  victim_entry에 해당하는 buffer_head값 update??
   *  victim_entry를 return
   * */
  struct buffer_head *candidate = NULL;
  while (1){
    clock_now = clock_now % BUFFER_CACHE_ENTRY_NB; 
    candidate = buffer_cache + clock_now++;

    lock_acquire(&candidate->buffer_lock);
    if (!candidate->valid || !candidate->clock){
      break;
    }
    candidate->clock = false;
    lock_release(&candidate->buffer_lock);
  }
  return candidate;
}

struct buffer_head* bc_lookup (block_sector_t sector){
  /*  buffer_head를 순회하며, 전달받은 sector값과 동일한
   *  sector 값을 갖는 buffer cache entry가 있는지 확인
   *  성공 : 찾은 buffer_head 반환, 실패 : NULL
   * */
  lock_acquire(&bc_lock);
  int i = 0;
  struct buffer_head *bc_entry = NULL;

  for (i = 0 ; i < BUFFER_CACHE_ENTRY_NB ; i ++){
    bc_entry = &buffer_cache[i];
    if (bc_entry->valid && bc_entry->address == sector){
      lock_acquire(&bc_entry->buffer_lock);
      lock_release(&bc_lock);
      return bc_entry;
    }
  }
  
  return NULL;
}

