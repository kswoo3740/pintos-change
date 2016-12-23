#include "vm/frame.h"
#include "threads/synch.h"
#include "lib/kernel/list.h"
#include "threads/thread.h"

struct list lru_list;
struct list_elem *lru_clock;
struct lock lru_list_lock;


void lru_list_init(void){
  list_init(&lru_list);
  lru_clock = NULL;
  lock_init(&lru_list_lock);
}

void add_page_to_lru_list(struct page* page){//used lock
  lock_acquire(&lru_list_lock);
  ASSERT(page);
  list_push_back(&lru_list, &page->lru);//lru_list에 page추가
  lock_release(&lru_list_lock);
}

void del_page_from_lru_list(struct page* page){//used lock
  ASSERT(lock_held_by_current_thread(&lru_list_lock));
  //lock_acquire(&lru_list_lock);
  if (&page->lru == lru_clock){
    lru_clock = list_remove(lru_clock);//if it's lru_clock
  }else {
    list_remove(&page->lru);
  }
  //lock_release(&lru_list_lock);
}

struct page* alloc_page(enum palloc_flags flags){
  void *kaddr = palloc_get_page(flags);//allocate page(virtual memory)

  while (kaddr == NULL){
    kaddr = try_to_free_pages(flags);
  }
  
  struct page *page = (struct page *)malloc(sizeof(struct page));
  if (page == NULL){
    return NULL;
  }
  ASSERT(page);
  //initalize struct page
  memset(page, 0, sizeof(struct page));
  page->kaddr = kaddr;//for kaddr
  page->thread = thread_current();//for thread
  add_page_to_lru_list(page);

  return page;
}

void free_page(void *kaddr){
  struct page *page;
  struct list_elem *elem,*tmp;
  lock_acquire(&lru_list_lock);
  for (elem = list_begin(&lru_list) ; 
       elem != list_end(&lru_list) ; ){

    tmp = list_next(elem);//elem이 삭제되는 상황 대비
    page = list_entry(elem, struct page, lru);
    
    if (page->kaddr == kaddr){//kaddr에 해당하는 page를 찾았을 때.
      __free_page(page);
      lock_release(&lru_list_lock);
      return;
    }
    elem = tmp;
  }
  lock_release(&lru_list_lock);
}

void __free_page(struct page* page){
  //memory deallocate
  ASSERT(lock_held_by_current_thread(&lru_list_lock));
  del_page_from_lru_list(page);//delete from lru_list (for lru)
  pagedir_clear_page(page->thread->pagedir, page->vme->vaddr);
  palloc_free_page(page->kaddr);//for kaddr
  free(page);//for page itself
}

struct page* find_page_with_kaddr(void *kaddr){
  struct list_elem *elem;
  struct page *page;
  int count = 0;

  for (elem = list_begin(&lru_list) ; 
       elem != list_end(&lru_list) ; 
       elem = list_next(elem)){
    page = list_entry(elem, struct page, lru);
    if (page->kaddr == kaddr){
      count ++;
    }
  }
  if (count == 1) return page;
  else if (count > 1) printf("what?\n");
  return NULL;
}

struct list_elem* get_next_lru_clock(void){//get_next_victim_elem
  if (lru_clock == NULL || lru_clock == list_end(&lru_list)){
    if(list_empty(&lru_list)){
      return NULL;
    }else {
      return (lru_clock = list_begin(&lru_list));
    }
  }
  lru_clock = list_next(lru_clock);
  if(lru_clock == list_end(&lru_list)){
    return get_next_lru_clock();
  }else {
    return lru_clock;
  }
}

extern struct lock filesys_lock;

void* try_to_free_pages(enum palloc_flags flags){
  lock_acquire(&lru_list_lock);

  struct list_elem *elem = get_next_lru_clock();
  struct page *victim = list_entry(elem, struct page, lru);
  //find next victim elem

  while(victim->vme->pinned || pagedir_is_accessed(victim->thread->pagedir, victim->vme->vaddr)){//accessed된 놈인가.
    pagedir_set_accessed(victim->thread->pagedir, victim->vme->vaddr, false);
    elem = get_next_lru_clock();
    victim = list_entry(elem, struct page, lru);
    ASSERT(victim);
    ASSERT(victim->thread);
    ASSERT(victim->thread->magic == 0xcd6abf4b);
    ASSERT(victim->vme);
  }

  bool dirty = pagedir_is_dirty(victim->thread->pagedir, victim->vme->vaddr);
  //release from physical memory
  switch (victim->vme->type){
    case VM_BIN:
      if (dirty){
        victim->vme->swap_slot = swap_out(victim->kaddr);
        victim->vme->type = VM_ANON;
      }
      //for demand paging
      break;
    case VM_FILE:
      if (dirty){
        lock_acquire(&filesys_lock);
        file_write_at(victim->vme->file, victim->kaddr, victim->vme->read_bytes, victim->vme->offset);
        lock_release(&filesys_lock);
      }

      //page deallocate
      break;
    case VM_ANON:
      victim->vme->swap_slot = swap_out(victim->kaddr);
      break;
    default:
      exit(-1234);//don't reach here
  }
  victim->vme->is_loaded = false;

  __free_page(victim);
  lock_release(&lru_list_lock);
  return palloc_get_page(flags);
}

extern struct lock swap_lock;

void free_all_pages(tid_t tid){
  lock_acquire(&lru_list_lock);
  struct list_elem *elem, *tmp;
  struct page * page;
  for (elem = list_begin(&lru_list) ; 
       elem != list_end(&lru_list) ; ){
    tmp = list_next(elem);
    page = list_entry(elem, struct page, lru);
    if (page->thread->tid == tid){
      del_page_from_lru_list(page);
    }
    elem = tmp;
  }
  lock_release(&lru_list_lock);
}
