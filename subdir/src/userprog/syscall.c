#include "userprog/syscall.h"
#include <stdio.h>
#include <syscall-nr.h>
#include "threads/interrupt.h"
#include "threads/thread.h"   // thread_exit()
#include "devices/shutdown.h" // shutdown_power_off()
#include "filesys/filesys.h"  // filesys_create(), filesys_remove()
#include "userprog/process.h" // process_execute(), process_wait()
#include "filesys/file.h"
#include "filesys/inode.h"
#include "filesys/directory.h"
#include "devices/input.h"
#include <string.h>

static void syscall_handler (struct intr_frame *f UNUSED);

void
syscall_init (void) 
{
  intr_register_int (0x30, 3, INTR_ON, syscall_handler, "syscall");
  lock_init(&filesys_lock);
}

static void
syscall_handler (struct intr_frame *f UNUSED) 
{
	void *esp = f->esp;
	int number = *(int *)(f->esp);
	int arg[4];						

  check_address(esp);
  //esp가 유효한지 검사합니다.
  
  switch(number){
	case SYS_HALT:
    halt();
    break;
	case SYS_EXIT:
    get_argument(f->esp,arg,1);
    exit(arg[0]);
    break;
  case SYS_CREATE :
    get_argument(f->esp, arg, 2);
		f->eax = create((const char *)arg[0], (unsigned int) arg[1]);
    break;
 	case SYS_REMOVE :
    get_argument(f->esp, arg ,1);
    f->eax = remove((const char *)arg[0]);
    break;
	case SYS_EXEC:
    get_argument(f->esp,arg,1);
    f->eax = exec((const char *)arg[0]);
    break;
  case SYS_OPEN :
    get_argument(f->esp,arg,1);
    f->eax = open((const char *)arg[0]);
    break;
  case SYS_FILESIZE :
    get_argument(f->esp,arg,1);
    f->eax = filesize((int) arg[0]);
    break;
  case SYS_READ :
		get_argument(f->esp,arg,3);
		f->eax = read((int) arg[0], (void *)arg[1], (unsigned) arg[2]);
    break;
  case SYS_WRITE :
    get_argument(f->esp,arg,3);
		f->eax = write((int) arg[0], (void *)arg[1], (unsigned) arg[2]);
    break;
  case SYS_SEEK :
		get_argument(f->esp,arg,2);
		seek((int) arg[0], (unsigned) arg[1]);
    break;
  case SYS_TELL :
		get_argument(f->esp,arg,1);
  	f->eax = tell((int) arg[0]);
    break;
  case SYS_CLOSE :
		get_argument(f->esp,arg,1);
		close((int) arg[0]);
    break;
  case SYS_WAIT : 
    get_argument(f->esp,arg,1);
    f->eax = wait((tid_t) arg[0]);
    break;
  case SYS_CHDIR:
    get_argument (f->esp, arg, 1);
    f->eax = chdir ((const char*) arg[0]);
    break;
  case SYS_READDIR:
    get_argument (f->esp, arg, 2);
    f->eax = readdir ((int) arg[0], (char*) arg[1]);
    break;
  case SYS_ISDIR:
    get_argument (f->esp, arg, 1);
    f->eax = isdir ((int) arg[0]);
    break;
  case SYS_INUMBER:
    get_argument (f->esp, arg, 1);
    f->eax = inumber ((int) arg[0]);
    break;
	}
}

void check_address(void *addr){
  if ((unsigned int)addr >= 0xc0000000 || (unsigned int)addr <= 0x8048000){
		exit(-1);
  }
}

void get_argument(void *esp, int *arg, int count){
	int i;
  ASSERT(count >= 1 && count <= 3);
  //count는 1~3까지 가질 수 있습니다.
	
  for (i = 0 ; i < count ; i ++){
    check_address(esp+4*i+4);
    //얻고자 하는 데이터가 유저스택안에 있는 지 확인합니다.
		arg[i] = *(int *)(esp + 4*i + 4);
	}

}

void halt(void){
  shutdown_power_off();
}

void exit(int status){
	thread_current()->exit_status = status;
  //종료상태를 저장합니다.
  printf("%s: exit(%d)\n",thread_name(), status);
	thread_exit();
}

int wait(tid_t tid){
	return process_wait(tid);
}	

tid_t exec(const char *cmd_line){
	tid_t tid;
	struct thread *t;

  if (cmd_line == NULL) return -1;
  //유효하지 않은 입력이 오면 종료합니다.
  tid = process_execute(cmd_line);
  //명령을 실행합니다.
  if (tid == TID_ERROR){
    return -1;
  }
	
  t = get_child_process(tid);
  //생성된 자식 프로세스의 포인터를 얻습니다.
	ASSERT(t);
  sema_down(&t->load_sema);
  //자식이 로드가 다 될때까지 기다립니다.

  if (t->is_loaded)
		return t->tid;
	
  else return -1;
}

bool create (const char *file, unsigned initial_size){
  if (file == NULL) exit(-1);
  //유효하지 않은 값이 들어오면 종료합니다.
  return filesys_create(file,initial_size);
}

bool remove (const char *file){
  if (file == NULL) return false;
  //유효하지 않은 값이 들어오면 종료합니다.
	return filesys_remove(file);
}

int open (const char *file){
  struct file* f; 
  int result = -1;
  if (file == NULL) return -1;
  //유요하지 않은 값이 들어오면 종료합니다.
  
  lock_acquire(&filesys_lock);
  //open중에 다른 프로세스에서의 접근을 막습니다.
  f = filesys_open(file);
  result = process_add_file(filesys_open (file));
  //프로세스의 fdt에 파일을 넣어줍니다.
  lock_release(&filesys_lock);
  //open이 끝나면 lock을 해제합니다.
  return result;
}

int filesize(int fd){
  struct file * f = process_get_file(fd);
  if (f == NULL) return -1;
  //fd에 대한 파일이 없으면 종료합니다.
  return file_length(f);
}

int read (int fd, void * buffer, unsigned size){
  struct file * f;
  off_t t = 0;
  unsigned int i = 0; 
  check_address(buffer);
  //버퍼가 유효한 값인지 검사합니다.
  lock_acquire(&filesys_lock);
  //read중에 다른 프로세서에서 접근을 막습니다.
  /*
  if (fd == 1){
    lock_release(&filesys_lock);
    return -1;
  }else*/ 
    if (fd == 0){//stdin을 읽을 경우
    while (i < size){
      ((char*)buffer)[i++] = input_getc();
    }
    lock_release(&filesys_lock);
    return i;
  }else{//나머지의 경우
    f = process_get_file(fd);
    //fd가 유효하지 않으면 null을 반환합니다.
    if (f == NULL){
      lock_release(&filesys_lock);
      return -1;
     }
    t =  file_read(f,buffer,(off_t)size);
    //fd가 유효하면 버퍼로 읽어들입니다.
  }
  lock_release(&filesys_lock);
  return t;
  
}
int write (int fd, void * buffer, unsigned size){
  struct file * f;
  off_t t = 0;
  check_address(buffer); 
  //버퍼가 유효한지 검사합니다.
  lock_acquire(&filesys_lock);
  //write중에 다른 프로세서에서의 접근을 막습니다.
  /*
  if (fd == 0){
    lock_release(&filesys_lock);
    return -1;
  }else */
    if (fd == 1){//stdout에 쓸 경우
    putbuf((char*)buffer,size);
    t = size;
    lock_release(&filesys_lock);
    return t;
  }else {//나머지의 경우
    f = process_get_file(fd);
    //fd가 유효하지 않으면 null을 반환합니다.
    if (f == NULL){
      lock_release(&filesys_lock);
      return -1;
    }
    t = file_write(f,buffer,(off_t) size);
    //fd가 유효하면 버퍼로 기록합니다.
  }
  lock_release(&filesys_lock);
  return t;
}
void seek(int fd, unsigned position){
  struct file * f;
  f = process_get_file(fd);
  //유효하지 않은 fd는 null을 리턴합니다.
  if (f != NULL) file_seek(f, position);
}
unsigned tell (int fd){
  struct file * f;
  f = process_get_file(fd);
  //유효하지 않은 fd는 null을 리턴합니다.
  if (f != NULL) return file_tell(f);
  return 0;
}
void close (int fd){
  process_close_file(fd);
  //fd가 유효하지 않으면 아무일도 하지 않습니다.
}

bool
chdir (char *name)
{
  char path[PATH_MAX_LENGTH + 1];
  strlcpy (path, name, PATH_MAX_LENGTH);
  strlcat (path, "\0", PATH_MAX_LENGTH);

  char file_name[PATH_MAX_LENGTH + 1];
  struct dir *dir = parse_path (path, file_name);
  
  if (!dir)
    return false;

  dir_close (thread_current()->working_dir);
  thread_current()->working_dir = dir;
  return true;
}

bool
mkdir (const char *dir)
{
  return filesys_create_dir (dir);
}

bool
readdir (int fd, char *name)
{
  struct file *f = process_get_file (fd);

  if (f == NULL)
    exit (-1);
  
  struct inode *inode = file_get_inode (f);

  if (!inode || !inode_is_dir (inode))
    return false;

  struct dir *dir = dir_open (inode);

  if (!dir)
    return false;

  int i;
  bool result = true;
  off_t *pos = (off_t *)f + 1;

  for (i = 0; i <= *pos && result; i++)
    result = dir_readdir (dir, name);

  if (i <= *pos == false)
    (*pos)++;
  
  return result;
}

bool
isdir (int fd)
{
  struct file *f = process_get_file (fd);
  if (f == NULL)
    exit (-1);

  return inode_is_dir (file_get_inode (f));
}

int
inumber (int fd)
{
  struct file *f = process_get_file (fd);
  if (f == NULL)
    exit (-1);
  return inode_get_inumber (file_get_inode (f));
}
