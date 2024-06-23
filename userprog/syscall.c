#include "userprog/syscall.h"
#include <stdio.h>
#include <syscall-nr.h>
#include "include/lib/user/syscall.h"
#include "threads/interrupt.h"
#include "threads/thread.h"
#include "threads/loader.h"
#include "userprog/gdt.h"
#include "threads/flags.h"
#include "intrinsic.h"
#include "userprog/process.h"

void syscall_entry (void);
void syscall_handler (struct intr_frame *);


pid_t sys_fork (const char *thread_name);
int sys_exec (const char *cmd_line);
int sys_wait (pid_t pid);
bool sys_create (const char *file, unsigned initial_size);
bool sys_remove (const char *file);
int sys_open (const char *file);
int sys_filesize (int fd);
int sys_read (int fd, void *buffer, unsigned size);
int sys_write (int fd, const void *buffer, unsigned size);
void sys_seek (int fd, unsigned position);
unsigned sys_tell (int fd);
void sys_close (int fd);
void sys_halt (void);
void sys_exit (int status);

/* System call.
 *
 * Previously system call services was handled by the interrupt handler
 * (e.g. int 0x80 in linux). However, in x86-64, the manufacturer supplies
 * efficient path for requesting the system call, the `syscall` instruction.
 *
 * The syscall instruction works by reading the values from the the Model
 * Specific Register (MSR). For the details, see the manual. */

#define MSR_STAR 0xc0000081         /* Segment selector msr */
#define MSR_LSTAR 0xc0000082        /* Long mode SYSCALL target */
#define MSR_SYSCALL_MASK 0xc0000084 /* Mask for the eflags */

void
syscall_init (void) {
	write_msr(MSR_STAR, ((uint64_t)SEL_UCSEG - 0x10) << 48  |
			((uint64_t)SEL_KCSEG) << 32);
	write_msr(MSR_LSTAR, (uint64_t) syscall_entry);

	/* The interrupt service rountine should not serve any interrupts
	 * until the syscall_entry swaps the userland stack to the kernel
	 * mode stack. Therefore, we masked the FLAG_FL. */
	write_msr(MSR_SYSCALL_MASK,
			FLAG_IF | FLAG_TF | FLAG_DF | FLAG_IOPL | FLAG_AC | FLAG_NT);
}

/* The main system call interface */
void
syscall_handler (struct intr_frame *f UNUSED) {
	// TODO: Your implementation goes here.
	{
		int64_t num_syscall = f->R.rax;
		int64_t argument1 = f->R.rdi;
		int64_t argument2 = f->R.rsi;
		int64_t argument3 = f->R.rdx;
		int64_t argument4 = f->R.r10;
		int64_t argument5 = f->R.r8;
		int64_t argument6 = f->R.r9;
		// TODO: 할것 user address 검사 필요.
		switch (num_syscall)
		{
		case SYS_HALT:                   /* Halt the operating system. */
			sys_halt();
			break;
		case SYS_EXIT:                   /* Terminate this process. */
			sys_exit(argument1);
			break;
		case SYS_FORK:                   /* Clone current process. */
			sys_fork(argument1);
			break;
		case SYS_EXEC:                   /* Switch current process. */
			break;
		case SYS_WAIT:                   /* Wait for a child process to die. */
			break;
		case SYS_CREATE:                 /* Create a file. */
			break;
		case SYS_REMOVE:                 /* Delete a file. */
			break;
		case SYS_OPEN:                   /* Open a file. */
			break;
		case SYS_FILESIZE:               /* Obtain a file's size. */
			break;
		case SYS_READ:                   /* Read from a file. */
			break;
		case SYS_WRITE:                  /* Write to a file. */
			f->R.rax = sys_write(argument1, argument2, argument3);
			break;
		case SYS_SEEK:                   /* Change position in a file. */
			break;
		case SYS_TELL:                   /* Report current position in a file. */
			break;
		case SYS_CLOSE:                  /* Close a file. */

			/* Project 3 and optionally project 4. */
			break;
		case SYS_MMAP:                   /* Map a file into memory. */
			break;
		case SYS_MUNMAP:                 /* Remove a memory mapping. */

			/* Project 4 only. */
			break;
		case SYS_CHDIR:                  /* Change the current directory. */
			break;
		case SYS_MKDIR:                  /* Create a directory. */
			break;
		case SYS_READDIR:                /* Reads a directory entry. */
			break;
		case SYS_ISDIR:                  /* Tests if a fd represents a directory. */
			break;
		case SYS_INUMBER:                /* Returns the inode number for a fd. */
			break;
		case SYS_SYMLINK:                /* Returns the inode number for a fd. */
			break;
		/* Extra for Project 2 */
		case SYS_DUP2:                   /* Duplicate the file descriptor */
			break;
		case SYS_MOUNT:
			break;
		case SYS_UMOUNT:
			break;
		default:
			ASSERT(false);// no reach
			break;
		}
	}
	printf ("system call!\n");
	// thread_exit ();
}

/*
tid_t process_create_initd (const char *file_name);
tid_t process_fork (const char *name, struct intr_frame *if_);
int process_exec (void *f_name);
int process_wait (tid_t);
void process_exit (void);
void process_activate (struct thread *next);

void thread_init (void);
void thread_start (void);

void thread_tick (void);
void thread_print_stats (void);

typedef void thread_func (void *aux);
tid_t thread_create (const char *name, int priority, thread_func *, void *);

void thread_block (void);
void thread_unblock (struct thread *);

struct thread *thread_current (void);
tid_t thread_tid (void);
const char *thread_name (void);

void thread_exit (void) NO_RETURN;
void thread_yield (void);

int thread_get_priority (void);
void thread_set_priority (int);

int thread_get_nice (void);
void thread_set_nice (int);
int thread_get_recent_cpu (void);
int thread_get_load_avg (void);

void do_iret (struct intr_frame *tf);


 threads/thread.c     |   13 
 threads/thread.h     |   26 +
 userprog/exception.c |    8 
 userprog/process.c   |  247 ++++++++++++++--
 userprog/syscall.c   |  468 ++++++++++++++++++++++++++++++-
 userprog/syscall.h   |    1 
 6 files changed, 725 insertions(+), 38 deletions(-)

*/
void sys_halt (void)
{
	power_off();
}

void sys_exit (int status)
{
	thread_set_exit_status(status);
	thread_exit();
}


pid_t sys_fork (const char *thread_name) {
	//process_create_initd();
	//process_create_initd(thread_name);
	//process_fork(thread_name, NULL);
	//tid = thread_create (file_name, PRI_DEFAULT, initd, fn_copy); 와 유사하게[]
	//thread_create (*thread_name, PRI_DEFAULT, thread_func *, void *);

}

int sys_exec (const char *cmd_line){


    process_create_initd(cmd_line);
}

int sys_wait (pid_t pid){
	//process_wait (process_create_initd (task));
}



/* ------------------------------- file -------------------------------*/
bool sys_create (const char *file, unsigned initial_size){
	process_create_initd(file);
}
bool sys_remove (const char *file);
int sys_open (const char *file);

int sys_filesize (int fd);
int sys_read (int fd, void *buffer, unsigned size);

int sys_write (int fd, const void *buffer, unsigned size){
	ASSERT (fd == STDOUT_FILENO);
	ASSERT (buffer != NULL);
	//write (STDOUT_FILENO, buf, strlen (buf));
	printf((char *)buffer);
}

void sys_seek (int fd, unsigned position);
unsigned sys_tell (int fd);
void sys_close (int fd);
