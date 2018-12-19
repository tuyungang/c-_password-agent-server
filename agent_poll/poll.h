/* @(#)11       1.31  src/bos/kernel/sys/poll.h, sysios, bos61F, 0842A_61F 9/25/08 01:40:05 */

#ifndef _H_POLL
#define _H_POLL
/*
 * COMPONENT_NAME: (SYSIOS) Poll system call header file
 *
 * ORIGINS: 3, 27
 *
 * (C) COPYRIGHT International Business Machines Corp. 1989, 1996
 * All Rights Reserved
 * Licensed Materials - Property of IBM
 *
 * US Government Users Restricted Rights - Use, duplication or
 * disclosure restricted by GSA ADP Schedule Contract with IBM Corp.
 */

#include <standards.h>
#include <sys/types.h>

typedef unsigned int nfds_t;

/*
 * Structure to be used (for file descriptors or file pointers)
 * with the POLL system call.
 */
#if _XOPEN_SOURCE_EXTENDED == 1

#ifdef _ALL_SOURCE

#ifdef  __64BIT__
/* pollfd.fd is always a 32 bit entity (XOPEN) */
struct	pollfd
{
	int	fd;			/* file descriptor or file ptr	*/
	short	events;			/* requested events		*/
	short	revents;		/* returned events		*/

};
#else /* __64BIT__ */
struct	pollfd
{
	long	fd;			/* file descriptor or file ptr	*/
	ushort	reqevents;		/* requested events		*/
	ushort	rtnevents;		/* returned events		*/
};
#define	events	reqevents		/* SVR3,4 pollfd member name	*/
#define	revents	rtnevents		/* SVR3,4 pollfd member name	*/
#endif /* __64BIT__ */

/*
 * Timeout values - used for poll() system call
 */
#ifndef NO_TIMEOUT
#define NO_TIMEOUT      0       /* don't wait for a response            */
#endif

#ifndef INF_TIMEOUT
#define INF_TIMEOUT     -1      /* wait until a response is received    */
#endif

/*
 * Structure to be used (for message queue ids)
 * with the POLL system call.
 */
struct	pollmsg
{
	int		msgid;			/* message queue id */
	ushort_t	reqevents;		/* requested events */
	ushort_t	rtnevents;		/* returned events  */
};

#else /* _ALL_SOURCE */

struct  pollfd
{
        int    fd;                  	/* file descriptor or file ptr */
        short  events;              	/* requested events */
        short  revents;             	/* returned events */
};

#endif /* _ALL_SOURCE */
#endif /* _XOPEN_SOURCE_EXTENDED */

#ifndef _NO_PROTO

#if _XOPEN_SOURCE_EXTENDED == 1

#ifndef _ALL_SOURCE

#ifndef _MSGQSUPPORT
extern int __fd_poll(struct pollfd *, nfds_t, int);
static int poll(struct pollfd *__listptr, nfds_t __nfds, int __timeout)
		{
			return __fd_poll(__listptr, __nfds, __timeout);
		}
#else
int	poll(struct pollfd *, nfds_t, int);
#endif /* _MSGQSUPPORT */

#else /* _ALL_SOURCE */

#ifndef _MSGQSUPPORT
extern int __fd_poll(void *, ulong_t, long);
static int poll(void *__listptr, ulong_t __nfds, long __timeout)
		{
			return __fd_poll(__listptr, __nfds, __timeout);
		}
#else
int	poll(void *listptr, ulong_t nfds, long timeout);
#endif /* _MSGQSUPPORT */

/* arguments:
 *	void 		*listptr;	ptr to pollfd/pollmsg/pollist structs
 *	ulong		nfds;		#elements in fds array
 *	long 		timeout;	max time to wait for select criteria
 */
 
int	fp_poll(void *listptr, ulong_t nfds, long timeout, uint_t flags);
/* arguments:
 *	void		*listptr;	ptr to pollfd/pollmsg/pollist structs
 *	ulong		nfds;		#elements in fds array
 *	long 		timeout;	max time to wait for select criteria
 *	register uint	flags;		does data contain fd's? or fp's?
 */
 
void selnotify(			/* notify waiters of event */
	long	sel_id,		/* device on which reqevent(s) occurred */
	int	unique_id,	/* entity on which reqevent(s) occurred */
	ushort	rtnevents);	/* returned events */

#endif /* _ALL_SOURCE */
#endif /* _XOPEN_SOURCE_EXTENDED */

#else

#if _XOPEN_SOURCE_EXTENDED == 1

#ifndef _ALL_SOURCE

#ifndef _MSGQSUPPORT
extern int __fd_poll();
static int poll()
		{
			return __fd_poll();
		}
#else
int	poll();
/* arguments:
 *	void 		*listptr;	ptr to pollfd/pollmsg/pollist structs
 *	ulong		nfds;		#elements in fds array
 *	long 		timeout;	max time to wait for select criteria
 */
#endif /* _MSGQSUPPORT */
 
int	fp_poll();
/* arguments:
 *	void		*listptr;	ptr to pollfd/pollmsg/pollist structs
 *	ulong		nfds;		#elements in fds array
 *	long 		timeout;	max time to wait for select criteria
 *	register uint	flags;		does data contain fd's? or fp's?
 */
 
void	selnotify();
/* arguments:
 *	int	sel_id;			device that reqevents occurred on
 *	int	unique_id;		entity that reqevents occurred on
 *	ushort	rtnevents;		returned events
 */

#endif /* _ALL_SOURCE */
#endif /* _XOPEN_SOURCE_EXTENDED */

#endif /* not _NO_PROTO */

/*
 * Macro used to define a pollist structure
 * for the POLL system call.
 */
#define	POLLIST(F,M)			\
struct					\
{					\
	struct pollfd fdlist[F];	\
	struct pollmsg msglist[M];	\
}

/*
 * Flags passed to fp_poll.
 */
#define	POLL_FDMSG	0x0001	/* input contains file descriptors	*/
#define	POLL_NESTED	0x0002	/* select/poll call is nested		*/
#define	POLL_NOMSGQS	0x0004	/* no message queues-only file descriptors */

/*
 * Requested and returned event flags for the poll system call.
 */
#define	POLLIN		0x0001		/* ready for reading		*/
#define	POLLOUT		0x0002		/* ready for writing		*/
#define	POLLPRI		0x0004		/* has an exceptional condition	*/
#define	POLLWRNORM	POLLOUT		/* same difference ...		*/
#define	POLLRDNORM	0x0010		/* non-priority message ready	*/
#define	POLLRDBAND	0x0020		/* priority message ready to read*/
#define	POLLWRBAND	0x0040		/* writable priority band exists*/
#define	POLLMSG		0x0080		/* signal message ready to read	*/
#define	POLLSYNC	0x8000		/* process requests synchronously*/

#ifdef _KERNSYS
#define POLLCACHE	0x0100		/* cached poll operation	*/
#endif


/*
 * Device type flags for sel_type parameter on selnotify service.
 * Device drivers use their dev_t as their sel_type identifier.
 */
#define	POLL_FIFO	-1		/* selnotify is for a FIFO	*/
#define	POLL_SOCKET	-2		/* selnotify is for a SOCKET	*/
#ifndef POLL_MSG
/* matches <sys/signal.h> */
#define	POLL_MSG	-3		/* selnotify is for a MSG QUEUE	*/
#endif
#define POLL_PROCFS	-4		/* selnotify is for a /proc file*/
#define POLL_AHAFS	-5		/* selnotify is for a file under /aha */
/*
 * Error returned event flags for the poll system call.
 */
#define	POLLNVAL	POLLSYNC	/* invalid data			*/
#define	POLLERR		0x4000		/* error occurred		*/
#define	POLLHUP		0x2000		/* ???				*/

#ifdef _ALL_SOURCE

#define POLLNORM POLLIN

#endif

#endif	/* _H_POLL */
