#include "liburing.h"
#include "math.h"
#include <fcntl.h>
#include <string.h>
#include <stdio.h>
#include <sys/socket.h>
#include <sys/types.h>
#include <regex.h>
#include <stdlib.h>
#include <unistd.h>
#include <netinet/ip.h>
#include <assert.h>
#include <netdb.h>
#include <float.h>

int parse_socket(char* sockdef, char *host, int hostlen, char *port, int portlen) {
  int ret;
  int retval;
  const int errbufflen = 200;
  char errbuff[errbufflen];
  const size_t re_arg_match_size = 3;
  regmatch_t re_arg_match[re_arg_match_size];
  const char *re_arg = "^(.+)\\:(.+)$";
  regex_t re_arg_preg;
  ret = regcomp(&re_arg_preg, re_arg, REG_EXTENDED);
  if ( ret ) {
    regerror(ret, &re_arg_preg, errbuff, errbufflen);
    fprintf(stderr, "Error compiling regex: %s\n", errbuff);
    return 1;
  }
  ret = regexec(&re_arg_preg, sockdef, re_arg_match_size, re_arg_match, 0);
  if ( ret ) {
    regerror(ret, &re_arg_preg, errbuff, errbufflen);
    fprintf(stderr, "Error executing regex: %s\n", errbuff);
    retval = 1;
    goto exit;
  }
  if ( re_arg_match[1].rm_eo - re_arg_match[1].rm_so + 1 > hostlen ) {
    fprintf(stderr, "Error hostname too long\n");
    retval = 1;
    goto exit;
  }
  memcpy(host, sockdef + re_arg_match[1].rm_so, re_arg_match[1].rm_eo - re_arg_match[1].rm_so);
  host[re_arg_match[1].rm_eo - re_arg_match[1].rm_so] = '\0';
  if ( re_arg_match[2].rm_eo - re_arg_match[2].rm_so + 1 > portlen ) {
    fprintf(stderr, "Error port too long\n");
    retval = 1;
    goto exit;
  }
  memcpy(port, sockdef + re_arg_match[2].rm_so, re_arg_match[2].rm_eo - re_arg_match[2].rm_so);
  port[re_arg_match[2].rm_eo - re_arg_match[2].rm_so] = '\0';
  retval = 0;
 exit:
  regfree(&re_arg_preg);
  return retval;
}

struct step {
  void * cur;
  int fd;
  void * data;
  size_t datalen;
  struct timespec timeout_end;
};

static void submit_step_send(struct io_uring *ring, int fd, void * data, size_t datalen) {
  struct io_uring_sqe *sqe;
  struct step *step;
  step = (struct step *) malloc(sizeof(struct step));
  memset(step, 0, sizeof(struct step));
  step->cur = submit_step_send;
  step->fd = fd;
  step->data = data;
  step->datalen = datalen;
  sqe = io_uring_get_sqe(ring);
  assert(sqe);
  io_uring_prep_send(sqe, fd, data, datalen, 0);
  io_uring_sqe_set_data(sqe, step);
  io_uring_submit(ring);
}

static void submit_step_close(struct io_uring *ring, int fd) {
  struct io_uring_sqe *sqe;
  struct step *step;
  step = (struct step *) malloc(sizeof(struct step));
  memset(step, 0, sizeof(struct step));
  step->cur = submit_step_close;
  step->fd = fd;
  sqe = io_uring_get_sqe(ring);
  assert(sqe);
  io_uring_prep_close(sqe, fd);
  io_uring_sqe_set_data(sqe, step);
  io_uring_submit(ring);
}

static void submit_step_wait(struct io_uring *ring, int fd, int mseconds) {
  struct io_uring_sqe *sqe;
  struct step *step;
  struct __kernel_timespec timeout;
  memset(&timeout, 0, sizeof(timeout));
  timeout.tv_sec = mseconds / 1000;
  timeout.tv_nsec = mseconds % 1000;
  step = (struct step *) malloc(sizeof(struct step));
  memset(step, 0, sizeof(struct step));
  step->cur = submit_step_wait;
  step->fd = fd;
  clock_gettime(CLOCK_MONOTONIC, &step->timeout_end);
  step->timeout_end.tv_sec += timeout.tv_sec;
  step->timeout_end.tv_nsec += timeout.tv_nsec;
  if ( step->timeout_end.tv_nsec > 1000000 ) {
    step->timeout_end.tv_nsec %= 1000000;
    step->timeout_end.tv_sec++;
  }
  sqe = io_uring_get_sqe(ring);
  assert(sqe);
  io_uring_prep_timeout(sqe, &timeout, 1, 0);
  io_uring_sqe_set_data(sqe, step);
  io_uring_submit(ring);
}

static int submit_step_connect(struct io_uring *ring, struct addrinfo *addrinfo) {
  int fd = socket(addrinfo->ai_family, addrinfo->ai_socktype, addrinfo->ai_protocol);
  if ( fd < 0 ) {
    fprintf(stderr, "Error opening socket: %s\n", strerror(errno));
    return 1;
  }  
  struct io_uring_sqe *sqe;
  struct step *step;
  step = (struct step *) malloc(sizeof(struct step));
  memset(step, 0, sizeof(struct step));
  step->cur = submit_step_connect;
  step->fd = fd;
  sqe = io_uring_get_sqe(ring);
  assert(sqe);
  io_uring_prep_connect(sqe, fd, addrinfo->ai_addr, addrinfo->ai_addrlen);  
  io_uring_sqe_set_data(sqe, step);
  io_uring_submit(ring);
  return 0;
}

int main(int argc, char * argv[]) {
  struct io_uring ring;
  int ret;
  int retval;
  const size_t hostlen = 200;
  char host[hostlen];
  const size_t portlen = 100;
  char port[portlen];
  struct addrinfo *addrinfo;
  struct addrinfo addrhints;
  int concurrency;
  int total;
  int timeout;
  if ( argc != 5 ) {
    fprintf(stderr, "Usage: %s host:port concurrency total timeoutmsec\n", argv[0]);
    return 1;
  }
  if ( parse_socket(argv[1], host, hostlen, port, portlen) ) {
    return 1;
  }
  concurrency = atoi(argv[2]);
  total = atoi(argv[3]);
  timeout = atoi(argv[4]);
  int ring_size = 64;
  if ( concurrency <= 0 ) {
    fprintf(stderr, "Error concurrency param is wrong: %s\n", argv[2]);
    return 1;
  }
  if ( total <= 0 ) {
    fprintf(stderr, "Error total param is wrong: %s\n", argv[2]);
    return 1;
  }
  if ( concurrency > ring_size) {
    fprintf(stderr, "Error concurrency param is bigger than ring size: %d\n", ring_size);
    return 1;
  }
  memset(&addrhints, 0, sizeof(addrhints));
  addrhints.ai_family = AF_INET;
  addrhints.ai_socktype = SOCK_STREAM;
  ret = getaddrinfo(host, port, &addrhints, &addrinfo);
  if ( ret ) {
    fprintf(stderr, "Error getting address info: %s\n", gai_strerror(ret));
    return -1;
  }
  ret = io_uring_queue_init(ring_size, &ring, 0);
  if (ret < 0) {
    fprintf(stderr, "Error in uring queue init: %s\n", strerror(-ret));
    retval = -1;
    goto exit;
  }
  int in_flight = 0;
  int done = 0;
  for (;;) {
    /* queue as many initial requests as possible */
    for (; in_flight < concurrency && in_flight < total - done; ) {
      if ( submit_step_connect(&ring, addrinfo) ) {
	fprintf(stderr, "Error in connect step\n");
      } else {
	in_flight++;
      }
    }
    /* wait for events on completion queue */
    struct io_uring_cqe *cqe;
    for (;;) {
      ret = io_uring_wait_cqe(&ring, &cqe);
      if ( ret == -EINTR ) {
	continue;
      } else if (ret < 0) {
	fprintf(stderr, "Error in waiting for completion: %s\n", strerror(-ret));
	retval = -1;
	goto exit;
      } else {
	break;
      }
    }
    /* handle completed event */
    struct step *step = (struct step *) io_uring_cqe_get_data(cqe);
    if ( step->cur == submit_step_connect ) {
      if ( cqe->res == -EINTR || cqe->res == -EAGAIN ) {
	fprintf(stderr, "Transient error in step connect, retrying: %s\n", strerror(-cqe->res));
	submit_step_connect(&ring, addrinfo);
	in_flight++;
      }	else if ( cqe->res != 0 ) {
	fprintf(stderr, "Error in step connect: %s\n", strerror(-cqe->res));
	submit_step_close(&ring, step->fd);
	in_flight++;
      } else {
	fprintf(stderr, "Connected fd %d\n", step->fd);
	char * post = "POST / HTTP/1.1\r\nHost: localhost:8080\r\nUser-Agent: curl/7.71.1\nAccept: */*\r\n\r\n";
	void * data = malloc(strlen(post));
	memcpy(data, post, strlen(post));
	submit_step_send(&ring, step->fd, data, strlen(post));
	in_flight++;
      }
    } else if ( step->cur == submit_step_send ) {
      if ( cqe->res == -EINTR || cqe->res == -EAGAIN || cqe->res == -EWOULDBLOCK ) {
	fprintf(stderr, "Transient error in step send, retrying: %s\n", strerror(-cqe->res));
	submit_step_send(&ring, step->fd, step->data, step->datalen);
	in_flight++;
      }	else if ( cqe->res < 0 ) {
	fprintf(stderr, "Error in step send: %s\n", strerror(-cqe->res));
	submit_step_close(&ring, step->fd);
	in_flight++;
	free(step->data);
      } else {
	fprintf(stderr, "Sent %d bytes to fd %d\n", cqe->res, step->fd);
	size_t reminder = step->datalen - cqe->res;
	if ( reminder ) {
	  submit_step_send(&ring, step->fd, step->data + cqe->res, reminder);
	  in_flight++;
	} else {
	  submit_step_wait(&ring, step->fd, timeout);
	  in_flight++;
	  free(step->data);
	} 
      }
    } else if ( step->cur == submit_step_wait ) {
      if ( cqe->res == -ETIME ) {
	fprintf(stderr, "Wait finished fd %d\n", step->fd);
	submit_step_close(&ring, step->fd);
	in_flight++;
      } else if ( cqe->res < 0 ) {
	fprintf(stderr, "Error in step wait: %s\n", strerror(-cqe->res));
	submit_step_close(&ring, step->fd);
	in_flight++;
      } else {
	struct timespec now;
	long int now_msec, reminder_msec;
	clock_gettime(CLOCK_MONOTONIC, &now);
	now_msec = now.tv_sec * 1000 + now.tv_nsec / 1000000;
	reminder_msec = now_msec - step->timeout_end.tv_sec * 1000 + step->timeout_end.tv_nsec / 1000000;
	if ( reminder_msec > 0 ) {
	  fprintf(stderr, "Wait for %ld more milliseconds on fd %d\n", reminder_msec, step->fd);
	  submit_step_wait(&ring, step->fd, reminder_msec);
	  in_flight++;
	} else {
	  fprintf(stderr, "Wait finished fd %d\n", step->fd);
	  submit_step_close(&ring, step->fd);
	  in_flight++;
	}	
      }
    } else if ( step->cur == submit_step_close ) {
      if ( cqe->res < 0 ) {
	fprintf(stderr, "Error in step close: %s\n", strerror(-cqe->res));
      } else {
	fprintf(stderr, "Closed fd %d\n", step->fd);
      }
      done++;
    } else {
      assert(false);
    }
    io_uring_cqe_seen(&ring, cqe);
    free(step);
    in_flight--;
    if ( in_flight == 0 && done >= total ) {
      break;
    }
  }
  retval = 0;
 exit:
  io_uring_queue_exit(&ring);
  freeaddrinfo(addrinfo);
  return retval;
}
