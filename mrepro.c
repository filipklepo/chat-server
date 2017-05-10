#include <stdio.h>
#include <sys/types.h>
#include <unistd.h>
#include <sys/socket.h>
#include <errno.h>
#include <stdlib.h>
#include <err.h>
#include "mrepro.h"
#include <netdb.h>
#include <arpa/inet.h>
#include <syslog.h>
#include <stdarg.h>

#define ERR_NO 1

extern int daemon_flag;

int Socket(int domain, int type, int protocol) {
  int sock_fd = socket(domain, type, protocol);
  if(sock_fd < 0) {
    my_print(LOG_ALERT, "Socket initialization failed.\n");
    exit(ERR_NO);
  }

  return sock_fd;
}

ssize_t Sendto(int sockfd, const void *buf, size_t len, int flags,
               const struct sockaddr *dest_addr, socklen_t addrlen) {
  int sent;
  sent = sendto(sockfd, buf, len, flags, dest_addr, addrlen);
  if(sent < 0) {
    errx(ERR_NO, "Error while sending datagram.");
  }

  return sent;
}

ssize_t Recvfrom(int sockfd, void *buf, size_t len, int flags,
                 struct sockaddr *src_addr, socklen_t *addrlen) {
  ssize_t msg_len;
  msg_len = recvfrom(sockfd, buf, len, flags, src_addr, addrlen);
  if(msg_len < 0) {
    my_print(LOG_ALERT, "Error while receiving datagram.\n");
    exit(ERR_NO);
  }

  return msg_len;
}

int Bind(int sockfd, const struct sockaddr *addr, socklen_t addrlen) {
  int result = bind(sockfd, addr, addrlen);
  if(result == -1) {
    my_print(LOG_ALERT, "Binding error.\n");
    exit(ERR_NO);
  }

  return result;
}

int Connect(int sockfd, const struct sockaddr *addr, socklen_t addrlen) {
  int result = connect(sockfd, addr, addrlen);
  if(result == -1) {
    errx(ERR_NO, "Connect error.");
  }

  return result;
}

int Listen(int sockfd, int backlog) {
  int result = listen(sockfd, backlog);
  if(result == -1) {
    my_print(LOG_ALERT, "Listen error.\n");
    exit(ERR_NO);
  }

  return result;
}

int Accept(int socket, struct sockaddr *cliaddr, socklen_t *addrlen) {
  int newfd = accept(socket, cliaddr, addrlen);
  if(newfd == -1) {
    my_print(LOG_ALERT, "Accept error.\n");
    exit(ERR_NO);
  }

  return newfd;
}

int Getaddrinfo(const char *node, const char *service,
                const struct addrinfo *hints,
                struct addrinfo **res) {
  int result = getaddrinfo(node, service, hints, res);
  if(result < 0) {
    my_print(LOG_ALERT, "%s\n", gai_strerror(result));
    exit(ERR_NO);
  }

  return result;
}

int Inet_pton(int af, const char *src, void *dst) {
  int result = inet_pton(af, src, dst);
  if(result != 1) {
    errx(ERR_NO, "%s is not a valid IP address.", src);
  }

  return result;
}

const char *Inet_ntop(int af, const void *src, char *dst, socklen_t size) {
  const char *result = inet_ntop(af, src, dst, size);
  if(!result) {
    my_print(LOG_ALERT, "Invalid representation of IP address.\n");
    exit(ERR_NO);
  }

  return result;
}

ssize_t readn(int fd, void *vptr, size_t n) {
  size_t nleft;
  ssize_t nread;
  char *ptr;

  ptr = vptr;
  nleft = n;

  while(nleft > 0) {
    if((nread = read(fd, ptr, nleft)) < 0) {
      if(errno == EINTR) {
        nread = 0;
      } else {
        errx(ERR_NO, "Error while sending data.");
      }
    } else if(nread == 0) {
      break;
    }
    nleft -= nread;
    ptr += nread;
  }

  return (n - nleft);
}

ssize_t writen(int fd, const void *vptr, size_t n) {
  size_t nleft;
  ssize_t nwritten;
  const char *ptr;

  ptr = vptr;
  nleft = n;

  while(nleft > 0) {
    if((nwritten = write(fd, ptr, nleft)) <= 0) {
      if(nwritten < 0 && errno == EINTR) {
        nwritten = 0;
      } else {
        my_print(LOG_ALERT, "Error while sending data.\n");
        exit(ERR_NO);
      }
    }
    nleft -= nwritten;
    ptr += nwritten;
  }

  return n;
}

int read_till_newline(void *buffer, int tcp_sock_fd) {
	char *ptr;
	ptr = buffer;
	ssize_t nread;
	struct addrinfo hints, *res;
	ssize_t bytes_read = 0;

	while(1) {
		if((nread = read(tcp_sock_fd, ptr, 1)) < 0) {
			if(errno == EINTR) {
				continue;
			} else {
				errx(2, "Error while sending data.");
			}
		}
		
		bytes_read += nread;
		ptr += nread;
		if(ptr != buffer && *(ptr - 1) == '\n') {
			break;
		} else if(nread == 0) {
			return 0;
		}
	}
	
	return  bytes_read;
}

void my_print(int priority, const char *fmt, ...) {
	va_list args;
	va_start(args, fmt);

	if(daemon_flag) {
		vsyslog(priority, fmt, args);
	} else {
		vfprintf(stderr, fmt, args);
	}
	
	va_end(args);	
}
