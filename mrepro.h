#include <sys/types.h>
#include <sys/socket.h>
#include <netdb.h>

int Socket(int domain, int type,int protocol);

ssize_t Sendto(int sockfd, const void *buf, size_t len, int flags,
               const struct sockaddr *dest_addr, socklen_t addrlen);

ssize_t Recvfrom(int sockfd, void *buf, size_t len, int flags,
                 struct sockaddr *src_addr, socklen_t *addrlen);

int Bind(int sockfd, const struct sockaddr *addr, socklen_t addrlen);

int Connect(int sockfd, const struct sockaddr *addr, socklen_t addrlen);

int Listen(int sockfd, int backlog);

int Accept(int socket, struct sockaddr *cliaddr, socklen_t *addrlen);

int Getaddrinfo(const char *node, const char *service,
                 const struct addrinfo *hints, struct addrinfo **res);

int Inet_pton(int af, const char *src, void *dst);

const char *Inet_ntop(int af, const void *src, char *dst, socklen_t size);

ssize_t readn(int fd, void *vptr, size_t n);

ssize_t writen(int fd, const void *vptr, size_t n);

int read_till_newline(void *buffer, int tcp_sock_fd);

void my_print(int priority, const char *fmt, ...);
