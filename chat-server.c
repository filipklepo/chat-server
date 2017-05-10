#include <stdio.h>
#include "mrepro.h"
#include <unistd.h>
#include <stdlib.h>
#include <sys/types.h>
#include <sys/socket.h>
#include <netdb.h>
#include <string.h>
#include <netinet/in.h>
#include <arpa/inet.h>
#include <err.h>
#include <syslog.h>
#include <stdarg.h>

#define PORT "1234"
#define BACKLOG 10
#define CONNECT_MSG "Spojio se"
#define DISCONNECT_MSG "Odspojio se"
#define RCV_BUF_LEN 1025
#define MSG_INFO_LEN 100
#define SND_BUF_LEN 1125
#define STDIN 0
#define TCP "TCP"
#define UDP "UDP"

int daemon_flag;

void print_usage() {
	fprintf(stderr, "Usage: char [-t tcp_port] [-u udp_port] \
			     [-k kontrolni_port lozinka]\n");
}

struct sockaddr_in get_conn_sockaddr(int conn_fd) {
	struct sockaddr_in cl_addr;
	socklen_t cl_addr_len;
		
	cl_addr_len = sizeof(cl_addr);
	if(getpeername(conn_fd, (struct sockaddr *)&cl_addr, &cl_addr_len) == -1) {
		my_print(LOG_ALERT, "getpeername error.");	
		exit(1);
	}

	return cl_addr;
}

void bind_service(int sock_fd, char *serv_name, int socktype) {
	struct addrinfo hints, *res;
	
	memset(&hints, 0, sizeof(hints));
	hints.ai_family = AF_INET;
	hints.ai_socktype = socktype;
	hints.ai_flags = AI_PASSIVE;
	Getaddrinfo(NULL, serv_name, &hints, &res);
	
	Bind(sock_fd, (struct sockaddr *)res->ai_addr, res->ai_addrlen);
}

char *get_msg_info(char *cause, struct sockaddr_in addr) {
	char *info, ip_addr[20]; 
	
	info = (char *)malloc(MSG_INFO_LEN * sizeof(char));
	
	Inet_ntop(AF_INET, &addr.sin_addr, &ip_addr[0], 20 * sizeof(char));
	
	sprintf(info, "%s:%s:%u", cause, ip_addr, ntohs(addr.sin_port));
	return info;
}

void send_msg(char *buf, int client_fd[5], int except) {
	for(int i = 0; i < 5; ++i) {
		if(i != except && client_fd[i] != 0) {
			writen(client_fd[i], buf, strlen(buf));
		}
	}
}

void delete_value(int array[5], int index) {
	int i = 0;
	while(i != index) ++i;
	while(i < 4) {
		array[i] = array[i + 1];
		++i;
	}
	array[4] = 0;
}

void init_working_sockets(int *listen_fd, char *tcp_port, int *udp_fd, 
		          char *udp_port, fd_set *fds) {
	*listen_fd = Socket(AF_INET, SOCK_STREAM, 0);
	bind_service(*listen_fd, tcp_port, SOCK_STREAM);		
	Listen(*listen_fd, BACKLOG);
	
	*udp_fd = Socket(AF_INET, SOCK_DGRAM, 0);
	bind_service(*udp_fd, udp_port, SOCK_DGRAM);
	
	FD_SET(*listen_fd, fds);
	FD_SET(*udp_fd, fds);
}

void run(int control_fd, char *pswd, char *tcp_port, char *udp_port) {
	fd_set read_fds, original_fds;
	int max_fd, new_conn_fd, nulterm_index, num_clients = 0, 
	    listen_fd = 0, udp_fd = 0;
	socklen_t udp_addr_len;
	char rcv_buf[RCV_BUF_LEN], *msg_info, snd_buf[SND_BUF_LEN], *colon, *dgram_pswd;
	struct sockaddr_in udp_from_addr;
	int client_fd[5] = {0}, colon_index, on_flag = 0;

	FD_ZERO(&original_fds);
	if(daemon_flag) {
		FD_SET(control_fd, &original_fds);
		max_fd = control_fd;
	} else {
		init_working_sockets(&listen_fd, tcp_port, &udp_fd, 
				     udp_port, &original_fds);
		FD_SET(STDIN, &original_fds);
		
		if(listen_fd >= udp_fd) {
			max_fd = listen_fd;
		} else {
			max_fd = udp_fd;
		}
	}
	
	while(1) {
		read_fds = original_fds;
		select(max_fd + 1, &read_fds, NULL, NULL, NULL);

		if(daemon_flag && FD_ISSET(control_fd, &read_fds)) {
			udp_addr_len = sizeof(udp_from_addr);
			
			nulterm_index = 
				Recvfrom(control_fd, rcv_buf, RCV_BUF_LEN, 0, 
					 NULL, NULL);
			rcv_buf[nulterm_index - 1] = '\0';
			
			colon = strchr(rcv_buf, ':');
			if(!colon) continue;
			colon_index = colon - rcv_buf;

			if(colon_index != 2 && colon_index != 3 && colon_index != 4)
				continue;
			dgram_pswd = rcv_buf + colon_index + 1;	
			if(strcmp(dgram_pswd, pswd)) continue;

			if(strstr(rcv_buf, "ON") == rcv_buf) {
				if(on_flag) continue;
		
				init_working_sockets(
						&listen_fd, tcp_port, &udp_fd, 
						udp_port, &original_fds);
				if(listen_fd >= udp_fd) {
					if(listen_fd > max_fd) {
						max_fd = listen_fd;
					}
				} else {
					if(udp_fd > max_fd) {
						max_fd = udp_fd;
					}
				}

				on_flag = 1;
			} else if(strstr(rcv_buf, "OFF") == rcv_buf) {
				if(!on_flag) continue;
				
				for(int i = 0; i < 5; ++i) {
					if(client_fd[i]) {
						close(client_fd[i]);
						client_fd[i] = 0;
					}
				}
				num_clients = 0;

				close(listen_fd);
				close(udp_fd);
				FD_ZERO(&original_fds);
				FD_SET(control_fd, &original_fds);
				
				on_flag = 0;
				continue;
			} else if(strstr(rcv_buf, "QUIT") == rcv_buf) {
				close(control_fd);
				closelog();
				exit(0);		
			}
		}

		if(FD_ISSET(listen_fd, &read_fds)) {
			new_conn_fd = Accept(listen_fd, NULL, NULL);
			if(num_clients == 5) {
				close(new_conn_fd);
			} else {
				if(new_conn_fd > max_fd) {
					max_fd = new_conn_fd;
				}
				
				client_fd[num_clients++] = new_conn_fd;	
				FD_SET(new_conn_fd, &original_fds);
				my_print(LOG_INFO, 
					"%s\n", 
					get_msg_info(CONNECT_MSG, 
			               		get_conn_sockaddr(new_conn_fd)));
			}
		}
;
		if(FD_ISSET(udp_fd, &read_fds)) {
			udp_addr_len = sizeof(udp_from_addr);
			nulterm_index = 
				Recvfrom(udp_fd, rcv_buf, RCV_BUF_LEN, 0,
					 (struct sockaddr *)&udp_from_addr,
					 &udp_addr_len);
			rcv_buf[nulterm_index] = '\0';

			msg_info = get_msg_info(UDP, udp_from_addr);
			my_print(LOG_INFO, "%s\n", msg_info);
				
			sprintf(snd_buf, "%s:%s", msg_info, rcv_buf);
			send_msg(snd_buf, client_fd, -1);
		}

		if(FD_ISSET(STDIN, &read_fds)) {
			fgets(rcv_buf, RCV_BUF_LEN, stdin);
			sprintf(snd_buf, "Server:%s", rcv_buf);
			send_msg(snd_buf, client_fd, -1);	
		}

		for(int i = 0; i < num_clients; ++i) {
			if(!FD_ISSET(client_fd[i], &read_fds)) continue;
			
		 	if(!(nulterm_index = read_till_newline(rcv_buf, client_fd[i]))) {
				my_print(LOG_INFO, 
			 		"%s\n", 
					get_msg_info(DISCONNECT_MSG,
						     get_conn_sockaddr(client_fd[i])));
				
				close(client_fd[i]);
				FD_CLR(client_fd[i], &read_fds);
				FD_CLR(client_fd[i], &original_fds);
				delete_value(client_fd, i);
				--num_clients;

				max_fd = udp_fd;
				for(int j = 0; j < 5; ++j) {
					if(client_fd[j] > max_fd) {
						max_fd = client_fd[j];
					}
				}
			} else {
				msg_info = get_msg_info(TCP, 
						        get_conn_sockaddr(client_fd[i]));
				rcv_buf[nulterm_index] = '\0';

				my_print(LOG_INFO, "%s\n", msg_info);
				sprintf(snd_buf, "%s:%s", msg_info, rcv_buf);
				send_msg(snd_buf, client_fd, i);
			}
		}
	}
}

int main(int argc, char *argv[]) {
	int cur_opt, tcp_fd, udp_fd, control_fd;
	char *tcp_port = PORT, *udp_port = PORT, 
	     *control_port = NULL, *pswd = NULL;
	daemon_flag = 0;	

	while((cur_opt = getopt(argc, argv, "t:u:k:" )) != -1) {
		switch(cur_opt) {
			case 't':
				tcp_port = optarg;
				break;
			case 'u':
				udp_port = optarg;
				break;
			case 'k':
				daemon_flag = 1;
				control_port = optarg;
				break;
			default:
				print_usage();
				exit(1);
		}
	}

	if((!daemon_flag && optind != argc) || (daemon_flag && optind != (argc - 1))) {
		print_usage();
		exit(1);
	}
	
	if(daemon_flag) {
		pswd = argv[optind];
		daemon(0, 0);
		openlog("fk48917:MrePro chat", LOG_PID, LOG_FTP);

		control_fd = Socket(AF_INET, SOCK_DGRAM, 0);
		bind_service(control_fd, control_port, SOCK_DGRAM);
	}

	run(control_fd, pswd, tcp_port, udp_port);
	return 0;
}
