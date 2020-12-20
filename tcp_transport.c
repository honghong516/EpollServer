#include"tcp_transport.h"
#include<stdio.h>
#include<fcntl.h>
#include<stdlib.h>
#include<sys/socket.h>
#include<netinet/in.h>
#include<arpa/inet.h>
#include<ifaddrs.h>
#include<net/if.h>
#define PORT 3260

int epfd;
int listenfd;
void connection_acception(int event, void* data);
int data_event_rx_handler(connection_t* conn);
int data_event_tx_handler(connection_t *conn);
int conn_destroy(connection_t* conn);
int conn_init(connection_t* conn);
int conn_exit(connection_t* conn);
int conn_close(connection_t* conn);
void conn_read_pdu(connection_t* conn);


int set_no_blocking(int fd){
	int flags = fcntl(fd, F_GETFL, 0);
	if(-1==flags){
		printf("get %d flags failed\n", fd);
		return -1;
	}
	return fcntl(fd,F_SETFL, flags | O_NONBLOCK);
}

int lld_init(){
        printf("begin do lld init, epfd:%d\n", epfd);
	struct ifaddrs *res,*res0;
	int err;
        if((err=getifaddrs(&res0))!=0){
                printf("get addr info failed, errno: %d, reason: %s\n", errno, strerror(errno));
                return -1;
        }
	int opt=0;
	int value;
	int fd;
        printf("epfd: %d\n", epfd);
        for(res=res0;res;res=res->ifa_next){
		if(res->ifa_addr==NULL)	continue;
		if(!res->ifa_flags & IFF_UP) continue;
		if(res->ifa_addr->sa_family==AF_INET6){printf("corrent not sopport ipv6\n");continue;}
		printf("interface name: %s\n", res->ifa_name);
		void *addr;
		socklen_t len;
		int port;
		char address_str[64];
		if(res->ifa_addr->sa_family==AF_INET){
			printf("type is ipv4\n");
			struct sockaddr_in *s4 = (struct sockaddr_in*)res->ifa_addr;
			addr = &s4->sin_addr;
			len = sizeof(struct sockaddr_in);
			s4->sin_port=8080;
			port = 8080;
		}else if(res->ifa_addr->sa_family==AF_INET6){
			printf("type is ipv6\n");
			struct sockaddr_in6* s6 = (struct sockaddr_in6*)res->ifa_addr;
			addr = &s6->sin6_addr;
			len = sizeof(struct sockaddr_in6);
			s6->sin6_port=8080;
			port = 8080;
		}else{
			continue;
		}
                fd = socket(res->ifa_addr->sa_family, SOCK_STREAM, 0);
                if(fd<0){
                        printf("get fd failed, errno:%d, reason: %s\n", errno, strerror(errno));
                        continue;
                }
                if((err=set_no_blocking(fd))<0){
                        printf("set fd no blocking, errno:%d, reason: %s\n", errno, strerror(errno));
                        close(fd);
                        continue;
                }
                value = 1;
                if((err=setsockopt(fd,SOL_SOCKET, SO_REUSEADDR,&value,sizeof(int)))<0){
                        printf("set resue failed\n");
                        close(fd);
                        continue;
                }
               if((err=bind(fd, res->ifa_addr,sizeof(struct sockaddr)))<0){
                        printf("bind failed, errno:%d, reason:%s\n", errno, strerror(errno));
                        close(fd);
                        continue;
                }
                if((err=listen(fd,SOMAXCONN))<0){
                        printf("listen meet err, errno:%d, reason:%s\n", errno, strerror(errno));
                        close(fd);
                        continue;
                }
                int* data = (int*)malloc(sizeof(int));
                *data = fd;
                if((err=epoll_event_add(fd,EPOLLIN, connection_acception, data))<0){
                        printf("add event failed, errno:%d, reason:%s\n", errno, strerror(errno));
                        close(fd);
                        continue;
                }
                opt = 1;
                printf("get fd: %d\n", fd);
                if(inet_ntop(res->ifa_addr->sa_family, addr, address_str, sizeof(address_str))==NULL){
                        printf("get addr failed\n");
                }
                printf("%s\n", address_str);
		printf("port:%d\n", port);
        }
        if(!opt){
                printf("get listen fd failed\n");
                return -1;
        }
        return 0;
}


void connection_acception(int event, void* data){
	int listenfd = *(int*)data;
	if(listenfd<0){
		printf("fd meet error\n");
		return;
	}
	int err;
        printf("event:%d, %d,  listenfd:%d\n", event, EPOLLIN, listenfd);
	struct sockaddr addr;
	socklen_t addrlen;
	bzero(&addr, sizeof(struct sockaddr));
	int fd = accept(listenfd, &addr, &addrlen);
	printf("get listen fd: %d\n", fd);
	if(fd<0){
		printf("connect failed:%d, %s\n", errno, strerror(errno));
		return;
	}
	if((err=set_no_blocking(fd))<0){
		printf("set blocking failed");
		close(fd);
		return;
	}
	char address_str[64];
	char address_local[64];
	struct sockaddr local_addr;
	memset(&local_addr,0,sizeof(local_addr));
	socklen_t local_addr_len;
	memset(&local_addr_len,0,sizeof(socklen_t));
	void* raddr;
	void* laddr;
	if((err=getsockname(fd, &local_addr, &local_addr_len))<0){
		printf("get sockname failed, error:%d, reason:%s\n", errno, strerror(errno));
		return;
	}
	if(addr.sa_family==AF_INET){
		struct sockaddr_in *t = (struct sockaddr_in*)&addr;
		raddr = &t->sin_addr;	
		laddr = &((struct sockaddr_in*)&local_addr)->sin_addr;
	}else if(addr.sa_family==AF_INET6){
		struct sockaddr_in6 *t = (struct sockaddr_in6*)&addr;
		raddr = &t->sin6_addr;
		laddr = &((struct sockaddr_in6*)&local_addr)->sin6_addr;
	}else{
		printf("family not support: %d\n", addr.sa_family);
		close(fd);
		return;
	}
	connection_t *conn = (connection_t*)malloc(sizeof(connection_t));
	if(!conn){
		printf("malloc mem failed for conn\n");
		close(fd);
		return;
	}
	if((err=conn_init(conn))<0){
		printf("init conn failed\n");
		conn_exit(conn);
		return;
	}
	inet_ntop(addr.sa_family,laddr, address_local,64);
	inet_ntop(addr.sa_family,raddr, address_str,64);
	memcpy(conn->initiator, address_str, strlen(address_str));
	memcpy(conn->target, address_local, strlen(address_local));
	conn->fd = fd;
	
	if(epoll_event_add(fd,EPOLLIN, tcp_data_event_handler, conn)<0){
		conn_exit(conn);
		return;
	}
	printf("connect succcessfully,fd:%d,initiator address: %s, target address: %s\n", fd, address_str, address_local);
	return;	
}
void conn_read_pdu(connection_t* conn){
	conn->rx_iostate = RX_HEADER;
	conn->rx_buffer = &conn->req;
	conn->rx_size = HEADER_LEN;
	conn->rx_iostate = RX_HEADER;
}
int conn_init(connection_t* conn){
	memset(conn,0, sizeof(connection_t));
	conn->rx_buffer = NULL;
	conn->tx_buffer = NULL;
	conn->fd = -10;
	conn->state = FREE;
	return 0;
}
int conn_exit(connection_t* conn){
	if(!conn)	return 0;
	int fd = conn->fd;
	if(fd>0){
		close(fd);
		conn->fd = -1;
	}
	if(conn->rx_buffer){
		printf("rx not free\n");
		free(conn->rx_buffer);
		conn->rx_buffer = NULL;
	}
	if(conn->tx_buffer){
		free(conn->tx_buffer);
		conn->tx_buffer = NULL;
	}
	if(conn){
		free(conn);
		conn = NULL;
	}
	return 0;
}
int conn_destroy(connection_t* conn){
	
}

int conn_close(connection_t* conn){
	if(!conn)	return 0;
	int fd = conn->fd;
	if(fd>0){
		epoll_event_del(fd);
		close(fd);
		conn->fd = -1;
	}
	return 0;	
}

void tcp_data_event_handler(int event, void* data){
	int err;
	connection_t *conn = (connection_t*)data;
        printf("event:%d, fd:%d\n", event, conn->fd);
	if(event & EPOLLIN){
		data_event_rx_handler(conn);
	}
	if(event & EPOLLOUT){
		data_event_tx_handler(conn);
	}
	if(conn->state==CLOSE){
		conn_close(conn);
	}
	return;
}

Task* rx_task_allocate(connection_t *conn){
	Task* task = (Task*)malloc(sizeof(Task));
	if(!task){
		printf("allocate mem for task failed\n");
		return NULL;
	}
	task->conn = conn;
	mybhs_t* req = &conn->req;
	task->len = req->len;
	task->off = req->off;
	if(task->len>0){
		void* data = malloc(task->len);
		if(!data){
			printf("allocate mem for task failed\n");
			free(task);
			return NULL;
		}
		task->data = data;
	}
	return task;
}

int rx_task_start(connection_t *conn){
	mypdu_t *req;
	Task* task = rx_task_allocate(conn);
	if(!task){
		return -1;
	} 
	conn->rx_task = task;
	conn->rx_iostate = RX_DATA;
	conn->rx_buffer = task->data;
	conn->rx_size = task->len;
	return 0;
}

int rx_task_done(connection_t *conn){
	Task* task = conn->rx_task;
	int len = task->len;
	int off = task->off;
	char* data = task->data;
	printf("off=%d, len=%d, data=%s\n", off, len, data);
	return 0;
}

int data_event_rx_handler(connection_t *conn){
	int ret;
	int fd = conn->fd;
	if(fd<0){
		printf("invalid fd: %d\n", fd);
		return -1;
	}
	switch(conn->rx_iostate){
	RX_HEADER:
		ret = do_recv(conn, RX_INIT_DATA);
		if(ret<0 || conn->rx_iostate != RX_INIT_DATA)
			break;
	RX_INIT_DATA:
		if(conn->state==SCSI){
			ret = rx_task_start(conn);
			if(ret<0||conn->rx_iostate != RX_DATA)
				break;
		}else{
			conn->rx_iostate = RX_DATA;
		}
	RX_DATA:
		ret = do_recv(conn, RX_END);
		if(ret<0 || conn->rx_iostate != RX_END)
			break;		
	RX_END:
		break;
	default:
		printf("unknown rx_iostate %d\n", conn->rx_iostate);
		conn->state = CLOSE;
		return -1;
	}
	if(ret<0 || conn->rx_iostate != RX_END || conn->state == CLOSE)
		return 0;
	if(conn->rx_size){
		printf("recv not finish, exit error, exit...\n");
		exit(1);
	} 
	if(conn->state==SCSI){
		ret = rx_task_done(conn);
		if(ret<0){
			conn->state = CLOSE;
			printf("rx_task_done failed, ret is %d\n", ret);
			return ret;
		}
	}else{
		ret = epoll_event_mod(fd, EPOLLOUT, tcp_data_event_handler, conn);
		if(ret<0){
			printf("mod event EPOLLOUT failed\n");
			conn->state = CLOSE;
			return ret;
		}
	}
	return 0;
}
int data_event_tx_handler(connection_t *conn){
	int fd = conn->fd;
	printf("tx handler is called, fd: %d, conn state:%d\n", conn->fd, conn->state);
	conn->state = SCSI;
	int ret = epoll_event_mod(fd, EPOLLIN, tcp_data_event_handler, conn);
	if(ret<0){
		printf("mod event EPOLLOUT failed\n");
		conn->state = CLOSE;
		return ret;
	}	
	return 0;
}

int epoll_event_add(int fd,int events, pfun fun, void* data){
	struct epoll_event event;
	event.events = events;
	usr_event_data_t *ed = (usr_event_data_t*) malloc(sizeof(usr_event_data_t));
	memset(ed,0,sizeof(usr_event_data_t));
	ed->fd = fd;
	ed->handler = fun;
	ed->data = data;
	//event.data.fd=fd;
        event.data.ptr= ed;
	return epoll_ctl(epfd, EPOLL_CTL_ADD, fd, &event);
}

int epoll_event_del(int fd){
	return epoll_ctl(epfd, EPOLL_CTL_DEL, fd, NULL);
}


int epoll_event_mod(int fd,int events, pfun fun, void* data){
        struct epoll_event event;
        event.events = events;
        usr_event_data_t *ed = (usr_event_data_t*) malloc(sizeof(usr_event_data_t));
	memset(ed,0,sizeof(usr_event_data_t));
        ed->fd = fd;
        ed->handler = fun;
        event.data.ptr= ed;
        return epoll_ctl(epfd, EPOLL_CTL_MOD, fd, &event);
}

mypdu_t* pdu_allocate(char* buff, int len){
	mypdu_t* pdu = (mypdu_t*)malloc(sizeof(mypdu_t));
	if(!pdu) return NULL;
	memset(&pdu->header, 0, sizeof(mybhs_t));
	pdu->header.off = 0;
	pdu->header.len = len;	
	pdu->data = malloc(len);
	if(!pdu->data){
		printf("alloc mem failed\n");
		if(pdu)	free(pdu);
		return NULL;
	}
	memcpy(pdu->data, buff, len);
	return pdu;
}

mypdu_t* pdu_init(){
	mypdu_t* pdu = (mypdu_t*)malloc(sizeof(mypdu_t));
	if(!pdu) return NULL;
	return pdu;	
}

void pdu_free(mypdu_t* pdu){
}

int send_message(int fd, mypdu_t* pdu){
	if(!pdu){
		printf("pdu is null\n");
		return -1;
	}
	if(fd<0){
		printf("fd %d is invalid\n",fd);
		return -2;
	}
	int err;
	if((err=write(fd, &pdu->header, sizeof(mybhs_t)))<0){
		printf("write failed, errno is %d, reason: %s\n", errno, strerror(errno));
		return err;
	}
	if(err!=sizeof(mybhs_t)){
		printf("pdu size not write\n");
		return -1;
	}
	int len = pdu->header.len;
	if(len){
		err= write(fd, pdu->data, len);
		printf("write %d bytes", err);
		if(err<=0)
			return -1;	
	}
	return 0;
}
// add signal interupt handle afterwords.
int recv_message(int fd, mypdu_t* pdu){
	int err;
	if(!pdu){
		printf("pdu is null\n");
		return -1;
	}
	if(fd<0){
		printf("fd %d is invalid\n", fd);
		return -2;
	}
	if((err=read(fd, pdu, PDU_LEN))<0){
		if(errno==EAGAIN || errno==EINTR){
			printf("errno is %d, need try again\n", errno);
			return 0;
		}
		printf("read failed, errno is %d, reason: %s\n", errno, strerror(errno));
		return err;
	}	
	if(err!=PDU_LEN){
		printf("message len: %d, message is not full, drop and close\n", err);
		return -1;
	}
	int datasize = pdu->header.len;
	if(datasize){
		char*rx_buff = malloc(datasize);
		if(!rx_buff){
			printf("alloc mem failed\n");
			return -1;
		}
		if((err=read(fd, rx_buff, datasize))<0){
			printf("read failed, errno is %d, reason: %s\n", errno, strerror(errno));
			return err;
		}
		if(err!=datasize){
			if(err==0){
				printf("connect has closed\n");
			}else{
				printf("message data len: %d, datasize:%d, message is not full, drop and close\n", err,datasize);
			}
			return -1;
		}		
		rx_buff[datasize-1] = '\0';
		pdu->data = rx_buff;
		return err;
	}
	return 0;
}

int do_recv(connection_t* conn, int next_state){
	int err;
	int fd = conn->fd;
	if(fd<0){
		printf("fd %d is invalid\n", fd);
		return -2;
	}
	if((err=read(fd, conn->rx_buffer, conn->rx_size))<0){
		if(errno==EAGAIN || errno==EINTR){
			printf("errno is %d, need try again\n", errno);
			return 0;
		}
		printf("read failed, errno is %d, reason: %s\n", errno, strerror(errno));
		conn->state = CLOSE;
		return err;
	}	
	conn->rx_buffer += err;
	conn->rx_size -= err;
	if(0==conn->rx_size)
		conn->rx_iostate = next_state;
	return err;
}

int do_send(connection_t* conn, int next_state){
	int err;
	int fd = conn->fd;
	if(fd<0){
		printf("fd %d is invalid\n", fd);
		return -2;
	}
	if((err=write(fd, conn->tx_buffer, conn->tx_size))<0){
		if(errno==EAGAIN || errno==EINTR){
			printf("errno is %d, need try again\n", errno);
			return 0;
		}
		printf("write failed, errno is %d, reason: %s\n", errno, strerror(errno));
		conn->state = CLOSE;
		return err;
	}	
	conn->tx_buffer += err;
	conn->tx_size -= err;
	if(0==conn->tx_size)
		conn->tx_iostate = next_state;
	return err;
}

