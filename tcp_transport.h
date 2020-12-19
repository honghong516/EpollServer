#ifndef __TCP_TRANSPORT_
#define __TCP_TRANSPORT_
#include<sys/epoll.h>
#include<errno.h>
#include<netdb.h>
#include<string.h>
#include<stdio.h>
#include<stdlib.h>
#include<unistd.h>

#define BUF_LEN 4096
#define NAME_LEN 64
#define PDU_LEN sizeof(mypdu_t)
#define HEADER_LEN sizeof(mybhs_t)

//typedef void (*pfun)(struct epoll_event event);

typedef void (*pfun)(int event, void* data);

enum CONN_STATE{
	FREE,
	SCSI
};
enum RX_STATE{
	RX_HEADER,
	RX_DATA
};
enum TX_STATE{
	TX_HEADER,
	TX_DATA
};

typedef struct{
        int fd;
        pfun handler;
        void* data;
}usr_event_data_t;

typedef struct{
	int state;
	int rx_iostate;
	int tx_iostate;
	mypdu_t req;
	mypdu_t rsp;
	int fd;
	int rx_size;
	char *rx_buffer;
	int tx_size;
	char *tx_buffer;
	char initiator[NAME_LEN];
	char target[NAME_LEN];
}connection_t;


typedef struct{
	int datasize;
}mybhs_t;

typedef struct{
	mybhs_t header;
	void* data;
}mypdu_t;

typedef struct{
	int fd;
}conn_params_t;

int lld_init();

int epoll_event_add(int fd,int events, pfun fun, void* data);

int epoll_event_mod(int fd,int events, pfun fun, void* data);
int epoll_event_del(int fd);

void tcp_data_event_handler(int event, void* data);

mypdu_t* pdu_init();
mypdu_t* pdu_allocate(char* buff, int len);
void pdu_free(mypdu_t* pdu);
int send_message(int fd, mypdu_t* pdu);
int recv_message(int fd, mypdu_t* pdu);
#endif
