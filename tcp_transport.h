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
#define HEADER_LEN sizeof(Request)
#define INCOMING_SIZE sizeof(Request)
#define OUTCOMING_SIZE sizeof(Request)
#define RESPONSE_LEN sizeof(Response)

//typedef void (*pfun)(struct epoll_event event);

typedef void (*pfun)(int event, void* data);

enum CONN_RESULT{
	SUCCESS,
	FAIL
};

enum CONN_STATE{
	FREE,
	LOGIN,
	SCSI,
	CLOSE
};
enum RX_STATE{
	RX_HEADER,
	RX_INIT_DATA,
	RX_DATA,
	RX_END
	
};
enum TX_STATE{
	TX_HEADER,
	TX_INIT_DATA,
	TX_DATA,
	TX_END
};

typedef struct{
        int fd;
        pfun handler;
        void* data;
}usr_event_data_t;



typedef struct{
	int opcode;
	char* filename;
	int off;
	int len;
}Request;
typedef struct{
	int result;
	char reason[100];
	int data_size;
	char *data;
}Response;
struct _Task;
typedef struct _Task Task;
typedef struct _conn_t{
	int state;
	int rx_iostate;
	int tx_iostate;
	Request req;
	Response rsp;
	int fd;
	int rx_size;
	void* req_buffer;
	void* rsp_buffer;
	void *rx_buffer;
	int tx_size;
	void *tx_buffer;
	Task* rx_task;
	Task* tx_task;
	char initiator[NAME_LEN];
	char target[NAME_LEN];
}connection_t;

typedef struct _Task{
	connection_t* conn;
	int off;
	int len;
	void* data;
}Task;


typedef struct{
	Request header;
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
int recv_message(int fd, Response* pdu);
int do_recv(connection_t* conn, int next_state);
int do_send(connection_t* conn, int next_state);
#endif
