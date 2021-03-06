#include"tcp_transport.h"
#define MAX_LISTEN_NUM 1024
#define MAX_EVENTS 1024

#include<arpa/inet.h>

int main(int argc, char* argv[]){
	printf("argc: %d\n", argc);
	if(argc<2){
		printf("too small argc\n");
		exit(1);
	}
	int fd;
	struct sockaddr_in addr;
	fd = socket(AF_INET, SOCK_STREAM, 0);
	bzero(&addr, sizeof(addr));
	addr.sin_family = AF_INET;
	addr.sin_port = 8080;
	inet_pton(AF_INET, argv[1], &addr.sin_addr);
	int err = connect(fd, (struct sockaddr*)&addr, sizeof(addr));
	printf("err = %d, fd=%d\n", err, fd);
	if(err<0){
		printf("connect failed,exit...\n");
		close(fd);
		return -1;
	}
	Request req;
	memset(&req, 0, sizeof(req));
	req.opcode = 0x01;
	req.len = 0;
	if((err=write(fd, &req, HEADER_LEN))<0){
		printf("login failed, errno: %d, reason:%s\n", errno, strerror(errno));
		exit(1);
	}
	printf("write %d nums\n", err);
	Response rsp;
	memset(&rsp,0,sizeof(Response));
	if((err=recv_message(fd, &rsp))<0){
		printf("recv message result failed\n");
		exit(1);
	}
	printf("response result is %d, detail: %s\n", rsp.result, rsp.reason);
	if(rsp.data){
		free(rsp.data);
		rsp.data = NULL;
	}
	char write_buff[BUF_LEN];
	int count;
	while(1){
		char* res = fgets(write_buff, BUF_LEN, stdin);
		if(!res){
			printf("fgets return is null\n");
			break;
		}
		int len = strlen(write_buff);
		if(len<1){
			printf("fgets failed, continue...\n");
			continue;
		}
		write_buff[len-1] = '\0';
		printf("write data:%s, len:%d\n", write_buff, len);
		mypdu_t* pdu = pdu_allocate(write_buff, len);
		if(!pdu){
			printf("pdu prepare failed, ignore...\n");
			break;
		}
		//count = tcp_write(fd, write_buff, strlen(write_buff));
		err = send_message(fd, pdu);
		if(err<0){
			printf("write meet error: %d, reason:%s\n", errno, strerror(errno));
			break;
		}
		memset(&rsp,0,sizeof(Response));
		if((err=recv_message(fd, &rsp))<0){
			printf("recv message result failed\n");
			exit(1);
		}
		printf("response result is %d, detail: %s\n", rsp.result, rsp.reason);	
		if(rsp.data){
			free(rsp.data);
			rsp.data = NULL;
		}	
	};
	close(fd);
	return 0;
}
