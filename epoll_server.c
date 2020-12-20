#include"tcp_transport.h"
#define MAX_LISTEN_NUM 1024
#define MAX_EVENTS 1024

int epfd;
int listenfd;
int lld_init();
//void event_handler(struct epoll_event event);

int main(){
	int nfds=-1;
	struct epoll_event event, events[MAX_EVENTS];
	int err;
	epfd = epoll_create(MAX_LISTEN_NUM);
	if(epfd<0){
		printf("create epfd failed, exit...\n");
		close(epfd);
		exit(1);
	}
	if((err=lld_init())<0){
		printf("lld init failed\n");
		close(epfd);
		exit(1);
	}
	while(1){
		nfds = epoll_wait(epfd, events, MAX_EVENTS,-1);
		printf("nfds=%d\n", nfds);
		for(int i=0;i<nfds;i++){
			event = events[i];
			usr_event_data_t* ep_data = (usr_event_data_t*)(event.data.ptr);
			pfun handler = ep_data->handler;
			//pfun handler =(event_data_t*) (event.data.ptr)->handler;
			void* data = ep_data->data;
			handler(event.events, data);
		}
	}
	if(epfd){
		close(epfd);
	}	
	return 0;
}
