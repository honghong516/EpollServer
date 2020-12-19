#include "tcp_transport.h"
int conn_init();
int conn_destroy(connection_t *conn);
int main(){
	connection_t* conn = (connection_t*)malloc(sizeof(connection_t));
	if(!conn){
		printf("conn is null, return\n");
		return -1;
	}
	int err = conn_init(conn);
	if(err<0){
		printf("conn init failed\n");
		return -1;
	}
	conn_destroy(conn);
	return 0;
}
