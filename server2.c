#include <stdio.h>
#include <stdlib.h>
#include <sys/types.h>
#include <sys/socket.h>
#include <netinet/in.h>
#include <string.h>
#include <errno.h>
#include <unistd.h>
#include <sqlite3.h> 
#include <arpa/inet.h>
#include <ctype.h>
#include <signal.h>

#define BACKLOG 10 
#define IP "127.0.0.5"

const int portnum = 1234;

sqlite3 *db;	
char client_ip[50];	

void complain(int sock);
void client_handler(int sock);
char * sanitize(char msg[]);


int main(int argc, char *argv[])
{

	int yes=1;

	// Create a socket
	int sockfd, newsockfd;

	struct sockaddr_in serv_addr, cli_addr;
	
	sockfd = socket(AF_INET, SOCK_STREAM, 0);
	if (sockfd < 0)
	{
		perror("Error in Socket: \n");
		exit(1);
	}

	if (setsockopt(sockfd, SOL_SOCKET, SO_REUSEADDR, &yes, sizeof(int)) == -1) {
            perror("Error in setsocketopt\n");
            exit(1);
        }

	serv_addr.sin_family = AF_INET;
	serv_addr.sin_port = htons(portnum);
	serv_addr.sin_addr.s_addr=inet_addr("127.0.0.5");

	// Bind to socket
	int res = bind(sockfd, (struct sockaddr *)&serv_addr, sizeof(serv_addr));
	if (res < 0)
	{
		perror("Can't bind to socket.");
		exit(1);
	}

	// listen for connections
	if (listen(sockfd, BACKLOG) == -1) {
        	printf("error in listen\n");
        	exit(1);
    	}

	int clilen = sizeof(cli_addr);
	
	// accept connections
	printf("server: waiting for connections...\n");


	while(1){

		newsockfd = accept(sockfd, (struct sockaddr *)&cli_addr, (socklen_t *)&clilen);
		if (newsockfd < 0){ 
			perror("Socket"); 
			continue; 
		}

	sprintf(client_ip,"Got connection from: %s:%d",inet_ntoa(cli_addr.sin_addr),ntohs(cli_addr.sin_port));
	printf("%s\n",client_ip);
	
	int pid= fork();
	if (pid<0){
		perror("Could no fork\n");
		exit(1);
	}	

	if(pid == 0){
		// child process
		close(sockfd);
		client_handler(newsockfd);
		close(newsockfd);
		exit(0);
		
		
	}

	else{
		 // This is the parent
		 close(newsockfd);
		}
	}// end while
	
	close(sockfd);
	return 0;
	
}// end main
	

void client_handler(int sock){

	const int NOT_AUTH = 0;
	const int LOGGED_IN = 1;
	
	char buf[1000];
	char username[50];

	// Open connection to database
	if (sqlite3_open("serverc2.db", &db) < 0)
	{
		perror("Can't open database\n");
		exit(1);
	}

	strcpy(buf, "250: Welcome to Server C!\n");
	send(sock, buf, strlen(buf), 0);
	
	int state = NOT_AUTH;	

	while(1){

		memset(buf,'\0',1000);

		// Wait for input from user
		int recvd = recv(sock, buf, 999, 0);
		if (recvd == 0){
			continue;		
		}
		buf[recvd] = '\0';
			
		//printf("Buffer contents: %s\n",buf);

		//printf("%s\n", client_ip);
		
		if (!strncmp("BYE", buf, 3))
		{
			close(sock);
			return;
		}

		else if (!strncmp("IAM", buf, 3)){
			int count = sscanf(buf, "IAM %s ", username);
			//printf("sscanf returned %d\n", count);

			if (count != 1)
			{
				strcpy(buf, "500 No user specified\n");
				send(sock, buf, strlen(buf), 0);
				printf("No user specified\n");
				continue;
			}

			printf("%s User is identified as %s\n", client_ip, username);
		
			char * sanitized_username=sanitize(username);
			sqlite3_stmt *stmt;
			char query[1000];
			char password[1000];
			int passwd_recvd;
			
			// check if user exists.
			sprintf(query, "select count(*) from users where uname = '%s'",sanitized_username);
			if (sqlite3_prepare_v2(db, query, strlen(query), &stmt, NULL)!=SQLITE_OK){
				perror("Error in prepare1: \n");
				exit(1);
			}
			sqlite3_step(stmt);
			int usercount = sqlite3_column_int(stmt, 0);
			//printf("Usercount: %d\n",usercount);

			// if user not regestered in database
			if (usercount == 0)
			{
				strcpy(buf, "404 New user. Enter a new password\n");
				send(sock, buf, strlen(buf), 0);
				strcpy(buf,"Password: ");
				send(sock, buf, strlen(buf), 0);
				passwd_recvd = recv(sock, buf, 999, 0);
				if (passwd_recvd==0){
					strcpy(buf,"Password not accepted\n");
					send(sock, buf, strlen(buf), 0);
					continue;
				}
				else{
					// enter username into database
					sscanf(buf,"%s ",password);
					char *sanitized_password=sanitize(password);
					sprintf(query,"insert into users (uname,password) values ('%s','%s');commit;" ,sanitized_username, sanitized_password);
					if(sqlite3_prepare_v2(db, query, strlen(query), &stmt, NULL)!=SQLITE_OK){
						perror("Error in prepare3 ");
						exit(1);
					}
					sqlite3_step(stmt);
					sqlite3_finalize(stmt);

					// send back confirmation
					strcpy(buf,"200: Logged in\n");
					send(sock, buf, strlen(buf),0);
					state=LOGGED_IN;
					
				}
			}// end if(usercount==0)

			// if user exists
			if (usercount==1){
			
				// check if password is correct 
				strcpy(buf, "User Exists. Enter password or create a new account\n");
				send(sock, buf, strlen(buf), 0);
				strcpy(buf, "Password: ");
				send(sock, buf, strlen(buf), 0);
				passwd_recvd = recv(sock, buf, 999, 0);
				if (passwd_recvd==0){
					strcpy(buf,"Password not accepted\n");
					send(sock, buf, strlen(buf), 0);
					continue;
				}
				else{
					
					sscanf(buf,"%s ",password);
					sprintf(query, "select password from users where uname = '%s'",sanitized_username);
					if (sqlite3_prepare_v2(db, query, strlen(query), &stmt, NULL)!=SQLITE_OK){
						perror("Error in prepare1: \n");
						exit(1);
					}
					sqlite3_step(stmt);
					char * check_password = sqlite3_column_text(stmt, 0);
					//printf("The password to check is: %s\n", check_password);
					//printf("The enterend password is: %s\n", password);
					if(strcmp(password,check_password)==0){
						// send back confirmation
						strcpy(buf,"200: Logged in\n");
						send(sock, buf, strlen(buf),0);
						state=LOGGED_IN;
						continue;
					}
					
					else{
						strcpy(buf,"200: Wrong password\n");
						send(sock, buf, strlen(buf),0);
						continue;
						
					}// end else

				}// end else
				
				
				
			}//end if
			
			
		}// end elseif (!strcmp)
			
		// list all users
		else if(!strncmp("USR",buf,3)){
			if (!state)  {
				complain(sock);
				continue;
			}

			strcpy(buf,"All Users\n");
			send(sock,buf,strlen(buf),0);

			// Query database for all users
			sqlite3_stmt *stmt;
			char *query="select uname from users order by uname";
			if(sqlite3_prepare_v2(db,query,strlen(query),&stmt,NULL)!=SQLITE_OK){
				perror("Error in Prepare: ");
				exit(1);
			}
				

			// Display all users
			while(sqlite3_step(stmt)!= SQLITE_DONE){
				sprintf(buf,"%s\n",(char *)sqlite3_column_text(stmt,0));
				send(sock,buf,strlen(buf),0);
			}

			// Send "."
			strcpy(buf,".\n");
			send(sock,buf,strlen(buf),0);
				
		}

		else if (!strncmp("MSG", buf, 3)){
			if (!state) { 
				complain(sock); 
				continue; 
			}

			char query[1000]={0};
			char to[995];
			char message[1000]={0};
			sqlite3_stmt *stmt;
			int j=0;

			int count = sscanf(buf, "MSG %s ", to);
			printf("count: %d\n",count);
			printf("to: %s\n",to);
			char *i=buf+5+strlen(to);
			while(*i!='\n'){
				message[j++]=*i++;
			}
			
			printf("Message: %s\n", message);

			if (count < 1)
			{
				strcpy(buf, "510 No user specified\n");
				send(sock, buf, strlen(buf), 0);
				continue;
			}
		
			
			// Check if user exists
			sprintf(query, "select count(*) from users where uname = '%s'",to);
			if (sqlite3_prepare_v2(db, query, strlen(query), &stmt, NULL)!=SQLITE_OK){
				perror("Error in prepare1: \n");
				exit(1);
			}
			sqlite3_step(stmt);
			int usercount = sqlite3_column_int(stmt, 0);
			printf("Usercount: %d\n",usercount);

			if (usercount == 0)
			{
				strcpy(buf, "404 User does not exist\n");
				send(sock, buf, strlen(buf), 0);
				sqlite3_finalize(stmt);
				continue;
			}
			sqlite3_finalize(stmt);

			// queue message
			printf("Username: %s",username);
			printf("Message: %s", message);
			char * sanitized_username=sanitize(username);
			char * sanitized_to=sanitize(to);
			char * sanitized_message=sanitize(message);
			sprintf(query,"insert into my_message_table(msg_from, msg_to, messages) values('%s', '%s', '%s'); commit;", sanitized_username,sanitized_to,sanitized_message);
			printf("Query: %s\n",query);
			if(sqlite3_prepare_v2(db, query, strlen(query), &stmt, NULL)!=SQLITE_OK){
				perror("Error in prepare2: ");
				exit(1);
			}
			sqlite3_step(stmt);
			sqlite3_finalize(stmt);
			
			strcpy(buf, "200 Message queued\n");
			send(sock, buf, strlen(buf), 0);
		}	

		else if (!strncmp("READ", buf, 4))
		{
			if (! state) { 
				complain(sock); 
				continue; 
			}

			strcpy(buf, "300 Here are your messages\n");
			send(sock, buf, strlen(buf), 0);
			

			// select messages from database
			sqlite3_stmt *stmt;
			sqlite3_stmt *stmt1;
			char query[1000];
			char query1[1000];
			char * sanitized_username=sanitize(username);
			sprintf(query, "select msg_from from my_message_table where msg_to = '%s' order by id",sanitized_username);
			sprintf(query1, "select messages from my_message_table where msg_to = '%s' order by id",sanitized_username);
			if(sqlite3_prepare_v2(db, query, strlen(query), &stmt, NULL)!=SQLITE_OK){
				perror("Error in prepare: \n");
				exit(1);
			}
			if(sqlite3_prepare_v2(db, query1, strlen(query), &stmt1, NULL)!=SQLITE_OK){
				perror("Error in prepare: \n");
				exit(1);
			}

			while ((sqlite3_step(stmt) != SQLITE_DONE) && (sqlite3_step(stmt1)!= SQLITE_DONE))
			{
				sprintf(buf, "Message from %s:\n", (char *)sqlite3_column_text(stmt, 0));
				send(sock, buf, strlen(buf), 0);
				sprintf(buf, "%s\n\n", (char *)sqlite3_column_text(stmt1, 0));
				send(sock, buf, strlen(buf), 0);
			}
			sqlite3_finalize(stmt);
			sqlite3_finalize(stmt1);
			
			// send a '.'
			strcpy(buf, ".\n");
			send(sock, buf, strlen(buf), 0);

			
		}

		
		else if (!strncmp("DELMSG", buf, 6)){
			if (!state) { 
				complain(sock); 
				continue; 
			}

			char query[1000]={0};
			sqlite3_stmt *stmt;
			char * sanitized_username=sanitize(username);
			sprintf(query, "delete from my_message_table where msg_to = '%s'; commit;", sanitized_username);
			if(sqlite3_prepare_v2(db, query, strlen(query), &stmt, NULL)!=SQLITE_OK){
				perror("Error in prepare3 ");
				exit(1);
			}
			sqlite3_step(stmt);
			sqlite3_finalize(stmt);

			strcpy(buf,"600 Messages Deleted\n");
			send(sock,buf,strlen(buf),0);

		}

		else if (!strncmp("LOGOUT", buf, 6)){
			if (!state) { 
				complain(sock); 
				continue; 
			}
			
			state = NOT_AUTH;
			strcpy(buf,"600 User logged out\n");
			send(sock,buf,strlen(buf),0);
			continue;
			
		}

		
		
		
	}// end while
	
}	

void complain(int sock)
{
	char buf[1000];
	strcpy(buf, "500 Not logged in\n");
	send(sock, buf, strlen(buf), 0);
}
	
char * sanitize(char msg[]){
	char *i=msg;
	int count =0;
	int size=0;
	while(*i!='\0'){
		if(*i==39)
			count++;
		size++;
		i++;
	}

	//printf("Count = %d\n",count);	
	char *j=i+count;
	while(size--!=0){
		if(*i==39){
			*j--=*i--;
			*j--=39;
		}
		else
			*j--=*i--;
	}// end while

	//printf("Sanitized message is %s\n",msg);
	return msg;
}
	

