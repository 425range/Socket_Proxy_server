#include <stdio.h>
#include <string.h>
#include <sys/types.h>
#include <sys/socket.h>
#include <netinet/in.h>
#include <arpa/inet.h>
#include <unistd.h>
#include <stdbool.h>
#include <stdlib.h>
#include <pwd.h>
#include <sys/stat.h>
#include <sys/wait.h>
#include <openssl/sha.h>
#include <fcntl.h>
#include <dirent.h>
#include <time.h>
#include <signal.h>
#include <netdb.h>


#define BUFFSIZE 1024
#define PORTNO 39999

char *sha1_hash(char *input_url, char *hashed_url);
char *getHomeDir(char *home);
void http_client_request(int client_fd, struct in_addr inet_client_address, struct sockaddr_in client_addr);
char* getIPAddr(char* addr);
int SubProcess(int client_fd, char* url, char* filedir);
bool is_hit(const char *subdir, const char *cache_file);
int hit(const char *subdir, const char *dir_name, const char *cache_file, const char *url, int client_fd);
void save_to_cache(const char* filedir, const char* response_header, const char* response_message);
int send_http_with_timeout(const char* host, const char* path, int client_fd);

// Sigchld handler
void sigchld_handler(){
	pid_t pid;
	int status;
    // Prevent zombie process
	while ((pid = waitpid(-1, &status, WNOHANG)) > 0);
}
// Sigalrm handler
void my_alarm(int signo){
    printf("========== NO RESPONSE ==========\n");
    exit(0);
}

// Semaphore p function
void p(int semid){
    Initialize Sem variables
    if(Lock section & check fail){
        exit(1);
    }
}
// Semaphore v function
void v(int semid){
    Initialize Sem variables
    if(Unlock section & check fail){
        exit(1);
    }
}

int main(){
    // SIGCHLD handler 
    signal(SIGCHLD, sigchld_handler);
    signal(SIGALRM, my_alarm);

    Create semaphore

    Create Socket for listen web browser
    
    Initialize socket components

    Bind socketaddr to socket

    Listen Client request

    while(Get client request){
        Accept client
        if(Accept error){
            printf("Server : accept failed\n");
            return 0;
        } 
        set client addr

        pid_t pid = fork();
        if(fork failed){
            printf("Fork failed\n");
            close(client_fd);
            continue;
        }
        if(child process){
            Handle http client request
            close(client_fd);
            exit(0);
        }
        else if(Parent process){
            close(client_fd);
            processcnt++;
        } 
    } 
    close(socket_fd);
    return 0;
} // end of main

// Fuction for http client request handling
void http_client_request(int client_fd, struct in_addr inet_client_address, struct sockaddr_in client_addr){
    Read data from client
    if(read error){
        close(client_fd);
        return;
    }
    tok url
    if(tok error){
        close(client_fd);
        return;
    }
    tok method from http

    if(url is NULL){
        close(client_fd);
        return;
    }
    strcpy(url, tok);
    printf("url = %s\n",url);

    if(url has favicon.ico){
        printf("Favicon request ignored.\n");
        close(client_fd);
        return;
    }
    if(url has firefox.com){
        printf("Firefox request ignored.\n");
        close(client_fd);
        return;
    }
    tok by line

    while (Extract host from url) {
        if (strncmp(line, "Host:", 5) == 0) {
            strncpy(host, line + 6, sizeof(host) - 1);
            erase enter
            break;
        }
        line = strtok(NULL, "\r\n");
    }
    Extract path from url
    if(path != NULL){
        path = strchr(path + 3, '/');
    }
    if(path == NULL){
        path = "/";
    }
    get IP address
    Make cache files & Get hit flag

    if(hit){          
        Open file
        if(file is ok){
            while (Read cache file)
                write(client_fd, cachebuf, n);
            close(fd);
        } 
    }
    else if(miss){
        Send request to http server
    }
    else{
        sprintf(response_message,"<h1>Disconnected</h1><br>");
    }
    Log disconnection
    close(client_fd);
}

// Function for sending http request to web server
int send_http_with_timeout(const char* host, const char* path, int client_fd) {
    get host by name
    if (host error) {
        perror("gethostbyname err");
        return -1;
    }

    Create server Socket
    if (socket error) {
        perror("socket err");
        return -1;
    }

    Initialize server components
    set alarm after 10 sec

    connect to server
    if (connect error) {
        perror("connect err");
        close(sockfd);
        return -1;
    }

    while(Get data from web server){
        send data to client
        write data to cache file
    }
    if (write error) {
        perror("write err");
        close(sockfd);
        return -1;
    }

    Check response and set alarm
    if (!read error) {
        reset alarm
    }
    else {
        read error
    }
    close(sockfd);
    return 0;
}


// Function for log information
void* LogFileThread(void* arg){
    LogArgs* logArgs = (LogArgs*)arg;

	Make fullpath	
	if(logfile not exist){
		mkdir(logdir, 0777);
	}
	umask(old_umask);

	Calculate time

    printf("*PID# %d is waiting for the semaphore.\n", getpid());
    p(semid);
    printf("*PID# %d create the *TID# %ld.\n", getpid(), pthread_self());
	Open logfile.txt
	if(file is ok){
		if(hit){
            Log hit info
		}
		else{
            Log miss info
		} 
		fclose(fp);
	} 
	else{
		perror("logfile open failed");
	} 
    printf("*TID# %ld is exited\n", pthread_self());
    printf("*PID# %d exited the critical zone.\n", getpid());
    v(semid);

    free(logArgs); // Free dynamic alloc
    pthread_exit(NULL); // Close thread
}

// Function for log HIT & MISS
int hit(const char *subdir, const char *dir_name, const char *cache_file, const char *url, int client_fd){
    make fullpath
    
    Check hit or miss
    
    Log with Thread

    Create thread
    Execute thread function
    Close thread

    Return hit flag
} 