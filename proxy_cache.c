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
#include <sys/ipc.h>
#include <sys/sem.h>
#include <pthread.h>

#define BUFFSIZE 1024
#define PORTNO 39999

char *sha1_hash(char *input_url, char *hashed_url);
char *getHomeDir(char *home);
void http_client_request(int client_fd, struct in_addr inet_client_address, struct sockaddr_in client_addr);
char* getIPAddr(char* addr);
int SubProcess(int client_fd, char* url, char* filedir);
bool is_hit(const char *subdir, const char *cache_file);
int hit(const char *subdir, const char *dir_name, const char *cache_file, const char *url, int client_fd);
int send_http_with_timeout(const char* host, const char* path, int client_fd, const char* filedir);
void LogFile(bool hit, const char* url, const char *dir_name, const char *cache_file);
void Terminate (int* runtime, int* processcnt);
void sigint_handler(int signo);

int processcnt = 0;
int semid;
time_t start_time;



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
    // Initialize Sem variables
    struct sembuf pbuf;
    pbuf.sem_num =  0;
    pbuf.sem_op = -1;
    pbuf.sem_flg = SEM_UNDO;
    // Lock section
    if((semop(semid, &pbuf, 1)) == -1){
        // P error
        perror("p : semop failed");
        exit(1);
    }
}
// Semaphore v function
void v(int semid){
    // Initialize Sem variables
    struct sembuf vbuf;
    vbuf.sem_num = 0;
    vbuf.sem_op = 1;
    vbuf.sem_flg = SEM_UNDO;
    // Unlock section
    if((semop(semid, &vbuf, 1)) == -1){
        // V error
        perror("v : semop failed");
        exit(1);
    }
}
typedef struct {
    bool hit;
    char url[512];
    char dir_name[4];
    char cache_file[38];
} LogArgs;

void* LogFileThread(void* arg) {
    LogArgs* logArgs = (LogArgs*)arg;

    // Make fullpath
    char home[256], logpath[512], logdir[512];
    getHomeDir(home);
    snprintf(logdir, sizeof(logdir), "%s/logfile", home);
    snprintf(logpath, sizeof(logpath), "%s/logfile/logfile.txt", home);

    // Initialize umask & Create file
    mode_t old_umask = umask(0);
    if(opendir(logdir) == NULL) mkdir(logdir, 0777);
    umask(old_umask);

    // Time variables
    time_t now = time(NULL);
    struct tm *localtm = localtime(&now);

    /////// Critical Section Start /////////
    printf("*PID# %d is waiting for semaphore.\n", getpid());
    p(semid);
    printf("*PID# %d create the *TID# %ld.\n", getpid(), pthread_self());
    // Create logfile
    FILE* fp = fopen(logpath, "a");
    if(fp != NULL){
        // hit log
        if(logArgs->hit){
            fprintf(fp, "[HIT]%s/%s - [%d/%d/%d, %d:%d:%d]\n", logArgs->dir_name, logArgs->cache_file,
                localtm->tm_year+1900, localtm->tm_mon+1, localtm->tm_mday,
                localtm->tm_hour, localtm->tm_min, localtm->tm_sec);
            fprintf(fp, "[HIT]%s\n", logArgs->url);
        }
        // miss log
        else {
            fprintf(fp, "[MISS]%s - [%d/%d/%d, %d:%d:%d]\n", logArgs->url,
                localtm->tm_year+1900, localtm->tm_mon+1, localtm->tm_mday,
                localtm->tm_hour, localtm->tm_min, localtm->tm_sec);
        }
        fclose(fp); // Close file
    } else {
        perror("logfile open failed");  // File open err
    }
    // print thread info
    printf("*TID# %ld is exited\n", pthread_self());
    printf("*PID# %d exited the critical section.\n", getpid());
    v(semid);
    //////// Critiacl Section End ////////
    free(logArgs); // Free dynamic alloc
    pthread_exit(NULL); // Close thread
} // end of function


// Main
int main(){
    struct sockaddr_in server_addr, client_addr;
    int socket_fd, client_fd, len, len_out;
    
    // SIGCHLD handler 
    signal(SIGCHLD, sigchld_handler);
    signal(SIGALRM, my_alarm);
    signal(SIGINT, sigint_handler);

    // Create semaphore
    union semun{
        int val;
        struct semid_ds *buf;
        unsigned short int *array;
    } arg;
    if((semid = semget((key_t)39999, 1, IPC_CREAT|0666)) == -1){
        perror("semget failed");
        exit(1);
    }

    arg.val = 1;
    if((semctl(semid, 0, SETVAL, arg)) == -1){
        perror("semctl failed");
        exit(1);
    }


    // Runtime start
    start_time = time(NULL);

    // Create Socket for listen web browser
    if((socket_fd = socket(PF_INET, SOCK_STREAM, 0)) < 0)
    {
        printf("Server : Can't open stream socket\n");
        return 0;
    }
    // Initialize socket components
    bzero((char*)&server_addr, sizeof(server_addr));
    server_addr.sin_family = AF_INET;
    server_addr.sin_addr.s_addr = htonl(INADDR_ANY);
    server_addr.sin_port = htons(PORTNO);

    // Bind socketaddr to socket
    if(bind(socket_fd, (struct sockaddr *)&server_addr, sizeof(server_addr)) < 0){
        printf("Server : Can't bind local address\n");
        return 0;
    }
    // Listen Client request
    listen(socket_fd, 5);

    // Get client request
    while(1){
        struct in_addr inet_client_address;
        char tmp[BUFFSIZE] = {0,};
        char method[20] = {0,};
        char url[BUFFSIZE] = {0,};
        char host[BUFFSIZE] = {0,};

        // Accept client
        len = sizeof(client_addr);
        client_fd = accept(socket_fd, (struct sockaddr*)&client_addr, &len);
        // Accept error
        if(client_fd < 0){
            printf("Server : accept failed\n");
            return 0;
        } // end of if
        inet_client_address.s_addr = client_addr.sin_addr.s_addr;

        // Create child process
        pid_t pid = fork();
        if(pid < 0){    // Fork failed
            printf("Fork failed\n");
            close(client_fd);
            continue;
        } // end of if
        if(pid == 0){   // Child process
            // Handle http client request
            http_client_request(client_fd, inet_client_address, client_addr);
            close(client_fd);
            exit(0);
        } // end of if
        else{           // Parent process
            processcnt++;
            close(client_fd);
        } // end of if
    } // end of while
    // close socket
    close(socket_fd);
    return 0;
} // end of main

// Hashing function
char *sha1_hash(char *input_url, char *hashed_url){
    unsigned char hashed_160bits[20];
    char hashed_hex[41];
    int i;

    SHA1(input_url, strlen(input_url), hashed_160bits);

    for(i = 0; i < sizeof(hashed_160bits); i++)
            sprintf(hashed_hex + i * 2, "%02x", hashed_160bits[i]);

    strcpy(hashed_url, hashed_hex);

    return hashed_url;
}

// Get home directory
char *getHomeDir(char *home) {
	struct passwd *usr_info = getpwuid(getuid());
	strcpy(home, usr_info->pw_dir);

	return home;
}

// Fuction for http client request handling
void http_client_request(int client_fd, struct in_addr inet_client_address, struct sockaddr_in client_addr){
    char buf[BUFFSIZE];
    char tmp[BUFFSIZE] = {0,};
    char method[20] = {0,};
    char url[BUFFSIZE] = {0,};
    char host[BUFFSIZE] = {0,};
    char* path;
    char response_header[BUFFSIZE] = {0,};
    char response_message[2048] = {0,};
    char* IPAddr;
    char filedir[BUFFSIZE] = {0, };

    // Read data from client
    int read_len = read(client_fd, buf, BUFFSIZE);
    // Check if read == NULL
    if(read_len <= 0){
        close(client_fd);
        return;
    } // end of if

    // Log request data on console
    strcpy(tmp, buf);

    char* tok = strtok(tmp, " ");
    // Check tok error
    if(tok == NULL){
        close(client_fd);
        return;
    } // end of if
    // tok method from http
    strcpy(method, tok);

    // Ignore POST, HEAD, OPTIONS
    if(strcmp(method, "GET") != 0){
        close(client_fd);
        return;
    } // end of if

    // Ignore NULL url
    tok = strtok(NULL, " ");
    if(tok == NULL){
        close(client_fd);
        return;
    } // end of if
    strcpy(url, tok);
    printf("url = %s\n",url);

    if(strstr(url, "favicon.ico") != NULL){
        printf("Favicon request ignored.\n");
        close(client_fd);
        return;
    } // end of if
    if(strstr(url, "firefox.com") != NULL){
        printf("Firefox request ignored.\n");
        close(client_fd);
        return;
    } // end of if

    puts("============================");
    printf("[%s : %d] client was connected\n", inet_ntoa(inet_client_address), client_addr.sin_port);

    char *line = strtok(buf, "\r\n");  // 줄 단위로 쪼개기

    // Extract host from url
    while (line != NULL) {
        if (strncmp(line, "Host:", 5) == 0) {
            // "Host: " 다음 부분을 추출 (공백 포함 6글자 넘김)
            strncpy(host, line + 6, sizeof(host) - 1);
            host[strcspn(host, "\r\n")] = 0;
            break;
        } // end of if
        line = strtok(NULL, "\r\n");
    } // end of while

    // Set path
    path = strchr(url, '/');
    if(path != NULL){
        path = strchr(path + 3, '/');
    }
    if(path == NULL){
        path = "/";
    }
    printf("path : %s\n", path);

    // debug host tok
    printf("Extracted Host: %s\n", host);

    // get IP address
    IPAddr = getIPAddr(host);
    // Make cache files & Get hit flag
    int hitflag = SubProcess(client_fd, host, filedir);

    // HIT 
    if(hitflag == 1){          
        // Open file
        int fd = open(filedir, O_RDONLY);
        if(fd != -1){
            ssize_t n;
            char cachebuf[BUFFSIZE];
            // Read cache file
            while ((n = read(fd, cachebuf, BUFFSIZE)) > 0)
                write(client_fd, cachebuf, n);
            close(fd);
        } // end of if
    } // end of if
    // MISS
    else if(hitflag == 0){
        // Send request to http server
        send_http_with_timeout(host, path, client_fd, filedir);
    } // end of else if
    // Disconnected
    else{
        sprintf(response_message,"<h1>Disconnected</h1><br>");
    } // end of else
    // Log disconnection
    printf("[%s : %d] client was disconnected\n", inet_ntoa(inet_client_address), client_addr.sin_port);
    close(client_fd);
} // end of function

char* getIPAddr(char* addr){
    struct hostent* hent;
    char* haddr;
    int len = strlen(addr);

    if((hent = (struct hostent*)gethostbyname(addr)) != NULL)
    {
        haddr = inet_ntoa(*((struct in_addr*)hent->h_addr_list[0]));
    }
    return haddr;
}

// Function for sending http request to web server
int send_http_with_timeout(const char* host, const char* path, int client_fd, const char* filedir) {
    int sockfd;
    struct sockaddr_in server_addr;
    struct hostent* hp;
    char request[BUFFSIZE];
    char response[BUFFSIZE];
    int fd;

    // 1. get host by name
    if ((hp = gethostbyname(host)) == NULL) {
        perror("gethostbyname err");
        return -1;
    }

    // 2. Create server Socket
    if ((sockfd = socket(AF_INET, SOCK_STREAM, 0)) < 0) {
        perror("socket err");
        return -1;
    }

    // 3. Initialize server components
    memset(&server_addr, 0, sizeof(server_addr));
    server_addr.sin_family = AF_INET;
    memcpy(&server_addr.sin_addr.s_addr, hp->h_addr_list[0], hp->h_length);
    server_addr.sin_port = htons(80);

    // 4. set alarm
    alarm(10); // alarm after 10 sec


    // 5. connect to server
    if (connect(sockfd, (struct sockaddr*)&server_addr, sizeof(server_addr)) < 0) {
        perror("connect err");
        close(sockfd);
        return -1;
    }

    // 6. Write HTTP request and send
    snprintf(request, sizeof(request),
        "GET %s HTTP/1.0\r\n"
        "Accept: */*\r\n"
        "Accept-Language: ko\r\n"
        "User-Agent: Mozilla/4.0 (compatible; MSIE 6.0; Windows NT 5.0; Net CLR 1.1.4322)\r\n"
        "Host: %s\r\n"
        "Connection: close\r\n\r\n", path, host);

    // 7. Send requset to web server
    if (write(sockfd, request, strlen(request)) < 0) {
        // Send error
        perror("write err");
        close(sockfd);
        return -1;
    } // end of if

    // 8. Cache file handling
    fd = open(filedir, O_WRONLY | O_CREAT | O_TRUNC, 0777);
    if(fd < 0){
        perror("cache file open failed");
    }
    // Get data from web server
    int n;
    while((n = read(sockfd, response, BUFFSIZE)) > 0){
        write(client_fd, response, n);
        // write data to cache file
        if(fd >= 0)
            write(fd, response, n);
    }
    // Close file & server socket
    if(fd >= 0) close(fd);
    close(sockfd);
    alarm(0);       // Alarm reset
    return 0;
} // end of function

// Function to execute SubProcess
int SubProcess(int client_fd, char* url, char* filedir){
    // Url string
	char hashed_input[256];
	char dir_name[4];			// dir name (front 3)
	char cache_file[38];		// file name (left 37)
	
	// Dir
	DIR *dp = NULL;
	char basedir[256];			// root directory
	char subdir[300];			// directory (front 3 letters)
	//char filedir[350];			// directory (left 37 letters)
	
	// Umask enable
	mode_t old_umask;

	// RunTime
	time_t startTime = time(NULL);
	time_t endTime;
	int runTime;

    // Disconnect if received data is "bye"
    if(!strncmp(url, "bye", 3)){
        return 0;
    } // end of else if

    // Hashing url
    sha1_hash(url, hashed_input);

    // dir Name copy
    strncpy(dir_name, hashed_input, 3);
    dir_name[3] = '\0';
    // cache file name copy
    strcpy(cache_file, hashed_input + 3);
    cache_file[37] = '\0';
    
    // Get home path
    getHomeDir(basedir);
    
    // Make full path
    strcat(basedir, "/cache");
    
    // Check basedir exists
    dp = opendir(basedir);
    if(dp == NULL){
        // Disable umask
        old_umask = umask(0);
        // Check mkdir success (basedir)
        if(mkdir(basedir, 0777) == 0){
            printf("basedir created\n");
        } // end of if
        // Fail mkdir (basedir)
        else{
            perror("basedir mkdir failed");
        } // end of else
        // Return umask back
        umask(old_umask);
    } // end of if
    // Cache dir exists
    else{
        printf("basedir already exists\n");
    } // end of else
    // Close dir
    closedir(dp);

    // Cat dir_name to subdir
    strcpy(subdir, basedir);
    strcat(subdir, "/");
    strcat(subdir, dir_name);
    
    // Check subdir exists
    dp = opendir(subdir);
    if(dp == NULL){
        // Disable umask
        old_umask = umask(0);
        // Check mkdir success (subdir)
        if(mkdir(subdir, 0777) == 0){
            printf("subdir created\n");
        } // end of if
        else{
            // Fail mkdir (subdir)
            perror("subdir mkdir failed");
        } // end of else
        // Return umask back
        umask(old_umask);
    } // end of if
    else{
        printf("cache already exists\n");
    } // end of else
    // Close subdir
    closedir(dp);

    // Cat cache_file to filedir
    strcpy(filedir, subdir);
    strcat(filedir, "/");
    strcat(filedir, cache_file);

    // Check filedir exists & hit, miss 
    int hitflag = hit(subdir, dir_name, cache_file, url, client_fd);
    return hitflag;
} // end of function

// Function for check HIT
bool is_hit(const char *subdir, const char *cache_file){
	// Open subdir
	DIR *dir = opendir(subdir);
	struct dirent *entry;
	
	// Check dir open success
	if(dir == NULL){
		perror("open subdir failed\n");
		return false;
	} // end of if
	// Read files in subdir
	while((entry = readdir(dir)) != NULL){
		// Find (file name == cache_file)
		if(strcmp(entry->d_name, cache_file) == 0){
			closedir(dir);
			return true;	// Found file name (HIT)
		} // end of if
	} // end of while
	closedir(dir);
	return false;		    // Cannot find file name (MISS)
} // end of function

// Function for log HIT & MISS
int hit(const char *subdir, const char *dir_name, const char *cache_file, const char *url, int client_fd){
    char filedir[512];
    snprintf(filedir, sizeof(filedir), "%s/%s", subdir, cache_file);

    // Check hit or miss
    bool isHit = is_hit(subdir, cache_file);
    printf("%s\n", isHit ? "HIT" : "MISS");

    // Log with Thread
    LogArgs* args = malloc(sizeof(LogArgs));
    args->hit = isHit;
    strcpy(args->url, url);
    strcpy(args->dir_name, dir_name);
    strcpy(args->cache_file, cache_file);

    // Create thread
    pthread_t tid;
    pthread_create(&tid, NULL, LogFileThread, (void*)args);
    pthread_detach(tid);

    // Return hit flag
    return isHit ? 1 : 0;
} // end of function

// Function for log SubTerminate info
void Terminate (int* runtime, int* processcnt){
	// Make full path
	char home[256], logpath[512], logdir[512];
	getHomeDir(home);
	snprintf(logdir, sizeof(logdir), "%s/logfile", home);
	snprintf(logpath, sizeof(logpath), "%s/logfile/logfile.txt", home);
	
	// mkdir ~/logfile 
	mode_t old_umask = umask(0);
	if(opendir(logdir) == NULL){
		mkdir(logdir, 0777);
	} // end of if
	umask(old_umask);

	// Open logfile.txt
	FILE* fp = fopen(logpath, "a");
	if(fp != NULL){
		// Print SubTerminated sign
		fprintf(fp, "**SERVER** [Terminated] run time: %d sec. #sub process: %d\n", *runtime, *processcnt);
		// file close
		fclose(fp);
	} // end of if
	else{
		perror("logfile open failed");
	} // end of else
}

// Sigint handler
void sigint_handler(int signo){
    // Calculate runtime
    time_t end_time = time(NULL);
    int runtime = (int)(end_time - start_time);
    // Log terminate info
    Terminate(&runtime, &processcnt);
    printf("\n[Terminated] Run time: %d sec, #SubProcess: %d\n", runtime, processcnt);
    exit(0);
}
