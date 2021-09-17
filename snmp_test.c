/*
 
The MIT License (MIT)
Copyright (c) 2021 Alexander Zazhigin mykeich@yandex.ru
Permission is hereby granted, free of charge, to any person obtaining a copy
of this software and associated documentation files (the "Software"), to deal
in the Software without restriction, including without limitation the rights
to use, copy, modify, merge, publish, distribute, sublicense, and/or sell
copies of the Software, and to permit persons to whom the Software is
furnished to do so, subject to the following conditions:
The above copyright notice and this permission notice shall be included in all
copies or substantial portions of the Software.
THE SOFTWARE IS PROVIDED "AS IS", WITHOUT WARRANTY OF ANY KIND, EXPRESS OR
IMPLIED, INCLUDING BUT NOT LIMITED TO THE WARRANTIES OF MERCHANTABILITY,
FITNESS FOR A PARTICULAR PURPOSE AND NONINFRINGEMENT. IN NO EVENT SHALL THE
AUTHORS OR COPYRIGHT HOLDERS BE LIABLE FOR ANY CLAIM, DAMAGES OR OTHER
LIABILITY, WHETHER IN AN ACTION OF CONTRACT, TORT OR OTHERWISE, ARISING FROM,
OUT OF OR IN CONNECTION WITH THE SOFTWARE OR THE USE OR OTHER DEALINGS IN THE
SOFTWARE.
*/

#include <stdio.h>
#include <stdlib.h>
#include <sys/types.h>
#include <sys/socket.h>
#include <string.h>
#include <netinet/in.h>
#include <time.h>
#include <sys/mman.h>
#include <sys/wait.h>



#define PORT 53265



/* Create UDP socket and another data*/
int createUdpSocket(){
    int udpsocket = 0;
    //open socket
    if((udpsocket= socket(AF_INET, SOCK_DGRAM, 0)) == -1){
        fprintf(stderr,"Exit: createUdpSocket: Can't open socket\n");
        return 0;
    }

    struct sockaddr_in si_me;
    memset((char *) &si_me, 0, sizeof(si_me));

    si_me.sin_family = AF_INET;
    si_me.sin_port = htons(PORT);
    si_me.sin_addr.s_addr = htonl(INADDR_ANY);
    //bind socket to port
    if( bind(udpsocket, (struct sockaddr*)&si_me, sizeof(si_me) ) == -1)
    {
        fprintf(stderr,"Exit: createUdpSocket: Can't bind port %i  \n",PORT);
        close(udpsocket);
        return 0;
    }

    int Enable=1;
    if(setsockopt(udpsocket , SOL_SOCKET, SO_BROADCAST, &Enable, sizeof(Enable))==-1){
        fprintf(stderr,"Exit: createUdpSocket: Can't set broadcast option\n");
        close(udpsocket);
        return 0;
    }

    int buffsize = 3 *1024 * 1024;
    if (setsockopt(udpsocket, SOL_SOCKET, SO_RCVBUF, &buffsize, sizeof(buffsize)) == -1) {
        fprintf(stderr,"Can't increase buffer size. Live with the default size.\n");
    }

    //Set timeout read socket
    struct timeval tv;
    tv.tv_sec = 0;
    tv.tv_usec = 100000;
    if (setsockopt(udpsocket, SOL_SOCKET, SO_RCVTIMEO,&tv,sizeof(tv)) < 0) {
        fprintf(stderr,"Exit: createUdpSocket: Can't set socket recv timeout");
        close(udpsocket);
        return 0;
    }
    return udpsocket;
}

unsigned char header[] = {
0x30, //Sequence of Sequence
0x00, // packet leght
// SNMP Version
0x02, // Type integer
0x01, // length
0x01, // snmpv2c
//Community
0x04,
};

//OPID sysDesr
unsigned char oid[] = {
0xa0,
0x1c,
0x02,
0x04,
0x3f,
0x81,
0x3f,
0x8d,
0x02,
0x01,
0x00,
0x02,
0x01,
0x00,
0x30,
0x0e,
0x30,
0x0c,
0x06,
0x08,
0x2b,
0x06,
0x01,
0x02,
0x01,
0x01,
0x01,
0x00,
0x05,
0x00
};

#define PACKET_LENGHT_POS  1

#define MAXSIZE_ARRAY 2
#define MAXSIZE_HOSTNAME 256
#define MAXSIZE_COMMUNITY 64

char *get_ip_str(const struct sockaddr *sa, char *s, size_t maxlen){
    switch(sa->sa_family) {
        case AF_INET:
            inet_ntop(AF_INET, &(((struct sockaddr_in *)sa)->sin_addr),
                s, maxlen);
            break;

        case AF_INET6:
            inet_ntop(AF_INET6, &(((struct sockaddr_in6 *)sa)->sin6_addr),
                s, maxlen);
            break;

        default:
            strncpy(s, "Unknown AF", maxlen);
            return NULL;
    }
    return s;
}




void sendsnmp(int udpsocket, char * host,char * comm){
    struct sockaddr_in to;
    int to_len = sizeof(struct sockaddr_in);
    memset(&to, 0, sizeof(to));
    to.sin_addr.s_addr = inet_addr(host);
    to.sin_family = AF_INET;
    to.sin_port   = htons(161);
    unsigned char data[1000];
    unsigned char *pdata = data;
    memset(data,0,sizeof(data));
    memcpy(pdata,header,sizeof(header));
    pdata += sizeof(header);
    // check size ?
    unsigned char comm_length = strlen(comm);
    *pdata = comm_length;
    pdata++;
    memcpy(pdata,comm,comm_length);
    pdata += comm_length;
    unsigned char oid_len = sizeof(oid);
    memcpy(pdata,oid,oid_len);
    //set packet size
    unsigned char data_size = oid_len + pdata - data ;
    data[PACKET_LENGHT_POS] = data_size - 2;

    int err = sendto(udpsocket,(void *)data,data_size,0,(struct sockaddr *)&to,to_len);
    if(err < 0){
        fprintf(stderr,"Error send UDP to %s Err=%d\n",host,err);
    }
}

int readFile(int udpsocket,char * filename){
    FILE * fp;
    char * line = NULL;
    size_t len = 0;
    ssize_t read;
    fp = fopen(filename, "r");
    if (fp == NULL){
        fprintf(stderr,"File %s not found.\n",filename);
        return 1;
    }
    int num = 0;
    while ((read = getline(&line, &len, fp)) != -1) {
        //hack to overflow socket buffer
        if((num % 1000) == 999){
            sleep(1);
        }
        if(line[read-1]=='\n'){
            line[read-1] = '\0';
        }
        char * host = strtok (line," ");
        char * comm = strtok (NULL, " ");
        if(host == NULL || comm == NULL){
            fprintf(stderr,"Wrong input line",line);
            continue;
        }
        sendsnmp(udpsocket,host,comm);
       num++;
    }
    fclose(fp);
    if (line){
        free(line);
    }
    return 0;
}

#define TIMEOUT 5

int timetoexit = 0;
void child_trap(int sig) {
    timetoexit = 1;
}
void recvsnmp(int udpsocket){
    struct sockaddr_in si;
    memset(&si,0,sizeof(si));
    int si_len = sizeof(si);
    unsigned char data[1000];
    char str[100];
    int len = 0;
    while(!timetoexit){
        len = recvfrom(udpsocket, data, 1000, 0, (struct sockaddr *)&si, &si_len);
        if(len > 0){
            char *host = get_ip_str((struct sockaddr *)&si,str,100);
            if(host != NULL){
                printf("%s|true\n",host);
            }
        }
    }
}
int main(int argc, char ** argv){
    char * filename = NULL;
    int timeout = 20;
    if(argc == 2){
        filename = argv[1];
    }else if(argc == 4 && argv[1][0] == '-' && argv[1][1] == 't' ){
       timeout = atoi(argv[2]);
       filename = argv[3];
    }else{
        printf("Usage: snmp_test file.name\n       snmp_test_ -t seconds file.name\nfile.name - file then contain ip and community lines.\nseconds - how long wait answerts from hosts.\n");
        exit(EXIT_FAILURE);
    }
    int exitstatus = EXIT_SUCCESS;
    int udpsocket = createUdpSocket();
    siginfo_t   siginfo;
    int pid = fork();
    if(pid < 0){
        fprintf(stderr,"Error fork\n");
        exitstatus = EXIT_FAILURE;
    } else if(pid == 0){
        signal(SIGINT, &child_trap);
        recvsnmp(udpsocket);
    } else{
        if( readFile(udpsocket,filename) ){
            exitstatus = EXIT_FAILURE;
        }else{
            sleep(timeout);
        }
        kill(pid, SIGINT);
    }
    int status = 0;
    while ( wait(&status) > 0);
    close(udpsocket);
    return exitstatus;
}
