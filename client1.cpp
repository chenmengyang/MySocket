#include <stdio.h>
#include <stdlib.h>
#include <netdb.h>
#include <netinet/in.h>
#include <unistd.h>
#include <string.h>
#include <iostream>
#include <assert.h>
#include <getopt.h>
#include <unistd.h>
#include <sys/types.h>
#include <sys/socket.h>
#include <errno.h>
#include <signal.h>

#include "mysocket.hh"
using namespace std;

#define MAX_RUNTIME 10  /* one hour in seconds */
static void watchdog(int signro)
{
  exit(signro);  /* process will exit when the timer signal arrives */
}

int main(int argc, char *argv[])
{
   if( signal(SIGALRM, watchdog) == SIG_ERR )
   {
	   exit(2); /* something went wrong in setting signal */
   }
   alarm( MAX_RUNTIME );

   int sockfd_tcp;
   struct sockaddr_in serv_addr;
   struct sockaddr_in6 serv_addr6;
   struct hostent *server;
   string server_name;

   // parse the command line arguments
   static struct option long_options[] =
   {
       {"debug",      no_argument,       0,  'd' },
       {"normal",     no_argument,       0,  'n' },
	   {"server",     required_argument, 0,  's' },
       {"port",       required_argument, 0,  'p' },
	   {"user",       required_argument, 0,  'u' },
	   {"pwd",        required_argument, 0,  'w' },
	   {"query",      required_argument, 0,  'q' },
	   {"ipv6",       no_argument,       0,  '6' },
       {0,            0,                 0,  0}
   };

   int opt= 0;
   int long_index =0;
   string mode;
   int portno;
   string user_name;
   string pwd;
   string query;
   char ipv='4';
   while ((opt = getopt_long_only(argc, argv,"",long_options, &long_index )) != -1)
   {
       switch (opt)
       {
            case 'd' : mode = "D";
                break;
            case 'n' : mode = "1";
                break;
            case 's' : server = gethostbyname(optarg); server_name = optarg;
                break;
            case 'p' : portno = atoi(optarg);
                break;
            case 'u' : user_name = optarg;
                break;
            case 'w' : pwd = optarg;
                break;
            case 'q' : query = optarg;
                break;
            case '6' : ipv = '6';
                break;
            default: printf("Usage: client --server 127.0.0.1 --port 12345 --user Name --pwd 123456 --[debug/normal] --[ipv6]\n");
                exit(EXIT_FAILURE);
       }
   }
   
   // set default mode to normal(Auth1)
   if(mode=="") mode="1";

   /* Create a socket point */
   if(ipv=='4')
   {
	   sockfd_tcp = socket(AF_INET, SOCK_STREAM, 0);
	   if (sockfd_tcp < 0)
	   {
	      perror("ERROR opening socket");
	      exit(1);
	   }
	   //
	   bzero((char *) &serv_addr, sizeof(serv_addr));
	   serv_addr.sin_family = AF_INET;
	   bcopy((char *)server->h_addr, (char *)&serv_addr.sin_addr.s_addr, server->h_length);
	   serv_addr.sin_port = htons(portno);
	   /* Now connect to the server */
	   if (connect(sockfd_tcp, (struct sockaddr*)&serv_addr, sizeof(serv_addr)) < 0)
	   {
	      perror("ERROR connecting ipv4");
	      exit(1);
	   }
   }
   else
   {
	   sockfd_tcp = socket(PF_INET6, SOCK_STREAM, 0);
	   if (sockfd_tcp < 0)
	   {
	      perror("ERROR opening socket");
	      exit(1);
	   }
	   //
	   bzero((char *) &serv_addr6, sizeof(serv_addr6));
	   serv_addr6.sin6_family = AF_INET6;
	   bcopy((char *)server->h_addr, (char *)&serv_addr6.sin6_addr, server->h_length);
	   serv_addr6.sin6_port = htons(portno);
	   serv_addr6.sin6_addr = in6addr_any;
	   /* Now connect to the server */
	   if (connect(sockfd_tcp, (struct sockaddr*)&serv_addr6, sizeof(serv_addr6)) < 0)
	   {
	      perror("ERROR connecting ipv6");
	      exit(1);
	   }
   }
   /*create a tcp message and serialize it into buffer*/
   string cmd = "T1" + to_string(user_name.size()) + user_name;
   tcp_message m1 = tcp_message(mode,cmd);
   /* Send user name to the server */
   writen_tcp(sockfd_tcp,m1);
   /* Now read the randomly generated number from server */
   string R = readn_tcp(sockfd_tcp);
   if(R=="")
   {
	   cout<<"User not exist!"<<endl;
	   return 0;
   }

   tcp_message m2 = unserialize_string(R);
   uint32_t r1 = stoll(m2.get_command());
   uint32_t r2 = ntohl(stoll(m2.get_command()));
   string c_pwd = pwd+to_string(r1);
   /* Send password to the server */
   string H1;
   if(mode=="D") H1="xxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxx";
   else H1 = calcSHA256(c_pwd.c_str(),r2);
   // define a new message and send to the server for verification
   tcp_message m3 = tcp_message(mode,"T3"+H1);
   writen_tcp(sockfd_tcp,m3);

   // read the verification result(sid) from the server.
   char * buf3 = readn_tcp(sockfd_tcp);
   tcp_message m4 = unserialize_string(buf3);
   int sid = ntohl(atoi(m4.get_command().c_str()));

   if(sid==654321 and mode!="D")
   {
	   cout<<"Password incorrect, connection failed!"<<endl;
	   return 0;
   }
   else if(sid==654321 and mode=="D" and m4.get_protocal_mode()!="D")
   {
	   cout<<"Connecting to a non-debug mode server using a debug mode client, failed!"<<endl;
	   return 0;
   }
   else cout<<"Connected to the server. Sid is:"<<sid<<endl;
   // close tcp and change to udp now
   close(sockfd_tcp);

   // define UPD client
   struct addrinfo hints, *serverinfo;
   // query the remote end information
   memset(&hints, 0, sizeof(hints));
   if(ipv=='6') hints.ai_family = AF_INET6;
   else hints.ai_family = AF_INET;
   hints.ai_socktype = SOCK_DGRAM;
   int rv = getaddrinfo(server_name.c_str(), to_string(portno).c_str(), &hints, &serverinfo );
   if( rv < 0 ) perror("getaddrinfo()");
   int sockfd_udp = socket( serverinfo->ai_family,
						    serverinfo->ai_socktype,
							serverinfo->ai_protocol);
   if( sockfd_udp < 0 ) perror("socket()");
   // define a UPD-query packet
   int tid = rand() % 9000 + 1000;
   udp_query_packet packet1 = udp_query_packet(mode,sid,tid,query,c_pwd);
   // send the UDP query packet to server (each field one by one)
   int x1 = sendto(sockfd_udp,packet1.direction.c_str(),1,0,serverinfo->ai_addr, serverinfo->ai_addrlen);
   if(x1<0) {perror("sendto"); return 0;}
   int x2 = sendto(sockfd_udp,packet1.version.c_str(),1,0,serverinfo->ai_addr, serverinfo->ai_addrlen);
   if(x2<0) {perror("sendto"); return 0;}
   int x3 = sendto(sockfd_udp,(char *)&packet1.length,sizeof(uint16_t),0,serverinfo->ai_addr, serverinfo->ai_addrlen);
   if(x3<0) {perror("sendto"); return 0;}
   int x4 = sendto(sockfd_udp,(char *)&packet1.sid,sizeof(uint32_t),0,serverinfo->ai_addr, serverinfo->ai_addrlen);
   if(x4<0) {perror("sendto"); return 0;}
   int x5 = sendto(sockfd_udp,(char *)&packet1.tid,sizeof(uint32_t),0,serverinfo->ai_addr, serverinfo->ai_addrlen);
   if(x5<0) {perror("sendto"); return 0;}
   int x6 = sendto(sockfd_udp,(char *)&packet1.query_length,sizeof(uint16_t),0,serverinfo->ai_addr, serverinfo->ai_addrlen);
   if(x6<0) {perror("sendto"); return 0;}
   int x7 = sendto(sockfd_udp,packet1.query_word.c_str(),packet1.query_word.size(),0,serverinfo->ai_addr, serverinfo->ai_addrlen);
   if(x7<0) {perror("sendto"); return 0;}
   int x8 = sendto(sockfd_udp,(char *)&packet1.maclen,sizeof(uint16_t),0,serverinfo->ai_addr, serverinfo->ai_addrlen);
   if(x8<0) {perror("sendto"); return 0;}
   int x9 = sendto(sockfd_udp,packet1.HMAC_SHA256.c_str(),packet1.HMAC_SHA256.size(),0,serverinfo->ai_addr, serverinfo->ai_addrlen);
   if(x9<0) {perror("sendto"); return 0;}

   // receive the result from server
   struct sockaddr_storage a1,a2,a3;
   socklen_t l1 = sizeof( a1 );
   socklen_t l2 = sizeof( a2 );
   socklen_t l3 = sizeof( a3 );
   uint32_t time1;
   uint16_t len1;
   int n1 = recvfrom(sockfd_udp,(char *)&time1,sizeof(uint32_t),0,
   		   (struct sockaddr*)&a1, &l1);
   if(n1<0) {cout<<"error receive time"; return 0;}
   else cout<<"Timestamp:"<<ntohl(time1)<<endl;
   int n2 = recvfrom(sockfd_udp,(char *)&len1,sizeof(uint16_t),0,
   		   (struct sockaddr*)&a2, &l2);
   if(n2<0) {cout<<"error receive len1"; return 0;}
   int len2 = ntohs(len1);
   const size_t BUFSIZE1 = len2;
   char *buf1 = new char[BUFSIZE1];
   int n3 = recvfrom(sockfd_udp,buf1,BUFSIZE1,0,
   		   (struct sockaddr*)&a3, &l3);
   if(n3<0) {cout<<"error receive buf1"; return 0;}
   // make sure the data is null-terminated and print it out
   buf1[n3] = '\0';
   printf("%d bytes data:'%s'\n", n3, buf1 );
   // dynamic list-return-value has to be free-ed in our code:
   freeaddrinfo( serverinfo );
   return 0;
}