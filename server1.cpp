#include <stdio.h>
#include <stdlib.h>
#include <unistd.h>
#include <netdb.h>
#include <netinet/in.h>
#include <iostream>
#include <string.h>
#include <iostream>
#include <fstream>
#include <sstream>
#include <assert.h>
#include <getopt.h>
#include <unistd.h>
#include <sys/types.h>
#include <sys/socket.h> /* socket routines */
#include <netinet/in.h> /* inetaddr */
#include <arpa/inet.h>  /* inet_pton() */
#include <errno.h>
#include <signal.h>

#include "curl/curl.h"
#include "json.hpp"
using json = nlohmann::json;

#include "mysocket.hh"
using std::cout;
using std::endl;
using std::string;
using std::ifstream;
using std::getline;

#define MAX_RUNTIME 60*60  /* one hour in seconds */
static void watchdog(int signro)
{
  exit(signro);  /* process will exit when the timer signal arrives */
}

// check whether the user exist or not.
bool verify_user(string mode,int sock,string &pwd,uint32_t &r)
{
   char * buffer = readn_tcp(sock);
   // unserialize the information to a tcp message
   tcp_message m1 = unserialize_string(buffer);
   string username = m1.get_command();
   printf("Requesting user name: %s\n",username.c_str());
   ifstream file("server.txt");
   string line = "";
   while(getline(file,line))
   {
		string name;
		istringstream linestream(line);
		getline(linestream,name,',');
		// b.erase(b.find_last_not_of(" \n\r\t")+1)
		if(name==username)
		{
			getline(linestream,pwd,',');
			// if user exist, generate a random number and sent to the server.
			if(mode=="D") r=123456;
			else r = getrandomint();
			// convert to network byte order
			uint32_t r1 = htonl(r);
			string R =to_string(r1);
			// define T2 message and tranfer to client.
			tcp_message m2 = tcp_message(mode,"T2"+R);
			//write(sock,m2.serialize_msg().c_str(),m2.get_msg_length());
			writen_tcp(sock,m2);
			return true;
		}
   }
   return false;
}

//verify whether the input password right or wrong. By comparing the hash code.
//close the current tcp socket, and create a udp socket and wait for query.
bool verify_passwd(string mode,int sock,string &pwd,uint32_t &r,const int &portno,char &ip)
{
   char *buffer = readn_tcp(sock);
   // convert the buffer into tcp message
   tcp_message m3 = unserialize_string(buffer);
   string H1 = m3.get_command();
   // concatenate password with random number
   //string c_pwd = pwd + to_string(htonl(r));
   pwd += to_string(htonl(r));
   string H2;
   if(mode=="D") H2="xxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxx";
   else H2 = calcSHA256(pwd.c_str(),r);
   if(H1==H2)
   {
	   srand(time(NULL));
	   int sid;
	   if(mode=="D") sid=654321;
	   else sid = rand() % 9000 + 1000;
	   // define tcp message and send to client
	   tcp_message m4 = tcp_message(mode,"T4"+to_string(htonl(sid))+'0');
	   //write(sock,succeed,1);
	   struct addrinfo hints, *serverinfo;
	   memset(&hints, 0, sizeof(hints));
	   if(ip=='6') hints.ai_family = AF_INET6;
	   else hints.ai_family = AF_INET;
	   hints.ai_socktype = SOCK_DGRAM;
	   hints.ai_flags = AI_PASSIVE;
	   int rv = getaddrinfo(NULL, to_string(portno).c_str(), &hints, &serverinfo );
	   if( rv < 0 ) perror( "getaddrinfo()" );
		 // try using the first returned value:
	   int sockfd_udp = socket(serverinfo->ai_family,
							   serverinfo->ai_socktype,
							   serverinfo->ai_protocol );
	   if( sockfd_udp < 0 ) perror("socket()");
	   // bind listening information and start accepting packet
	   rv = bind(sockfd_udp, serverinfo->ai_addr,serverinfo->ai_addrlen);
	   if( rv < 0 ) perror("bind()");
		 // free the dynamic return value
	   freeaddrinfo(serverinfo);
	   //write(sock,m4.serialize_msg().c_str(),m4.get_msg_length());
	   writen_tcp(sock,m4);
	   close(sock);
	   return true;
   }
   else
   {
	   cout<<"Incorrect pwd!!"<<endl;
	   tcp_message m4 = tcp_message(mode,"T4"+to_string(htonl(654321))+"3");
	   writen_tcp(sock,m4);
	   //write(sock,m4.serialize_msg().c_str(),m4.get_msg_length());
	   return false;
   }
   return false;
}

static std::unique_ptr< std::string > collector;
static size_t GetData(void* data, size_t size, size_t n, void* )
{
    auto totalSize = size * n;
    collector->append( static_cast<char*>(data), totalSize );
    return totalSize;
}

std::string get_result(const char *query_str)
{
	std::string URL = "http://api.duckduckgo.com/?format=json";
	URL += "&no_html=1&skip_disambig=1&q=";
	auto curl = curl_easy_init();
	if( curl )
	{
		char* ESCword = nullptr;
		ESCword = curl_easy_escape(curl, query_str, 0 );
		if(ESCword == nullptr)
		{
			std::cerr << "word escape failed" << std::endl;
			exit(1);
		}
		URL += std::string( ESCword );
        collector = std::make_unique< std::string >();
        curl_easy_setopt(curl, CURLOPT_URL, URL.c_str() );
        curl_easy_setopt(curl, CURLOPT_FOLLOWLOCATION, 1L);
        curl_easy_setopt(curl, CURLOPT_WRITEFUNCTION, GetData );
        auto res = curl_easy_perform(curl);
		if( res != CURLE_OK )
		{
			std::cerr << "curl error "
					  << curl_easy_strerror(res) << std::endl;
		}
		curl_easy_cleanup(curl);
		curl_free(ESCword);
		auto jdata = json::parse( *collector );
		std::string result = "NOT FOUND";
		if( jdata["Abstract"] != "" ) result = jdata["Abstract"];
		else if( jdata["Definition"] != "" ) result = jdata["Definition"];
		else if( jdata["Answer"] != "" ) result = jdata["Answer"];
		else
		{
			auto r = jdata["RelatedTopics"];
			for( auto& i : r ) {
				if( i["Text"] != "" ) {
					result = i["Text"];
					break;
				}
			}
		}
		return result;
	}
	else
	{
		return "curl init failed.";
	}
}

int main( int argc, char *argv[] ) {

   if( signal(SIGALRM, watchdog) == SIG_ERR )
   {
	   exit(2); /* something went wrong in setting signal */
   }
   alarm( MAX_RUNTIME );
   int sockfd, newsockfd;
   unsigned int clilen;
   int pid;

   //Specifying the expected options, the port argument expect an number
   //use getopt to read the port number from command line
   static struct option long_options[] = {
       {"debug",      no_argument,       0,  'd' },
       {"normal",     no_argument,       0,  'n' },
	   {"concurrency",no_argument,       0,  'c' },
       {"port",       required_argument, 0,  'p' },
	   {"ipv6",       no_argument,       0,  '6' },
       {0,            0,                 0,  0}
   };

   char ipv='4';
   int opt= 0;
   int long_index =0;
   string mode;
   int portno; //= 41492;
   while ((opt = getopt_long_only(argc, argv,"",long_options, &long_index )) != -1)
   {
       switch (opt)
       {
            case 'd' : mode = "D";
                break;
            case 'n' : mode = "1";
                break;
            case 'c' : mode = "C";
            	break;
            case 'p' : portno = atoi(optarg);
                break;
            case '6' : ipv = '6';
            	break;
            default: printf("Usage: server --port 12345 --[debug/normal/authN] [--ipv6]\n");
                exit(EXIT_FAILURE);
       }
   }
   
   // Set default mode to normal
   if(mode=="") mode="1";

   // ipv4 or ipv6
   struct sockaddr_in serv_addr;
   struct sockaddr cli_addr;
   struct sockaddr_in6 serv_addr6, cli_addr6;

   /* First call to socket() function */
   if(ipv=='4')
   {
	   sockfd = socket(AF_INET, SOCK_STREAM, 0);
	   if (sockfd < 0)
	   {
	      perror("ERROR opening socket");
	      exit(1);
	   }
	   /* Initialize socket structure */
	   bzero((char *) &serv_addr, sizeof(serv_addr));
	   serv_addr.sin_family = AF_INET;
	   serv_addr.sin_addr.s_addr = INADDR_ANY;
	   serv_addr.sin_port = htons(portno);
	   /* Now bind the host address using bind() call.*/
	   if (bind(sockfd, (struct sockaddr *) &serv_addr, sizeof(serv_addr)) < 0)
	   {
	      perror("ERROR on binding");
	      exit(1);
	   }
	   clilen = sizeof(cli_addr);
   }
   else
   {
	   sockfd = socket(PF_INET6, SOCK_STREAM, 0);
	   if (sockfd < 0)
	   {
	      perror("ERROR opening socket");
	      exit(1);
	   }
	   /* Initialize socket structure */
	   bzero((char *) &serv_addr6, sizeof(serv_addr6));

	   serv_addr6.sin6_family = AF_INET6;
	   serv_addr6.sin6_addr = in6addr_any;
	   serv_addr6.sin6_port = htons(portno);
	   /* Now bind the host address using bind() call.*/
	   if (bind(sockfd, (struct sockaddr *) &serv_addr6, sizeof(serv_addr6)) < 0)
	   {
	      perror("ERROR on binding");
	      exit(1);
	   }
	   clilen = sizeof(cli_addr6);
   }

   /* Now start listening for the clients, here
      * process will go in sleep mode and will wait
      * for the incoming connection
   */

   listen(sockfd,128);

   // concurrency
   if(mode=="C")
   {
	   while (1) {
		  if(ipv=='4') newsockfd = accept(sockfd, (struct sockaddr *) &cli_addr, &clilen);
		  else newsockfd = accept(sockfd, (struct sockaddr *) &cli_addr6, &clilen);
		  if (newsockfd < 0)
		  {
			 perror("ERROR on accept");
			 exit(1);
		  }

		  /* Create child process for supporting concurrency */
		  pid = fork();
		  if(pid<0)
		  {
			  perror("ERROR on fork");
			  exit(1);
		  }
		  if (pid==0)
		  {
			  /* This is the client process */
			  close(sockfd);
			  string passwd="";
			  uint32_t r;
			  if(verify_user(mode,newsockfd,passwd,r))
			  {
				  if(verify_passwd(mode,newsockfd,passwd,r,portno,ipv))
				  {

					  // reserve space for return values (recvfrom)
					  string direction,version,word,HMAC;
					  char dir[2];
					  char ver[2];
					  uint16_t len1,len2,len3;
					  uint32_t sid,tid;
					  // now receive 9 fields one by one
					  struct sockaddr_storage a1,a2,a3,a4,a5,a6,a7,a8,a9;
					  socklen_t addr_len1 = sizeof( a1 );
					  socklen_t addr_len2 = sizeof( a2 );
					  socklen_t addr_len3 = sizeof( a3 );
					  socklen_t addr_len4 = sizeof( a4 );
					  socklen_t addr_len5 = sizeof( a5 );
					  socklen_t addr_len6 = sizeof( a6 );
					  socklen_t addr_len7 = sizeof( a7 );
					  socklen_t addr_len8 = sizeof( a8 );
					  socklen_t addr_len9 = sizeof( a9 );
					  int x1 = recvfrom(sockfd,dir,1,0,(struct sockaddr*)&a1,&addr_len1);
					   dir[x1] = '\0';
					   int x2 = recvfrom(sockfd,ver,1,0,(struct sockaddr*)&a2,&addr_len2);
					   ver[x2] = '\0';
					   int x3 = recvfrom(sockfd,(char *)&len1,sizeof(uint16_t),0,(struct sockaddr*)&a3,&addr_len3);
					   if(x3<0) perror("recvfrom(");
					   int x4 = recvfrom(sockfd,(char *)&sid,sizeof(uint32_t),0,(struct sockaddr*)&a4,&addr_len4);
					   if(x4<0) perror("recvfrom(");
					   int x5 = recvfrom(sockfd,(char *)&tid,sizeof(uint32_t),0,(struct sockaddr*)&a5,&addr_len5);
					   if(x5<0) perror("recvfrom(");
					   int x6 = recvfrom(sockfd,(char *)&len2,sizeof(uint16_t),0,(struct sockaddr*)&a6,&addr_len6);
					   if(x6<0) perror("recvfrom(");
					  int query_len = ntohs(len2);
					  char *query_word=new char[query_len];
					  int x7 = recvfrom(sockfd,query_word,query_len,0,(struct sockaddr*)&a7,&addr_len7);
					  query_word[x7] = '\0';
					  int x8 = recvfrom(sockfd,(char *)&len3,sizeof(uint16_t),0,(struct sockaddr*)&a8,&addr_len8);
					  if(x8<0) perror("recvfrom(");
					  int maclen = ntohs(len3);
					  char *HMAC_SHA256=new char[maclen];
					  int x9 = recvfrom(sockfd,HMAC_SHA256,maclen,0,(struct sockaddr*)&a9,&addr_len9);
					  HMAC_SHA256[x9] = '\0';
					  // check signature
					  direction = dir;
					  version = ver;
					  word = query_word;
					  HMAC = HMAC_SHA256;
					  string con = direction+version+to_string(len1)+to_string(sid)+
							  to_string(tid)+to_string(len2)+word;
					  string Server256 = HMACSHA256((uint8_t*)(con.c_str()),con.size(),passwd.c_str());
					  if(Server256==HMAC)
					  {
						  // define a reply packet and send back to client
						  string k = get_result(query_word);
						  udp_reply_packet p2 = udp_reply_packet(mode,ntohl(sid),ntohl(tid)+1,k,passwd);
						   // send timestamp and query result back to cilent
						   int n1 = sendto(sockfd,(char *)&p2.timestamp,sizeof(uint32_t),0,(struct sockaddr*)&a9,addr_len9);
						   if(n1<0) perror("sendto");
						   int n2 = sendto(sockfd,(char *)&p2.reply_length,sizeof(uint16_t),0,(struct sockaddr*)&a9,addr_len9);
						   if(n2<0) perror("sendto");
						   int n3 = sendto(sockfd,p2.reply_string.c_str(),p2.reply_string.size(),0,(struct sockaddr*)&a9,addr_len9);
						   if(n3<0) perror("sendto");
					  }
					  else
					  {
						  cout<<"Signature failed!"<<endl;
						  exit(0);
					  }
				  }
				  else cout<<"Password incorrect!"<<endl;
			  }
			  exit(0);
		  }
		  else
		  {
			  close(newsockfd);
		  }
	   } /* end of while */
   }
   else
   {
	   if(ipv=='4') newsockfd = accept(sockfd, (struct sockaddr *) &cli_addr, &clilen);
	   else newsockfd = accept(sockfd, (struct sockaddr *) &cli_addr6, &clilen);
	   if (newsockfd < 0)
	   {
		   perror("ERROR on accept");
		   exit(1);
	   }
	   close(sockfd);
	   string passwd="";
	   uint32_t r;
	   if(verify_user(mode,newsockfd,passwd,r))
	   {
		   if(verify_passwd(mode,newsockfd,passwd,r,portno,ipv))
		   {
			   string direction,version,word,HMAC;
			   char dir[2];
			   char ver[2];
			   uint16_t len1,len2,len3;
			   uint32_t sid,tid;
			   // now receive 9 fields one by one
			   struct sockaddr_storage a1,a2,a3,a4,a5,a6,a7,a8,a9;
			   socklen_t addr_len1 = sizeof( a1 );
			   socklen_t addr_len2 = sizeof( a2 );
			   socklen_t addr_len3 = sizeof( a3 );
			   socklen_t addr_len4 = sizeof( a4 );
			   socklen_t addr_len5 = sizeof( a5 );
			   socklen_t addr_len6 = sizeof( a6 );
			   socklen_t addr_len7 = sizeof( a7 );
			   socklen_t addr_len8 = sizeof( a8 );
			   socklen_t addr_len9 = sizeof( a9 );
			   int x1 = recvfrom(sockfd,dir,1,0,(struct sockaddr*)&a1,&addr_len1);
			   dir[x1] = '\0';
			   int x2 = recvfrom(sockfd,ver,1,0,(struct sockaddr*)&a2,&addr_len2);
			   ver[x2] = '\0';
			   int x3 = recvfrom(sockfd,(char *)&len1,sizeof(uint16_t),0,(struct sockaddr*)&a3,&addr_len3);
			   if(x3<0) perror("recvfrom(");
			   int x4 = recvfrom(sockfd,(char *)&sid,sizeof(uint32_t),0,(struct sockaddr*)&a4,&addr_len4);
			   if(x4<0) perror("recvfrom(");
			   int x5 = recvfrom(sockfd,(char *)&tid,sizeof(uint32_t),0,(struct sockaddr*)&a5,&addr_len5);
			   if(x5<0) perror("recvfrom(");
			   int x6 = recvfrom(sockfd,(char *)&len2,sizeof(uint16_t),0,(struct sockaddr*)&a6,&addr_len6);
			   if(x6<0) perror("recvfrom(");
			   int query_len = ntohs(len2);
			   char *query_word=new char[query_len];
			   int x7 = recvfrom(sockfd,query_word,query_len,0,(struct sockaddr*)&a7,&addr_len7);
			   query_word[x7] = '\0';
			   int x8 = recvfrom(sockfd,(char *)&len3,sizeof(uint16_t),0,(struct sockaddr*)&a8,&addr_len8);
			   if(x8<0) perror("recvfrom(");
			   int maclen = ntohs(len3);
			   char *HMAC_SHA256=new char[maclen];
			   int x9 = recvfrom(sockfd,HMAC_SHA256,maclen,0,(struct sockaddr*)&a9,&addr_len9);
			   HMAC_SHA256[x9] = '\0';
			   // check signature
			   direction = dir;
			   version = ver;
			   word = query_word;
			   HMAC = HMAC_SHA256;
			   string Server256;
			   if(mode!="D")
			   {
				   string con = direction+version+to_string(len1)+to_string(sid)+
						   to_string(tid)+to_string(len2)+word;
				   Server256 = HMACSHA256((uint8_t*)(con.c_str()),con.size(),passwd.c_str());
			   }
			   else Server256="X";
			   if(Server256==HMAC)
			   {
					  // define a reply packet and send back to client
					  string k = get_result(query_word);
					  udp_reply_packet p2 = udp_reply_packet(mode,ntohl(sid),ntohl(tid)+1,k,passwd);
					  // send timestamp and query result back to cilent
					  int n1 = sendto(sockfd,(char *)&p2.timestamp,sizeof(uint32_t),0,(struct sockaddr*)&a9,addr_len9);
					  if(n1<0) perror("sendto");
					  int n2 = sendto(sockfd,(char *)&p2.reply_length,sizeof(uint16_t),0,(struct sockaddr*)&a9,addr_len9);
					  if(n2<0) perror("sendto");
					  int n3 = sendto(sockfd,p2.reply_string.c_str(),p2.reply_string.size(),0,(struct sockaddr*)&a9,addr_len9);
					  if(n3<0) perror("sendto");
			  }
			  else
			  {
				  cout<<"Signature failed!"<<endl;
			  }
		   }
		  else cout<<"Password incorrect!"<<endl;
	  }
	  close(newsockfd);
	  exit(0);
   }
   return 0;
}