#include <iostream>
#include <iostream>
#include <fstream>
#include <sstream>
#include <time.h>
#include <string>
#include <sys/types.h>
#include <sys/socket.h>
#include <nettle/hmac.h>
#include <nettle/sha.h>
using std::cout;
using std::endl;
using std::string;
using std::to_string;
using std::istringstream;

#define DIGEST_ASCII (SHA256_DIGEST_SIZE*2+1)

const char* calcSHA256(const char* const passwordString,const uint32_t number)
{
  unsigned char digest[SHA256_DIGEST_SIZE];
  static char ascii_hex[ DIGEST_ASCII ];
  assert( passwordString != NULL );
  struct sha256_ctx SHA_Buffer;
  sha256_init(&SHA_Buffer);
  sha256_update(&SHA_Buffer,strlen(passwordString),(uint8_t*)passwordString );
  sha256_update( &SHA_Buffer, 4, (uint8_t*)&number );
  sha256_digest( &SHA_Buffer, SHA256_DIGEST_SIZE, digest );
  {
	  int di;
	  for (di = 0; di < SHA256_DIGEST_SIZE; ++di)
		  sprintf(ascii_hex + di * 2, "%02x", digest[di]);
  }
  ascii_hex[DIGEST_ASCII-1] = '\0';
  return ascii_hex;
}

const char* HMACSHA256( const uint8_t* const data,
			unsigned int dataLen,
			const char* const password )
{
  // digest in binary
  unsigned char digest[SHA256_DIGEST_SIZE];
  static char ascii_hex[ DIGEST_ASCII ];
  unsigned int passwordLen = strlen( password );
  // check parameter constraints
  assert( data != NULL );
  assert( dataLen > 0 );
  assert( password != NULL );
  assert( passwordLen > 0 );
  /* HMACSHA256 with nettle lib: */
  { struct hmac_sha256_ctx hmacBuf;
    hmac_sha256_set_key( &hmacBuf, passwordLen, (uint8_t*)password );
    hmac_sha256_update( &hmacBuf, dataLen, data );
    // get the binary signature
    hmac_sha256_digest( &hmacBuf, SHA256_DIGEST_SIZE, digest );
  }
  // convert binary to ascii-hex format:
  { int di;
  for (di = 0; di < SHA256_DIGEST_SIZE; ++di)
    sprintf(ascii_hex + di * 2, "%02x", digest[di]);
  }
  // make sure that the string has terminating NUL
  ascii_hex[DIGEST_ASCII-1] = '\0';

  return ascii_hex;
}

// Generate a random number used for encrypt.
uint32_t getrandomint( void )
{
  uint32_t i;
  const size_t NUMSIZE = sizeof( i );
  FILE* rawdata = NULL;

  rawdata = fopen("/dev/urandom", "r");
  if( rawdata == NULL ) { perror("/dev/urandom"); exit(1); }

  if( fread( &i, 1, NUMSIZE, rawdata ) != NUMSIZE )
  {
	  perror("urandom fread()"); exit(1);
  }
  fclose(rawdata);

  return i;
}

class tcp_message
{
private:
	int msg_length;
	string identification;
	string protocal_mode;
	string cmd;
public:
	tcp_message():msg_length(0),identification("DISTRIB2016"),protocal_mode("D"),cmd("x"){}
	// constructor used when unserialize string to a message
	tcp_message(string mode, string c,int l)
	{
		protocal_mode = mode;
		identification = "DISTRIB2016";
		cmd = c;
		msg_length = l;
	}
	// constructor used when define a new message sending to client/server.
	tcp_message(string mode, string c)
	{
		protocal_mode = mode;
		identification = "DISTRIB2016";
		cmd = c;
		msg_length = 14 + c.size();
	}
	// get the length of the message
	int get_msg_length()
	{
		return this->msg_length;
	}

	string serialize_msg()
	{
		return to_string(msg_length) + identification + protocal_mode + cmd;
	}
	
	string get_protocal_mode()
	{
	    return this->protocal_mode;
	}

	string get_command()
	{
		string cmd_type = cmd.substr(0,2);
		if(cmd_type=="T1")
		{
			string sub_cmd = cmd.substr(2, cmd.size()-1);
			istringstream linestream(sub_cmd);
			int length;
			linestream>>length;
			string res;
			linestream>>res;
			return res;
		}
		else if(cmd_type=="T2" or cmd_type=="T3")
		{
			return cmd.substr(2,cmd.size());
		}
		else if(cmd_type=="T4")
		{
			return cmd.substr(2,cmd.size()-3);
		}
		else
		{
			return "error!";
		}
	}
};

// convert a string into tcp message
tcp_message unserialize_string(string s)
{
	cout<<"s:"<<s<<endl;
	string m = s.substr(13,1);
	int len = atoi(s.substr(0,2).c_str());
	string cmd = s.substr(14,s.size()-1);
	return tcp_message(m,cmd,len);
}

// partial read TCP message
int readn(int sockfd, char* bufptr, size_t len)
{
    int count = len, received = 0;
    while(count>0)
    {
        received = recv(sockfd,bufptr,count,0);
        if(received<0)
        {
            if(errno == EINTR) continue;
            else return -1;
        }
        if(received==0) // EOF
            return len - count;
        bufptr += received-1;
        count  -= received;
        //lbytes += received;
    }
    return len;
}

char* readn_tcp(int sockfd)
{
	int n1,n2;
	uint16_t nlength;
	//  receive length
	n1 = readn(sockfd,(char *)&nlength,sizeof(uint16_t));
	int length = ntohs(nlength);
	// receive message
	char *buffer2 = new char[length];
	bzero(buffer2,length);
	n2 = readn(sockfd,buffer2,length);
	buffer2[n2] = '\0';
	return buffer2;
}

// partial send TCP message
int writen(int sockfd,const char* bufptr, size_t len)
{
	int count = 0, sent = 0, left=len;
	while(count<int(len))
	{
		sent = send(sockfd,bufptr+count,left,0);
		if(sent<0)
		{
            if(errno == EINTR) continue;
            else return -1;
		}
        if(sent==int(len)) // EOF, all had been sent out
            return len - count;
        count += sent;
        left -= sent;
	}
	return len;
}

void writen_tcp(const int &sockfd,tcp_message m)
{
	int n1,n2;
	// first send the length of message
	uint16_t nlength = htons(m.get_msg_length());
	n1 = writen(sockfd,(char *)&nlength,sizeof(uint16_t));
	// then send the message
	n2 = writen(sockfd, m.serialize_msg().c_str(), m.get_msg_length());
}

// udp query packet
class udp_query_packet
{
public:
	string direction;
	string version;
	uint16_t length;
	uint32_t sid;
	uint32_t tid;
	uint16_t query_length;
	string query_word;
	uint16_t maclen;
	string HMAC_SHA256;
	udp_query_packet(string v,int sid,int tid,string w,string pwd)
	{
		this->direction = "P";
//		this->version = v;
		if(v=="") this->version = "1";
		else this->version = v;
		this->length = htons(sizeof(this->direction)+sizeof(this->version)+sizeof(this->length)
				+sizeof(this->sid)+sizeof(this->tid)+sizeof(this->query_length)+sizeof(this->query_word));
		this->sid = htonl(sid);
		this->tid = htonl(tid);
		this->query_word = w;
		this->query_length = htons(w.size());
		if(v=="D")
		{
			this->HMAC_SHA256 = "X";
			this->maclen = htons(1);
		}
		else
		{
			this->HMAC_SHA256 = HMACSHA256((uint8_t*)(this->get_string_17().c_str()),this->get_string_17().size(),pwd.c_str());
			this->maclen = htons(HMAC_SHA256.size());
		}
	}
	// Concatenate fields 1-7 together
	string get_string_17()
	{
		return direction+version+to_string(length)+
				to_string(sid)+to_string(tid)+to_string(query_length)+query_word;
	}
};

// udp reply packet
class udp_reply_packet
{
public:
	string direction;
	string version;
	uint16_t length;
	uint32_t sid;
	uint32_t tid;
	uint32_t timestamp;
	uint16_t reply_length;
	string reply_string;
	uint16_t maclen;
	string HMAC_SHA256;
	udp_reply_packet(string v,int sid,int tid,string s,string pwd)
	{
		this->direction = "A";
		// default case the version is normal, which is "1"
		if(v=="") this->version = "1";
		else this->version = v;
		this->length = htons(sizeof(this->direction)+sizeof(this->version)+sizeof(this->length)
				+sizeof(this->sid)+sizeof(this->tid)+sizeof(this->timestamp)+sizeof(this->reply_length)
				+sizeof(reply_string));
		this->sid = htonl(sid);
		this->tid = htonl(tid);
		this->timestamp = htonl((uint32_t) time(0));
		this->reply_string = s;
		this->reply_length = htons(s.size());
		if(v=="D")
		{
			this->HMAC_SHA256 = "X";
			this->maclen = htons(1);
		}
		else
		{
			this->HMAC_SHA256 = HMACSHA256((uint8_t*)this->get_string_18().c_str(),this->get_string_18().size(),pwd.c_str());;
			this->maclen = htons(HMAC_SHA256.size());
		}
	}

	// Concatenate fields 1-8 together
	string get_string_18()
	{
		return direction+version+to_string(length)+
				to_string(sid)+to_string(tid)+to_string(timestamp)+
				to_string(reply_length)+reply_string;
	}
};
