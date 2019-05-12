/*

Pcap data insertion into postgresql database
SQL transactions are implemented for improving performance

Writtend by Sabri Khemissa sabri.khemissa[at]gmail.com

Compilation command:
	cc -o netmapPGSql netmapPGSql.c -l pcap -I/usr/include/postgresql -lpq 

*/

#include <stdio.h>
#include <string.h> 
#include <stdlib.h>
#include <time.h>
#include <pcap.h>
#include <sys/types.h>
#include <sys/socket.h>
#include <netinet/in.h>
#include <arpa/inet.h>
#include <netinet/ether.h>
#include <netinet/if_ether.h>
#include <libpq-fe.h>

// Globale pcap variables
#define SIZE_ETHERNET 14

#define IPv4_ETHERTYPE 0x800

#define IP_HL(ip)		(((ip)->ip_vhl) & 0x0f)
#define IP_V(ip)		(((ip)->ip_vhl) >> 4)


#define BUFFER_SIZE 256

// Ethernet header
struct sniff_ethernet {
	u_char          ether_dhost[ETHER_ADDR_LEN];	/* Destination host address */
	u_char          ether_shost[ETHER_ADDR_LEN];	/* Source host address */
	u_short         ether_type;	/* IP? ARP? RARP? etc */
};

// IP header 
struct sniff_ip {
	u_char          ip_vhl;	/* version << 4 | header length >> 2 */
	u_char          ip_tos;	/* type of service */
	u_short         ip_len;	/* total length */
	u_short         ip_id;	/* identification */
	u_short         ip_off;	/* fragment offset field */
	#define IP_RF 0x8000		/* reserved fragment flag */
	#define IP_DF 0x4000		/* dont fragment flag */
	#define IP_MF 0x2000		/* more fragments flag */
	#define IP_OFFMASK 0x1fff	/* mask for fragmenting bits */
	u_char          ip_ttl;	/* time to live */
	u_char          ip_p;	/* protocol */
	u_short         ip_sum;	/* checksum */
	struct in_addr  ip_src, ip_dst;	/* source and dest address */
};

// TCP header
typedef u_int tcp_seq;

struct sniff_tcp {
	u_short th_sport;	/* source port */
	u_short th_dport;	/* destination port */
	tcp_seq th_seq;		/* sequence number */
	tcp_seq th_ack;		/* acknowledgement number */
	u_char th_offx2;	/* data offset, rsvd */
	#define TH_OFF(th)	(((th)->th_offx2 & 0xf0) >> 4)
	u_char th_flags;
	#define TH_FIN 0x01
	#define TH_SYN 0x02
	#define TH_RST 0x04
	#define TH_PUSH 0x08
	#define TH_ACK 0x10
	#define TH_URG 0x20
	#define TH_ECE 0x40
	#define TH_CWR 0x80
	#define TH_FLAGS (TH_FIN|TH_SYN|TH_RST|TH_ACK|TH_URG|TH_ECE|TH_CWR)
	u_short th_win;		/* window */
	u_short th_sum;		/* checksum */
	u_short th_urp;		/* urgent pointer */
};

int main(int argc, char *argv[])
{
	/* database configuration file variables */
	FILE *dbconfig;
	char* filename = "db.cfg";
	char buf[100];

	/* Db connection variables */
	char dbhost[20];
	char dbport[5];
	char dbname[20];
	char dbusername[20]; 
	char dbpassword[25]; 
	char commitcounter[10];
	char db_connect[100];

	/* Pcap variables */
	char *device, errbuf[PCAP_ERRBUF_SIZE];
	pcap_t *handle;
	const u_char *packet;
	struct pcap_pkthdr header;
	const struct sniff_ethernet *ethernet;
	const struct sniff_ip *ip;
	const struct sniff_tcp *tcp; 
	char timestamp[100];
	u_char *ptr;
	u_int size_ip;

	/* Others variables */
	int count = 0;

	/* Verifing that an field has been provided as argument */
	if (argc < 2) {
		fprintf(stderr, "Incorrect number of arguments provided\n");
		fprintf(stderr, "Usage: program <interface_name>\n");
		return (2);
	}
	
	/* Loading database configuration file */
	dbconfig = fopen(filename, "r");
	if (dbconfig  == NULL){
    		perror("fopen source-file");
		return 1;
	}

	/* Loading database connection data */
	while (fgets(buf, sizeof(buf), dbconfig) != NULL) {
		const char *standard_white_space = " \f\n\r\t\v";
		if (buf[0] == '#') continue;
		char* field_1 = strtok(buf, standard_white_space);
		char* field_2 = strtok(NULL, standard_white_space);
		if (field_1 == NULL) continue;
		if (strcmp(field_1, "dbhost") == 0){
			strcpy(dbhost, field_2);
		}
		if (strcmp(field_1, "dbport") == 0){
			strcpy(dbport, field_2);
		}
		if (strcmp(field_1, "dbname") == 0){
			strcpy(dbname, field_2);
			
		}
		if (strcmp(field_1, "dbusername") == 0){ 
			strcpy(dbusername, field_2);
		}
		if (strcmp(field_1, "dbpassword") == 0){ 
			strcpy(dbpassword, field_2);
		}
		if (strcmp(field_1, "commitcounter") == 0){ 
			strcpy(commitcounter, field_2);
		}
	}

	fclose (dbconfig);	

	snprintf(db_connect, sizeof(db_connect), \
		"host=%s port=%s dbname=%s user=%s password=%s", \
		dbhost, dbport, dbname, dbusername, dbpassword);
	
	/* Initiating database connection */
	PGconn *conn = PQconnectdb(db_connect);

    	if (PQstatus(conn) == CONNECTION_BAD) {
        	fprintf(stderr, "Connection to database failed: %s\n",
            	PQerrorMessage(conn));
		PQfinish(conn);
		exit(1);
    	}

	/* Opening the network interface */
	device = argv[1];
	handle = pcap_open_live(
		device,
		BUFSIZ,
		-1,
		0,
		errbuf);	
	if (handle == NULL) {
		fprintf(stderr, "Couldn't open network interface %s: %s\n", device, errbuf);
		return (2);
	}

	/* Begin SQL transaction */
     	PGresult *res = PQexec(conn, "BEGIN"); 
    	if (PQresultStatus(res) != PGRES_COMMAND_OK) {
	        printf("BEGIN command failed\n");        
        	PQclear(res);
		exit(1);
    	}    
    	PQclear(res); 

	/* Startng packets collection */
	while(1) {
		char insert_query[1000] = "";
		packet = pcap_next(handle,&header);
		ethernet = (struct sniff_ethernet*)packet;
         	if (ntohs(ethernet->ether_type) == IPv4_ETHERTYPE) {
			ip = (struct sniff_ip *) (packet + SIZE_ETHERNET);
			size_ip = IP_HL(ip) * 4;
			if (IP_V(ip) == 4) {
				tcp = (struct sniff_tcp*)(packet + SIZE_ETHERNET + size_ip);

				/* Preparing the SQL query */
				snprintf(timestamp, sizeof(timestamp),"%d",header.ts);
				snprintf(insert_query,sizeof(insert_query),\
				  "INSERT INTO capture VALUES(DEFAULT, '%s', '%s', '%s', '%s', '%s', %d, %d)",\
					timestamp,\
					inet_ntoa(ip->ip_src), ether_ntoa(ethernet->ether_shost),\
					inet_ntoa(ip->ip_dst), ether_ntoa(ethernet->ether_dhost),\
					ntohs(tcp->th_dport), ip->ip_p);

				/* Executing the SQL query */
				res = PQexec(conn, insert_query);
				if (PQresultStatus(res) != PGRES_COMMAND_OK) {
					printf("INSERT command failed\n");        
        				PQclear(res);
					exit(1);
    				}
				PQclear(res);
				count++;

				/* When count =100, the SQL transaction is committed 
				then a new transaction is started  */
				if (count == atoi(commitcounter)){
					res = PQexec(conn, "COMMIT"); 
					if (PQresultStatus(res) != PGRES_COMMAND_OK) {
						printf("COMMIT command failed\n");        
        					PQclear(res);
						exit(1);
    					}       
					PQclear(res);
					PGresult *res = PQexec(conn, "BEGIN");
					if (PQresultStatus(res) != PGRES_COMMAND_OK) {
						printf("BEGIN command failed\n");        
        					PQclear(res);
						exit(1);
    					}
    					PQclear(res);  
					count=0;
				}
			}
	        }
	}
	return (0);
}
