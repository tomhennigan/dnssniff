
#include "dnssniff.h"
#include "dbconf.h"

char errbuf[PCAP_ERRBUF_SIZE];

char * format_ip_address(ip_address addr)
{
  char * ret = malloc(sizeof(char) * 16);
  sprintf(ret, "%d.%d.%d.%d", addr.byte1, addr.byte2, addr.byte3, addr.byte4);
  return ret;
}

int usage_printed = 0;

void usage(int argc, char * argv[]);
void usage(int argc, char * argv[])
{
  if(usage_printed != 0)
  {
    return;
  }
  
  #define USAGE_FLAG "%s %-10s\t\t%s\n"
  
  usage_printed = 1;
  fprintf(stderr, "usage: %s -i <interface>\n\n", argv[0]);
  
  fprintf(stderr, USAGE_FLAG, "-i", "<interface>", "listen on the specified interface");
  fprintf(stderr, USAGE_FLAG, "-d", "", "run as a daemon (background)");
}

char * addr_to_hostname(char * ip_addr);
char * addr_to_hostname(char * ip_addr)
{
  struct hostent * he;
  char addr[4];
  char * ret;
  
  inet_pton(AF_INET, ip_addr, &addr);
  
  he = gethostbyaddr(&addr, sizeof(addr), AF_INET);
  
  int len = 1;
  
  if(!he)
  {
    
    
    int iplen = strlen(ip_addr);
    ret = malloc(sizeof(char) * iplen + 1);
    memcpy(ret, ip_addr, iplen);
    ret[iplen] = '\0';
    return ret;
  }
  
  // printf("Host name: %s\n", he->h_name);
  
  len = strlen(he->h_name);
  
  ret = strdup(he->h_name);
  
  return ret;
}

MYSQL * db;

void connect_to_db();
void connect_to_db()
{
  if(db != NULL)
  {
    return;
  }
  
  db = mysql_init(NULL);
  
  if(!db)
  {
    fprintf(stderr, "error: couldn't init mysql %u: %s\n", mysql_errno(db), mysql_error(db));
    exit(1);
  }
  
  if(mysql_real_connect(db, MYSQL_HOST, MYSQL_USER, MYSQL_PASS, MYSQL_DBSE, MYSQL_CPRT, NULL, 0) == NULL) {
    printf("error: couldn't connect to db %u: %s\n", mysql_errno(db), mysql_error(db));
    exit(1);
  }
}

void save_to_db(char * src_host, char * srcip, char * dst_host, char * dstip, char * domain_name);
void save_to_db(char * src_host, char * srcip, char * dst_host, char * dstip, char * domain_name)
{
  char * buf;
  size_t len, s_len;
  
  char * e_domain_name, * e_src_host, * e_srcip, * e_dst_host, * e_dstip;
  
  // domain_name
  s_len = strlen(domain_name);
  len = (s_len * 2) + 1;
  buf = malloc(sizeof(char) * len);
  bzero(buf, len);
  
  mysql_real_escape_string(db, buf, domain_name, s_len);
  
  e_domain_name = buf;
  
  // src_host
  s_len = strlen(src_host);
  len = (s_len * 2) + 1;
  buf = malloc(sizeof(char) * len);
  bzero(buf, len);
  
  mysql_real_escape_string(db, buf, src_host, s_len);
  
  e_src_host = buf;
  
  // srcip
  s_len = strlen(srcip);
  len = (s_len * 2) + 1;
  buf = malloc(sizeof(char) * len);
  bzero(buf, len);
  
  mysql_real_escape_string(db, buf, srcip, s_len);
  
  e_srcip = buf;
  
  // src_host
  s_len = strlen(dst_host);
  len = (s_len * 2) + 1;
  buf = malloc(sizeof(char) * len);
  bzero(buf, len);
  
  mysql_real_escape_string(db, buf, dst_host, s_len);
  
  e_dst_host = buf;
  
  // dstip
  s_len = strlen(dstip);
  len = (s_len * 2) + 1;
  buf = malloc(sizeof(char) * len);
  bzero(buf, len);
  
  mysql_real_escape_string(db, buf, dstip, s_len);
  
  e_dstip = buf;
  
  // Produce the query.
  static char query_fmt[] = "INSERT INTO house_log.dns (`domain`, `src_ip`, `src_host`, `dst_ip`, `dst_host`, `when`) VALUES ('%s', '%s', '%s', '%s', '%s', NOW())";
  
  size_t qry_len = strlen(query_fmt) + strlen(e_domain_name) + strlen(e_srcip) + strlen(e_src_host) + strlen(e_dstip) + strlen(e_dst_host) + 1;
  
  char * qry = malloc(sizeof(char) * qry_len);
  bzero(qry, qry_len);
  
  sprintf(qry, query_fmt, e_domain_name, e_srcip, e_src_host, e_dstip, e_dst_host);
  
  if(mysql_query(db, qry))
  {
    fprintf(stderr, "error: couldn't add to log %u: %s\n", mysql_errno(db), mysql_error(db));
    exit(1);
  }
  
  // Clean up.
  free(qry);
  free(e_domain_name);
  free(e_src_host);
  free(e_srcip);
  free(e_dst_host);
  free(e_dstip);
}

int main(int argc, char * argv[])
{
  // char * name = addr_to_hostname("152.78.102.169");
  
  // printf("name: %s\n", name);
  
  // free(name);
  
  // return 0;
  
  // Some default values for the options.
  char * dev = NULL;
  int daemon = 0;
  
  char c;
  while((c = getopt(argc, argv, "i:d")) != -1)
  {
    switch(c)
    {
      case 'i':
        dev = optarg;
      break;
      
      case 'd':
        daemon = 1;
      break;
      
      case '?':
        usage(argc, argv);
      break;
      
      default:
        fprintf(stderr, "error: unknown option %c\n", c);
        exit(1);
      break;
    }
  }
  
  // Sanity check the options given.
  if(dev == NULL)
  {
    usage(argc, argv);
    exit(1);
  }
  
  // Connect to the DB
  connect_to_db();
  
  if(daemon == 1)
  {
    if(fork() != 0)
    {
      // Close foreground if all is good and we're meant to daemonise.
    	exit(0);
    }
  }
  
  pcap_t * handle;
  
  bpf_u_int32 mask; // The netmask of the capture device.
  bpf_u_int32 ip;  // The IP address of the sniffing interface.
  
  if (pcap_lookupnet(dev, &ip, &mask, errbuf) == -1) {
 		 fprintf(stderr, "Can't get netmask for device %s\n", dev);
     exit(1);
 	 }
  
  handle = pcap_open_live(dev, 65536, 1, 1000, errbuf);
  
  if(handle == NULL)
  {
    fprintf(stderr, "error: couldn't start capture on %s: %s\n", dev, errbuf);
    exit(1);
  }
  
  struct bpf_program fp; // The filter extension.
  
  char * filter_exp = "udp dst port 53";
  if(pcap_compile(handle, &fp, filter_exp, 1, ip) == -1)
  {
    fprintf(stderr, "Couldn't parse filter %s: %s\n", filter_exp, pcap_geterr(handle));
    exit(1);
  }
  
  if(pcap_setfilter(handle, &fp) == -1)
  {
    fprintf(stderr, "Couldn't install filter %s: %s\n", filter_exp, pcap_geterr(handle));
    exit(1);
  }
  
  pcap_loop(handle, 0, packet_handler, NULL);

  pcap_close(handle);
	
  return 0;
}

void packet_handler(u_char *param, const struct pcap_pkthdr *header, const u_char *packet)
{
  int tcp_len, url_length;
  u_char *url, *end_url, *final_url, *tcp_payload;
  u_int ip_len;
  
  // printf("Jacked a packet with length of [%d]\n", header->len);
  
  ip_header * iph = (ip_header *)(packet + 14); // 14: length of ethernet header.
  
  char * srcip = format_ip_address(iph->saddr);
  char * dstip = format_ip_address(iph->daddr);
  // printf("src: %s, dst: %s\n", srcip, dstip);
  
  /* retireve the position of the tcp header */
  ip_len = (iph->ver_ihl & 0xf) * 4;
  
  /* retireve the position of the tcp payload */
  tcp_len = (((u_char*)iph)[ip_len + 12] >> 4) * 4;
  u_char * tcpPayload = (u_char*)iph + ip_len + tcp_len;
  
  int payload_len = header->len - (ip_len + tcp_len);
  
  // dns_header * dns_h = (dns_header *)&tcpPayload;
  
  u_char * dns_payload = &tcpPayload[sizeof(dns_header) + 8];
  
  size_t dns_payload_len = payload_len - sizeof(dns_header) - 8;
  
  // Maximum domain name size is 254 + '\0'.
  char * domain_name = malloc(sizeof(char) * 255);
  bzero(domain_name, 255);
  
  int pos = 0;
  int len = 0;
  int crs = (int)((char)dns_payload[0]);
  
  while(crs != 0 && pos < 255 && crs < 255)
  {
    memcpy(domain_name + len, dns_payload + pos + 1, crs);
    len += crs;
    pos += (crs + 1);
    crs = (int)((char)dns_payload[pos]);
    
    if(crs != 0) {
      domain_name[len] = '.';
      len++;
    }
  }
  
  // printf("getting src host %s\n", srcip);
  char * src_host = addr_to_hostname(srcip);
  // printf("got src host: %s\n", src_host);
  
  // printf("getting dst host %s\n", dstip);
  char * dst_host = addr_to_hostname(dstip);
  // printf("got dst host: %s\n", dst_host);
  
  // Ignore local reverse lookups.
  if(strstr(domain_name, ".in-addr.arpa") == NULL) {
    save_to_db(src_host, srcip, dst_host, dstip, domain_name);
    //printf("%s (%s) -> %s (%s) : %s\n", src_host, srcip, dst_host, dstip, domain_name);
  }
  
  free(domain_name);
  free(srcip);
  free(dstip);
  free(src_host);
  free(dst_host);
}
