#include <stdio.h>          // for printing
#include <getopt.h>         // for arg parse
#include <iostream>         // cout
#include <cstring>          // working with strlen
#include <pcap.h>           // work with interface
#include <netinet/ether.h>  // work with ether header
#include <signal.h>         // CTRL + C



/* ethernet headers are always exactly 14 bytes [1] */
#define ETHERNET_HEADER 14      // size of ethernet header
#define ETHER_TYPE_ARP 1544     // ether type for ARP
#define ETHER_TYPE_IPV4 8       //  -for IPv4
#define ETHER_TYPE_IPV6 56680   //  -for IPv6

//structure stores ethernet header
struct ethernet_header
{
    u_char dst1;
    u_char dst2;
    u_char dst3;
    u_char dst4;
    u_char dst5;
    u_char dst6;

    u_char src1;
    u_char src2;
    u_char src3;
    u_char src4;
    u_char src5;
    u_char src6;

    u_short ether_type;
};

//structure stores output data
struct output_data
{
    struct timeval ts ;
    int frame_len;
    struct in_addr src;
    struct in_addr dst;
    u_short src_port;
    u_short dst_port;
};

// this structure stores argument values/ argument initialization
struct argumentos
{
    char* interface = nullptr;
    char* port = nullptr;
    int tcp = 0;
    int udp = 0;
    int arp = 0;
    int icmp = 0;
    int n = 1;
};

// this structures just stores layer 4 data of source and destination port
struct sniff_layer4 {
        u_short sport;               /* source port */
        u_short dport;               /* destination port */
};

// this structure is from https://www.tcpdump.org/pcap.html
struct sniff_ip {
    u_char ver_head_len;    /* version << 4 | header length >> 2 */
    u_char type_of_ser;		/* type of service */
    u_short total_len;		/* total length */
    u_short id;		        /* identification */
    u_short frag_of;		/* fragment offset field */
    u_char time2live;		/* time to live */
    u_char protocol;		/* protocol */
    u_short check_sum;      /* checksum */
    struct in_addr src,dst; /* source and dest address */
};

// function to exit  program
void ctrl_c(int signum)
{
    std::cout<< "\nUser initialized shut down of program.\nShuting down " << signum << std::endl;
    exit(signum);
}

// this function prints packet header with port
void print_header_w_port(struct output_data data, struct ethernet_header head )
{
    char tmbuf[64];

    //calculate time offset
    time_t t = time(NULL);
    struct tm lt = {0};
    localtime_r(&t, &lt);

    // calculate curr time
    // I used few lines of this page as tutorial https://stackoverflow.com/questions/2408976/struct-timeval-to-printable-format
    // staring here
    time_t nowtime;
    struct tm *nowtm;
    gettimeofday(&(data.ts), NULL);
    nowtime = data.ts.tv_sec;
    nowtm = localtime(&nowtime);
    strftime(tmbuf, sizeof tmbuf, "%Y-%m-%dT%H:%M:%S", nowtm);
    // to here
    printf("timestamp    : %s.%06ld + %ld:00\n", tmbuf, data.ts.tv_usec,(lt.tm_gmtoff)/3600);
    printf("src MAC      : %x:%x:%x:%x:%x:%x\n",head.src1,head.src2,head.src3,head.src4,head.src5,head.src6);
    printf("dst MAC      : %x:%x:%x:%x:%x:%x\n",head.dst1,head.dst2,head.dst3,head.dst4,head.dst5,head.dst6);
    printf("frame length : %d bytes\n",data.frame_len);
    printf("src IP       : %s\n",inet_ntoa(data.src));
    printf("dst IP       : %s\n",inet_ntoa(data.dst));
    printf("src port     : %d\n",ntohs(data.src_port));
    printf("dst port     : %d\n",ntohs(data.dst_port));
}

// this function prints header of packet with no ports
void print_header_no_port(struct output_data data, struct ethernet_header head )
{
    char tmbuf[64];

    //calculate time offset
    time_t t = time(NULL);
    struct tm lt = {0};
    localtime_r(&t, &lt);

    // calculate curr time
    // I used few lines of this page as tutorial https://stackoverflow.com/questions/2408976/struct-timeval-to-printable-format
    // starting here
    time_t nowtime;
    struct tm *nowtm;
    gettimeofday(&(data.ts), NULL);
    nowtime = data.ts.tv_sec;
    nowtm = localtime(&nowtime);
    strftime(tmbuf, sizeof tmbuf, "%Y-%m-%dT%H:%M:%S", nowtm);
    // to here
    printf("timestamp    : %s.%06ld + %ld:00\n", tmbuf, data.ts.tv_usec,(lt.tm_gmtoff)/3600);
    printf("src MAC      : %x:%x:%x:%x:%x:%x\n",head.src1,head.src2,head.src3,head.src4,head.src5,head.src6);
    printf("dst MAC      : %x:%x:%x:%x:%x:%x\n",head.dst1,head.dst2,head.dst3,head.dst4,head.dst5,head.dst6);
    printf("frame length : %d bytes\n",data.frame_len);
    printf("src IP       : %s\n",inet_ntoa(data.src));
    printf("dst IP       : %s\n",inet_ntoa(data.dst));
}

// this function prints packet itself with hexadecimal value and as printable characters
void print_packet(const u_char *packet,const struct pcap_pkthdr *header)
{
    int size = header->len;
    u_char buf[16] = {' '};
    u_int count = 0;
    int index=0;
    // while we have something to print
    while (size > 0)
    {
        // print start of the line
        if (index == 0)
        {
            printf("0x%04hhx: ",count);
        }
        if (index == 8)
        {
            printf(" ");
        }
        
        // print
        u_char ch =*(packet + count);
        printf("%02x ",ch);
        if (isprint(ch))
            buf[index] = ch;
        else
            buf[index] = '.';
        index++;
        size = size -1;
        count++;
        // if we got to the end of line
        if ((index == 16) || (size < 1))
        {
            // align rows
            int len = 16 - index;
            if (index > 7 )
            {
                printf("  ");
            }
            else
            {
                printf("   ");
            }
            while ( len > 0)
            {
                printf("   ");
                len--;
            }
            // print buffer with printable characters or '.'
            for(int i = 0; i < 16; i++)
            {
                printf("%c",buf[i]);
                if (i ==7)
                {
                    printf(" ");
                }
                buf[i] = ' ';
            }
            printf("\n");
            index = 0;
        }
    }
}

// function is called when program catches packet which is suitable
void got_packet(u_char *args, const struct pcap_pkthdr *header, const u_char *packet)
    {

        struct ethernet_header *ether_head;
        struct sniff_ip *zahlavie;
        struct output_data output_data_t ;
        const struct sniff_layer4 *tcpudp;
        const char *payload; 
        int payload_size;

        output_data_t.ts = header->ts;
        output_data_t.frame_len = header->len;
        // mapping of packet
        ether_head = (struct ethernet_header*)(packet);

        // switch based on protocol
        switch(ether_head->ether_type) {
            case ETHER_TYPE_IPV6:
            // this switch is for IPv4 ICMP 
            case ETHER_TYPE_IPV4:
                // overlay structure on correct position
                zahlavie = (struct sniff_ip*)(packet + ETHERNET_HEADER);
                output_data_t.src = zahlavie->src;
                output_data_t.dst = zahlavie->dst;
                // in this case store TCP or UDP data which are located on same place
                if ((zahlavie->protocol == IPPROTO_TCP) || (zahlavie->protocol == IPPROTO_UDP) ){
                    int size_ip = ((zahlavie->ver_head_len) & 0x0f) * 4 ;
                    tcpudp = (struct sniff_layer4*)(packet + ETHERNET_HEADER + size_ip);
                    output_data_t.src_port = tcpudp->sport;
                    output_data_t.dst_port = tcpudp->dport;
                    print_header_w_port(output_data_t , *ether_head);
                }
                else
                {
                    // in this case print ICMP
                    print_header_no_port(output_data_t , *ether_head);
                }
                break;
                // in this case print ARP protocol
            case ETHER_TYPE_ARP:
                struct in_addr* tmp;
                tmp = (struct in_addr*)(packet+28);
                output_data_t.src = *tmp;
                tmp = (struct in_addr*)(packet+38);
                output_data_t.dst = *tmp;
                print_header_no_port(output_data_t , *ether_head);
                break;
            default:
                return;
        }
        printf("\n");
        print_packet(packet,header);
        printf("\n");

    }

// side function which returns string without '=' as first letter
char remove_eq(char * some){
    int i,lengy;
    int index = 0;
    if (some[0] == '='){
        i = 1;
        lengy = strlen(some)-1;
    }
    else{
        i = 0;
        lengy = strlen(some);
    }
    char tmp[lengy];
    for(i; i < lengy; i++)
    {
        tmp[index] = some[i];
        index ++;
    }
    return *tmp;
}

// converts int to char. symbol of equality is ignored
int char_to_int(char * some){
    int sum = 0;
    int i;
    if (some[0] == '='){
        i = 1;
    }
    else{
        i = 0;
    }
    for(i; i < strlen(some); i++)
    {
        if ((some[i] < '0')|| (some[i] > '9'))
        {
            std::cout << "Invalid number in argument " << errno << std::endl;
            exit(EXIT_FAILURE);
        }
        sum = sum*10 + int(some[i])-48;
    }
    return sum;
}



int main(int argc, char *argv[]) 
{
    
    // ctrl c exits program
    signal(SIGINT, ctrl_c);
    
    //////////// work with arguments
    // while working with arguments  I used https://www.gnu.org/software/libc/manual/html_node/Getopt-Long-Option-Example.html
    // as a tutorial
    int argum;
    int opt_in = 0;
    struct argumentos arguments;
    static struct option long_options[] = {
            {"interface",   required_argument, 0,  0 },
            {"port",        required_argument, 0,  0 },
            {"tcp",         no_argument,       0,  0 },
            {"udp",         no_argument,       0,  0 },
            {"arp",         no_argument,       0,  0 },
            {"icmp",        no_argument,       0,  0 },
            {"n",           required_argument, 0,  0 },
            {"help",        no_argument,       0,  0 },
            {0,             0,                 0,  0 }
        };

    // based on arguments structure arguments is initialized
    // this structure will be used later on when working with arguments
    while((argum = getopt_long(argc, argv,":i:p:thun:",long_options, &opt_in)) != -1) 
    { 
        switch(argum) 
        { 
            // case of long arguments
            case 0:
                switch(long_options[opt_in].name[0])
                {
                    case 'i':
                        // interface has optarg
                        if (optarg)
                        {
                            if (optarg[0] == '-')
                            {
                                std::cout << "Invalid argument. \nUsage\n./ipk-sniffer [-i rozhraní | --interface rozhraní] {-p ­­port} {[--tcp|-t] [--udp|-u] [--arp] [--icmp] } {-n num} errno: " << errno << std::endl;
                                exit(EXIT_FAILURE);
                            }
                            else
                            {
                                if (arguments.interface ==nullptr) {arguments.interface = optarg;}
                                else {std::cout << "Redefinition of argument \n " << errno << std::endl; exit(EXIT_FAILURE);}     
                            }
                        }
                        // icmp doesnt have optarg
                        else
                        {
                            if (arguments.icmp == 0) {arguments.icmp = 1;}
                            else {std::cout << "Redefinition of argument \n " << errno << std::endl; exit(EXIT_FAILURE);}
                        }
                        break;
                
                    // tcp case
                    case 't':
                        if (arguments.tcp == 0){arguments.tcp = 1;}
                        else {std::cout << "Redefinition of argument \n " << errno << std::endl;exit(EXIT_FAILURE);}
                        break;
                    // udp case
                    case 'u':
                        if (arguments.udp == 0){arguments.udp = 1;}
                        else {std::cout << "Redefinition of argument \n " << errno << std::endl;exit(EXIT_FAILURE);}
                        break;
                    // arp case
                    case 'a':
                        if (arguments.arp == 0){arguments.arp = 1;}
                        else {std::cout << "Redefinition of argument \n " << errno << std::endl;exit(EXIT_FAILURE);}
                        break;
                    // print help
                    case 'h':
                        printf("\nThis program works as a packet sniffer. Specify interface -i, port -p,number of packets -n and protocol below \n");
                        printf("Usage\n./ipk-sniffer [-i interface | --interface interface] {-p ­­port} {[--tcp|-t] [--udp|-u] [--arp] [--icmp] } {-n num}\n");
                        exit(0);
                }
                break;
            // case of short arguments
            // case tcp
            case 't':
                if (arguments.tcp == 0){arguments.tcp = 1;}
                else {std::cout << "Redefinition of argument \n " << errno << std::endl;exit(EXIT_FAILURE);}
                break;
            // case udp
            case 'u':
                if (arguments.udp == 0){arguments.udp = 1;}
                else {std::cout << "Redefinition of argument \n " << errno << std::endl;exit(EXIT_FAILURE);}
                break;
            // interfce case 
            case 'i': 
                if (optarg)
                {
                    if (optarg[0] == '-')
                    {
                        break;
                        std::cout << "Invalid argument. \nUsage\n./ipk-sniffer [-i rozhraní | --interface rozhraní] {-p ­­port} {[--tcp|-t] [--udp|-u] [--arp] [--icmp] } {-n num} errno: " << errno << std::endl;
                        exit(EXIT_FAILURE);
                    }
                    else
                    {
                        if (optarg[0] == '=') {memmove(optarg, optarg+1, strlen(optarg));}
                        if (arguments.interface ==nullptr) {arguments.interface =optarg;}
                        else {std::cout << "Redefinition of interface. Interface can be called only once \n " << errno << std::endl; exit(EXIT_FAILURE);}     
                    }
                }
                break;
            // port initialization
            case 'p':
                if (optarg)
                {
                    if (optarg[0] == '-')
                    {
                        std::cout << "Invalid argument port must be integer. \nUsage\n./ipk-sniffer [-i interface | --interface interface] {-p ­­port} {[--tcp|-t] [--udp|-u] [--arp] [--icmp] } {-n num} errno: " << errno << std::endl;
                        exit(EXIT_FAILURE);
                    }
                    else
                    {
                        //arguments.port = optarg;
                        if (arguments.port == nullptr ) {arguments.port = optarg;}
                        else {std::cout << "Redefinition of port. \n " << errno << std::endl; exit(EXIT_FAILURE);}     
                    }
                }
                break; 
            // num case
            case 'n': 
                if (optarg)
                {
                    if (optarg[0] == '-')
                    {
                        std::cout << "Invalid argument. -n must be integer. \nUsage\n./ipk-sniffer [-i rozhraní | --interface rozhraní] {-p ­­port} {[--tcp|-t] [--udp|-u] [--arp] [--icmp] } {-n num} errno: " << errno << std::endl;
                        exit(EXIT_FAILURE);
                    }
                    else
                    {
                        if ( char_to_int(optarg) < 1 ){std::cout << "Argument n must be integer greater than 0 \n " << errno << std::endl; exit(EXIT_FAILURE);}                       
                        if (arguments.n == 1) {arguments.n = char_to_int(optarg);}
                        else {std::cout << "Redefinition of argument -n \n " << errno << std::endl; exit(EXIT_FAILURE);}    
                    }
                }
                break; 
            case 'h':
                printf("\nThis program works as a packet sniffer. Specify interface -i, port -p,number of packets -n and protocol below \n");
                printf("Usage\n./ipk-sniffer [-i interface | --interface interface] {-p ­­port} {[--tcp|-t] [--udp|-u] [--arp] [--icmp] } {-n num}\n");
                exit(0);
            case ':': 
                std::cout << "Argument needs a value. \nUsage\n./ipk-sniffer [-i rozhraní | --interface rozhraní] {-p ­­port} {[--tcp|-t] [--udp|-u] [--arp] [--icmp] } {-n num} errno: " << errno << std::endl;
                exit(EXIT_FAILURE);
                break;
            case '?': 
                std::cout << "Invalid argument. \nUsage\n./ipk-sniffer [-i rozhraní | --interface rozhraní] {-p ­­port} {[--tcp|-t] [--udp|-u] [--arp] [--icmp] } {-n num} errno: " << errno << std::endl;
                exit(EXIT_FAILURE);
        } 
    }

    ////////////////////// Interface work
    // this part of program is inspired by article we were given as study literature.
    // inspired part is marked by row of ****************
    // https://www.tcpdump.org/pcap.html

    // erbuf for error printing
    char errbuf[100];

    // all interfaces 
    pcap_if_t *alldevs;
    if( pcap_findalldevs( &alldevs  , errbuf) )
    {
        std::cout << "Error finding devices \n" << errno << std::endl;	   
        fprintf(stderr,"%s" , errbuf);
        exit(EXIT_FAILURE);
    }

    // if interface was not specified , print all interfaces
    if  (arguments.interface == nullptr)
    {
        while (alldevs != NULL)
        {
            printf("%s\n",alldevs->name);
            alldevs = alldevs->next;
        }
        exit(0);
    }    

    // check if specifeid interface exists
    do
    {
        std::string str1 (alldevs->name);
        std::string str2 (arguments.interface);
        if (str1.compare(str2) == 0){
            break;
        }
        if ((alldevs == nullptr)||(alldevs->next == nullptr))
        {
            std::cout << "Program could not find specified interface \n" << errno << std::endl;
            exit(EXIT_FAILURE);
        }
        alldevs = alldevs->next;
    } while ( alldevs != nullptr);
    
    //*****************************************************
    char *dev =arguments.interface;
    pcap_t *handle;
    struct pcap_pkthdr header;	// The header that pcap gives us 
    const u_char *packet;		// The actual packet 
    struct bpf_program fp;	    // compiled filter expression
   //******************************************************

    // create filter expression which is string with logical operands
    char filter_exp[100] = {' '};
    int filter_len = 0;

    // check for port and tcp
    if (arguments.tcp == 1)
    {
        if (arguments.port != 0)
        {
            strncat(filter_exp, "(port ", 7);
            strncat(filter_exp,arguments.port, 20);
            strncat(filter_exp, " and tcp) ", 11);
        }
        else
        {
            strncat(filter_exp, "tcp ", 20);
        }
        filter_len = 4;
    }

    // check for port and udp
    if (filter_len > 0)
    {
        if (arguments.udp == 1)
        {
            if (arguments.port != nullptr)
            {
                strncat(filter_exp, "or (port ", 20);
                strncat(filter_exp,arguments.port, 20);
                strncat(filter_exp, " and udp) ", 20);
            }
            else
            {
                strncat(filter_exp, "or udp ", 20);
            }
            filter_len = 4;
        }
    }
    else
    {
        if (arguments.udp == 1)
        {
            if (arguments.port != nullptr)
            {
                strncat(filter_exp, "(port ", 20);
                strncat(filter_exp,arguments.port, 20);
                strncat(filter_exp, " and udp) ", 20);
            }
            else
            {
                strncat(filter_exp, "udp ", 20);
            }
            filter_len = 4;
        }
    }

    // check for arp
    if (filter_len > 0)
    {
        if (arguments.arp == 1)
        {
            strncat(filter_exp, "or arp ", 20);
            filter_len = 4;
        }
    }
    else
    {
        if (arguments.arp == 1)
        {
            strncat(filter_exp, "arp ", 20);
            filter_len = 4;
        }
    }
    // check for icmp
    if (filter_len > 0)
    {
        if (arguments.icmp == 1)
        {
            strncat(filter_exp, "or icmp ", 20);
            filter_len = 4;
        }
    }
    else
    {
        if (arguments.icmp == 1)
        {
            strncat(filter_exp, "icmp ", 20);
            filter_len = 4;
        }
    }
    
    // check for expression with port only
    if ((filter_len < 2) && (arguments.port != nullptr))
    {
            strncat(filter_exp, "(port ", 7);
            strncat(filter_exp,arguments.port, 20);
            strncat(filter_exp, " and tcp) or (port ", 30);
            strncat(filter_exp,arguments.port, 20);
            strncat(filter_exp, " and udp) or arp or icmp ", 30);
            filter_len = 4;
    }
    if (filter_len < 2)
    {
        strncat(filter_exp, "icmp or arp or tcp or udp ", 30);
        filter_len = 4;
    }

    //printf("%s\n",filter_exp);

    //  dev = specified interface
    // BUFSIZE = how much bytes should we accept
    // promiscuity mode 1/0 on/off
    // read time in miliseconds
    // error buffer

    // ****************************************************************************
    // inspired part
    bpf_u_int32 net;	        // IP of our device	
    bpf_u_int32 mask;		    // Our netmask 

    // looks up network
    if (pcap_lookupnet(dev, &net, &mask, errbuf) == -1) {
        fprintf(stderr, "Can not get netmask for device %s: %s\n", dev, errbuf);
        exit(2);
    }
    // opens network
    handle = pcap_open_live(dev, BUFSIZ, 1, 1000, errbuf);
    if (handle == NULL) {
        fprintf(stderr, "Can not open device %s: %s\n", dev, errbuf);
        exit(2);
    }

    // create filter to fp

    if (pcap_compile(handle, &fp, filter_exp, 0, net) == -1) {
        fprintf(stderr, "Can not create filter %s: %s\n", filter_exp, pcap_geterr(handle));
        exit(2);
    }

    // apply fp filter
    if (pcap_setfilter(handle, &fp) == -1) {
        fprintf(stderr, "Can not install filter %s: %s\n", filter_exp, pcap_geterr(handle));
        exit(2);
    }
    //***********************************************************************************
    //This document is Copyright 2002 Tim Carstens. All rights reserved. Redistribution and use, with or without modification, are permitted provided that the following conditions are met:
    //Redistribution must retain the above copyright notice and this list of conditions.
    //The name of Tim Carstens may not be used to endorse or promote products derived from this document without specific prior written permission.
    /* Insert 'wh00t' for the BSD license here */ 

    // call loop for n packets
    // call got_packet function when packet is found
    pcap_loop(handle, arguments.n, got_packet, NULL);

    // close handle
    pcap_close(handle);
}