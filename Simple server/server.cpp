// Autor: Matej Slivka

#include <sys/socket.h> // praca so socketom
#include <netinet/in.h> // pre sockaddr_in
#include <cstdlib> // exit() and EXIT_FAILURE
#include <iostream> // cout
#include <unistd.h> // read
#include <string.h> // strtok
#include <signal.h> // CTRL + C


// funkcia na ukoncenie pomocou ctrl c
void ctrl_c(int signum)
{
	std::cout<< "\nShuting down server " << signum << std::endl;
	exit(signum);
}

// funkcai na porovnanie strngu s load
int compare_load(char ptr[])
{
        char hostname[] = "load";
        for (int i = 0; i<4; i++)
        {
                if (ptr[i] != hostname[i])
                {
                        return 0;
                }
        }
        return 1;
}

// funkcai na porovnaneie stringu s hostname
int compare_cpu(char ptr[])
{
	char hostname[] = "cpu-name";
	for (int i = 0; i<8; i++)
	{
		if (ptr[i] != hostname[i])
		{
			return 0;
		}
	}
	return 1;
}

// funkcai na porovnaneie stringu s hostname
int compare_host(char ptr[])
{
	char hostname[] = "hostname";
	for (int i = 0; i<8; i++)
	{
		if (ptr[i] != hostname[i])
		{
			return 0;
		}
	}
	return 1;
}

int main(int argc, const char* argv[]) 
{

        // chceme len 1 argument a tym je port
        if (argc != 2)
        {
		fprintf(stderr,"usage: %s <port>\n", argv[0]);
       		exit(EXIT_FAILURE);
       	}

	// vytvorime si socket 
	int sock;
  	if ((sock = socket(AF_INET, SOCK_STREAM, 0 )) == -1) 
	{
    		std::cout << "Unable to create socket. errno: " << errno << std::endl;
    		exit(EXIT_FAILURE);
  	}

	// chceme dany socket namapovat na adresu
	// vytvorime si adresu
	sockaddr_in sockaddr;
	int port = atoi(argv[1]);
	sockaddr.sin_family = AF_INET;
	sockaddr.sin_addr.s_addr = INADDR_ANY;
	sockaddr.sin_port = htons (port);

	// a spojime ju so socketom
	if ((bind(sock, (struct sockaddr*)&sockaddr, sizeof(sockaddr))) == -1)
	{
    		std::cout << "Unable to bind to port. errno: " << errno << std::endl;
    		exit(EXIT_FAILURE);
	}

	// zacnem pocuvat ci na danom porte sa nenachadza poziadavka
	// mozem mat nanajvys 1 poziadavku. ostatne budu zrusene	
	if (listen(sock, 1) == -1) {
    		std::cout << "Socket is not listening. errno: " << errno << std::endl;
    		exit(EXIT_FAILURE);
  	}

	// deklaracia mimo cyklu pre optimalizaciu
	int addrlen = sizeof( sockaddr );

	// zistim si hostname
  	char hostname[50];
  	int result;
  	result = gethostname(hostname, 50);
  	if (result)
    	{
      		perror("gethostname");
      		exit (EXIT_FAILURE);
    	}

	// otvori subor s cuinfo
	// nacita 5 raidok kde je info o cpu mene
	// odstrani zahlavie a ulozi do cpu_name
        FILE *cpuinfo = fopen("/proc/cpuinfo", "rb");
        char *arg = 0;
        size_t size = 0;
        getdelim(&arg, &size, '\n', cpuinfo);
        getdelim(&arg, &size, '\n', cpuinfo);
        getdelim(&arg, &size, '\n', cpuinfo);
        getdelim(&arg, &size, '\n', cpuinfo);
        getdelim(&arg, &size, '\n', cpuinfo);
        char *cpu_name;
        cpu_name = strtok(arg, ":");
        cpu_name = strtok(NULL, ":");
        free(arg);
	fclose(cpuinfo);
	
	signal(SIGINT, ctrl_c);

	std::cout << "\nServer has been initialized.\nWaiting for clients.\n";

	// teraz vyckavajna poziadavku
	while (1)
	{
		// zober z rady jedno pripojenie
		int connect = accept( sock, (struct sockaddr*)&sockaddr, (socklen_t*)&addrlen);
		if (connect < 0) {
    			std::cout << "Failed to grab connection. errno: " << errno << std::endl;
    			exit(EXIT_FAILURE);
  		}

		// do buffer zapisem co bolo na vstupe 
		char buffer[100];
		read(connect, buffer, 100);
		
		// nas argument uloz do ptr
		char *ptr = strtok(buffer, "/");
		ptr = strtok(NULL, "/");
		ptr = strtok(ptr, " ");
		
		// porovnajho s hostname
		if (compare_host(ptr) == 1)
		{
			std::string response = hostname;
	                send(connect, response.c_str(), response.size(), 0);
			response = "\n";
                        send(connect, response.c_str(), response.size(), 0);
		}
		
		// provnaj s cpu-name
		else if (compare_cpu(ptr) == 1)
                {
                        std::string response = cpu_name;
                        send(connect, response.c_str(), response.size(), 0);
                }
		
		// porovnaj s load
		else if (compare_load(ptr) == 1)
                {
			double load[3];
    			long num = sysconf(_SC_NPROCESSORS_ONLN);
    			getloadavg(load, 3);
                        std::string response = std::to_string(load[0]/num*100);
                        send(connect, response.c_str(), response.size() , 0);
			response = "%\n";
                        send(connect, response.c_str(), response.size() , 0);
                }

		// ak si nic nenasiel posli bad request
		else
		{
                        std::string response = "400 Bad Request\n";
                        send(connect, response.c_str(), response.size(), 0);
		}

		close(connect);
	}
}
