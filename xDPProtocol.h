#pragma once
#include <vector>

using namespace std;

class xDPProtocol
{
private:
	int source_port;
	int destination_port;
	int checksum;
	string name;
public:
	xDPProtocol();
	xDPProtocol(int source_port, int destination_port, string name);
	void set_name(string name);
	void set_source_port(int source_ort);
	void set_destination_port(int destination_port);
	int get_source_port(void);
	int get_destination_port(void);
	virtual void generateBytes(vector<unsigned char> *bytesVector) = 0;
	string get_name(void);
	~xDPProtocol();
};

