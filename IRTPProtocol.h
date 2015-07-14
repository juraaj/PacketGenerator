#pragma once
#include <vector>

using namespace std;
class IRTPProtocol
{
private:
	unsigned char type;
	unsigned char port;
	int sequence_number;
	int length;
	int checksum;
	void calculate_checksum(vector <unsigned char> *bytesVector);
public:
	void set_type(unsigned char type);
	void set_port(unsigned char port);
	void set_sequence_number(int sequence_number);
	void generateBytes(vector<unsigned char> *bytesVector);
	
	IRTPProtocol(unsigned char type, unsigned char port, int sequence_number, int length);
	~IRTPProtocol();
};

