#pragma once
#include "xDPProtocol.h"

class UDPProtocol :
	public xDPProtocol
{
private:
	int length;
public:
	UDPProtocol(int source_port, int destination_port,string name, int length = 8);
	void set_length(int length);
	int get_length(void);
	void generateBytes(vector<unsigned char> *bytesVector) override;
	~UDPProtocol();
};

