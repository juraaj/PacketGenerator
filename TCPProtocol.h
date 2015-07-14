#include "xDPProtocol.h"
#pragma once

class TCPProtocol
	: public xDPProtocol
{
private:
	int sequence_number;
	int acknowl_number;
	int offset;
	int reserved;
	int flags;
	int window;
	int urgent_pointer;
public:
	TCPProtocol(int source_port, int destination_port, string name, int sequence_number = 0,
				int acknowl_number = 0, int offset = 5, int reserved = 0, int flags = 0,
				int window = 0, int urgent_pointer = 0);
	void set_sequence_number(int sequence_number);
	void set_acknowl_number(int acknowl_number);
	void set_offset(int offset);
	void set_reserved(int reserved);
	void set_flags(int flags);
	void set_window(int window);
	void set_urgent_pointer(int urgent_pointer);
	void generateBytes(vector<unsigned char> *bytesVector) override;
	~TCPProtocol();
};

