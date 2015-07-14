#include "xDPProtocol.h"

xDPProtocol::xDPProtocol(int source_port, int destination_port, string name)
{
	this->source_port = source_port;
	this->destination_port = destination_port;
	this->name = name;
}

void xDPProtocol::set_source_port(int source_port)
{
	this->source_port = source_port;
}

void xDPProtocol::set_destination_port(int destination_port)
{
	this->destination_port = destination_port;
}

int xDPProtocol::get_source_port(void)
{
	return this->source_port;
}

int xDPProtocol::get_destination_port(void)
{
	return this->destination_port;
}

void xDPProtocol::set_name(string name)
{
	this->name = name;
}

string xDPProtocol::get_name(void)
{
	return this->name;
}

void xDPProtocol::generateBytes(vector<unsigned char> *bytesVector)
{
	bytesVector->at(0);
}
xDPProtocol::~xDPProtocol()
{
}
