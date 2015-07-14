#include "UDPProtocol.h"


UDPProtocol::UDPProtocol(int source_port, int destination_port, string name, int length)
	:xDPProtocol(source_port,destination_port,name)
{
		this->length = length;
}

void UDPProtocol::set_length(int lenght)
{
	this->length = lenght;
}

int UDPProtocol::get_length(void)
{
	return this->length;
}

void UDPProtocol::generateBytes(vector<unsigned char> *bytesVector)
{
	int sourcePort, destinationPort, firstByte, secondByte;

	sourcePort = get_source_port();
	destinationPort = get_destination_port();

	firstByte = sourcePort >> 8;
	secondByte = sourcePort - (firstByte << 8);

	bytesVector->push_back(firstByte); //sourceport
	bytesVector->push_back(secondByte);

	firstByte = destinationPort >> 8;
	secondByte = destinationPort - (firstByte << 8);

	bytesVector->push_back(firstByte); //destinationport
	bytesVector->push_back(secondByte);

	bytesVector->push_back(0x00); //length
	bytesVector->push_back(0x08);
		
}
UDPProtocol::~UDPProtocol()
{
}
