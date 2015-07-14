#include "TCPProtocol.h"


TCPProtocol::TCPProtocol(int source_port, int destination_port, string name, int sequence_number,
						 int acknowl_number, int offset, int reserved, int flags, int window,
						 int urgent_pointer)
	: xDPProtocol(source_port, destination_port, name)
{
		this->sequence_number = sequence_number;
		this->acknowl_number = acknowl_number;
		this->offset = offset;
		this->reserved = reserved;
		this->flags = flags;
		this->window = window;
		this->urgent_pointer = urgent_pointer;
}

void TCPProtocol::set_sequence_number(int sequence_number)
{
	this->sequence_number = sequence_number;
}
void TCPProtocol::set_acknowl_number(int acknowl_number)
{
	this->acknowl_number = acknowl_number;
}
void TCPProtocol::set_offset(int offset)
{
	this->offset = offset;
}
void TCPProtocol::set_reserved(int reserved)
{
	this->reserved = reserved;
}
void TCPProtocol::set_flags(int flags)
{
	this->flags = flags;
}
void TCPProtocol::set_window(int window)
{
	this->window = window;
}
void TCPProtocol::set_urgent_pointer(int urgent_pointer)
{
	this->urgent_pointer = urgent_pointer;
}

void TCPProtocol::generateBytes(vector<unsigned char> *bytesVector)
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

	bytesVector->push_back(0x00);
	bytesVector->push_back(0x00);
	bytesVector->push_back(0x00);
	bytesVector->push_back(sequence_number);

	bytesVector->push_back(0x00);
	bytesVector->push_back(0x00);
	bytesVector->push_back(0x00);
	bytesVector->push_back(acknowl_number);

	bytesVector->push_back(0x50); //data ofset
	
	bytesVector->push_back(0x00); //flags
	
	bytesVector->push_back(0x00); // window
	bytesVector->push_back(0x00);

	bytesVector->push_back(0x00);  // checksum
	bytesVector->push_back(0x00);

	bytesVector->push_back(0x00); // urgent pointer
	bytesVector->push_back(0x00);




}

TCPProtocol::~TCPProtocol()
{
}
