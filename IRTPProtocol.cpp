#include "IRTPProtocol.h"


IRTPProtocol::IRTPProtocol(unsigned char type, unsigned char port, 
						   int sequence_number, int length)
{
	this->type = type;
	this->port = port;
	this->sequence_number = sequence_number;
	this->length = length;
}

void IRTPProtocol::calculate_checksum(vector<unsigned char> *bytesVector)
{
	int tmp = 0;

	tmp += type << 8;
	tmp += port;
	tmp += (sequence_number >> 8) << 8;
	tmp += sequence_number & 0xFF;
	tmp += (length >> 8) << 8;
	tmp += length & 0xFF;

	tmp = ~tmp & 0xFFFF;

	bytesVector->push_back(tmp >> 8);
	bytesVector->push_back(tmp & 0xFF);
}

void IRTPProtocol::generateBytes(vector<unsigned char> *bytesVector)
{
	
	bytesVector->push_back(type); //type

	bytesVector->push_back(port); // port 128
	
	bytesVector->push_back(sequence_number>>8);//sequence num
	bytesVector->push_back(sequence_number & 0xFF);//sequence num
	
	bytesVector->push_back(length >> 8);
	bytesVector->push_back(length & 0xFF); //length

	calculate_checksum(bytesVector);


}

IRTPProtocol::~IRTPProtocol()
{
}
