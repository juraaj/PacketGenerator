#include "FrameEthernet.h"


FrameEthernet::FrameEthernet()
{
}

void FrameEthernet::set_version(int version)
{
	this->version = version;
}
void FrameEthernet::set_local_address(string local_address)
{
	this->local_address = local_address;
}
void FrameEthernet::set_remote_address(string remote_address)
{
	this->remote_address = remote_address;
}
void FrameEthernet::set_protocol_type(xDPProtocol *protocol_type)
{
	this->protocol_type = protocol_type;
}
void FrameEthernet::set_protocol_irtp(IRTPProtocol *protocol_type)
{
	this->irtp_protocol = protocol_type;
}
void FrameEthernet::set_local_port(int local_port)
{
	this->local_port = local_port;
}
void FrameEthernet::set_remote_port(int remote_port)
{
	this->remote_port = remote_port;
}

string Frame::get_local_mac_address()
{
	return this->local_mac_address;
}

string Frame::get_remote_mac_address()
{
	return this->remote_mac_address;
}

string Frame::get_protocol()
{
	return this->protocol;
}

int Frame::get_packets_num()
{
	return this->packets_num;
}
void FrameEthernet::make_checksum(vector<unsigned char> *bytesVector)
{
	int tmp = 0, fifthByte;

	if (version == 4)
		tmp += 0x4500;
	else
		;

	tmp += bytesVector->at(16) << 8;
	tmp += bytesVector->at(17);
	tmp += bytesVector->at(18) << 8;
	tmp += bytesVector->at(19);
	tmp += bytesVector->at(20) << 8;
	tmp += bytesVector->at(21);
	tmp += bytesVector->at(22) << 8;
	tmp += bytesVector->at(23);
	tmp += bytesVector->at(26) << 8;
	tmp += bytesVector->at(27);
	tmp += bytesVector->at(28) << 8;
	tmp += bytesVector->at(29);
	tmp += bytesVector->at(30) << 8;
	tmp += bytesVector->at(31);
	tmp += bytesVector->at(32) << 8;
	tmp += bytesVector->at(33);

	fifthByte = (tmp & 0xF0000) >> 16;
	tmp = tmp & 0xFFFF;
	tmp += fifthByte;
	tmp = ~tmp & 0xFFFF;
 
	bytesVector->at(24) = tmp >> 8;
	bytesVector->at(25) = tmp & 0xFF;

}
void FrameEthernet::local_and_remote_address_to_bytes(vector<unsigned char> *bytesVector)
{
	string tmp;
	int i, num, endIndex, startIndex;
	
	
	tmp = local_address;
	startIndex = 0;

	for (i = 0; i < 4; i++)
	{
		endIndex = tmp.find_first_of('.', startIndex);
		num = atoi(local_address.substr(startIndex, endIndex-startIndex).c_str());
		bytesVector->push_back(num);
		startIndex = endIndex+1;
	}

	tmp = remote_address;
	startIndex = 0;

	for (i = 0; i < 4; i++)
	{
		endIndex = tmp.find_first_of('.', startIndex);
		num = atoi(remote_address.substr(startIndex, endIndex - startIndex).c_str());
		bytesVector->push_back(num);
		startIndex = endIndex + 1;
	}
}
void FrameEthernet::make_IPv4_header_bytes(vector<unsigned char> *bytesVector)
{
	char inner_protocol;

	//zistenie aky mame vnoreny protocol
	if (this->irtp_protocol != NULL) // mame irp vnoreny
		inner_protocol = 1;
	else if (!strcmp(protocol_type->get_name().c_str(), "UDP")) // mame UDP vnoreny
		inner_protocol = 2;
	else
		inner_protocol = 3; // mame TCP vnoreny


	bytesVector->push_back(0x45);

	bytesVector->push_back(0x00); // type of service
	bytesVector->push_back(00); // total length

	if (inner_protocol == 3)
		bytesVector->push_back(40); // dlzka TCP
	else if (inner_protocol == 2)
		bytesVector->push_back(28); // dlzka UDP
	else
		bytesVector->push_back(28); // dlzka IRTP

	bytesVector->push_back(0x00); // identification
	bytesVector->push_back(0x07);
	bytesVector->push_back(0x40); // flag 3 bity ???
	bytesVector->push_back(0x00);
	bytesVector->push_back(0x07); // TTL

	if (inner_protocol == 3)
		bytesVector->push_back(0x06); // identifikacne cislo TCP
	else if (inner_protocol == 2)
		bytesVector->push_back(0x11); // identifikacne cislo UDP
	else
		bytesVector->push_back(0x1C); // identifikacne cislo IRTP

	bytesVector->push_back(0x00); // checksum bytes
	bytesVector->push_back(0x00);

	local_and_remote_address_to_bytes(bytesVector);

	

}
void FrameEthernet::make_IP_header_bytes(vector<unsigned char> *bytesVector)
{
	if (version == 4)
	{
		bytesVector->push_back(0x08);
		bytesVector->push_back(0x00);
		make_IPv4_header_bytes(bytesVector);
	}
	else if (version == 6)
	{
	}
	else
		return;
}
void FrameEthernet::make_protocol_bytes(vector<unsigned char> *bytesVector)
{
	UDPProtocol * udpProtocol;
	TCPProtocol * tcpProtocol;
	
	if (protocol_type != NULL)
	{

		if (!strcmp(protocol_type->get_name().c_str(), "UDP"))
		{
			udpProtocol = dynamic_cast<UDPProtocol*>(this->protocol_type);
			udpProtocol->generateBytes(bytesVector);
		}
		else if (!strcmp(protocol_type->get_name().c_str(), "TCP"))
		{
			tcpProtocol = dynamic_cast<TCPProtocol*>(this->protocol_type);
			tcpProtocol->generateBytes(bytesVector);
		}
	}
	else
	{
		this->irtp_protocol->generateBytes(bytesVector);
	}
	

}
void FrameEthernet::make_inner_protocol_checksum(vector <unsigned char> *bytesVector)
{
	int tmp = 0,fifthByte = 0;

	if (protocol_type == NULL)
		return;
	
	if (!strcmp(this->protocol_type->get_name().c_str(), "UDP"))
	{
		tmp = bytesVector->at(26) << 8;
		tmp += bytesVector->at(27);
		tmp += bytesVector->at(28) << 8;
		tmp += bytesVector->at(29);
		tmp += bytesVector->at(30) << 8;
		tmp += bytesVector->at(31);
		tmp += bytesVector->at(32) << 8;
		tmp += bytesVector->at(33);

		tmp += 17; // protocol
		tmp += 8; // ip length
		tmp += protocol_type->get_source_port();
		tmp += protocol_type->get_destination_port();
		tmp += 8; //

		fifthByte = (tmp & 0xF0000) >> 16;
		tmp = tmp & 0xFFFF;
		tmp += fifthByte;
		tmp = ~tmp & 0xFFFF;

		bytesVector->push_back(tmp>>8);
		bytesVector->push_back(tmp & 0xFF);	
	}
	else
	{
		
		tmp = bytesVector->at(26) << 8;
		tmp += bytesVector->at(27);
		tmp += bytesVector->at(28) << 8;
		tmp += bytesVector->at(29);
		tmp += bytesVector->at(30) << 8;
		tmp += bytesVector->at(31);
		tmp += bytesVector->at(32) << 8;
		tmp += bytesVector->at(33);

		tmp += 0x06; // TCP
		tmp += 20; //TCP length

		tmp += protocol_type->get_source_port();
		tmp += protocol_type->get_destination_port();

		tmp += 0x5000; //asi data offset + reserved

		fifthByte = (tmp & 0xF0000) >> 16; //magic stuff
		tmp = tmp & 0xFFFF;
		tmp += fifthByte;
		tmp = ~tmp & 0xFFFF;

		bytesVector->at(50) =  tmp >> 8;
		bytesVector->at(51) = tmp & 0xFF;

	}

	
	

}
vector<unsigned char> FrameEthernet::generateBytes()
{
	vector<unsigned char> bytes;
		
	local_and_remote_mac_address_to_bytes(&bytes);
	make_IP_header_bytes(&bytes);
	make_protocol_bytes(&bytes);
	make_inner_protocol_checksum(&bytes);
	make_checksum(&bytes);
	
	return bytes;
}
FrameEthernet::~FrameEthernet()
{
}
