#include "Frame802_3.h"


Frame802_3::Frame802_3()
{
}

void Frame802_3::set_local_net_address(string local_net_address)
{
	this->local_net_address = local_net_address;
}
void Frame802_3::set_local_socket_address(string local_socket_address)
{
	this->local_socket_address = local_socket_address;
}
void Frame802_3::set_remote_net_address(string remote_net_address)
{
	this->remote_net_address = remote_net_address;
}
void Frame802_3::set_remote_socket_address(string remote_socket_address)
{
	this->remote_socket_address = remote_socket_address;
}
void Frame802_3::set_protocol_type(string protocol_type)
{
	this->protocol_type = protocol_type;
}
void Frame802_3::make_network_node_socket_bytes(vector<unsigned char> *bytesVector)
{
	string tmp;
	int i, num;

	tmp = remote_net_address; // remote_network
	for (i = 0; i < 4; i++)
	{
		num = strtol(tmp.substr(3 * i, 2).c_str(),NULL, 16);
		bytesVector->push_back(num);
	}

	
	tmp = get_remote_mac_address(); //remote_node
	for (i = 0; i < 6; i++)
	{
		num = strtol(tmp.substr(3 * i, 2).c_str(), NULL, 16);
		bytesVector->push_back(num);
	}

	tmp = remote_socket_address; // remote_socket
	for (i = 0; i < 2; i++)
	{
		num = strtol(tmp.substr(3 * i, 2).c_str(), NULL, 16);
		bytesVector->push_back(num);
	}

	tmp = local_net_address; // local_network
	for (i = 0; i < 4; i++)
	{
		num = strtol(tmp.substr(3 * i, 2).c_str(), NULL, 16);
		bytesVector->push_back(num);
	}


	tmp = get_local_mac_address(); //local_node
	for (i = 0; i < 6; i++)
	{
		num = strtol(tmp.substr(3 * i, 2).c_str(), NULL, 16);
		bytesVector->push_back(num);
	}

	tmp = local_socket_address; // local_socket
	for (i = 0; i < 2; i++)
	{
		num = strtol(tmp.substr(3 * i, 2).c_str(), NULL, 16);
		bytesVector->push_back(num);
	}




}
void Frame802_3::make_IPX_header_bytes(vector<unsigned char> *vectorBytes)
{
	vectorBytes->push_back(0x00);
	vectorBytes->push_back(30);

	vectorBytes->push_back(0xFF); //always 0xFFFF
	vectorBytes->push_back(0xFF);

	vectorBytes->push_back(0x00);
	vectorBytes->push_back(0x1E); // length
	vectorBytes->push_back(0x00); //transport control

	
	if (!strcmp(protocol_type.c_str(), "PEP")) // type
		vectorBytes->push_back(0x04);
	else
		vectorBytes->push_back(0x00);

	make_network_node_socket_bytes(vectorBytes);


}
vector<unsigned char> Frame802_3::generateBytes()
{
	vector<unsigned char> bytes;

	local_and_remote_mac_address_to_bytes(&bytes);
	make_IPX_header_bytes(&bytes);
	

	return bytes;
}

Frame802_3::~Frame802_3()
{
}
