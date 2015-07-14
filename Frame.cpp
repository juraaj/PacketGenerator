#include "Frame.h"
#include <vector>

Frame::Frame()
{
}
void Frame::set_index(int index)
{
		this->index = index;
}
void Frame::set_frame_type(string frame_type)
{
	this->frame_type = frame_type;
}
void Frame::set_local_mac_address(string local_mac_address)
{
	this->local_mac_address = local_mac_address;
}
void Frame::set_remote_mac_address(string remote_mac_address)
{
	this->remote_mac_address = remote_mac_address;
}
void Frame::set_protocol(string protocol)
{
	this->protocol = protocol;
}
void Frame::set_packets_num(int packets_num)
{
	this->packets_num = packets_num;
}
void Frame::local_and_remote_mac_address_to_bytes(vector<unsigned char> *bytesVector)
{
	string tmp;
	int i, hexNum;

	tmp = get_local_mac_address();

	for (i = 0; i < 6; i++)
	{
		hexNum = stoi(tmp.substr(3 * i, 2), 0, 16);
		bytesVector->push_back(hexNum);
	}

	tmp = get_remote_mac_address();

	for (i = 0; i < 6; i++)
	{
		hexNum = stoi(tmp.substr(3 * i, 2), 0, 16);
		bytesVector->push_back(hexNum);
	}
}

vector<unsigned char> Frame::generateBytes()
{
	vector<unsigned char> a;

	return a;
}

Frame::~Frame()
{
}
