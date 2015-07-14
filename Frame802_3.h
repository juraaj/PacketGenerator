#pragma once
#include "Frame.h"
class Frame802_3 :
	public Frame
{
private:
	string local_net_address;
	string local_socket_address;
	string remote_net_address;
	string remote_socket_address;
	string protocol_type;
	void make_IPX_header_bytes(vector<unsigned char> *vectorBytes);
	void make_network_node_socket_bytes(vector<unsigned char> *vectorBytes);
public:
	Frame802_3();
	void set_local_net_address(string local_net_address);
	void set_local_socket_address(string local_socket_address);
	void set_remote_net_address(string set_remote_net_address);
	void set_remote_socket_address(string remote_socket_address);
	void set_protocol_type(string protocol_type);
	vector<unsigned char> generateBytes() override;
	~Frame802_3();
};

