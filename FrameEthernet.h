#pragma once
#include "Frame.h"
#include "UDPProtocol.h"
#include "TCPProtocol.h"
#include "IRTPProtocol.h"

using namespace std;

class FrameEthernet : 
	public Frame
{
private:
	int version;
	string local_address;
	string remote_address;
	xDPProtocol *protocol_type;
	IRTPProtocol *irtp_protocol;	
	int local_port;
	int remote_port;
	void local_and_remote_address_to_bytes(vector<unsigned char> *bytesVector);
	void make_IP_header_bytes(vector<unsigned char> *bytesVector);
	void make_IPv4_header_bytes(vector<unsigned char> *bytesVector);
	void make_protocol_bytes(vector<unsigned char> *bytesVector);
	void make_checksum(vector<unsigned char> *bytesVector);
	void make_inner_protocol_checksum(vector<unsigned char> *bytesVector);
	public:
	FrameEthernet();
	void set_version(char version);
	void set_local_address(string local_address);
	void set_remote_address(string remote_address);
	void set_protocol_type(xDPProtocol *protocol_type);
	void set_protocol_irtp(IRTPProtocol * protocol_type);
	void set_version(int version);
	void set_local_port(int local_port);
	void set_remote_port(int remote_port);
	vector<unsigned char> generateBytes() override;
	~FrameEthernet();
};

