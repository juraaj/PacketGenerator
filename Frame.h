#pragma once
#include <string>
#include <vector>

using namespace std;

class Frame
{
private:
	int index;
	string frame_type;
	string local_mac_address;
	string remote_mac_address;
	string protocol;
	int packets_num;
public:
	Frame();
	string get_local_mac_address();
	string get_remote_mac_address();
	void local_and_remote_mac_address_to_bytes(vector<unsigned char> *bytesVector);
	string get_protocol();
	int get_packets_num();
	void set_index(int index);
	void set_frame_type(string frame_type);
	void set_local_mac_address(string local_mac_address);
	void set_remote_mac_address(string remote_mac_address);
	void set_protocol(string protocol);
	void set_packets_num(int packets_num);
	virtual vector<unsigned char> generateBytes(void);
	~Frame();
};

