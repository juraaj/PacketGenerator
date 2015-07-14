#pragma once
#include <string>
#include <vector>

#include "tinyxml.h"

using namespace std;

class TCP_UDPMenic
{
private:
	TiXmlElement *filter_params, *change_params;
	vector<vector<unsigned char>> packets;
	vector<vector<unsigned char>> *filtered;
	string SrcMAC;
	string DstMAC;
	string changeSrcMAC;
	string changeDstMAC;
	string SrcIP;
	string DstIP;
	string changeSrcIP;
	string changeDstIP;
	string SrcPort;
	string DstPort;
	string changeSrcPort;
	string changeDstPort;
	bool checkParams(vector<unsigned char> actualPacket);
	bool checkSrcMAC(vector<unsigned char> actualPacket);
	bool checkDstMAC(vector<unsigned char> actualPacket);
	bool checkSrcIP(vector<unsigned char> actualPacket);
	bool checkDstIP(vector<unsigned char> actualPacket);
	void getParsedAddress(unsigned char *part1, unsigned char *part2, unsigned char *part3, unsigned char *part4, string address);
	void calculateChecksumTCP_UDP(vector<unsigned char> *packet, string tcp_udp);
	void calculateChecksumIPv4(vector<unsigned char> *packet);
	void filterTCPPackets();
	void filterUDPPackets();
	bool checkSrcPort(vector<unsigned char> actualPacket);
	bool checkDstPort(vector<unsigned char> actualPacket);
	void getTCPChangeParams();
	void getUDPCHangeParams();
	void getUDPFilteringParams();
	void getTCPFilteringParams();
	void changeUDPPacket(vector<unsigned char> *actualPacket);
	void changeTCPPacket(vector<unsigned char> *actualPacket);
public:
	TCP_UDPMenic(TiXmlElement *filter_params, TiXmlElement *change_params, vector<vector<unsigned char>> packets, vector<vector<unsigned char>> *filtered);
	
	void performFiltering(string tcp_udp);
	~TCP_UDPMenic();
};

