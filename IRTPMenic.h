#pragma once
#include <string>
#include <vector>

#include "tinyxml.h"

using namespace std;

class IRTPMenic
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
	string IRTPType;
	string IRTPPort;
	string IRTPSeqNumber;
	string changeIRTPType;
	string changeIRTPPort;
	string changeIRTPSeqNumber;
	void changeIRTPPacket(vector<unsigned char> *actualPacket);
	bool checkSrcMAC(vector<unsigned char> actualPacket);
	bool checkDstMAC(vector<unsigned char> actualPacket);
	bool checkSrcIP(vector<unsigned char> actualPacket);
	bool checkDstIP(vector<unsigned char> actualPacket);
	void getParsedAddress(unsigned char *part1, unsigned char *part2, unsigned char *part3, unsigned char *part4, string address);
	bool checkParams(vector<unsigned char> actualPacket);
	bool checkType(vector<unsigned char> actualPacket);
	bool checkPort(vector<unsigned char> actualPacket);
	bool checkSeqNumber(vector<unsigned char> actualPacket);
	void calculateChecksum(vector<unsigned char> *actualPacket);
	void calculateChecksumIPv4(vector<unsigned char> *packet);
	void filterIRTPPackets();
	void getIRTPFilteringParams();
	void getIRTPChangeParams();
public:
	IRTPMenic(TiXmlElement *filter_params, TiXmlElement *change_params, vector<vector<unsigned char>> packets, vector<vector<unsigned char>> *filtered);
	void performFiltering();
	~IRTPMenic();
};

