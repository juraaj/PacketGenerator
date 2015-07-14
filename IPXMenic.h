#pragma once
#include <vector>
#include <string>

#include "tinyxml.h"

using namespace std;

class IPXMenic
{
private:
	TiXmlElement *filter_params, *change_params;
	vector<vector<unsigned char>> packets;
	vector<vector<unsigned char>> *filtered;
	string SrcMAC;
	string DstMAC;
	string transControl;
	string type;
	string DstNetwork;
	string DstNode;
	string DstSocket;
	string SrcNetwork;
	string SrcNode;
	string SrcSocket;
	string changeSrcMAC;
	string changeDstMAC;
	string changetransControl;
	string changeType;
	string changeDstNetwork;
	string changeDstNode;
	string changeDstSocket;
	string changeSrcNetwork;
	string changeSrcNode;
	string changeSrcSocket;
	void changeIPXPacket(vector<unsigned char> *actualPacket);
	bool checkTransControl(vector<unsigned char> actualPacket);;
	bool checkType(vector<unsigned char> actualPacket);;
	bool checkDstNetwork(vector<unsigned char> actualPacket);
	bool checkDstNode(vector<unsigned char> actualPacket);
	bool checkDstSocket(vector<unsigned char> actualPacket);
	bool checkSrcNetwork(vector<unsigned char> actualPacket);
	bool checkSrcNode(vector<unsigned char> actualPacket);
	bool checkSrcSocket(vector<unsigned char> actualPacket);
	bool checkSrcMAC(vector<unsigned char> actualPacket);
	bool checkDstMAC(vector<unsigned char> actualPacket);
	unsigned char getNumOfProtocol(string type);
	void getParsedAddress(unsigned char *part1, unsigned char *part2, unsigned char *part3, unsigned char *part4, string address);
	bool checkParams(vector<unsigned char> actualPacket);
	void filterIPXPackets();
	void getIPXFilteringParams();
	void getIPXChangeParams();
public:
	IPXMenic(TiXmlElement *filter_params, TiXmlElement *change_params, vector<vector<unsigned char>> packets, vector<vector<unsigned char>> *filtered);
	void performFiltering();
	~IPXMenic();
};

