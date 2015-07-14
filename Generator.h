#pragma once
#include <vector>
#include <iostream>
#include <pcap.h>

#include "tinyxml.h"
#include "FrameEthernet.h"
#include "Frame802_3.h"
#include "TCPProtocol.h"
#include "UDPProtocol.h"
#include "IRTPProtocol.h"


using namespace std;

class Generator
{
private:
	vector<Frame*> packets;
	vector<unsigned char> bytesVector;
	unsigned char *bytes;
	bool fillFrameEthernet(TiXmlElement *item, FrameEthernet *frameEthernet);
	bool fillFrame802_3(TiXmlElement *item, Frame802_3 *frame802_3);
	bool is_number(string numStr);
	int dumpToFile(pcap_t *p, pcap_dumper_t *out_file, int count);
	int makeBytesVector(int index);
	int bytesVector2BytesArray(void);
	void fill_TCP_UDP(TiXmlElement *item, FrameEthernet *frameEthernet, string protocol_type);
	void fill_IRTP(TiXmlElement *item, FrameEthernet *frameEthernet);
public:
	Generator();
	int parseXmlAndCreateObjects(string filename);
	int generatePackets(string inFileName, string outFileName);
	~Generator();
};

