#pragma once
#include <vector>
#include <string>
#include <iostream>
#include <pcap.h>
#include <stdlib.h>
#include <iomanip>

#include "tinyxml.h"
#include "TCP_UDPMenic.h"
#include "IRTPMenic.h"
#include "IPXMenic.h"


using namespace std;

class Menic
{
private:
	vector<vector<unsigned char>> packets;
	vector<vector<unsigned char>> filtered;
		
	
	unsigned char* vectorToBytes(vector<unsigned char> actualPacket);
	void dumpToFile(vector<vector<unsigned char>> filtered, string outFileName);
	int filterAndChange(string filename);
	int readBytesFromDump(string filename);
	int performFiltering(string fileXml, string filename);
public:
	Menic();
	int change(string inFileXml, string inFile, string outFile);
	~Menic();
};

