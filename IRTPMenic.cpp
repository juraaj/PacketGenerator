#include "IRTPMenic.h"


IRTPMenic::IRTPMenic(TiXmlElement *filter_params, TiXmlElement *change_params, vector<vector<unsigned char>> packets,
				     vector<vector<unsigned char>> *filtered)
{
	this->filter_params = filter_params;
	this->change_params = change_params;
	this->packets = packets;
	this->filtered = filtered;
}
void IRTPMenic::getParsedAddress(unsigned char *part1, unsigned char *part2, unsigned char *part3, unsigned char *part4, string address)
{
	string tmp;
	int i, num, endIndex, startIndex;
	vector<int> results;


	tmp = address;
	startIndex = 0;

	for (i = 0; i < 4; i++)
	{
		endIndex = tmp.find_first_of('.', startIndex);
		num = atoi(address.substr(startIndex, endIndex - startIndex).c_str());

		results.push_back(num);
		startIndex = endIndex + 1;
	}

	*part1 = results.at(0); //vratenie premennych
	*part2 = results.at(1);
	*part3 = results.at(2);
	*part4 = results.at(3);

}
bool IRTPMenic::checkSrcMAC(vector<unsigned char> actualPacket)
{
	unsigned char MAC[6];
	int tmp;

	if (SrcMAC.empty())
		return true;

	for (int i = 0; i < 6; i++)
	{
		tmp = (unsigned char)stoi(SrcMAC.substr(i * 3, 2).c_str(), 0, 16);
		if (tmp != actualPacket[i])
			return false;
	}
	
	return true;

}
bool IRTPMenic::checkDstMAC(vector<unsigned char> actualPacket)
{
	unsigned char MAC[6];
	int tmp;

	if (DstMAC.empty())
		return true;

	for (int i = 0; i < 6; i++)
	{
		tmp = (unsigned char)stoi(DstMAC.substr(i * 3, 2).c_str(), 0, 16);
		if (tmp != actualPacket[i + 6])
			return false;
	}

	return true;
}
bool IRTPMenic::checkSrcIP(vector<unsigned char> actualPacket)
{
	unsigned char addrPart1, addrPart2, addrPart3, addrPart4;

	if (SrcIP.empty())
		return true;

	getParsedAddress(&addrPart1, &addrPart2, &addrPart3, &addrPart4, SrcIP);

	return (addrPart1 == actualPacket.at(26) &&
		addrPart2 == actualPacket.at(27) &&
		addrPart3 == actualPacket.at(28) &&
		addrPart4 == actualPacket.at(29));
}
bool IRTPMenic::checkParams(vector<unsigned char> actualPacket)
{
	return (checkSrcMAC(actualPacket) && checkDstMAC(actualPacket) &&
			checkSrcIP(actualPacket) &&	checkDstIP(actualPacket) && 
			checkType(actualPacket)  && checkPort(actualPacket)  &&
			checkSeqNumber(actualPacket));
}
bool IRTPMenic::checkDstIP(vector<unsigned char> actualPacket)
{
	unsigned char addrPart1, addrPart2, addrPart3, addrPart4;

	if (DstIP.empty())
		return true;

	getParsedAddress(&addrPart1, &addrPart2, &addrPart3, &addrPart4, DstIP);

	return (addrPart1 == actualPacket.at(30) &&
		addrPart2 == actualPacket.at(31) &&
		addrPart3 == actualPacket.at(32) &&
		addrPart4 == actualPacket.at(33));
}
bool IRTPMenic::checkType(vector<unsigned char> actualPacket)
{
	unsigned char type;

	if (IRTPType.empty())
		return true;

	type = atoi(IRTPType.c_str());

	if (type == actualPacket.at(34))
		return true;

	return false;


}
bool IRTPMenic::checkPort(vector<unsigned char> actualPacket)
{
	unsigned char port;

	if (IRTPPort.empty())
		return true;

	port = atoi(IRTPPort.c_str());

	if (port == actualPacket.at(35))
		return true;

	return false;
}
bool IRTPMenic::checkSeqNumber(vector<unsigned char> actualPacket)
{
	int seqNum, seqNumInPacket;

	if (IRTPSeqNumber.empty())
		return true;

	seqNum = atoi(IRTPType.c_str());

	seqNumInPacket = actualPacket.at(36)<<8;
	seqNumInPacket += actualPacket.at(37);

	if (seqNum == seqNumInPacket)
		return true;

	return false;
}
void IRTPMenic::changeIRTPPacket(vector<unsigned char> *actualPacket)
{
	unsigned char type, port;
	unsigned char addrPart1, addrPart2, addrPart3, addrPart4;
	int seqNum, tmp;

	if (!changeSrcMAC.empty())
	{
		for (int i = 0; i < 6; i++)
		{
			tmp = (unsigned char)stoi(changeSrcMAC.substr(i * 3, 2).c_str(), 0, 16);
			actualPacket->at(i) = tmp;
		}
	}
	if (!changeDstMAC.empty())
	{
		for (int i = 0; i < 6; i++)
		{
			tmp = (unsigned char)stoi(changeDstMAC.substr(i * 3, 2).c_str(), 0, 16);
			actualPacket->at(i+6) = tmp;
		}
	}
	if (!changeSrcIP.empty())
	{
		getParsedAddress(&addrPart1, &addrPart2, &addrPart3, &addrPart4, changeSrcIP);
		actualPacket->at(26) = addrPart1;
		actualPacket->at(27) = addrPart2;
		actualPacket->at(28) = addrPart3;
		actualPacket->at(29) = addrPart4;
	}
	if (!changeDstIP.empty())
	{
		getParsedAddress(&addrPart1, &addrPart2, &addrPart3, &addrPart4, changeDstIP);
		actualPacket->at(30) = addrPart1;
		actualPacket->at(31) = addrPart2;
		actualPacket->at(32) = addrPart3;
		actualPacket->at(33) = addrPart4;
	}
	if (!changeIRTPType.empty())
	{
		type = atoi(changeIRTPType.c_str());
		actualPacket->at(34) = type;
	}
	if (!changeIRTPPort.empty())
	{
		port = atoi(changeIRTPPort.c_str());
		actualPacket->at(35) = port;
	}
	if (!changeIRTPSeqNumber.empty())
	{
		seqNum = atoi(changeIRTPSeqNumber.c_str());
		actualPacket->at(36) = seqNum >> 8;
		actualPacket->at(37) = seqNum & 0xFF;
	}
}
void IRTPMenic::calculateChecksum(vector<unsigned char> *actualPacket)
{
	int tmp = 0;

	tmp += actualPacket->at(34) << 8;
	tmp += actualPacket->at(35);
	tmp += actualPacket->at(36) << 8;
	tmp += actualPacket->at(37);
	tmp += actualPacket->at(38) << 8;
	tmp += actualPacket->at(39);

	tmp = ~tmp & 0xFFFF;

	actualPacket->at(40) = tmp >> 8;
	actualPacket->at(41) = tmp & 0xFF;
}
void IRTPMenic::calculateChecksumIPv4(vector<unsigned char> *packet)
{
	int tmp = 0, fifthByte;


	tmp += 0x4500;


	tmp += packet->at(16) << 8;
	tmp += packet->at(17);
	tmp += packet->at(18) << 8;
	tmp += packet->at(19);
	tmp += packet->at(20) << 8;
	tmp += packet->at(21);
	tmp += packet->at(22) << 8;
	tmp += packet->at(23);
	tmp += packet->at(26) << 8;
	tmp += packet->at(27);
	tmp += packet->at(28) << 8;
	tmp += packet->at(29);
	tmp += packet->at(30) << 8;
	tmp += packet->at(31);
	tmp += packet->at(32) << 8;
	tmp += packet->at(33);

	fifthByte = (tmp & 0xF0000) >> 16;
	tmp = tmp & 0xFFFF;
	tmp += fifthByte;
	tmp = ~tmp & 0xFFFF;

	packet->at(24) = tmp >> 8;
	packet->at(25) = tmp & 0xFF;
}
void IRTPMenic::filterIRTPPackets()
{
	vector<unsigned char> actualPacket;
	int i;

	for (i = 0; i < packets.size(); i++)
	{
		actualPacket = packets[i];

		if ((actualPacket[23] == 0x1C) && checkParams(actualPacket))
		{
			changeIRTPPacket(&actualPacket);
			calculateChecksum(&actualPacket);
			calculateChecksumIPv4(&actualPacket);
			filtered->push_back(actualPacket);
		}
	}
}
void IRTPMenic::getIRTPChangeParams()
{
	TiXmlElement *element;

	element = change_params->FirstChildElement("local_mac_address");
	if (element != NULL)
		changeSrcMAC = element->GetText();

	element = change_params->FirstChildElement("remote_mac_address");
	if (element != NULL)
		changeDstMAC = element->GetText();

	element = change_params->FirstChildElement("local_address");
	if (element != NULL)
		changeSrcIP = element->GetText();

	element = change_params->FirstChildElement("remote_address");
	if (element != NULL)
		changeDstIP = element->GetText();

	element = change_params->FirstChildElement("type");
	if (element != NULL)
		changeIRTPType = element->GetText();

	element = change_params->FirstChildElement("port");
	if (element != NULL)
		changeIRTPPort = element->GetText();

	element = change_params->FirstChildElement("sequence_number");
	if (element != NULL)
		changeIRTPSeqNumber = element->GetText();
}
void IRTPMenic::getIRTPFilteringParams()
{
	TiXmlElement *element;

	element = filter_params->FirstChildElement("local_mac_address");
	if (element != NULL)
		SrcMAC = element->GetText();

	element = filter_params->FirstChildElement("remote_mac_address");
	if (element != NULL)
		DstMAC = element->GetText();

	element = filter_params->FirstChildElement("local_address");
	if (element != NULL)
		SrcIP = element->GetText();

	element = filter_params->FirstChildElement("remote_address");
	if (element != NULL)
		DstIP = element->GetText();

	element = filter_params->FirstChildElement("type");
	if (element != NULL)
		IRTPType = element->GetText();

	element = filter_params->FirstChildElement("port");
	if (element != NULL)
		IRTPPort = element->GetText();

	element = filter_params->FirstChildElement("sequence_number");
	if (element != NULL)
		IRTPSeqNumber = element->GetText();
}
void IRTPMenic::performFiltering()
{
	getIRTPFilteringParams();
	getIRTPChangeParams();
	filterIRTPPackets();
}
IRTPMenic::~IRTPMenic()
{
}
