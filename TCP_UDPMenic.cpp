#include "TCP_UDPMenic.h"


TCP_UDPMenic::TCP_UDPMenic(TiXmlElement *filter_params, TiXmlElement *change_params, vector<vector<unsigned char>> packets, 
							vector<vector<unsigned char>> *filtered)
{
	this->filter_params = filter_params;
	this->change_params = change_params;
	this->packets = packets;
	this->filtered = filtered;
}

void TCP_UDPMenic::getParsedAddress(unsigned char *part1, unsigned char *part2, unsigned char *part3, unsigned char *part4, string address)
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
bool TCP_UDPMenic::checkParams(vector<unsigned char> actualPacket)
{
	return (checkSrcMAC(actualPacket) && checkDstMAC(actualPacket) && checkSrcPort(actualPacket) &&
			checkDstPort(actualPacket) && checkSrcIP(actualPacket) &&
			checkDstIP(actualPacket));
}
bool TCP_UDPMenic::checkSrcMAC(vector<unsigned char> actualPacket)
{
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
bool TCP_UDPMenic::checkDstMAC(vector<unsigned char> actualPacket)
{
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
bool TCP_UDPMenic::checkSrcIP(vector<unsigned char> actualPacket)
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
bool TCP_UDPMenic::checkDstIP(vector<unsigned char> actualPacket)
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
bool TCP_UDPMenic::checkSrcPort(vector<unsigned char> actualPacket)
{
	int srcPortInPacket;

	if (SrcPort.empty())
		return true;

	srcPortInPacket = actualPacket.at(34) << 8;
	srcPortInPacket += actualPacket.at(35);

	if (srcPortInPacket == atoi(SrcPort.c_str()))
		return true;

	return false;
}
bool TCP_UDPMenic::checkDstPort(vector<unsigned char> actualPacket)
{
	int dstPortInPacket;

	if (DstPort.empty())
		return true;

	dstPortInPacket = actualPacket.at(36) << 8;
	dstPortInPacket += actualPacket.at(37);

	if (dstPortInPacket == atoi(DstPort.c_str()))
		return true;

	return false;
}
void TCP_UDPMenic::filterTCPPackets()
{
	vector<unsigned char> actualPacket;
	int i;

	for (i = 0; i < packets.size(); i++)
	{
		actualPacket = packets[i];
		if ((actualPacket[23] == 0x06) && checkParams(actualPacket))
		{
			changeTCPPacket(&actualPacket);
			calculateChecksumTCP_UDP(&actualPacket, "TCP");
			calculateChecksumIPv4(&actualPacket);
			filtered->push_back(actualPacket);
		}

	}
}
void TCP_UDPMenic::filterUDPPackets()
{
	vector<unsigned char> actualPacket;
	int i;

	for (i = 0; i < packets.size(); i++)
	{
		actualPacket = packets[i];
		if ((actualPacket[23] == 0x11) && checkParams(actualPacket))
		{
			changeUDPPacket(&actualPacket);
			calculateChecksumTCP_UDP(&actualPacket, "UDP");
			calculateChecksumIPv4(&actualPacket);
			filtered->push_back(actualPacket);
		}

	}
}
void TCP_UDPMenic::getTCPChangeParams()
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

	element = change_params->FirstChildElement("local_port");
	if (element != NULL)
		changeSrcPort = element->GetText();

	element = change_params->FirstChildElement("remote_port");
	if (element != NULL)
		changeDstPort = element->GetText();
}
void TCP_UDPMenic::getUDPCHangeParams()
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

	element = change_params->FirstChildElement("local_port");
	if (element != NULL)
		changeSrcPort = element->GetText();

	element = change_params->FirstChildElement("remote_port");
	if (element != NULL)
		changeDstPort = element->GetText();
}
void TCP_UDPMenic::getUDPFilteringParams()
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

	element = filter_params->FirstChildElement("local_port");
	if (element != NULL)
		DstPort = element->GetText();

	element = filter_params->FirstChildElement("remote_port");
	if (element != NULL)
		SrcPort = element->GetText();
}
void TCP_UDPMenic::getTCPFilteringParams()
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

	element = filter_params->FirstChildElement("local_port");
	if (element != NULL)
		DstPort = element->GetText();

	element = filter_params->FirstChildElement("remote_port");
	if (element != NULL)
		SrcPort = element->GetText();
}
void TCP_UDPMenic::changeTCPPacket(vector<unsigned char> *actualPacket)
{
	int srcPort, dstPort;
	unsigned char addrPart1, addrPart2, addrPart3, addrPart4, tmp;

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
			actualPacket->at(i + 6) = tmp;
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
	if (!changeSrcPort.empty())
	{
		srcPort = atoi(changeSrcPort.c_str());

		actualPacket->at(34) = (unsigned char)srcPort >> 8;
		actualPacket->at(35) = (unsigned char)srcPort & 0xFF;
	}
	if (!changeDstPort.empty())
	{
		dstPort = atoi(changeDstPort.c_str());

		// ked je cislo vacsie ako 256 pretypovanie na unsigned char hornych 8 bitov pokazi... neviem preco :D
		actualPacket->at(36) = (unsigned char)dstPort >> 8;
		actualPacket->at(37) = (unsigned char)dstPort & 0xFF;
	}
}
void TCP_UDPMenic::changeUDPPacket(vector<unsigned char> *actualPacket)
{
	int srcPort, dstPort;
	unsigned char addrPart1, addrPart2, addrPart3, addrPart4,tmp;

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
			actualPacket->at(i + 6) = tmp;
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
		actualPacket->at(26) = addrPart1;
		actualPacket->at(27) = addrPart2;
		actualPacket->at(28) = addrPart3;
		actualPacket->at(29) = addrPart4;
	}
	if (!changeSrcPort.empty())
	{
		srcPort = atoi(changeSrcPort.c_str());

		actualPacket->at(34) = (unsigned char)srcPort >> 8;
		actualPacket->at(35) = (unsigned char)srcPort & 0xFF;
	}
	if (!changeDstPort.empty())
	{
		dstPort = atoi(changeDstPort.c_str());

		actualPacket->at(36) = (unsigned char)dstPort >> 8;
		actualPacket->at(37) = (unsigned char)dstPort & 0xFF;
	}
}
void TCP_UDPMenic::calculateChecksumTCP_UDP(vector<unsigned char> *packet, string tcp_udp)
{
	int tmp, fifthByte;

	if (!strcmp(tcp_udp.c_str(), "UDP"))
	{
		tmp = packet->at(26) << 8;
		tmp += packet->at(27);
		tmp += packet->at(28) << 8;
		tmp += packet->at(29);
		tmp += packet->at(30) << 8;
		tmp += packet->at(31);
		tmp += packet->at(32) << 8;
		tmp += packet->at(33);

		tmp += 0x11; // protocol
		tmp += 8; //length
		tmp += packet->at(34) << 8;
		tmp += packet->at(35);
		tmp += packet->at(36) << 8;
		tmp += packet->at(37);
		tmp += 8; //

		fifthByte = (tmp & 0xF0000) >> 16;
		tmp = tmp & 0xFFFF;
		tmp += fifthByte;
		tmp = ~tmp & 0xFFFF;

		packet->at(40) = tmp >> 8;
		packet->at(41) = tmp & 0xFF;
	}
	else if (!strcmp(tcp_udp.c_str(), "TCP"))
	{
		tmp = packet->at(26) << 8;
		tmp += packet->at(27);
		tmp += packet->at(28) << 8;
		tmp += packet->at(29);
		tmp += packet->at(30) << 8;
		tmp += packet->at(31);
		tmp += packet->at(32) << 8;
		tmp += packet->at(33);

		tmp += 0x06; // TCP
		tmp += 20; //TCP length

		tmp += packet->at(34) << 8;
		tmp += packet->at(35);
		tmp += packet->at(36) << 8;
		tmp += packet->at(37);

		tmp += 0x5000; // data offser + reserved + flags

		fifthByte = (tmp & 0xF0000) >> 16;
		tmp = tmp & 0xFFFF;
		tmp += fifthByte;
		tmp = ~tmp & 0xFFFF;
	}

}
void TCP_UDPMenic::calculateChecksumIPv4(vector<unsigned char> *packet)
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
void TCP_UDPMenic::performFiltering(string tcp_udp)
{
	if (!strcmp(tcp_udp.c_str(), "UDP"))
	{
		getUDPFilteringParams();
		getUDPCHangeParams();
		filterUDPPackets();
	}
	else
	{
		getTCPFilteringParams();
		getTCPChangeParams();
		filterTCPPackets();
	}
}
TCP_UDPMenic::~TCP_UDPMenic()
{
}
