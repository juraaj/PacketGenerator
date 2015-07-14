#include "IPXMenic.h"


IPXMenic::IPXMenic(TiXmlElement *filter_params, TiXmlElement *change_params, vector<vector<unsigned char>> packets, vector<vector<unsigned char>> *filtered)
{
	this->filter_params = filter_params;
	this->change_params = change_params;
	this->packets = packets;
	this->filtered = filtered;
}
unsigned char IPXMenic::getNumOfProtocol(string type)
{
	if (!strcmp(type.c_str(), "Unknown"))
		return 0x00;
	else if (!strcmp(type.c_str(), "RIP"))
		return 0x01;
	else if (!strcmp(type.c_str(), "Echo"))
		return 0x02;
	else if (!strcmp(type.c_str(), "PEP"))
		return 0x04;
	else if (!strcmp(type.c_str(), "SPX"))
		return 0x05;
	else if (!strcmp(type.c_str(), "NCP"))
		return 0x11;

	return 0x00;
}
void IPXMenic::changeIPXPacket(vector<unsigned char> *actualPacket)
{
	int tmp;

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
	if (!changetransControl.empty())
	{
		actualPacket->at(18) = (unsigned char)stoi(type, 0, 16);
	}
	if (!changeType.empty())
	{
		tmp = getNumOfProtocol(changeType);
		actualPacket->at(19) = tmp;
	}
	if (!changeDstNetwork.empty())
	{
		for (int i = 0; i < 4; i++)
		{
			tmp = (unsigned char)stoi(changeDstNetwork.substr(i * 3, 2).c_str(), 0, 16);
			actualPacket->at(20 + i) = tmp;
		}
	}
	if (!changeDstNode.empty())
	{
		for (int i = 0; i < 4; i++)
		{
			tmp = (unsigned char)stoi(changeDstNode.substr(i * 3, 2).c_str(), 0, 16);
			actualPacket->at(24 + i) = tmp;
		}
	}
	if (!changeDstSocket.empty())
	{
		actualPacket->at(30) = stoi(changeDstSocket.substr(0, 2).c_str(), 0, 16);
		actualPacket->at(31) = stoi(changeDstSocket.substr(3, 2).c_str(), 0, 16);
	}
	if (!changeSrcNetwork.empty())
	{
		for (int i = 0; i < 4; i++)
		{
			tmp = (unsigned char)stoi(changeSrcNetwork.substr(i * 3, 2).c_str(), 0, 16);
			actualPacket->at(32 + i) = tmp;
		}
	}
	if (!changeSrcNode.empty())
	{
		for (int i = 0; i < 6; i++)
		{
			tmp = (unsigned char)stoi(changeSrcNode.substr(i * 3, 2).c_str(), 0, 16);
			actualPacket->at(36 + i) = tmp;
		}
	}
	if (!changeSrcSocket.empty())
	{
		actualPacket->at(42) = stoi(changeSrcSocket.substr(0, 2).c_str(), 0, 16);
		actualPacket->at(43) = stoi(changeSrcSocket.substr(3, 2).c_str(), 0, 16);
	}
}
bool IPXMenic::checkSrcMAC(vector<unsigned char> actualPacket)
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
bool IPXMenic::checkDstMAC(vector<unsigned char> actualPacket)
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
bool IPXMenic::checkParams(vector<unsigned char> actualPacket)
{
	return (checkSrcMAC(actualPacket) && checkDstMAC(actualPacket) &&
			checkTransControl(actualPacket) && checkType(actualPacket) &&
			checkSrcNetwork(actualPacket) && checkSrcNode(actualPacket) &&
			checkSrcSocket(actualPacket) && checkDstNetwork(actualPacket) &&
			checkDstNode(actualPacket) && checkDstSocket(actualPacket));
}
bool IPXMenic::checkTransControl(vector<unsigned char> actualPacket)
{
	if (transControl.empty())
		return true;

	if (actualPacket[18] == stoi(transControl.c_str(), 0, 16));
		return true;

	return false;
}
bool IPXMenic::checkType(vector<unsigned char> actualPacket)
{
	unsigned char tmp;

	if (type.empty())
		return true;

	tmp = getNumOfProtocol(type);

	if (actualPacket[19] == tmp);
		return true;

	return false;
}
bool IPXMenic::checkDstNetwork(vector<unsigned char> actualPacket)
{
	int tmp;

	if (DstNetwork.empty())
		return true;

	for (int i = 0; i < 4; i++)
	{
		tmp = (unsigned char)stoi(DstNetwork.substr(i * 3, 2).c_str(), 0, 16);
		if (tmp != actualPacket[20 + i])
			return false;
	}
	return true;
}
bool IPXMenic::checkDstNode(vector<unsigned char> actualPacket)
{
	int tmp;

	if (DstNode.empty())
		return true;

	for (int i = 0; i < 4; i++)
	{
		tmp = (unsigned char)stoi(DstNode.substr(i * 3, 2).c_str(), 0, 16);
		if (tmp != actualPacket[24 + i])
			return false;
	}
	return true;
}
bool IPXMenic::checkDstSocket(vector<unsigned char> actualPacket)
{

	if (DstSocket.empty())
		return true;

	return ((actualPacket[30] == stoi(DstSocket.substr(0, 2).c_str(), 0, 16)) &&
			(actualPacket[31] == stoi(DstSocket.substr(3, 2).c_str(), 0, 16)));
	
}
bool IPXMenic::checkSrcNetwork(vector<unsigned char> actualPacket)
{
	int tmp;

	if (SrcNetwork.empty())
		return true;

	for (int i = 0; i < 4; i++)
	{
		tmp = (unsigned char)stoi(SrcNetwork.substr(i * 3, 2).c_str(), 0, 16);
		if (tmp != actualPacket[32 + i])
			return false;
	}

	return true;

}
bool IPXMenic::checkSrcNode(vector<unsigned char> actualPacket)
{
	int tmp;

	if (SrcNode.empty())
		return true;

	for (int i = 0; i < 6; i++)
	{
		tmp = (unsigned char)stoi(SrcNode.substr(i * 3, 2).c_str(), 0, 16);
		if (tmp != actualPacket[36 + i])
			return false;
	}
	return true;
}
bool IPXMenic::checkSrcSocket(vector<unsigned char> actualPacket)
{
	if (SrcSocket.empty())
		return true;

	return ((actualPacket[42] == stoi(SrcSocket.substr(0, 2).c_str(), 0, 16)) &&
			(actualPacket[43] == stoi(SrcSocket.substr(3, 2).c_str(), 0, 16)));
}
void IPXMenic::filterIPXPackets()
{
	vector<unsigned char> actualPacket;
	int i;

	for (i = 0; i < packets.size(); i++)
	{
		actualPacket = packets[i];

		if ((actualPacket[14] == 0xFF) && (actualPacket[15] == 0xFF) && 
			checkParams(actualPacket))
		{
			changeIPXPacket(&actualPacket);
			filtered->push_back(actualPacket);
		}
	}
}
void IPXMenic::getIPXChangeParams()
{
	TiXmlElement *element;

	element = change_params->FirstChildElement("local_mac_address");
	if (element != NULL)
		changeSrcMAC = element->GetText();

	element = change_params->FirstChildElement("remote_mac_address");
	if (element != NULL)
		changeDstMAC = element->GetText();

	element = change_params->FirstChildElement("transport_control");
	if (element != NULL)
		changetransControl = element->GetText();

	element = change_params->FirstChildElement("protocol_type");
	if (element != NULL)
		changeType = element->GetText();

	element = change_params->FirstChildElement("remote_net_address");
	if (element != NULL)
		changeDstNetwork = element->GetText();

	element = change_params->FirstChildElement("remote_mac_address");
	if (element != NULL)
		changeDstNode = element->GetText();

	element = change_params->FirstChildElement("remote_socket_address");
	if (element != NULL)
		changeDstSocket = element->GetText();
	/*********************************************************************/
	element = change_params->FirstChildElement("local_net_address");
	if (element != NULL)
		changeSrcNetwork = element->GetText();

	element = change_params->FirstChildElement("local_mac_address");
	if (element != NULL)
		changeSrcNode = element->GetText();

	element = change_params->FirstChildElement("local_socket_address");
	if (element != NULL)
		changeSrcSocket = element->GetText();
}
void IPXMenic::getIPXFilteringParams()
{
	TiXmlElement *element;

	element = filter_params->FirstChildElement("local_mac_address");
	if (element != NULL)
		SrcMAC = element->GetText();

	element = filter_params->FirstChildElement("remote_mac_address");
	if (element != NULL)
		DstMAC = element->GetText();

	element = filter_params->FirstChildElement("transport_control");
	if (element != NULL)
		transControl = element->GetText();

	element = filter_params->FirstChildElement("protocol_type");
	if (element != NULL)
		type = element->GetText();

	element = filter_params->FirstChildElement("remote_net_address");
	if (element != NULL)
		DstNetwork = element->GetText();

	element = filter_params->FirstChildElement("remote_mac_address");
	if (element != NULL)
		DstNode = element->GetText();

	element = filter_params->FirstChildElement("remote_socket_address");
	if (element != NULL)
		DstSocket = element->GetText();
	/*********************************************************************/
	element = filter_params->FirstChildElement("local_net_address");
	if (element != NULL)
		SrcNetwork = element->GetText();

	element = filter_params->FirstChildElement("local_mac_address");
	if (element != NULL)
		SrcNode = element->GetText();

	element = filter_params->FirstChildElement("local_socket_address");
	if (element != NULL)
		SrcSocket = element->GetText();

	


}
void IPXMenic::performFiltering()
{
	getIPXFilteringParams();
	getIPXChangeParams();
	filterIPXPackets();
}
IPXMenic::~IPXMenic()
{
}
