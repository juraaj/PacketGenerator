#include "Generator.h"

Generator::Generator()
{
}
bool Generator::is_number(string numStr)
{
	return !numStr.empty() && numStr.find_first_not_of("0123456789") == numStr.npos;
}
void Generator::fill_TCP_UDP(TiXmlElement *item, FrameEthernet *frameEthernet, string protocol_type)
{
	string tmp, local_port, remote_port;

	local_port = item->FirstChildElement("local_port")->GetText();
	
	remote_port = item->FirstChildElement("remote_port")->GetText();
	

	if (!strcmp(protocol_type.c_str(), "UDP"))
	{
		frameEthernet->set_protocol_type(new UDPProtocol(atoi(local_port.c_str()), atoi(remote_port.c_str()), "UDP"));
	}
	else if (protocol_type.c_str(), "TCP")
	{
		frameEthernet->set_protocol_type(new TCPProtocol(atoi(local_port.c_str()), atoi(remote_port.c_str()), "TCP"));
	}


	tmp = item->FirstChildElement("packets_num")->GetText();
	if (is_number(tmp))
		frameEthernet->set_packets_num(atoi(tmp.c_str()));
	

}
void Generator::fill_IRTP(TiXmlElement *item, FrameEthernet *frameEthernet)
{
	string type, port, sequence_number;

	type = item->FirstChildElement("type")->GetText();
	port = item->FirstChildElement("port")->GetText();
	sequence_number = item->FirstChildElement("sequence_number")->GetText();
	
 	frameEthernet->set_protocol_irtp(new IRTPProtocol(atoi(type.c_str()), atoi(port.c_str()), atoi(sequence_number.c_str()), 8));

	frameEthernet->set_packets_num(atoi(item->FirstChildElement("packets_num")->GetText()));
}
bool Generator::fillFrameEthernet(TiXmlElement *item, FrameEthernet *frameEthernet)
{
	string tmp;
		

	tmp = item->FirstChildElement("index")->GetText();
	if (is_number(tmp))
		frameEthernet->set_index(atoi(tmp.c_str()));
	else
		return 0;

	frameEthernet->set_frame_type("Ethernet");
	
	if(item->FirstChildElement("local_mac_address")->GetText() == NULL)
		frameEthernet->set_local_mac_address("FF-FF-FF-FF-FF-FF");
	else
		frameEthernet->set_local_mac_address(item->FirstChildElement("local_mac_address")->GetText());
		
	if(item->FirstChildElement("remote_mac_address")->GetText() == NULL)
		frameEthernet->set_remote_mac_address("FF-FF-FF-FF-FF-FF");
	else
	 frameEthernet->set_remote_mac_address(item->FirstChildElement("remote_mac_address")->GetText());

	
	frameEthernet->set_protocol(item->FirstChildElement("protocol")->GetText());
	frameEthernet->set_version(atoi(item->FirstChildElement("version")->GetText()));
	frameEthernet->set_local_address(item->FirstChildElement("local_address")->GetText());
	frameEthernet->set_remote_address(item->FirstChildElement("remote_address")->GetText());
	tmp = item->FirstChildElement("protocol_type")->GetText();

	if (!strcmp(tmp.c_str(), "TCP") || !strcmp(tmp.c_str(), "UDP"))
		fill_TCP_UDP(item, frameEthernet, tmp);
	else
		fill_IRTP(item, frameEthernet);

	 
	return 1;
}
bool Generator::fillFrame802_3(TiXmlElement *item, Frame802_3 *frame802_3)
{
	string tmp;

	tmp = item->FirstChildElement("index")->GetText();
	if (is_number(tmp))
		frame802_3->set_index(atoi(tmp.c_str()));
	else
		return 0;
	frame802_3->set_frame_type("802.3");
	frame802_3->set_local_mac_address(item->FirstChildElement("local_mac_address")->GetText());
	frame802_3->set_remote_mac_address(item->FirstChildElement("remote_mac_address")->GetText());
	frame802_3->set_protocol(item->FirstChildElement("protocol")->GetText());
	frame802_3->set_local_net_address(item->FirstChildElement("local_net_address")->GetText());
	frame802_3->set_local_socket_address(item->FirstChildElement("local_socket_address")->GetText());
	frame802_3->set_remote_net_address(item->FirstChildElement("remote_net_address")->GetText());
	frame802_3->set_remote_socket_address(item->FirstChildElement("remote_socket_address")->GetText());
	frame802_3->set_protocol_type(item->FirstChildElement("protocol_type")->GetText());

	tmp = item->FirstChildElement("packets_num")->GetText();
	if (is_number(tmp))
		frame802_3->set_packets_num(atoi(tmp.c_str()));
	else
		return 0;

	return 1;
	
}
int Generator::parseXmlAndCreateObjects(string filename)
{
	TiXmlDocument XmlFile;
	TiXmlElement *root,*item;
	string elementName;
	FrameEthernet *frameEthernet;
	Frame802_3 *frame802_3;
	
	
	XmlFile.LoadFile(filename.c_str()); //konverzia na const char*
	root = XmlFile.FirstChildElement();


	for (item = root->FirstChildElement(); item != NULL; item = item->NextSiblingElement())
	{
		elementName = item->FirstChildElement("frame_type")->GetText();
		if (!strcmp(elementName.c_str(), "Ethernet"))
		{
			frameEthernet = new FrameEthernet();
			if (fillFrameEthernet(item, frameEthernet))
				packets.push_back(frameEthernet);
			else
				return 0;
		}
		else if (!strcmp(elementName.c_str(), "802.3"))
		{
			frame802_3 = new Frame802_3();
			if (fillFrame802_3(item, frame802_3))
			    packets.push_back(frame802_3);
			else
				return 0;
		}
		else
		{
			cout << "Unknown value in tag <frame_type>." << endl;
			return 0;
		}
	} // end of for

	return 1;

}
int Generator::makeBytesVector(int index)
{
	vector<unsigned char> tmp;

	tmp = packets[index]->generateBytes(); // moze sa deletnut cez tmp
	bytesVector.insert(bytesVector.begin(), tmp.begin(), tmp.end());	
	
	return packets[index]->get_packets_num();
}
int Generator::bytesVector2BytesArray()
{
	int size;

	size = (int)bytesVector.size();
	this->bytes = new unsigned char[bytesVector.size()];

	for (int i = 0; i < size; i++)
		this->bytes[i] = this->bytesVector[i];

	return 1;
}
int Generator::dumpToFile(pcap_t *p, pcap_dumper_t *out_file, int amount)
{
	pcap_pkthdr header;
	timeval *ts;

	ts = (timeval*)malloc(sizeof(pcap_pkthdr));
	header.caplen = this->bytesVector.size();
	header.len = this->bytesVector.size();
	header.ts = *ts;

	for (int i = 0; i < amount; i++)
		pcap_dump((u_char*)out_file, &header, bytes);

	return 1;
}
int Generator::generatePackets(string inFileName, string outFileName)
{
	pcap_t *p;
	pcap_dumper_t *out_file;
	int packetsSize, amount;

	
	if (!parseXmlAndCreateObjects(inFileName))
		return 0;
	
	packetsSize = (int)packets.size();
	
	p = pcap_open_dead(1, 65536);
	out_file = pcap_dump_open(p, outFileName.c_str());

	for (int i = 0; i < packetsSize; i++)
	{
		amount = makeBytesVector(i); //funkcia vrati pocet, kolko ma byt podla xml vygenerovanych paketov (ch)
		bytesVector2BytesArray();
		dumpToFile(p,out_file, amount);
				
		bytesVector.clear();
		delete[] bytes;
	}
	
	return 1;
}
Generator::~Generator()
{
}
