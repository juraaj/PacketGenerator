#include "Menic.h"


Menic::Menic()
{
}

int Menic::readBytesFromDump(string filename)
{
	vector <unsigned char> tmp;
	char errbuff[PCAP_ERRBUF_SIZE];
	struct pcap_pkthdr *header;
	const u_char *data;
	int row = 0;

	
	pcap_t *pcap = pcap_open_offline(filename.c_str(), errbuff);
	if (pcap == NULL)
		return 0;

	u_int packetCount = 0;

		while (int returnValue = pcap_next_ex(pcap, &header, &data) >= 0)
		{
			this->packets.push_back(tmp);
			for (u_int i = 0; i < header->caplen; i++)
			{
				this->packets[row].push_back(data[i]);
			}
			row++;
		}
		return 1;
}
int Menic::performFiltering(string fileXml, string outFile)
{
	TiXmlDocument XmlFile;
	TiXmlElement *configure_summary, *item, *filter_params, *change_params;
	string elementName, parameter;
	string a;
	TCP_UDPMenic *tcpUdpMenic;
	IRTPMenic *irtpMenic;
	IPXMenic *ipxMenic;
	


	XmlFile.LoadFile(fileXml.c_str());
	configure_summary = XmlFile.FirstChildElement();
	if (configure_summary == NULL)
		return -1;

	for (item = configure_summary->FirstChildElement(); item != NULL; item = item->NextSiblingElement())
	{
		
		filter_params = item->FirstChildElement("filter_parameters");
		change_params = item->FirstChildElement("change_parameters");
		parameter = filter_params->FirstChildElement("protocol")->GetText();

		if (!strcmp(parameter.c_str(), "TCP"))
		{
			tcpUdpMenic = new TCP_UDPMenic(filter_params, change_params, packets, &filtered);
			tcpUdpMenic->performFiltering("TCP");
		
			tcpUdpMenic = NULL;
		}
		if (!strcmp(parameter.c_str(), "UDP"))
		{
			tcpUdpMenic = new TCP_UDPMenic(filter_params, change_params, packets, &filtered);
			tcpUdpMenic->performFiltering("UDP");

			tcpUdpMenic = NULL;
		}
		if (!strcmp(parameter.c_str(), "IRTP"))
		{
			irtpMenic = new IRTPMenic(filter_params, change_params, packets, &filtered);
			irtpMenic->performFiltering();

			irtpMenic = NULL;
		}
		if (!strcmp(parameter.c_str(), "IPX"))
		{
			ipxMenic = new IPXMenic(filter_params, change_params, packets, &filtered);
			ipxMenic->performFiltering();

			ipxMenic = NULL;
		}

	}

	dumpToFile(filtered, outFile);
	
	return 1;

}
unsigned char* Menic::vectorToBytes(vector<unsigned char> actualPacket)
{
	int size;
	unsigned char *bytes;

	size = (int)actualPacket.size();
	bytes = new unsigned char[size];

	for (int i = 0; i < size; i++)
		bytes[i] = actualPacket.at(i);


	return bytes;
}
void Menic::dumpToFile(vector<vector<unsigned char>> filtered, string outFileName)
{
	pcap_pkthdr header;
	timeval *ts;
	pcap_t *p;
	pcap_dumper_t *out_file;
	unsigned char *bytes;

	p = pcap_open_dead(1, 65536);
	out_file = pcap_dump_open(p, outFileName.c_str());

	ts = (timeval*)malloc(sizeof(pcap_pkthdr));
	
	for (int i = 0; i < filtered.size(); i++)
	{
		header.caplen = this->filtered.at(i).size();
		header.len = this->filtered.at(i).size();
		header.ts = *ts;
		bytes = vectorToBytes(filtered.at(i));
		pcap_dump((u_char*)out_file, &header, bytes);
	}

}
int Menic::change(string in_fileXml, string inFile, string outFile)
{
	int OK;

	OK = readBytesFromDump(inFile);

	if (!OK)
		return 0;

	OK = performFiltering(in_fileXml, outFile);
	if (OK == -1)
		return -1;

	return 1;
}
Menic::~Menic()
{
}
