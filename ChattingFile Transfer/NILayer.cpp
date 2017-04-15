// NILayer.cpp: implementation of the CNILayer class.
// 네트워크 인터페이스 계층으로써의 역할이 주. 
// 데이터를 송수신하는 기능에 송수신하기 위해 네트워크 어댑터의 객체포인터를 가지고 그를 접근하기 위한 기능이 전부이다. 
//////////////////////////////////////////////////////////////////////

#include "stdafx.h"
#include "ipc.h"
#include "NILayer.h"

#ifdef _DEBUG
#undef THIS_FILE
static char THIS_FILE[]=__FILE__;
#define new DEBUG_NEW
#endif

//////////////////////////////////////////////////////////////////////
// Construction/Destruction
//////////////////////////////////////////////////////////////////////

CNILayer::CNILayer( char *pName, LPADAPTER *pAdapterObject, int iNumAdapter )
	: CBaseLayer( pName )
{
	m_AdapterObject = NULL;
	m_iNumAdapter = iNumAdapter;
	m_thrdSwitch = TRUE;
	SetAdapterList(NULL);
}

CNILayer::~CNILayer()
{
}

void CNILayer::PacketStartDriver()
{//패킷 드라이버 동작의 시작을 알리는 함수. 인자는 패킷 드라이버가 제공하는 서비스의 종류. 
	char errbuf[PCAP_ERRBUF_SIZE];

	if(m_iNumAdapter == -1){
		AfxMessageBox("Not exist NICard");
		return;
	}
	
	m_AdapterObject = pcap_open_live(m_pAdapterList[m_iNumAdapter]->name,1500,PCAP_OPENFLAG_PROMISCUOUS,2000,errbuf);
	if(!m_AdapterObject){
		AfxMessageBox(errbuf);
		return;
	}
	AfxBeginThread(ReadingThread, this);
}

pcap_if_t *CNILayer::GetAdapterObject(int iIndex)
{
	return m_pAdapterList[iIndex];
}

void CNILayer::SetAdapterNumber(int iNum)
{
	m_iNumAdapter = iNum;
}

void CNILayer::SetAdapterList(LPADAPTER *plist)
{
	pcap_if_t *alldevs;
	pcap_if_t *d;
	int i=0;
	
	char errbuf[PCAP_ERRBUF_SIZE];

	for(int j=0;j<NI_COUNT_NIC;j++)
	{
		m_pAdapterList[j] = NULL;
	}

	if(pcap_findalldevs(&alldevs, errbuf) == -1)
	{
		AfxMessageBox("Not exist NICard");
		return;
	}
	if(!alldevs)
	{
		AfxMessageBox("Not exist NICard");
		return;
	}

	for(d=alldevs; d; d=d->next)
	{
		m_pAdapterList[i++] = d;
	}
}

BOOL CNILayer::Send(unsigned char *ppayload, int nlength)
{
	if(pcap_sendpacket(m_AdapterObject,ppayload,nlength))
	{
	  //pcap_sendpacket() is called to send a hand-crafted packet.
      //pcap_sendpacket()은 전송하려는 데이터, 버퍼의 길이, 어댑터의 argument들을 가진다. 
      //it returns 0 on success.
		AfxMessageBox("패킷 전송 실패");
		return FALSE;
	}
	return TRUE;
}

BOOL CNILayer::Receive( unsigned char* ppayload )
{
	BOOL bSuccess = FALSE;

	bSuccess = mp_aUpperLayer[0]->Receive(ppayload);
	return bSuccess;
}

UINT CNILayer::ReadingThread(LPVOID pParam)
{
	//////////////////////// fill the blank ///////////////////////////////
	struct pcap_pkthdr *header;
	const u_char *pkt_data;
	int result;

	AfxBeginThread(FileTransferThread, (LPVOID)pParam);
	CNILayer *pNI = (CNILayer *)pParam;

	while(pNI->m_thrdSwitch){
		result = pcap_next_ex(pNI->m_AdapterObject,&header,&pkt_data);

		if(result==0){
		}else if(result==1){
			pNI->Receive((u_char *)pkt_data);
		}else if(result<0){
		}
	}
	return 0;
	///////////////////////////////////////////////////////////////////////
}

UINT CNILayer::FileTransferThread(LPVOID pParam)
{
	CNILayer *pNI = (CNILayer *)pParam;

	return 0;
}