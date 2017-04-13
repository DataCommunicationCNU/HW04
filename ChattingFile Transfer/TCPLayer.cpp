// TCPLayer.cpp: implementation of the TCPLayer class.
//
//////////////////////////////////////////////////////////////////////

#include "stdafx.h"
#include "ipc.h"
#include "TCPLayer.h"

#ifdef _DEBUG
#undef THIS_FILE
static char THIS_FILE[]=__FILE__;
#define new DEBUG_NEW
#endif

//////////////////////////////////////////////////////////////////////
// Construction/Destruction
//////////////////////////////////////////////////////////////////////

CTCPLayer::CTCPLayer( char* pName )
: CBaseLayer( pName )
{
	ResetHeader( ) ;
}

CTCPLayer::~CTCPLayer()
{
}

void CTCPLayer::ResetHeader()
{
	m_sHeader.tcp_sport = 0x0000;
	m_sHeader.tcp_dport = 0x0000;
	m_sHeader.tcp_seq = 0x00000000;
	m_sHeader.tcp_ack = 0x00000000;
	m_sHeader.tcp_offset = 0x00;
	m_sHeader.tcp_flag = 0x00;
	m_sHeader.tcp_window = 0x0000;
	m_sHeader.tcp_cksum = 0x0000;
	m_sHeader.tcp_urgptr = 0x0000;
	memset(m_sHeader.tcp_data,0,TCP_DATA_SIZE);
}


void CTCPLayer::SetSourcePort(unsigned int ipAddress)  //�ʿ����
{
	m_sHeader.tcp_sport = ipAddress;
}

void CTCPLayer::SetDestionPort(unsigned int ipAddress)
{
	m_sHeader.tcp_dport = ipAddress;
}

BOOL CTCPLayer::Send(unsigned char *ppayload, int nlength)
{
	memcpy( m_sHeader.tcp_data, ppayload, nlength ) ;
	
	BOOL bSuccess = FALSE ;
	bSuccess = mp_UnderLayer->Send((unsigned char*)&m_sHeader,nlength+TCP_HEADER_SIZE);	
	

	return bSuccess ;
}

BOOL CTCPLayer::Receive( unsigned char* ppayload )
{
	PTCP_HEADER pFrame = (PTCP_HEADER) ppayload;
	
	BOOL bSuccess = FALSE;

	if(pFrame->tcp_dport == TCP_PORT_CHAT){
		bSuccess = mp_aUpperLayer[1]->Receive((unsigned char*)pFrame->tcp_data); 
	}else if(pFrame->tcp_dport==TCP_PORT_FILE){
		bSuccess = mp_aUpperLayer[0]->Receive((unsigned char*)pFrame->tcp_data);
	}


	return bSuccess ;
}
