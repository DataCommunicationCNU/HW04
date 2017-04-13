// TcpLayer.h: interface for the TcpLayer class.
//
//////////////////////////////////////////////////////////////////////

#if _MSC_VER > 1000
#pragma once
#endif // _MSC_VER > 1000

#include "BaseLayer.h"

class CTCPLayer
: public CBaseLayer  
{
private:
	inline void		ResetHeader( );

public:
	BOOL			Receive( unsigned char* ppayload ) ;
	BOOL			Send( unsigned char* ppayload, int nlength );

	void			SetDestionPort( unsigned int ipAddress );
	void			SetSourcePort (unsigned int ipAddress );

	CTCPLayer( char* pName );
	virtual ~CTCPLayer();

	typedef struct _TCP_HEADER {
unsigned short tcp_sport;	// source port
		unsigned short tcp_dport;	// destination port
		unsigned int tcp_seq;		// sequence number
		unsigned int tcp_ack;		// acknowledged sequence
		unsigned char tcp_offset;	// no use
		unsigned char tcp_flag;		// control flag
		unsigned short tcp_window;	// no use
		unsigned short tcp_cksum;	// check sum
		unsigned short tcp_urgptr;	// no use
		unsigned char Padding[4];
		unsigned char tcp_data[ TCP_DATA_SIZE ]; // data part

	} _TCP_HEADER, *PTCP_HEADER ;

protected:
	_TCP_HEADER	m_sHeader;
};

