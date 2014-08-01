unit uProtocolDef;

{///////////////////////////////////////////////////////////////////////////////

  unit desc:      定义监听对象组件
  unit author:    net_xray@hotmail.com
  created date:   2003/10/01

################################################################################
  Ethernet Transmission Line
  ________________________________________________________________________
 |                 |           |            |                 |           |
 | Ethernet Header | IP Header | TCP Header | Appln Header    | User Data |
 |-----------------+-----------+------------+-----------------------------|
 | 14 Bytes        | 20 Bytes  |  20 Bytes  | variable length             |
 |_________________|___________|____________|_____________________________|
 <-------------------------- Ethernet Frame ------------------------------>

################################################################################
  Format of Ethernet Data Frame
  ___________________________________________________________
 |                  |             |            |             |
 | Destination Addr | Source Addr | Frame Type | Frame Data  |
 |------------------+-------------+------------+-------------|
 |  6 Bytes         |  6 Bytes    |  2  Bytes  | 2 Bytes     |
 |__________________|_____________|____________|_____________|

  If the packet is a valid IP packet then the value of
  Frame type field (13th and 14th bytes) will be 08 00.

################################################################################
  Format of IP Datagram
 _____  _________________________________________________________________________
  /|   | Version | Header Length | Type of Service| Total Packet Length(2 bytes) |
   |   |(4 Bits) |  (4 Bits)     | (8 Bits )      |          (16 bits)           |
   |   |-------------------------+----------------+------------------------------|
   |   | Identication (16 bits)  | Flags(3 bits)  | Fragment Offset (13 bits)    |
  20   |------------------------------------------+------------------------------|
 Bytes | Time to Live(8 bits) | Protocol (8 bits) |  Header Check Sum. (16 bits) |
   |   |-------------------------------------------------------------------------|
   |   |                  Source IP Address (32 bits)                            |
   |   |-------------------------------------------------------------------------|
  \|   |                  Destination IP Address (32 bits)                       |
  -----|-------------------------------------------------------------------------|
       |          Options (if any)   |      Padding ( if Required )              |
       |-------------------------------------------------------------------------|
       |                            Data                                         |
       |_________________________________________________________________________|

################################################################################
  The Common TCP/IP Protocol that use IP
  Prot       Value
  -----------------
  TCP  ---> 06
  UDP  ---> 17
  ICMP ---> 01
  IGMP ---> 02
################################################################################
  Format of TCP Segement
   _______________________________________________________________
  | Source Port (2 Bytes)         | Destination Port (2 Bytes)    |
  |---------------------------------------------------------------|
  |                    Sequence Number (4 Bytes)                  |
  |---------------------------------------------------------------|
  |                    Acknowledge Number (4 Bytes)               |
  |---------------------------------------------------------------|
  | Hlen   |  Reserverd   | Code Bits |    Window                 |
  |(4 Bits)| (6 Bits )    | (6 Bits ) |    (2 Bytes )             |
  |-----------------------------------+---------------------------|
  |        Checksum (2 Bytes)         |    Urgent Data (2 Bytes)  |
  |---------------------------------------------------------------|
  |        Options (If Any - 3 Bytes )     |  Padding (1 Bytes )  |
  |---------------------------------------------------------------|
  |                          DATA                                 |
  |_______________________________________________________________|

///////////////////////////////////////////////////////////////////////////////}

interface

uses Windows, WinSock, SysUtils, uCommon;

type

  PETHERNET_HDR = ^ETHERNET_HDR;        //Ethernet Data Frame
  ETHERNET_HDR = packed record
    Destination: array[0..5] of UCHAR;
    Source:      array[0..5] of UCHAR;
    Protocol:    array[0..1] of UCHAR;
    Data:        array[0..0] of UCHAR;
  end;

  PP3oE_HDR = ^P3oE_HDR;                // PPP over Ethernet
  P3oE_HDR = packed record
    VerType:     UCHAR;   // 4bit version, 4bit type
    Code:        UCHAR;   // 8 bit
    SessionID:   WORD;    // 16 bit
    Length:      WORD;    // 16 bit
    Protocol:    WORD;    // 16 bit
    Data:        array[0..0] of UCHAR;
  end;

  PIP_RHDR = ^IP_RHDR;
  IP_RHDR = packed record
    Verlen:       UCHAR;                // 4bit version 4bit length (bytes/8)
    Service:      UCHAR;                // Type Of Service 8bits
    Length:       WORD;                 // 16 bits
    Ident:        WORD;                 // 16 bits
    Flagoff:      array[0..1] of UCHAR; // 3bit flag - 13 bit offset
    TimeLive:     UCHAR;                // TTL 8 bits
    Protocol:     UCHAR;                // 8 bits
    Checksum:     WORD;                 // 16 bits
    SrcIP:        array[0..3] of UCHAR; // 32 bits
    DestIP:       array[0..3] of UCHAR; // 32 bits
    Data:         array[0..0] of UCHAR; // Pointer
  end;

{
  IP_RHDR.VerLen (version and length, explains length below)
  ---------------
    Internet Header Length is the length of the internet header in 32
    bit words, and thus points to the beginning of the data.  Note that
    the minimum value for a correct header is 5.

  IP_RHDR.Length
  ---------------
    Total Length is the length of the datagram, measured in octets,
    including internet header and data.  This field allows the length of
    a datagram to be up to 65,535 octets.  Such long datagrams are
    impractical for most hosts and networks.  All hosts must be prepared
    to accept datagrams of up to 576 octets (whether they arrive whole
    or in fragments).  It is recommended that hosts only send datagrams
    larger than 576 octets if they have assurance that the destination
    is prepared to accept the larger datagrams.

    The number 576 is selected to allow a reasonable sized data block to
    be transmitted in addition to the required header information.  For
    example, this size allows a data block of 512 octets plus 64 header
    octets to fit in a datagram.  The maximal internet header is 60
    octets, and a typical internet header is 20 octets, allowing a
    margin for headers of higher level protocols.
}

  RIPv6_RHDR = ^ IPv6_RHDR;                     //Problem is here!!!
  IPv6_RHDR = Packed record
    Ver         :     UCHAR;                    //4bit version and 4bit priority
    FlowLabel   :     array[0..2] of UCHAR;     //8+16bit
    PayloadLen  :     WORD;
    NextHeader  :     UCHAR;
    HopLimit    :     UCHAR;
    SrcAddr     :     array[0..15] of UCHAR;    //128 bytes 8*16 or 16*8 or 32*4?
    DestAddr    :     array[0..15] of UCHAR;    //128 bytes
  end;

  PTCP_RHDR = ^TCP_RHDR;
  TCP_RHDR = Packed record
    SrcPort     : WORD;                 // 16 bits
    DestPort    : WORD;                 // 16 bits
    SequenceNr  : DWORD; //array[0..3] of UCHAR; // 32 bits
    AckNumber   : DWORD; //array[0..3] of UCHAR; // 32 bits
    LenResvFlags: array[0..1] of UCHAR; // length(4bits) rsvd(6bits) flags(6bits)
    WindowSize  : WORD;//array[0..1] of UCHAR; // 16 bits
    Checksum    : WORD;//array[0..1] of UCHAR; // 16 bits
    UrgentPtr   : WORD;//array[0..1] of UCHAR; // 16 bits
    Data        : array[0..0] of UCHAR; // Pointer to User Data
  end;

  PUDP_RHDR = ^UDP_RHDR;
  UDP_RHDR = Packed record
    SrcPort     : WORD;
    DestPort    : WORD;
    Length      : WORD;
    Checksum    : WORD;
    Data        : array[0..0] of UCHAR;
  end;

  PARP_RHDR = ^ARP_RHDR;              //problem is here!!!
  ARP_RHDR = Packed record            //Address Resolution Protocol.
    ar_hrd :    WORD;                 //16 bits
    ar_pro :    WORD;                 //16 bits
    ar_hln :    UCHAR;                // 8 bits
    ar_pln :    UCHAR;                // 8 bits
    ar_op  :    WORD;                 //16 bits
    ar_sha :    array[0..5] of UCHAR; //48 bits   长度==ar_hln ?
    ar_spa :    array[0..3] of UCHAR; //32 bits   长度==ar_pln ?
    ar_tha :    array[0..5] of UCHAR; //48 bits
    ar_tpa :    array[0..3] of UCHAR; //32 bits
  end;

  PETHARP_RHDR = ^ETHARP_RHDR;
  ETHARP_RHDR = Packed record           //Ethernet Address Resolution Protocol.
	  ea_hdr  :   ARP_RHDR;	              {* fixed-size header *}
    arp_sha :   array[0..5] of UCHAR;   {* sender hardware address *}
	  arp_spa :   array[0..3] of UCHAR;	  {* sender protocol address *}
	  arp_tha :   array[0..5] of UCHAR;	  {* target hardware address *}
	  arp_tpa :   array[0..3] of UCHAR;	  {* target protocol address *}
  end;

//  ICMP_RHDR = Packed record
//  end;

  PIGMP_RHDR = ^IGMP_RHDR;
  IGMP_RHDR = packed record
    VerType   :   UCHAR;
    Unused    :   UCHAR;
    Checksum  :   WORD;
    GrpAddr   :   array[0..3] of UCHAR;
  end;

  PPING_RHDR = ^PING_RHDR;
  PING_RHDR = Packed record
    p_type     :  UCHAR;
    p_code     :  UCHAR;
    Checksum   :  WORD;
    Identifier :  WORD;
    Sequence   :  WORD;
    Data       :  array[0..0] of UCHAR;
  end;

{
  PICMP_HDR = ^ICMP_HDR;
  ICMP_HDR = packed record
  	VerPrio     : UCHAR;
	  FlowLabel   : array[0..2] of UCHAR;
  	Length      : WORD;
	  NextHadr    : UCHAR;
  	HopLimit    : UCHAR;
	  Source      : array[0..15] of UCHAR;
  	Destination : array[0..15] of UCHAR;
  end;
}

	PICMP_RHDR = ^ICMP_RHDR;
	ICMP_RHDR = packed record
	  ICMPType    : UCHAR;
	  Code        : UCHAR;
	  Checksum    : array[0..1] of BYTE;
	  ICMPrest    : array[0..0] of BYTE;    //according to the type of icmp packet, structure varies
	end;
	
	PICMP_ERROR = ^ICMP_ERROR;         //icmp error message
	ICMP_ERROR = packed record
	  HeaderTailer: array[0..3] of BYTE;  //chunk of zeros.
	  Data        : array[0..0] of BYTE
	end;
	
	PICMP_QUERY_ECHO = ^ICMP_QUERY_ECHO;   //echo relpy/request
	ICMP_QUERY_ECHO = packed record
	  Identifier  : array[0..1] of BYTE;
	  SeqNumber   : array[0..1] of BYTE;
	  OptionalData: array[0..0] of BYTE;
	end;
	
	PICMP_QUERY_TIME = ^ICMP_QUERY_TIME;   //timestamp request/reply
	ICMP_QUERY_TIME = packed record
	  Identifier  : array[0..1] of BYTE;
	  SeqNumber   : array[0..1] of BYTE;
	  OriTimestamp: array[0..3] of BYTE;
	  RxTimestamp : array[0..3] of BYTE;
	  TxTimestamp : array[0..3] of BYTE;
	end;
	
	PICMP_QUERY_MASK = ^ICMP_QUERY_MASK;   //mask relpy/request
	ICMP_QUERY_MASK = packed record
	  Identifier  : array[0..1] of BYTE;
	  SeqNumber   : array[0..1] of BYTE;
	  AddMask     : array[0..3] of BYTE;
	end;
	
	PICMP_QUERY_ROUTER_SOLI = ^ICMP_QUERY_ROUTER_SOLI ;   //ROUTER-solicitation message
	ICMP_QUERY_ROUTER_SOLI  = packed record
	  Identifier  : array[0..1] of BYTE;
	  SeqNumber   : array[0..1] of BYTE
	end;
	
	PICMP_QUERY_ROUTER_ADVE = ^ICMP_QUERY_ROUTER_ADVE ;   //ROUTER-advertisement message
	ICMP_QUERY_ROUTER_ADVE  = packed record
	  Address     : BYTE;
	  AddressSize : BYTE;
	  Lifetime    : array[0..1] of BYTE;
	  rest        : array[0..0] of BYTE;
	end;
	
	type
	  TIcmpType = record
	    Category: integer;
	    Description: string[28];
	end;
	
	 //         RFC792,RFC950,RFC1256,RFC1393,RFC1475
	const
	  ICMP_Type: array[1..16] of TIcmpType = (
	      (Category: 0; Description: 'Echo reply'),
	      (Category: 3; Description: 'Destination unreachable'),
	      (Category: 4; Description: 'Source quench'),
	      (Category: 5; Description: 'Redirection'),
	      (Category: 6; Description: 'Alternate host address'),
	      (Category: 8; Description: 'Echo request'),
	      (Category: 9; Description: 'Router advertisement'),
	      (Category: 10; Description: 'Router sollicitation'),
	      (Category: 11; Description: 'Time exceeded'),
	      (Category: 12; Description: 'Parameter problem'),
	      (Category: 13; Description: 'Timestamp request'),
	      (Category: 14; Description: 'Timestamp reply'),
	      (Category: 15; Description: 'Information request'),
	      (Category: 16; Description: 'Information reply'),
	      (Category: 17; Description: 'Address mask request'),
	      (Category: 18; Description: 'Address mask reply')
    );

const
  PROTO_IP      = $0800;    //08 00 (IP)
  PROTO_LB      = $0900;    //LOOPBACK???
  PROTO_IPv6    = $86DD;    //86 DD (IPv6)
  PROTO_ARP     = $0806;    //08 06 (ARP)
  PROTO_PPPoE   = $8864;    //PPPoE Session
  PROTO_RAPR    = $8035;    //80 35 (RARP)
  PROTO_IPX     = $8137;    //81 37 (IPX)
  PROTO_NOVELL  =	$8138;
  PROTO_GSMP    = $800C;    //Gerneral Switch Management Protocol
  PROTO_CSCST   = $3002;    //cisco stacker
  PROTO_NTBIOS  = $3C00;    //3C00 - 3c0D NETBIOS(3COM)
  PROTO_AARP    = $80F3;    //Apple AppleTalk ARP
  PROTO_LAP     = $809B;    //Apple Link Access Protocol
  PROTO_DDP     = $80C4;    //VIP VINES IP
  PROTO_XNS     =	$0600;
  PROTO_SNMP    =	$814C;
  PROTO_MOP1    = $6001;    //60 01/02 (MOP)
  PROTO_MOP2    = $6002;    //MOP
  PROTO_DRP     = $6003;    //60 03 (DRP)
  PROTO_LAT     = $6004;    //60 04 (LAT)
  PROTO_LAVC    = $6007;    //60 07 (LAVC)

  //
  function GetIPVer(VerLen: UCHAR): string;
  function GetIPLen(VerLen: UCHAR): string;
  function GetIPTOS(TOS: Byte): string;
  function GetIPLength(Len: WORD): string;
  function GetIPIdent(Ident: WORD): string;
  function GetIPFragFlag(FlagOff: array of UCHAR): string;
  function GetIPFragOffset(FlagOff: array of UCHAR): string;
  function GetIPTimeToLive(TimeLive: UCHAR):string;
  function GetIPProtocol(proto: UCHAR): string;
  function GetIPCheckSum(cs: WORD): string;
  //
  function GetTCPPort(port: WORD): string;
  function GetTCPSeqAck(seqack: DWORD): string;
  function GetTCPLen(LenResvFlags: array of UCHAR): string;
  function GetTCPRsv(LenResvFlags: array of UCHAR): string;
  function GetTCPFlg(LenResvFlags: array of UCHAR): string;
  function GetTCPWin(WindowSize: WORD): string;
  function GetTCPCheckSum(Checksum: WORD): string;
  function GetTCPUrgent(UrgentPtr: WORD): string;
  //
  function GetUDPPort(port: WORD): string;
  function GetUDPLen(len: WORD): string;
  function GetUDPCheckSum(cs: WORD): string;
  //
  function GetPPPoEVer(vertype: UCHAR): string;
  function GetPPPoEType(vertype: UCHAR): string;
  function GetPPPoECode(code: UCHAR): string;
  function GetPPPoESess(session: WORD): string;
  function GetPPPoELen(length: WORD): string;
  function GetPPPoEPro(protocol: WORD): string;
  //
  function GetARPHardware(hw: WORD): string;
  function GetARPProtocol(pt: WORD): string;
  function GetARPAddrLength(hal: UCHAR): string;
  function GetARPOperation(op: WORD): string;
  function GetARPHA(sha: array of UCHAR): string;
  function GetARPIA(sia: array of UCHAR): string;

implementation

function GetIPVer(VerLen: UCHAR): string;
begin
  Result := Format('%d', [VerLen shr 4]);
end;

function GetIPLen(VerLen: UCHAR): string;
begin
  //The number of 32 bit words in the TCP Header.
  //This indicates where the data begins.
  Result := Format('%d', [VerLen and $0F]);
end;

function GetIPTOS(TOS: Byte): string;
var
  I: integer;
  Tmp: string;
begin
  Tmp := '';
  For I := 0 To 7 do begin
    Tmp := Tmp + Format('%d', [(TOS and $01) shr I]);
  end;
  Result := Tmp;
end;

function GetIPLength(Len: WORD): string;
begin
  Result := Format('%d', [Winsock.ntohs(Len)]);
  // 16 or 32 bit integer 需要处理little-endian问题, intel=big-endian
end;

function GetIPIdent(Ident: WORD): string;
begin
  Result := Format('%d', [Winsock.ntohs(Ident)]);
end;

function GetIPFragFlag(FlagOff: array of UCHAR): string;
var
  I: integer;
  Tmp: string;
begin
  For I := 0 To 2 do begin
    tmp := tmp + Format('%d', [(FlagOff[0] shr (5+I)) and $01]);
  end;
  Result := tmp;
end;

function GetIPFragOffset(FlagOff: array of UCHAR): string;
var
  tmp: WORD;
begin
  tmp := (FlagOff[0] and $1F);
  tmp := tmp shl 8 and FlagOff[1];
  Result := Format('%d', [tmp]); 
end;

function GetIPTimeToLive(TimeLive: UCHAR):string;
begin
  Result := Format('%d', [TimeLive]);
end;

function GetIPProtocol(proto: UCHAR): string;
begin
  Result := Format('%d', [Proto]);
end;

function GetIPCheckSum(cs: WORD): string;
begin
  Result := '0x'+IntToHex(Winsock.ntohs(cs), 4);
end;

////////////////////////////////////////////////////////////////////////////////
function GetTCPPort(port: WORD): string;
begin
  Result := Format('%d', [Winsock.ntohs(port)]);
end;

//some error ....
function GetTCPSeqAck(seqack: DWORD): string;
//var
//  tmp: DWORD;
begin
//  tmp := (tmp or seqack[0]) shl 24;
//  tmp := (tmp or seqack[1]) shl 16;
//  tmp := (tmp or seqack[2]) shl 8;
//  tmp := (tmp or seqack[3]);
  Result := Format('%u', [Winsock.ntohl(seqack)]);
end;

function GetTCPLen(LenResvFlags: array of UCHAR): string;
var
  tmp : UCHAR;
begin
  //4,6,6
  tmp := LenResvFlags[0] shr 4;
  Result := IntToStr(tmp); 
end;

function GetTCPRsv(LenResvFlags: array of UCHAR): string;
var
  tmp: UCHAR;
  I: integer;
begin
  Result := '';
  tmp := ((LenResvFlags[0] shl 2) and $3C) and
        (LenResvFlags[1] shr 6);
  For I := 0 To 5 do begin
    Result := Format('%d', [((tmp shr I) and $01)]) + Result;
  end;
end;

function GetTCPFlg(LenResvFlags: array of UCHAR): string;
var
  I: integer;
begin
  Result := '';
  For I := 0 To 5 do begin
    Result := Format('%d', [(LenResvFlags[1] shr I) and $01]) + Result;
  end;
end;

function GetTCPWin(WindowSize: WORD): string;
begin
  Result := Format('%d', [Winsock.ntohs(WindowSize)]);
end;

function GetTCPCheckSum(CheckSum: WORD): string;
begin
  Result := '0x'+IntToHex(Winsock.ntohs(CheckSum), 4);
end;

function GetTCPUrgent(UrgentPtr: WORD): string;
begin
  Result := IntToHex(ntohs(UrgentPtr), 4);
end;

////////////////////////////////////////////////////////////////////////////////
function GetUDPPort(port: WORD): string;
begin
  Result := Format('%d', [Winsock.ntohs(port)]);
end;

function GetUDPLen(len: WORD): string;
begin
  Result := Format('%d', [Winsock.ntohs(len)]);
end;

function GetUDPCheckSum(cs: WORD): string;
begin
  Result := Format('%d', [Winsock.ntohs(cs)]);
end;

////////////////////////////////////////////////////////////////////////////////
function GetPPPoEVer(vertype: UCHAR): string;
begin
  Result := Format('%d', [(vertype and $F0) shr 4]);
end;

function GetPPPoEType(vertype: UCHAR): string;
begin
  Result := Format('%d', [vertype and $0F]);
end;

function GetPPPoECode(code: UCHAR): string;
begin
  Result := '0x'+IntToHex(code, 2);
end;

function GetPPPoESess(session: WORD): string;
begin
  Result := Format('%d', [ntohs(session)]);
end;

function GetPPPoELen(length: WORD): string;
begin
  Result := Format('%d', [ntohs(length)]);
end;

function GetPPPoEPro(protocol: WORD): string;
begin
  Result := '0x'+ IntToHex(ntohs(protocol), 4);
end;

function GetARPHardware(hw: WORD): string;
begin
  Result := Format('%d', [ntohs(hw)]);
end;

function GetARPProtocol(pt: WORD): string;
begin
  Result := '0x'+IntToHex(pt, 4);
end;

function GetARPAddrLength(hal: UCHAR): string;
begin
  Result := Format('%d', [hal]);
end;

function GetARPOperation(op: WORD): string;
begin
  Result := Format('%d', [ntohs(op)]);
end;

function GetARPHA(sha: array of UCHAR): string;
begin
  Result := MACtoStr(sha);
end;

function GetARPIA(sia: array of UCHAR): string;
begin
  Result := IPToStr(sia);
end;

end.
