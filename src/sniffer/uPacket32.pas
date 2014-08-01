unit uPacket32;

{///////////////////////////////////////////////////////////////////////////////

  unit desc:      API for the Packet Capture Driver
                  thanks to Lars Peter Christiansen's NETZNIFFER
                  up-to-date for WinPCap 3.0
  unit author:    net_xray@hotmail.com
  created date:   2003/10/01

///////////////////////////////////////////////////////////////////////////////}

interface

uses Windows, SysUtils, WinSock;

const
  DLL = 'Packet.dll';
  DEFAULT_DRIVERBUFFER = 1000000; // Dimension of the buffer in driver
  MAX_LINK_NAME_LENGTH = 64;      // Adapters symbolic names maximum length
  //DOSNAMEPREFIX = 'Packet_';
  NMAX_PACKET = 65535;
  //BPF_ALIGNMENT = sizeof(Tbpf_int32);
  Packet_ALIGNMENT = sizeof(Integer);
  
  DLT_NULL        =0;	  //* no link-layer encapsulation */
  DLT_EN10MB      =1;	  //* Ethernet (10Mb) */
  DLT_EN3MB       =2;	  //* Experimental Ethernet (3Mb) */
  DLT_AX25        =3;	  //* Amateur Radio AX.25 */
  DLT_PRONET      =4;	  //* Proteon ProNET Token Ring */
  DLT_CHAOS       =5;	  //* Chaos */
  DLT_IEEE802     =6;	  //* IEEE 802 Networks */
  DLT_ARCNET      =7;	  //* ARCNET */
  DLT_SLIP        =8;	  //* Serial Line IP */
  DLT_PPP         =9;	  //* Point-to-point Protocol */
  DLT_FDDI        =10;	//* FDDI */
  DLT_ATM_RFC1483 =11;	//* LLC/SNAP encapsulated atm */
  DLT_RAW         =12;	//* raw IP */
  DLT_SLIP_BSDOS  =13;	//* BSD/OS Serial Line IP */
  DLT_PPP_BSDOS   =14;	//* BSD/OS Point-to-point Protocol */

  //New types for Win32
  DLT_EN100MB     =100;	//* Ethernet (100Mb) */
  DLT_PPP_WIN32   =101;	//* Win32 dial up connection */

type

  Tbpf_u_int32 = LongWord;
  Tbpf_int32   = Integer;

  // Unix's way of timestamping. taken from the BSD file sys/time.h
  // Windows platform : WINSOCK.H
  PunixTimeVal = ^TunixTimeVal;
  TunixTimeVal = record
    tv_Sec : LongWord; // Secs since 1/1/1970
    tv_uSec: LongWord; // microseconds
  end;

  PNetType = ^TNetType;
  TNetType = packed record
    LinkType : LongWord;
    LinkSpeed : LongWord;
  end;

//  PIPAddr = ^TIPAddr;
//  TIPAddr = packed record
//    addr4,addr3,addr2,addr1 : Byte;
//  end;

  Tbpf_insn = record
    code : Word;
    jt   : Byte;
    jf   : Byte;
    k    : Integer;
  end;

  Pbpf_program = ^Tbpf_program;
  Tbpf_program = record
    bf_len  : LongWord;
    bf_insns: ^Tbpf_insn;
  end;

  Pbpf_stat = ^Tbpf_stat;
  Tbpf_stat = record
    bs_recv   : LongWord;
    bs_drop   : LongWord;
    // wpcapsrc 3.0
	  ps_ifdrop : LongWord;		///< drops by interface. XXX not yet supported
	  bs_capt   : LongWord;		///< number of packets that pass the filter, find place in the kernel buffer and
						                ///< thus reach the application.
  end;

  Pbpf_hdr = ^Tbpf_hdr;        //Structure prepended to each packet.
  Tbpf_hdr = record
    bh_tstamp : TunixTimeval;	//* time stamp */
    bh_caplen : Tbpf_u_int32;	//* length of captured portion */
    bh_datalen: Tbpf_u_int32;	//* original length of packet */
    bh_hdrlen : Word ;       	//* length of bpf header (this struct plus alignment padding) */
  end;

  Pdump_bpf_hdr = ^Tdump_bpf_hdr;
  Tdump_bpf_hdr = record
    ts      : TunixTimeval;		///< Time stamp of the packet
    caplen  : Tbpf_u_int32;		///< Length of captured portion. The captured portion can smaller than the 
								              ///< the original packet, because it is possible (with a proper filter) to
								              ///< instruct the driver to capture only a portion of the packets.
    len     : Tbpf_u_int32;		///< Length of the original packet (off wire).
  end;

  // Adapter with which the driver communicates
  PAdapter = ^TAdapter;
  TAdapter = packed Record
    hFile        : THandle;       //HANDLE
    SymbolicLink : array [0..MAX_LINK_NAME_LENGTH-1] of char;//TCHAR
    NumWrites    : Integer;
    ReadEvent    : THandle;       //HANDLE , 新版增加的.
    // wpcapsrc 3.0
    ReadTimeOut  : Tbpf_u_int32; ///< \internal The amount of time after which a read on the driver will be released and 
								///< ReadEvent will be signaled, also if no packets were captured
  end;

//  typedef struct _ADAPTER  {
//						   HANDLE hFile;
//               TCHAR  SymbolicLink[MAX_LINK_NAME_LENGTH];
//						   int NumWrites;
//						   HANDLE ReadEvent;
//						 }  ADAPTER, *LPADAPTER;


  // Packet the driver uses as means of data transport.
  // both snooped data and certain device controlling
  PPacket = ^TPacket;
  TPacket = packed record
    hEvent             :THandle;
    OverLapped         :TOVERLAPPED;
    Buffer             :Pointer;
    Length             :Longword;
   //Next               :Pointer;     // also commented out in "packet32.h"
    ulBytesReceived    :LongWord;
    bIoComplete        :Boolean;
  end;

//  typedef struct _PACKET {
//						  HANDLE       hEvent;
//              OVERLAPPED   OverLapped;
//              PVOID        Buffer;
//              UINT         Length;
//						  UINT         ulBytesReceived;
//						  BOOLEAN      bIoComplete;
//						}  PACKET, *LPPACKET;


  PPACKET_OID_DATA = ^TPACKET_OID_DATA;
  TPACKET_OID_DATA = packed record
    Oid   : LongWord;               // Device control code
    Length: LongWord;               // Length of data field
    Data  : Pointer;                // Start of data field
  end;

  Tnpf_if_addr = packed record
	  IPAddress   : TSockAddr;	///< IP address.
	  SubnetMask  : TSockAddr;	///< Netmask for that address.
	  Broadcast   : TSockAddr;	///< Broadcast address.
  end;
  
  function Packet_WORDALIGN(X:LongWord) : LongWord;  //Force data to be aligned

  function PacketAllocatePacket : PPacket; cdecl external DLL;
//ULONG PacketGetAdapterNames(PTSTR pStr,PULONG  BufferSize);
//  function PacketGetAdapterNames  ( pStr: PChar; BufferSize: PLongWord ): LongWord; cdecl external DLL;
// change into 以上函数在新版里的原型如下
//BOOLEAN PacketGetAdapterNames(PTSTR pStr,PULONG  BufferSize);
  function PacketGetAdapterNames  ( pStr: PChar; BufferSize: PLongWord ): LongBool; cdecl external DLL;
//BOOLEAN PacketGetNetInfo(LPTSTR AdapterName, PULONG netp, PULONG maskp);
  function PacketGetNetInfo       ( AdapterName: PChar; netp: PLongWord; maskp: PLongWord ): LongBool; cdecl external DLL;
  function PacketGetNetType       ( AdapterObject: PAdapter; nettype: PNetType ): LongBool; cdecl external DLL;
  function PacketGetStats         ( AdapterObject: PAdapter; s: Pbpf_stat ): LongBool; cdecl external DLL;
  function PacketOpenAdapter      ( AdapterName: PChar ): PAdapter; cdecl external DLL;
  function PacketReceivePacket    ( AdapterObject: PAdapter; lpPacket: PPacket; Sync: Boolean ): LongBool; cdecl external DLL;
  function PacketRequest          ( AdapterObject: PAdapter; boolSet: Boolean; OidData: PPACKET_OID_DATA ): LongBool; cdecl external DLL;
  function PacketResetAdapter     ( AdapterObject: PAdapter ): LongBool; cdecl external DLL;
  function PacketSendPacket       ( AdapterObject: PAdapter; lpPacket: PPacket; Sync: Boolean ): LongBool; cdecl external DLL;
  function PacketSetBpf           ( AdapterObject: PAdapter; fp: Pbpf_program ): LongBool; cdecl external DLL;
  function PacketSetBuff          ( AdapterObject: PAdapter; dim: Integer ): LongBool; cdecl external DLL;
  function PacketSetHwFilter      ( AdapterObject: PAdapter; Filter: LongWord ): LongBool; cdecl external DLL;
  function PacketSetMode          ( AdapterObject: PAdapter; mode: Integer ): LongBool; cdecl external DLL;
  function PacketSetNumWrites     ( AdapterObject: PAdapter; nwrites: Integer ): LongBool; cdecl external DLL;
  function PacketSetReadTimeout   ( AdapterObject: PAdapter; timeout: Integer ): LongBool; cdecl external DLL;
  function PacketWaitPacket       ( AdapterObject: PAdapter; lpPacket: PPacket ): LongBool; cdecl external DLL;
//BOOLEAN PacketSetMinToCopy(LPADAPTER AdapterObject,int nbytes);  新版增加
  function PacketSetMinToCopy     ( AdapterObject: PAdapter; nbytes: Integer ): LongBool; cdecl external DLL;
  function PacketGetVersion: PChar; cdecl external DLL;

  procedure PacketCloseAdapter    ( lpAdapter: PAdapter ); cdecl external DLL;
  procedure PacketFreePacket      ( lpPacket: PPacket ); cdecl external DLL;
  procedure PacketInitPacket      ( lpPacket: PPacket; Buffer: Pointer; Length: LongWord ); cdecl external DLL;

{
  PCHAR PacketGetVersion();
  BOOLEAN PacketGetStatsEx(LPADAPTER AdapterObject,struct bpf_stat *s);
  INT PacketSendPackets(LPADAPTER AdapterObject,PVOID PacketBuff,ULONG Size, BOOLEAN Sync);
  BOOLEAN PacketGetNetInfoEx(LPTSTR AdapterName, npf_if_addr* buffer, PLONG NEntries);
  HANDLE PacketGetReadEvent(LPADAPTER AdapterObject);
  BOOLEAN PacketSetDumpName(LPADAPTER AdapterObject, void *name, int len);
  BOOLEAN PacketSetDumpLimits(LPADAPTER AdapterObject, UINT maxfilesize, UINT maxnpacks);
  BOOLEAN PacketIsDumpEnded(LPADAPTER AdapterObject, BOOLEAN sync);
  BOOL PacketStopDriver();
}

implementation

function Packet_WORDALIGN(X:LongWord) : LongWord;
begin
//#define Packet_ALIGNMENT sizeof(int)
//#define Packet_WORDALIGN(x) (((x)+(Packet_ALIGNMENT-1))&~(Packet_ALIGNMENT-1))
  result := (((X)+(Packet_ALIGNMENT-1))and not(Packet_ALIGNMENT-1));
end;

end.
