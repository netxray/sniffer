unit uWpCapImpl;

{///////////////////////////////////////////////////////////////////////////////

  unit desc:      Plibcap Highlevel API for Packet Capture Driver
  unit author:    net_xray@hotmail.com
  created date:   2003/10/01

///////////////////////////////////////////////////////////////////////////////}

interface

uses
  Windows, Messages, SysUtils, Variants, Classes, uPacket32, uProtocolDef,
  uNdis_def, Math, JclDatetime, JclSysInfo, uWpCap;

type
  
  //SINFFER指针, PACKET HEADER, 包的全部数据
  PPacketHdr = Ppcap_pkthdr;        // Wrapped Drivers packetHeader

  PPCap = ^TPCap;
  TPCap = record
    Adapter  : PAdapter;
    Packet   : PPacket;
    LinkType : Integer;                // Type and speed of net
    BufSize  : Integer;
    Buffer   : Pointer;
    bp       : Pointer;
    cc       : Integer;
  end;

  TSnifferHandle = procedure(User: Pointer; const Header: PPacketHdr; const Data: PChar);

  function GetAdapters(var ErrMsg: string;
            DevNameLst, DevDescLst: TStringList): boolean;
            
  function GetWpCapVersion: String;

  function ActivatePCap(const Host: String; var ErrMsg: String): Ppcap_t;

  function SniffPacket(PC: Ppcap_t; CNT: Integer; CallBack: TSnifferHandle; User: Pointer): Integer;
  procedure DeActivatePCap(var PC: Ppcap_t);

const
  PCAP_ERRBUF_SIZE = 255;

var
  g_major_ver, g_minor_ver: integer;

implementation

function GetAdapters(var ErrMsg: string;
  DevNameLst, DevDescLst: TStringList): boolean;
var
  alldevs, d: Ppcap_if_t;
  I: integer;
  errbuf: array [0..PCAP_ERRBUF_SIZE] of AnsiChar;
begin
  Result := False;
  DevNameLst.Clear;
  DevDescLst.Clear;
  I := 0;
  {* Retrieve the device list *}
  if (pcap_findalldevs(@alldevs, errbuf) = -1) then
  begin
    ErrMsg := Format('Error in pcap_findalldevs: %s\n', [errbuf]);
    Exit;
  end;

  d := alldevs;
  while d <> nil do begin
    Inc(I);
    DevNameLst.Add(d^.name);
    DevDescLst.Add(d^.description);
    d := d^.next;
  end;

  if I = 0 then
  begin
    ErrMsg := '\nNo interfaces found! Make sure WinPcap is installed.\n';
    Exit;
  end;

  {* We don't need any more the device list. Free it *}
  pcap_freealldevs(alldevs);
end;

function GetWpCapVersion: String;
begin
  Result := IntToStr(g_major_ver) + '.' + IntToStr(g_minor_ver);
end;

function ActivatePCap(const Host: String; var ErrMsg: String): Ppcap_t;
var
  iNum: integer;
  I, snaplen, flags, timeout: integer;
  adhandle: Ppcap_t;
  auth: Tpcap_rmtauth;
  errbuf: array [0..PCAP_ERRBUF_SIZE] of AnsiChar;
begin
  Result := nil;
  snaplen := 1600;
  flags := 1;
  timeout := 100;
  auth.m_type := RPCAP_RMTAUTH_NULL;
  auth.username := '';
  auth.password := '';
	{* Open the adapter *}
  //adhandle := pcap_open_live(PChar(Device), 65536, 1, TimeOut, errbuf);
  adhandle := pcap_open_live(PAnsiChar(Host), 65535, 1, 1000, errbuf);
  //pcap_open(PAnsiChar(Host), snaplen, flags, timeout, @auth, errbuf);
 	if (adhandle = nil) then
	begin
		ErrMsg := Format('Unable to open the adapter. %s is not supported by WinPcap.', [Host]);
		Exit;
	end;

  {* get winpcap version *}
  g_major_ver := pcap_major_version(adhandle);
  g_minor_ver := pcap_minor_version(adhandle);
	
//  {* start the capture *}
//	pcap_loop(adhandle, 0, pcap_handler, NULL);
	Result := adhandle;
	Exit;
end;

function SniffPacket(PC: Ppcap_t; CNT: Integer; CallBack: TSnifferHandle; User: Pointer): Integer;
var
  header: Ppcap_pkthdr;
  pkt_data: pchar;
begin
	{* Retrieve the packets *}
  Result := pcap_next_ex(PC, @header, @pkt_data);
  if Result >= 0 then begin
    CallBack(User, header, pkt_data); 
  end;
	
	if Result = -1 then begin
		//Format('Error reading the packets: %s\n', [pcap_geterr(PC)]);
	end;
	
end;

procedure DeActivatePCap(var PC: Ppcap_t);
begin
  pcap_close(pc);
  pc := nil;
end;

initialization
  g_major_ver := 0;
  g_minor_ver := 0;

end.
 