unit uWinPCap;

{///////////////////////////////////////////////////////////////////////////////

  unit desc:      Plibcap Highlevel API for Packet Capture Driver
  unit author:    net_xray@hotmail.com
  created date:   2003/10/01

///////////////////////////////////////////////////////////////////////////////}

interface

uses
  Windows, Messages, SysUtils, Variants, Classes, uPacket32, uProtocolDef,
  uNdis_def, Math, JclDatetime, JclSysInfo;

type
  
  //SINFFER指针, PACKET HEADER, 包的全部数据
  PPacketHdr = ^TPacketHdr;        // Wrapped Drivers packetHeader
  TPacketHdr = record
    ts     : TUnixTimeVal;             // Time of capture
    CapLen : Integer;                  // captured length
    Len    : Integer;                  // actual length of packet
  end;

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

  PSnifferHandle =^TSnifferHandle;
  TSnifferHandle = procedure(User: Pointer; const Header: PPacketHdr; const Data: PChar);

  function GetAdapters(Delimiter: Char): String;
  function GetWpCapVersion: String;
  function ActivatePCap(const Device: String; Promisc: boolean;
         TimeOut: Integer; var ErrMsg: String): PPCap;
  function SniffPacket(PC: PPCap; CNT: Integer; CallBack: TSnifferHandle; User: Pointer): Integer;
  procedure DeActivatePCap(var PC: PPCap);

const
  PCapBufSize = 256000;
  DEFAULT_DRIVERBUFFER = 512000;

implementation

function GetAdapters(Delimiter: Char): String;
var
  WinVer : TWindowsVersion;
  AdapterNameList : Array [0..(2048*2)-1] of char;
  AdapterLength : LongWord;
  I : LongWord;
begin
  AdapterLength := 2048;
  WinVer := GetWindowsVersion;
  FillChar(AdapterNameList, 2048, 0);
  PacketGetAdapterNames(AdapterNameList,@AdapterLength); //Read Adapter List From Registry
  if WinVer in [wvWin95, wvWin95OSR2, wvWin98, wvWin98SE, wvWinME] then
    //win95/98/me 8 bits per character
    begin
      for I:=0 to AdapterLength-1 do
        begin
         // modified
          if ( (AdapterNameList[I] = #0) and (AdapterNameList[I+1] = #0) )then
            break
          else
            if (AdapterNameList[I] = ' ') or (AdapterNameList[I] = #0) then
              AdapterNameList[I] := Delimiter;
        end;
      Result := AdapterNameList;
    end
  else
    //win2000/NT/XP is UNICODE, 16 bits per character
    begin
      for i:=0 to AdapterLength-1 do
        begin
        if (Pwidechar(@AdapterNameList)[i]=#0)and (PwideChar(@AdapterNameList)[i+1]<>#0) then
          PwideChar(@AdapterNameList)[i]:=WideChar(Delimiter);
        end;
      Result := WideCharToString(PWideChar(@AdapterNameList)) ;
    end
end;

function GetWpCapVersion: String;
begin
  Result := String(PacketGetVersion);
end;

function ActivatePCap(const Device: String; Promisc: boolean;
       TimeOut: Integer; var ErrMsg: String): PPCap;
var
  PInst : PPCap;
  S : PChar;
  NetType : TNetType;

     procedure CleanUp;
     begin
       if PInst.Adapter <> nil then PacketCloseAdapter(PInst.adapter);
       if PInst.Packet <> nil then PacketFreePacket(PInst.Packet);
       if PInst.Buffer<>nil then FreeMem(PInst.Buffer,PCapBufSize);
       Freemem(PInst,SizeOf(TPCap));
     end;

begin
  Result := nil;
  // CREATE PCAP OBJECT
  GetMem(PInst,SizeOf(TPCap));
  if PInst = nil then
    begin
      ErrMsg := 'Cannot allocate PCap object';
      exit;
    end;
  FillChar(PInst^, SizeOf(TPCap),0);
  PInst.Adapter := nil;

  // CREATE ADAPTER OBJECT
  GetMem(S, 2048);                       // Making temporary pchar
  StrPCopy(S, Device);
  PInst.Adapter := PacketOpenAdapter(S);
  FreeMem(S, 2048);
	if (PInst.Adapter = nil) or
      (PInst.Adapter.hFile = INVALID_HANDLE_VALUE) then
    begin
      ErrMsg := 'Cannot Open Adapter "'+Device+'"';
      CleanUp;
      exit;
    end;

  if Promisc then
    begin
  	// set the network adapter in promiscuous mode //混杂模式
      if not PacketSetHwFilter(PInst.Adapter, NDIS_PACKET_TYPE_PROMISCUOUS) then
        begin
          ErrMsg := 'Error: Can not initialize net device';
          CleanUp;
          Exit;
        end;
    end else if not PacketSetHWFilter(PInst.Adapter,NDIS_PACKET_TYPE_ALL_LOCAL) then
      begin
        ErrMsg:= 'Error: Cannot set Device Filter to All_LOCAL mode';
        CleanUp;
        Exit;
      end;

  if not PacketGetNetType(PInst.Adapter,@Nettype) then
    Begin
      ErrMsg := 'Error: Cannot determine network type and speed';
      CleanUp;
      Exit;
    end;

  Case TNDIS_MEDIUM(NetType.LinkType) of
    NdisMediumWan   : PInst.LinkType := DLT_PPP_WIN32;
    NdisMediumFddi  :	PInst.LinkType := DLT_FDDI;
    NdisMedium802_5 : PInst.LinkType := DLT_IEEE802;
    NdisMediumAtm   : PInst.LinkType := DLT_ATM_RFC1483;
    NdisMediumArcnet878_2 :PInst.LinkType := DLT_ARCNET;
    NdisMedium802_3 : begin
        if NetType.LinkSpeed = 100000000 then
          PInst.LinkType := DLT_EN100MB
        else if NetType.LinkSpeed=10000000 then
          PInst.LinkType := DLT_EN10MB
        else PInst.LinkType:=DLT_PPP_WIN32;
      end;
    else PInst.LinkType := DLT_EN10MB;
  end;

  PInst.BufSize := PCapBufSize;
  GetMem(PInst.Buffer,PCapBufSize);
  if PInst.Buffer = nil then
    begin
      ErrMsg := 'Error: Cannot allocate Link Header space';
      CleanUp;
      Exit;
    end;

  PInst.Packet := PacketAllocatePacket;
	if PInst.Packet = nil then
    begin
      ErrMsg := 'Error: Failed to allocate the PPACKET structure!';
      CleanUp;
      Exit;
	  end;

	PacketInitPacket(PInst.Packet, PInst.Buffer, PInst.BufSize);
	// set a 512K buffer in the driver
  if not PacketSetBuff(PInst.Adapter, DEFAULT_DRIVERBUFFER) then
    begin
      ErrMsg := 'Error: Not enough memory to allocate Driver buffer!';
      CleanUp;
      Exit;
    end;
	//allocate and initialize a packet structure that will be used to receive the packets.
	//Notice that the user buffer is only 256K to save memory.
	//For best capture performances a buffer of 512K
	// (i.e the same size of the kernel buffer) can be used.
	PacketSetReadTimeout(PInst.Adapter, TimeOut);
  Result := PInst;
end;

function SniffPacket(PC: PPCap; CNT: Integer; CallBack: TSnifferHandle; User: Pointer): Integer;
var
  cc   : Longword;//Counter ?
  n    : integer;
  bp,ep: pointer; //Begin and End Point ?
  hdrlen,         //Length of Header
  caplen: integer;//Length of captured
begin

  PC.cc := 0;
  cc := PC.cc;
  n  := 0;
  Result := n;

  if PC.cc = 0 then begin
    if not PacketReceivePacket(PC.Adapter, PC.Packet, TRUE) then
      begin
        //PC.errbuf :='Error: PacketRecievePacket failed.';
        Result := -1;
        exit;
      end;
    cc := PC.Packet.ulBytesReceived;  //收到的字节数
    bp := PC.Packet.Buffer;           //NOTES: Please see WPCapSrc:pcap-win32.c
  end else bp := PC.bp;
  // Loop through each packet.
  ep := Ptr( LongWord(bp) + cc ); //move end pointer
  while ( LongWord(bp) < LongWord(ep) ) do
    begin
      caplen := Pbpf_hdr(bp).bh_caplen;
      hdrlen := Pbpf_hdr(bp).bh_hdrlen;

      // XXX A bpf_hdr matches apcap_pkthdr.
      CallBack( User, PPacketHdr(bp), Ptr(LongWord(bp) + HdrLen) );
      //Ptr(LongWord(bp) + HdrLen) --> mean is get pointer to packet data expect header.

      LongWord(bp) := LongWord(bp) + Packet_WORDALIGN(caplen + hdrlen);
      INC(n);
      if (n >= CNT) and (CNT > 0) then
        begin
          PC.bp := bp;
          PC.cc := LongWord(ep) - LongWord(bp);
          Result := n;
          Exit;
        end;
    end;
end;

procedure DeActivatePCap(var PC: PPCap);
begin
  if PC = nil then exit;
  if PC.Adapter <> nil then
    begin
      PacketCloseAdapter(PC.Adapter);
      PC.Adapter:=nil;
    end;

  if PC.Packet <> nil then
    begin
      PacketFreePacket(PC.Packet);
      PC.Packet := nil;
    end;

  if PC.Buffer <> nil then
    begin
      FreeMem(PC.Buffer,PC.BufSize);
      PC.Buffer := nil;
    end;

  FreeMem(PC,SizeOf(TPCap));
  PC := nil;
end;


end.
 