unit uPacketAnaysis;

{///////////////////////////////////////////////////////////////////////////////

  unit desc:      数据分析
  unit author:    net_xray@hotmail.com
  created date:   2003/10/06

  problem: 用XML定义协议格式

///////////////////////////////////////////////////////////////////////////////}

interface

uses
  Windows, Messages, SysUtils, Variants, Classes, Graphics, Controls, Forms,
  Dialogs, ComCtrls, WinSock,
  uSniffHelper, uProtocolDef, uNDIS_def, uCommon;

type

  TPacketAnalyzer = class
    private
      F_ProtoTree: PTreeView;
      //
      procedure AddPacketNode(p: PSniffData; pno: integer);
      procedure AddEtherNode(p: PETHERNET_HDR);
      function AddIPNode(p: PIP_RHDR; prt: WORD): integer; // Options Offset
      function AddTcpNode(p: PTCP_RHDR; prt: WORD): integer; // Options Offset
      procedure AddUdpNode(p: PUDP_RHDR; prt: WORD);
      procedure AddPPPoENode(p: PP3oE_HDR; prt: WORD);
      procedure AddPPPNode(p: WORD);
      procedure AddARPNode(p: PARP_RHDR; prt: WORD);
      procedure AddICMPNode(p: PICMP_RHDR; prt: WORD);
      procedure AddAppDataNode(p: PChar; prt: WORD; srcport, dstport: integer);
    public
      constructor Create;
      destructor Destroy; override;
      //
      procedure PrepareProtoTree(tv: PTreeView);
      procedure ParsePacketInTreeView(p: PSniffData; pno: integer);
      class procedure ParsePacketAddrInfo(p: PSniffData; inaddr, outaddr: PMAC2IP);
  end;

implementation

uses uProtoXml;

{ TPacketAnalyzer }
constructor TPacketAnalyzer.Create;
begin
  //
end;

destructor TPacketAnalyzer.Destroy;
begin
  //
  inherited;
end;

////////////////////////////////////////////////////////////////////////////////
////////////////////////////////////////////////////////////////////////////////
procedure TPacketAnalyzer.AddPacketNode(p: PSniffData; pno: integer);
var
  PacketNode: TTreeNode;
  no: PNodeObj;
begin
  no := New(PNodeObj);
  no^.FontColor := clBlue;
  no^.FontStyle := [fsBold, fsUnderline];
  with F_ProtoTree^.Items do begin
    PacketNode := AddChildObject(nil, 'Packet ['+IntToStr(pno)+'] Info', no);
    AddChildObject(PacketNode, 'Length: '+IntToStr(p^.Length), nil);
  end;
end;

procedure TPacketAnalyzer.AddEtherNode(p: PETHERNET_HDR);
var
  EtherNode, tmpNode: TTreeNode;
  no: PNodeObj;
begin
  no := New(PNodeObj);
  no^.FontColor := clBlue;
  no^.FontStyle := [fsBold, fsUnderline];
  with F_ProtoTree^.Items do begin
    EtherNode := AddChildObject(nil, 'Ethernet', no);
    tmpNode := AddChildObject(EtherNode, 'Destination:          '+MACtoStr(p^.Destination), nil);
    tmpNode.ImageIndex := 2;
    tmpNode.StateIndex := 2;
    tmpNode.SelectedIndex := 2;
    tmpNode := AddChildObject(EtherNode, 'Source:               '+MACtoStr(p^.Source), nil);
    tmpNode.ImageIndex := 2;
    tmpNode.StateIndex := 2;
    tmpNode.SelectedIndex := 2;
    tmpNode := AddChildObject(EtherNode, 'Protocol Type:        '+
               G_ProtoXml.GetETProtoDesc(GetEtherType(p^.Protocol)), nil);
  end;
end;

function TPacketAnalyzer.AddIPNode(p: PIP_RHDR; prt: WORD): integer;
var
  IPNode, tmpNode: TTreeNode;
  no: PNodeObj;
  strProto, strOption, strTemp: string;
  buff: PChar;
  IPLen, I: Integer;
begin
  no := New(PNodeObj);
  no^.FontColor := clBlue;
  no^.FontStyle := [fsBold, fsUnderline];
  with F_ProtoTree^.Items do begin
    strProto := G_ProtoXml.GetETProtoDesc(prt);
    IPLen := StrToInt(GetIPLen(p^.Verlen))*4;
    if Trim(strProto) = '' then strProto := G_ProtoXml.GetP3ProtoDesc(prt);
    IPNode := AddChildObject(nil, 'IP Header - '+strProto, no);
    AddChildObject(IPNode, 'Version:              '+GetIPVer(p^.Verlen), nil);
    AddChildObject(IPNode, 'Header Length:        '+GetIPLen(p^.Verlen) +
                   '[' + IntToStr(IPLen) + ' bytes]', nil);
    AddChildObject(IPNode, 'Type Of Service:      '+GetIPTOS(p^.Service), nil);
    AddChildObject(IPNode, 'Total Length:         '+GetIPLength(p^.Length), nil);
    AddChildObject(IPNode, 'Identifier:           '+GetIPIdent(p^.Ident), nil);
    AddChildObject(IPNode, 'Fragmentataion Flags: '+GetIPFragFlag(p^.Flagoff), nil);
    AddChildObject(IPNode, 'Fragmente offset:     '+GetIPFragOffset(p^.Flagoff), nil);
    AddChildObject(IPNode, 'Time To Live:         '+GetIPTimeToLive(p^.TimeLive), nil);
    AddChildObject(IPNode, 'Protocol:             '+GetIPProtocol(p^.Protocol) + ' -- ' +
                   G_ProtoXml.GetIPProtoDesc(p^.Protocol), nil);
    AddChildObject(IPNode, 'Header CheckSum:      '+GetIPCheckSum(p^.Checksum), nil);
    tmpNode := AddChildObject(IPNode, 'Source IP:            '+IPToStr(p^.SrcIP), nil);
    tmpNode.ImageIndex := 3;
    tmpNode.StateIndex := 3;
    tmpNode.SelectedIndex := 3;
    tmpNode := AddChildObject(IPNode, 'Destination IP:       '+IPToStr(p^.DestIP), nil);
    tmpNode.ImageIndex := 3;
    tmpNode.StateIndex := 3;
    tmpNode.SelectedIndex := 3;
    // 尚未处理 IP Options
    Result := IPLen - 20;
    if Result > 0 then begin
      tmpNode := AddChildObject(IPNode, 'IP Options', nil);
      //HexToBin
      buff := AllocMem(Result + 1); // 8 bit + \0;
      for I := 0 to Result - 1 do begin
        strOption := DecToBinStr(p^.Data[I]);
        strOption := FmtStrWithZeroPrefix(8, strOption);
        AddChildObject(tmpNode, strOption + '           [0x' + IntToHex(p^.Data[I], 4) +']', nil);
      end;
      FreeMem(buff);
    end else begin
      AddChildObject(IPNode, 'IP Option:            [No Options]', nil);
    end;
  end;
end;

function TPacketAnalyzer.AddTcpNode(p: PTCP_RHDR; prt: WORD): integer;
var
  TcpNode, tmpNode: TTreeNode;
  no: PNodeObj;
  strOption, strTemp: string;
  buff: PChar;
  TCPLen, I: Integer;
begin
  no := New(PNodeObj);
  no^.FontColor := clBlue;
  no^.FontStyle := [fsBold, fsUnderline];
  with F_ProtoTree^.Items do begin
    TcpLen := StrToInt(GetTCPLen(p^.LenResvFlags))*4;
    TcpNode := AddChildObject(nil, 'TCP Header - '+G_ProtoXml.GetIPProtoDesc(prt), no);
    AddChildObject(TcpNode, 'Source Port:          '+GetTcpPort(p^.SrcPort), nil);
    AddChildObject(TcpNode, 'Destination Port:     '+GetTcpPort(p^.DestPort), nil);
    AddChildObject(TcpNode, 'Sequence Number:      '+GetTCPSeqAck(p^.SequenceNr), nil);
    AddChildObject(TcpNode, 'ACK Number:           '+GetTCPSeqAck(p^.AckNumber), nil);
    AddChildObject(TcpNode, 'Offset:               '+GetTCPLen(p^.LenResvFlags) +
                   '[' + IntToStr(TcpLen) + ' bytes]', nil);
    AddChildObject(TcpNode, 'Reserved:             '+GetTCPRsv(p^.LenResvFlags), nil);
    AddChildObject(TcpNode, 'Flags:                '+GetTCPFlg(p^.LenResvFlags), nil);
    AddChildObject(TcpNode, 'Window:               '+GetTCPWin(p^.WindowSize), nil);
    AddChildObject(TcpNode, 'CheckSum:             '+GetTCPCheckSum(p^.Checksum), nil);
    AddChildObject(TcpNode, 'Urgent Pointer:       '+GetTCPUrgent(p^.UrgentPtr), nil);
    // 尚未处理 TCP Options
    Result := TcpLen - 20;
    if Result > 0 then begin
      tmpNode := AddChildObject(TcpNode, 'TCP Options', nil);
      //HexToBin
      buff := AllocMem(Result + 1); // 8 bit + \0;
      for I := 0 to Result - 1 do begin
        strOption := DecToBinStr(p^.Data[I]);
        strOption := FmtStrWithZeroPrefix(8, strOption);
        AddChildObject(tmpNode, strOption + '           [0x' + IntToHex(p^.Data[I], 4) +']', nil);
      end;
      FreeMem(buff);
    end else begin
      AddChildObject(TcpNode, 'TCP Option:           [No Options]', nil);
    end;
  end;
end;

procedure TPacketAnalyzer.AddUdpNode(p: PUDP_RHDR; prt: WORD);
var
  UdpNode, tmpNode: TTreeNode;
  no: PNodeObj;
begin
  no := New(PNodeObj);
  no^.FontColor := clBlue;
  no^.FontStyle := [fsBold, fsUnderline];
  with F_ProtoTree^.Items do begin
    UdpNode := AddChildObject(nil, 'UDP Header - '+G_ProtoXml.GetIPProtoDesc(prt), no);
    AddChildObject(UdpNode, 'Source Port:          '+GetUdpPort(p^.SrcPort), nil);
    AddChildObject(UdpNode, 'Destination Port:     '+GetUdpPort(p^.DestPort), nil);
    AddChildObject(UdpNode, 'Length:               '+GetUdpPort(p^.Length), nil);
    AddChildObject(UdpNode, 'CheckSum:             '+GetUdpPort(p^.Checksum), nil);
  end;
end;

////////////////////////////////////////////////////////////////////////////////
procedure TPacketAnalyzer.AddPPPNode(p: WORD);
var
  PPPNode: TTreeNode;
  no: PNodeObj;
begin
  no := New(PNodeObj);
  no^.FontColor := clBlue;
  no^.FontStyle := [fsBold, fsUnderline];
  with F_ProtoTree^.Items do begin
    PPPNode := AddChildObject(nil, 'Point-to-Point Protocol', no);
    AddChildObject(PPPNode, 'PPP:                  '+GetPPPoEPro(p)+' - '+ 
                   G_ProtoXml.GetP3ProtoDesc(p), nil);
  end;
end;

procedure TPacketAnalyzer.AddPPPoENode(p: PP3oE_HDR; prt: WORD);
var
  PPPoENode, tmpNode: TTreeNode;
  no: PNodeObj;
begin
  no := New(PNodeObj);
  no^.FontColor := clBlue;
  no^.FontStyle := [fsBold, fsUnderline];
  with F_ProtoTree^.Items do begin
    PPPoENode := AddChildObject(nil, 'PPPoE - '+G_ProtoXml.GetETProtoDesc(prt), no);
    AddChildObject(PPPoENode, 'Version:              '+GetPPPoEVer(p^.VerType), nil);
    AddChildObject(PPPoENode, 'Type:                 '+GetPPPoEType(p^.VerType), nil);
    AddChildObject(PPPoENode, 'Code:                 '+GetPPPoECode(p^.Code), nil);
    AddChildObject(PPPoENode, 'Session Id:           '+GetPPPoESess(p^.SessionID), nil);
    AddChildObject(PPPoENode, 'Length:               '+GetPPPoELen(p^.Length), nil);
  end;
end;

procedure TPacketAnalyzer.AddARPNode(p: PARP_RHDR; prt: WORD);
var
  ARPNode, tmpNode: TTreeNode;
  no: PNodeObj;
begin
  no := New(PNodeObj);
  no^.FontColor := clBlue;
  no^.FontStyle := [fsBold, fsUnderline];
  with F_ProtoTree^.Items do begin
    ARPNode := AddChildObject(nil, 'ARP - '+G_ProtoXml.GetETProtoDesc(prt), no);
    AddChildObject(ARPNode, 'Hardware:             '+GetARPHardware(p^.ar_hrd), nil);
    AddChildObject(ARPNode, 'Protocol:             '+GetARPProtocol(p^.ar_pro), nil);
    AddChildObject(ARPNode, 'Hardware Addr Length: '+GetARPAddrLength(p^.ar_hln), nil);
    AddChildObject(ARPNode, 'Protocol Addr Length: '+GetARPAddrLength(p^.ar_pln), nil);
    AddChildObject(ARPNode, 'Operation:            '+GetARPOperation(p^.ar_op), nil);
    tmpNode := AddChildObject(ARPNode, 'Sender Hardware Addr: '+GetARPHA(p^.ar_sha), nil);
    tmpNode.ImageIndex := 2;
    tmpNode.StateIndex := 2;
    tmpNode.SelectedIndex := 2;
    tmpNode := AddChildObject(ARPNode, 'Sender Protocol Addr: '+GetARPIA(p^.ar_spa), nil);
    tmpNode.ImageIndex := 3;
    tmpNode.StateIndex := 3;
    tmpNode.SelectedIndex := 3;
    tmpNode := AddChildObject(ARPNode, 'Target Hardware Addr: '+GetARPHA(p^.ar_tha), nil);
    tmpNode.ImageIndex := 2;
    tmpNode.StateIndex := 2;
    tmpNode.SelectedIndex := 2;
    tmpNode := AddChildObject(ARPNode, 'Target Protocol Addr: '+GetARPIA(p^.ar_tpa), nil);
    tmpNode.ImageIndex := 3;
    tmpNode.StateIndex := 3;
    tmpNode.SelectedIndex := 3;
  end;
end;

procedure TPacketAnalyzer.AddICMPNode(p: PICMP_RHDR; prt: WORD);
var
  ICMPNode, tmpNode: TTreeNode;
  no: PNodeObj;
begin
end;

procedure TPacketAnalyzer.AddAppDataNode(p: PChar; prt: WORD; srcport, dstport: integer);
var
  AppDataNode, tmpNode: TTreeNode;
  no: PNodeObj;
  port: integer;
  desc: string;
begin
  no := New(PNodeObj);
  no^.FontColor := clBlue;
  no^.FontStyle := [fsBold, fsUnderline];
  if (srcport <= 1024) then begin
    desc := trim(G_ProtoXml.GetPortDesc(prt, srcport));
    port := srcport;
  end;
  if (dstport <= 1024) then begin
    desc := trim(G_ProtoXml.GetPortDesc(prt, dstport));
    port := dstport;
  end;
  with F_ProtoTree^.Items do begin
    AppDataNode := AddChildObject(nil, 'Application Data - '+desc, no);
    //AddChildObject(AppDataNode, 'Data:                 '+p, nil);
  end;
end;

////////////////////////////////////////////////////////////////////////////////
procedure TPacketAnalyzer.ParsePacketInTreeView(p: PSniffData; pno: integer);
var
  tmp, ipp, ipdp, tcpdp: pointer;
  //ether_pointer, ip pointer, ip data pointer, tcp data pointer.
  prt: WORD;
  pktlen, offset, port: integer;
begin
  offset := 0;
  pktlen := p^.Length;
  AddPacketNode(p, pno);
  tmp := PETHERNET_HDR(p^.Buffer);
  prt := GetEtherType(PETHERNET_HDR(tmp)^.Protocol);
  AddEtherNode(tmp);
  case prt of
    PROTO_IP:     begin
      offset := AddIPNode(@(PETHERNET_HDR(tmp)^.Data), prt);
      ipp := PIP_RHDR(@(PETHERNET_HDR(tmp)^.Data));
    end;
    PROTO_PPPoE:  begin
      AddPPPoENode(@(PETHERNET_HDR(tmp)^.Data), prt);
      AddPPPNode(PP3oE_HDR(@(PETHERNET_HDR(tmp)^.Data))^.Protocol);
      if ntohs(PP3oE_HDR(@(PETHERNET_HDR(tmp)^.Data))^.Protocol) = 33 then begin
        prt := PP3oE_HDR(@(PETHERNET_HDR(tmp)^.Data))^.Protocol;
        offset := AddIPNode( @( PP3oE_HDR(@(PETHERNET_HDR(tmp)^.Data))^.Data ) , prt);
        ipp := PIP_RHDR(@( PP3oE_HDR(@(PETHERNET_HDR(tmp)^.Data))^.Data ));
      end;
    end;
    PROTO_ARP:    begin
      AddARPNode(@(PETHERNET_HDR(tmp)^.Data), prt);
      Exit;
    end;
  else
    Exit;
  end;
  //
  if ipp = nil then exit;
  prt := PIP_RHDR(ipp)^.Protocol;
  ipdp := PChar(@PIP_RHDR(ipp)^.Data) + offset;
  case prt of
    6 : begin
      offset := AddTCPNode(PTCP_RHDR(ipdp), prt);
      tcpdp := PChar(@PTCP_RHDR(ipdp)^.Data) + offset;
      AddAppDataNode(tcpdp, prt, StrToInt(GetTcpPort(PTCP_RHDR(ipdp)^.SrcPort)),
                     StrToInt(GetTcpPort(PTCP_RHDR(ipdp)^.DestPort)));
    end;
    17: begin
      AddUDPNode(PUDP_RHDR(ipdp), prt);
    end;
  else
    Exit;
  end;
end;

procedure TPacketAnalyzer.PrepareProtoTree(tv: PTreeView);
begin
  F_ProtoTree := tv;
end;

class procedure TPacketAnalyzer.ParsePacketAddrInfo(p: PSniffData;
  inaddr, outaddr: PMAC2IP);
var
  tmp: pointer;
  I: integer;
begin
  FillChar(inaddr^.MAC, 6, 0);
  FillChar(inaddr^.IP, 4, 0);
  FillChar(outaddr^.MAC, 6, 0);
  FillChar(outaddr^.IP, 4, 0);
  tmp := PETHERNET_HDR(p^.Buffer);
  for I:=0 to 5 do begin
    inaddr^.MAC[I] := PETHERNET_HDR(tmp)^.Destination[I];
    outaddr^.MAC[I] := PETHERNET_HDR(tmp)^.Source[I];
  end;
  case GetEtherType(PETHERNET_HDR(tmp)^.Protocol) of
    PROTO_IP:     begin
      for I := 0 To 3 do begin
        inaddr^.IP[I] := PIP_RHDR(@(PETHERNET_HDR(tmp)^.Data))^.DestIP[I];
        outaddr^.IP[I] := PIP_RHDR(@(PETHERNET_HDR(tmp)^.Data))^.SrcIP[I];
      end;
    end;
  else
    Exit;
  end;
end;

end.
