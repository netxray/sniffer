unit uProtoXml;

{
  create & destroy in uMain
  references in uPacketAnaysis
}

interface

uses
  Classes, SysUtils, Variants, Xmldom, XmlIntf, MsXmlDom, XmlDoc,
  WinSock, uCommon;

type

  // ppp assigned number conf structure
  PP3Number = ^TP3Number;
  TP3Number = record
  	value  : integer;
  	hex		 : string;
	  desc 	 : string;
	  references : string;
  end;

  PP3NumList = ^TP3NumList;
  TP3NumList = record
    m_count  : integer;
    m_list   : array of TP3Number;
  end;

  // ip packet conf structure
  PIPNumber = ^TIPNumber;
  TIPNumber = record
  	decimal    : integer;
  	keyword		 : string;
	  protocol 	 : string;
	  references : string;
  end;

  PIPNumList = ^TIPNumList;
  TIPNumList = record
    m_count  : integer;
    m_list   : array of TIPNumber;
  end;

  // ethernet frame conf structure
  PETNumber = ^TETNumber;
  TETNumber = record
  	decimal    : integer;
  	hex		     : string;
	  desc 	     : string;
	  references : string;
  end;

  PETNumList = ^TETNumList;
  TETNumList = record
    m_count  : integer;
    m_list   : array of TETNumber;
  end;

  // port number conf structure
  PPortNumber = ^TPortNumber;
  TPortNumber = record
    m_number : integer;
    m_desc   : string;
  end;

  PPortList = ^TPortList;
  TPortList = record
    m_count   : integer;
    m_type    : integer;
    m_ports   : array of TPortNumber; 
  end;

  PPTNumList = ^TPTNumList;
  TPTNumList = record
    m_count   : integer;
    m_portlist: array of TPortList;
  end;

  PIPNumberCls = ^TIPNumberCls;
  TIPNumberCls = class
    private
      G_Xml: TXMLDocument;
      G_Nlst: PIPNumList;
      G_Elst: PETNumList;
      G_Plst: PPTNumList;
      G_3lst: PP3NumList;
      function GetP3Numbers(cnt: integer): boolean;
      function GetIPNumbers(cnt: integer): boolean;
      function GetETNumbers(cnt: integer): boolean;
      function GetPortList(cnt: integer): boolean;
      function GetPortNumber(now_item: IXMLNode; t, cnt: integer): boolean;
      function LoadIPXml(const XmlFile: string): boolean;
      function LoadETXml(const XmlFile: string): boolean;
      function LoadPTXml(const XmlFile: string): boolean;
      function LoadP3Xml(const XmlFile: string): boolean;
    public
      constructor Create;
      destructor Destory;
      procedure Free;
      //IP Assigned Numbers
      function ParseIPXml(xml: TXMLDocument): boolean;
      //Ethernet Type Code
      function ParseETXml(xml: TXMLDocument): boolean;
      //UDP & TCP Port Number
      function ParsePTXml(xml: TXMLDocument): boolean;
      //PPP Assigned Number
      function ParseP3Xml(xml: TXMLDocument): boolean;
      // public
      function GetIPProtoDesc(no: integer): string;
      function GetETProtoDesc(no: integer): string;
      function GetPortDesc(porttype, no: integer): string;
      function GetP3ProtoDesc(no: integer): string;
  end;

var
  G_ProtoXml: TIPNumberCls; // Global Variable

implementation

{ TIPNumberCls }

function TIPNumberCls.ParseIPXml(xml: TXMLDocument): boolean;
begin
  G_Xml := xml;
  Result := LoadIPXml(G_Xml.FileName);
  G_Xml := nil;
end;

constructor TIPNumberCls.Create;
begin
  G_Nlst := New(PIPNumList);
  G_Nlst^.m_count := 0;
  G_Elst := New(PETNumList);
  G_Elst^.m_count := 0;
  G_Plst := New(PPTNumList);
  G_Plst^.m_count := 0;
  G_3lst := New(PP3NumList);
  G_3lst^.m_count := 0;
end;

destructor TIPNumberCls.Destory;
begin
  Free;
end;

procedure TIPNumberCls.Free;
var
  I: integer;
begin
  G_3lst^.m_list := nil;
  Dispose(G_3lst);
  G_Nlst^.m_list := nil;
  Dispose(G_Nlst);
  G_Elst^.m_list := nil;
  Dispose(G_Elst);
  for I := 0 To G_Plst^.m_count - 1 do begin
    G_Plst^.m_portlist[I].m_ports := nil;
  end;
  G_Plst^.m_portlist := nil;
  Dispose(G_Plst);
end;

////////////////////////////////////////////////////////////////////////////////

function TIPNumberCls.GetIPProtoDesc(no: integer): string;
var
  I: integer;
begin
  Result := '';
  For I := 0 To G_Nlst^.m_count - 1 do begin
    if G_Nlst^.m_list[I].decimal = no then begin
      Result := '[' + G_Nlst^.m_list[I].keyword + '] ' + G_Nlst^.m_list[I].protocol;
      Exit;
    end;
  end;
end;

function TIPNumberCls.GetIPNumbers(cnt: integer): boolean;
var
  I, J : Integer;
  Root : IXMLNode; 				//point to root node
  tagList : IXMLNodeList;
begin
  J := 0;
  Result := False;
  Root := G_Xml.DocumentElement;
  tagList := Root.ChildNodes;
  for I := 0 to tagList.Count - 1 do    // Iterate
  begin
    If IsCommentsNode(tagList.Nodes[I]) then Continue;
    if CompareText(UpperCase(tagList.Nodes[I].NodeName), 'number') = 0 then
    begin
      G_Nlst^.m_list[J].decimal     := GetAttribute(tagList.Nodes[I], 'decimal', 'unknown');
      G_Nlst^.m_list[J].keyword     := GetAttribute(tagList.Nodes[I], 'keyword', 'unknown');
      G_Nlst^.m_list[J].protocol    := GetAttribute(tagList.Nodes[I], 'protocol', '');
      G_Nlst^.m_list[J].references  := GetAttribute(tagList.Nodes[I], 'references', '');
    end
    else
      Exit;
    Inc(J);
  end;    // for
  Result := True;
end;

function TIPNumberCls.LoadIPXml(const XmlFile: string): boolean;
var
  Root : IXMLNode; 				//point to root node
begin
  Result := False;
  G_Xml.LoadFromFile(XmlFile);
  Root := G_Xml.DocumentElement;
  G_Nlst^.m_count := Root.ChildNodes.Count;;
  SetLength(G_Nlst^.m_list, G_Nlst^.m_count);
  Result := GetIPNumbers(G_Nlst^.m_count);
end;

////////////////////////////////////////////////////////////////////////////////

function TIPNumberCls.GetETNumbers(cnt: integer): boolean;
var
  I, J : Integer;
  Root : IXMLNode; 				//point to root node
  tagList : IXMLNodeList;
begin
  J := 0;
  Result := False;
  Root := G_Xml.DocumentElement;
  tagList := Root.ChildNodes;
  for I := 0 to tagList.Count - 1 do    // Iterate
  begin
    If IsCommentsNode(tagList.Nodes[I]) then Continue;
    if CompareText(UpperCase(tagList.Nodes[I].NodeName), 'number') = 0 then
    begin
      G_Elst^.m_list[J].decimal     := GetAttribute(tagList.Nodes[I], 'decimal', 'unknown');
      G_Elst^.m_list[J].hex         := GetAttribute(tagList.Nodes[I], 'hex', 'unknown');
      G_Elst^.m_list[J].desc        := GetAttribute(tagList.Nodes[I], 'description', '');
      G_Elst^.m_list[J].references  := GetAttribute(tagList.Nodes[I], 'references', '');
    end
    else
      Exit;
    Inc(J);
  end;    // for
  Result := True;
end;

function TIPNumberCls.GetETProtoDesc(no: integer): string;
var
  I: integer;
begin
  Result := '';
  For I := 0 To G_Elst^.m_count - 1 do begin
    if G_Elst^.m_list[I].decimal = no then begin
      Result := '[' + G_Elst^.m_list[I].hex + '] ' + G_Elst^.m_list[I].desc;
      Exit;
    end;
  end;
end;

function TIPNumberCls.LoadETXml(const XmlFile: string): boolean;
var
  Root : IXMLNode; 				//point to root node
begin
  Result := False;
  G_Xml.LoadFromFile(XmlFile);
  Root := G_Xml.DocumentElement;
  G_Elst^.m_count := Root.ChildNodes.Count;;
  SetLength(G_Elst^.m_list, G_Elst^.m_count);
  Result := GetETNumbers(G_Elst^.m_count);
end;

function TIPNumberCls.ParseETXml(xml: TXMLDocument): boolean;
begin
  G_Xml := xml;
  Result := LoadETXml(G_Xml.FileName);
  G_Xml := nil;
end;

////////////////////////////////////////////////////////////////////////////////

function TIPNumberCls.GetPortDesc(porttype, no: integer): string;
var
  I, J: integer;
begin
  Result := '';
  For I := 0 To G_Plst^.m_count - 1 do begin
    if G_Plst^.m_portlist[I].m_type = porttype then begin
      For J := 0 To G_Plst^.m_portlist[I].m_count - 1 do begin
        if G_Plst^.m_portlist[I].m_ports[J].m_number = no then begin
          Result := G_Plst^.m_portlist[I].m_ports[J].m_desc;
        end;
      end;
    end;
  end;
end;

function TIPNumberCls.LoadPTXml(const XmlFile: string): boolean;
var
  Root : IXMLNode; 				//point to root node
begin
  Result := False;
  G_Xml.LoadFromFile(XmlFile);
  Root := G_Xml.DocumentElement;
  G_Plst^.m_count := Root.ChildNodes.Count;;
  SetLength(G_Plst^.m_portlist, G_Plst^.m_count);
  Result := GetPortList(G_Plst^.m_count);
end;

function TIPNumberCls.ParsePTXml(xml: TXMLDocument): boolean;
begin
  G_Xml := xml;
  Result := LoadPTXml(G_Xml.FileName);
  G_Xml := nil;
end;

function TIPNumberCls.GetPortList(cnt: integer): boolean;
var
  I, J : Integer;
  Root : IXMLNode; 				//point to root node
  tagList : IXMLNodeList;
begin
  J := 0;
  Result := False;
  Root := G_Xml.DocumentElement;
  tagList := Root.ChildNodes;
  for I := 0 to tagList.Count - 1 do    // Iterate
  begin
    If IsCommentsNode(tagList.Nodes[I]) then Continue;
    if CompareText(UpperCase(tagList.Nodes[I].NodeName), 'portlist') = 0 then
    begin
      G_Plst^.m_portlist[J].m_type     := GetAttribute(tagList.Nodes[I], 'type', 'unknown');
      G_Plst^.m_portlist[J].m_count    := tagList.Nodes[I].ChildNodes.Count;
      if G_Plst^.m_portlist[J].m_count <=0 then G_Plst^.m_portlist[J].m_count := 0;
      SetLength(G_Plst^.m_portlist[J].m_ports, G_Plst^.m_portlist[J].m_count);
      if not GetPortNumber(tagList.Nodes[I], J, G_Plst^.m_portlist[J].m_count) then begin
        Exit;
      end;
    end
    else
      Exit;
    Inc(J);
  end;    // for
  Result := True;
end;

function TIPNumberCls.GetPortNumber(now_item: IXMLNode; t, cnt: integer): boolean;
var
  I, J : Integer;
  tagList : IXMLNodeList;
begin
  J := 0;
  Result := False;
  tagList := now_item.ChildNodes;
  for I := 0 to tagList.Count - 1 do    // Iterate
  begin
    If IsCommentsNode(tagList.Nodes[I]) then Continue;
    if CompareText(UpperCase(tagList.Nodes[I].NodeName), 'port') = 0 then
    begin
      G_Plst^.m_portlist[t].m_ports[J].m_number := GetAttribute(tagList.Nodes[I], 'number', 'unknown');
      G_Plst^.m_portlist[t].m_ports[J].m_desc := GetAttribute(tagList.Nodes[I], 'desc', 'unknown');
    end
    else
      Exit;
    Inc(J);
  end;    // for
  Result := True;
end;

////////////////////////////////////////////////////////////////////////////////

function TIPNumberCls.GetP3Numbers(cnt: integer): boolean;
var
  I, J : Integer;
  Root : IXMLNode; 				//point to root node
  tagList : IXMLNodeList;
begin
  J := 0;
  Result := False;
  Root := G_Xml.DocumentElement;
  tagList := Root.ChildNodes;
  for I := 0 to tagList.Count - 1 do    // Iterate
  begin
    If IsCommentsNode(tagList.Nodes[I]) then Continue;
    if CompareText(UpperCase(tagList.Nodes[I].NodeName), 'number') = 0 then
    begin
      G_3lst^.m_list[J].value     := GetAttribute(tagList.Nodes[I], 'value', 'unknown');
      G_3lst^.m_list[J].hex       := GetAttribute(tagList.Nodes[I], 'hex', 'unknown');
      G_3lst^.m_list[J].desc      := GetAttribute(tagList.Nodes[I], 'desc', '');
      G_3lst^.m_list[J].references:= GetAttribute(tagList.Nodes[I], 'references', '');
    end
    else
      Exit;
    Inc(J);
  end;    // for
  Result := True;
end;

function TIPNumberCls.GetP3ProtoDesc(no: integer): string;
var
  I: integer;
begin
  Result := '';
  For I := 0 To G_3lst^.m_count - 1 do begin
    if G_3lst^.m_list[I].value = ntohs(no) then begin
      Result := G_3lst^.m_list[I].desc;
      Exit;
    end;
  end;
end;

function TIPNumberCls.LoadP3Xml(const XmlFile: string): boolean;
var
  Root : IXMLNode; 				//point to root node
begin
  Result := False;
  G_Xml.LoadFromFile(XmlFile);
  Root := G_Xml.DocumentElement;
  G_3lst^.m_count := Root.ChildNodes.Count;;
  SetLength(G_3lst^.m_list, G_3lst^.m_count);
  Result := GetP3Numbers(G_3lst^.m_count);
end;

function TIPNumberCls.ParseP3Xml(xml: TXMLDocument): boolean;
begin
  G_Xml := xml;
  Result := LoadP3Xml(G_Xml.FileName);
  G_Xml := nil;
end;

end.
