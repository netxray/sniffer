unit uCommon;

interface

uses
  Windows, Classes, Controls, ComCtrls, ExtCtrls, Grids, StdCtrls,
  SysUtils, Variants, WinSock, Xmldom, XmlIntf, MsXmlDom, XmlDoc, Math,
  Graphics; //, uHexDumpGrid;

Type

  PTreeNode = ^TTreeNode;
  PTreeView = ^TTreeView;

  PMAC2IP = ^TMAC2IP;
  TMAC2IP = record
    MAC:     array [0..5] of UCHAR;   // mac address
    IP:      array [0..3] of UCHAR;   // node ip
  end;

  PNodeObj = ^TNodeObj;
  TNodeObj = Record
    FontColor: TColor;
    FontStyle: TFontStyles;
  end;

  function GetNameByIP(MIP:string; var Name:string):boolean;
  function HexToInt(const HexStr: string): LongInt;
  function MACtoStr(MAC: array of byte):string;
  function IPToStr(ip: array of UCHAR): string;
  function GetEtherType(p: array of UCHAR): WORD;
  function CompareMAC(MAC1, MAC2: array of byte): boolean;
  function CompareIP(IP1, IP2: array of byte): boolean;
  function IsValidIP(IP: array of byte): boolean;
  function IsValidMAC(MAC: array of byte): boolean;
  //
  function GetAttribute(NowNode: IXMLNode; AttrName: string; DefVal: string): OleVariant;
  function IsCommentsNode(NowNode: IXMLNode): boolean;
  function DecToBinStr(N: Integer): string;
  function FmtStrWithZeroPrefix(const Count: integer; srcstr: string):String;
  //
  function TransChar(AChar: Char): Integer;
  function StrToHex(AStr: string): string;
  function HexToStr(AStr: string): string;
  function BufToStr(var buf; bufSize: integer) : string;
  procedure StrToBuf(var buf; str: string);
  procedure BinToHex(Buffer, Text: PAnsiChar; BufSize: Integer);
  function IsPrintable(const c:AnsiChar): boolean;

implementation

function IsPrintable(const c:AnsiChar): boolean;
begin
  Result := (c in [#$20 .. #$7E]);
end;

procedure BinToHex(Buffer, Text: PAnsiChar; BufSize: Integer);
const
  Convert: array[0..15] of AnsiChar = '0123456789ABCDEF';
var
  I: Integer;
begin
  for I := 0 to BufSize - 1 do
  begin
    Text[0] := Convert[Byte(Buffer[I]) and $F];
    Inc(Text);
  end;
end;

function GetAttribute(NowNode: IXMLNode; AttrName, DefVal: string): OleVariant;
begin
  if VarIsNull(NowNode.Attributes[AttrName]) then
    Result := DefVal
  else
    Result := NowNode.Attributes[AttrName];
end;

function IsCommentsNode(NowNode: IXMLNode): boolean;
begin
  if (NowNode.NodeType = ntComment) then
    Result := True
  else
    Result := False;    
end;

function MACtoStr(MAC: array of byte):string;
var
  I: integer;
begin   //.2 set prec for hex num
 For I:=0 to 5 do begin
   Result := Result + IntToHex(MAC[I],2);
   If I <> 5 Then Result := Result + ':';
 end;
 Result := Result;
end;

function IPToStr(ip: array of UCHAR): string;
begin
  Result := Format('%d.%d.%d.%d', [ip[0], ip[1], ip[2], ip[3]]);
end;

function GetEtherType(p: array of UCHAR): WORD;
begin
  Result := (p[0] shl 8) or p[1];//08,00 --> 0800
end;

function CompareMAC(MAC1, MAC2: array of byte): boolean;
var
  I: integer;
begin
  Result := False;
  For I := 0 To 5 do begin
    if MAC1[I] <> MAC2[I] Then Exit;
  end;
  Result := True;
end;

function CompareIP(IP1, IP2: array of byte): boolean;
var
  I: integer;
begin
  Result := False;
  For I := 0 To 3 do begin
    if IP1[I] <> IP2[I] Then Exit;
  end;
  Result := True;
end;

function IsValidIP(IP: array of byte): boolean;
var
  I: integer;
begin
  Result := False;
  For I := 0 To 3 do begin
    if IP[I] = 0 Then Exit;
  end;
  Result := True;
end;

function IsValidMAC(MAC: array of byte): boolean;
var
  I, J: integer;
begin
  J := 0;
  Result := False;
  For I := 0 To 5 do begin
    if MAC[I] = 0 Then Inc(J);
  end;
  if J = 6 Then Exit;
  Result := True;
end;

Function GetNameByIP(MIP:string; var Name:string):boolean;
var
  PHt:PHostEnt;
  WSData: TWSAData;
  i:Word;
  j:integer;
  k:u_long;
begin
  Result := False;
  i := MAKEWORD(1,1);
  if WSAStartup(i,WSData)<>0 then exit;
  k := inet_addr(PAnsiChar(MIP));
  PHt := gethostbyaddr(@k,4,PF_INET);
  if PHt = nil then begin
     j := WSAGetLastError;
     Name := ''; //'Error:'+inttostr(j-WSABASEERR);
  end else begin
     Name := PHt.h_name;
     Result := True;
  end;
  WSACleanup;
end;

function HexToInt(const HexStr: string): LongInt;
var
  iNdx: integer;
  cTmp: Char;
begin
  Result := 0;
  for iNdx := 1 to Length(HexStr) do begin
    cTmp := HexStr[iNdx]; // 字符串string内存中的第一位是length标识
    case cTmp of
      '0'..'9': Result := 16 * Result + (Ord(cTmp) - $30);
      'A'..'F': Result := 16 * Result + (Ord(cTmp) - $37);
      'a'..'f': Result := 16 * Result + (Ord(cTmp) - $57);
    else
      raise EConvertError.Create('Illegal character in hex string');
    end;
  end;
end;

function DecToBinStr(N: Integer): string;
var
  S: string;
  i: Integer;
  Negative: Boolean;
begin
  Negative := False;
  if N < 0 then Negative := True;
  N := Abs(N);
  for i := 1 to SizeOf(N) * 8 do
  begin
    if N < 0 then S := S + '1'
    else S := S + '0';
    N := N shl 1;
  end;
  Delete(S, 1, Pos('1', S) - 1);
  if Negative then S := '-' + S;
  Result := S;
end;

function FmtStrWithZeroPrefix(const Count: integer; srcstr: string):String; 
Var 
  s1, s2: String;
begin 
  s1 := srcstr;
  s2 := '00000000';
  if (Length(s1) >= count) then
    s2:=''
  else if(count > 8) then
    SetLength(S2, 8 - Length(s1))
  else
    SetLength(S2, count - Length(s1));

  Result := S2 + S1; 
end;

function TransChar(AChar: Char): Integer;
begin
  if AChar in ['0'..'9'] then
  Result := Ord(AChar) - Ord('0')
  else
  Result := 10 + Ord(AChar) - Ord('A');
end;

function StrToHex(AStr: string): string;
var
  I ,Len: Integer;
  s:char;
begin
  len:=length(AStr);
  Result:='';
  for i:=1 to len  do
  begin
    s:=AStr[i];
    Result:=Result +' '+IntToHex(Ord(s),2); //将字符串转化为16进制字符串，
                                            //并以空格间隔。
  end;
  Delete(Result,1,1); //删去字符串中第一个空格
end;

function HexToStr(AStr: string): string;
var
  I,len : Integer;
  CharValue: Word;
  Tmp:string;
  s:char;
begin
  Tmp:='';
  len:=length(Astr);
  for i:=1 to len  do
  begin
    s:=Astr[i];
    if s <> ' ' then Tmp:=Tmp+ string(s);
  end;
  Result := '';
  For I := 1 to Trunc(Length(Tmp)/2) do
  begin
    Result := Result + ' ';
    CharValue := TransChar(Tmp[2*I-1])*16 + TransChar(Tmp[2*I]);
    if (charvalue < 32) or (charvalue > 126)  then Result[I] := '.'   //非可见字符填充
    else Result[I] := Char(CharValue);
  end;
end;

function BufToStr(var buf; bufSize: integer) : string;
begin
  SetLength(result, bufSize);
  Move(buf, pointer(result)^, bufSize);
end;

procedure StrToBuf(var buf; str: string);
begin
  Move(pointer(str)^, buf, Length(str));
end;

end.
