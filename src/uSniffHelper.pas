unit uSniffHelper;

{///////////////////////////////////////////////////////////////////////////////

  unit desc:      定义监听数据缓冲区的内存结构定义
  unit author:    net_xray@hotmail.com
  created date:   2003/10/06

  problem: TList是不是线程安全的

///////////////////////////////////////////////////////////////////////////////}

interface

uses
  Windows, SysUtils, Classes, JclSynch;

type

  PPacketInfo = ^TPacketInfo;
  TPacketInfo = record
    //Packet Info
    PacketNo  : Integer;
    SrcAddr   : array [0..5] of byte;
    DstAddr   : array [0..5] of byte;
    DataFlag  : string;
    Length    : integer;
    TimeStamp : string;
    Protocol  : WORD;
    Descript  : string;
    //Packet Data Pointer
    Data      : Pointer;
  end;

  PSniffData = ^TSniffData;
  TSniffData = record
    Length: Word;     // packet length
    Buffer: Pointer;  // packet data
  end;

  TSniffHelper = class
    private
      F_Optex: TJclOptex;
      F_DataList : TThreadList;     // stores sniff data, threadsafe
      F_Threshold : Integer;  // threshold of packets
      F_CountNow : Integer;   //
      F_MemUsage : Integer;   //
    public
      constructor Create;
      destructor Destroy; override;
      procedure Free;
      // user define
      procedure Restart;
      procedure AddPacketData(Data: Pointer; Len: Word);
      procedure UpdatePktThreshold;
      function IsThreshold: boolean;
      function GetPacketDataInNewMem(const Index: Integer): PSniffData;
      function GetPacketDataInReadOnly(const Index: Integer): PSniffData;
      function GetPacketCount: Integer;
      function GetMemoryUsage: Integer;
      //
      property PktThreshold: Integer read F_Threshold write F_Threshold;
      property PktCountNow: Integer read F_CountNow write F_CountNow;
  end;

const
  STR_SNIFF_OPTEX = 'AddSniffData';

implementation

{ TSniffHelper }

constructor TSniffHelper.Create;
begin
  F_CountNow := 0;
  F_MemUsage := 0;
  F_DataList := TThreadList.Create;
  F_Optex := TJclOptex.Create(STR_SNIFF_OPTEX);
end;

destructor TSniffHelper.Destroy;
begin
  Free;
  inherited;
end;

procedure TSniffHelper.Free;
var
  i : integer;
begin
  try
    with F_DataList.LockList do begin
      for i := 0 to Count - 1 do FreeMem(Items[i]);
      Clear;
    end;
  finally
    F_DataList.UnlockList;
  end;
  F_DataList.Clear;
  F_DataList.Free;
  F_Optex.Free;
end;

procedure TSniffHelper.AddPacketData(Data: Pointer; Len: Word);
var
  PSD: PSniffData;
  P: Pointer;
begin
  F_Optex.Enter;
  try
    if not IsThreshold Then begin
      P := AllocMem(Len);
      CopyMemory(P, Data, Len);
      ///////////////////////////////
      PSD := New(PSniffData);
      with PSD^ do begin
        Length := Len;
        Buffer := P;
      end;
      F_DataList.Add(PSD);
    end;
    Inc(F_CountNow);
    Inc(F_MemUsage, Len);
  finally
    F_Optex.Leave;
  end;
end;

function TSniffHelper.GetMemoryUsage: Integer;
begin
  Result := F_MemUsage;
end;

function TSniffHelper.GetPacketCount: Integer;
begin
  Result := F_CountNow;
end;

function TSniffHelper.GetPacketDataInNewMem(const Index: Integer): PSniffData;
var
  tPSD : TSniffData;
  pPSD : PSniffData;
  pTmp : Pointer;
begin
  Result := nil;
  try
    with F_DataList.LockList do begin
      If (Index >= Count) or (Index < 0) Then Exit;
      GetMem(pPSD, Sizeof(TSniffData));
      FillChar(pPSD, SizeOf(TSniffData), 0);
      tPSD.Length := PSniffData(Items[Index])^.Length;
      tPSD.Buffer := AllocMem(pPSD^.Length);
      CopyMemory(tPSD.Buffer, PSniffData(Items[Index])^.Buffer, tPSD.Length);
      pPSD := @tPSD;
    end;
    Result := pPSD;
  finally
    F_DataList.UnlockList;
  end;
end;

function TSniffHelper.GetPacketDataInReadOnly(const Index: Integer): PSniffData;
begin
  Result := nil;
  try
    with F_DataList.LockList do begin
      If (Index >= Count) or (Index < 0) Then Exit;
      Result := PSniffData(Items[Index]);
    end;
  finally
    F_DataList.UnlockList;
  end;
end;

procedure TSniffHelper.Restart;
var
  i: integer;
begin
  try
    with F_DataList.LockList do begin
      for i := 0 to Count - 1 do FreeMem(Items[i]);
      Clear;
    end;
  finally
    F_DataList.UnlockList;
  end;
  F_DataList.Clear;
  F_DataList.Free;
  F_CountNow := 0;
  F_MemUsage := 0;
  F_DataList := TThreadList.Create;
end;

function TSniffHelper.IsThreshold: boolean;
begin
  If (F_CountNow >= F_Threshold) and (F_Threshold > 0) Then
    Result := True
  else
    Result := False;
end;

procedure TSniffHelper.UpdatePktThreshold;
begin
  F_Threshold := F_Threshold + F_CountNow;
end;

end.
