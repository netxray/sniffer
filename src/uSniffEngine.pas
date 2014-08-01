unit uSniffEngine;

{///////////////////////////////////////////////////////////////////////////////

  unit desc:      监听引擎，作为控制器管理读/写线程，并由MAIN进行调用
  unit author:    net_xray@hotmail.com
  created date:   2003/10/06

  problem: 用XML定义协议格式

///////////////////////////////////////////////////////////////////////////////}

interface

uses
  Windows, Messages, SysUtils, Variants, Classes, StdCtrls,
  ComCtrls, JclSynch, JclDateTime, uCommon,
  uProtocolDef, uSniffer, uSniffHelper, uPacketAnaysis;

type

  TThreadPacketReader = class;
  PListView = ^TListView;
  TSniffEngineStopEvent = procedure(var AutoStop: boolean) of object;

  TSniffEngine = class
    private
      F_Count : Integer;
      F_OnStop: TSniffEngineStopEvent;
      F_IsAutoStop : Boolean;
      F_Sniffer: TSniffer;
      F_SniffHelper: TSniffHelper;
      F_ErrMsg : string;
      F_Thread : TThreadPacketReader;
      F_PktThreshold: Integer;
      //TJclMultiReadExclusiveWrite
      procedure SetPktThreshold(thres: Integer);
    public
      PrintPacket: procedure(pp: PPacketInfo; mem: Integer) of object;
      constructor Create;
      destructor Destroy; override;
      //
      function Start: boolean;
      function Stop: boolean;
      function GetAdapterList: TStringList;
      function SetSniffAdapter(Index: Integer): boolean;
      //
      property ErrMsg: string read F_ErrMsg;
      property PktThreshold: Integer read F_PktThreshold write SetPktThreshold;
      property OnStop: TSniffEngineStopEvent read F_OnStop write F_OnStop;
      property IsAutoStop: Boolean read F_IsAutoStop write F_IsAutoStop;
      property PacketCounts: Integer read F_Count write F_Count;
  end;

  TThreadPacketReader = class(TThread)
  private
    F_ReadCount : Integer;
    F_Optex: TJclOptex;
    F_SniffEngine: TSniffEngine;
  protected
    Constructor Create(SE: TSniffEngine);
    Destructor Destroy; override;
    procedure Execute; override;
    procedure OutputPacketInfo;
  end;

const
  STR_READER_OPTEX = 'TTHREAD_PACKET_READER';


implementation

{ TSniffEngine }

constructor TSniffEngine.Create;
begin
  F_Count := 0;
  F_ErrMsg      := '';
  F_IsAutoStop  := False;
  F_Sniffer     := TSniffer.Create;
  F_SniffHelper := TSniffHelper.Create;
  F_PktThreshold := 0;
  F_SniffHelper.PktThreshold := F_PktThreshold;
  F_Sniffer.OnPacket := F_SniffHelper.AddPacketData;
end;

destructor TSniffEngine.Destroy;
begin
  F_SniffHelper.Destroy;
  F_Sniffer.Destroy;
  inherited;
end;

function TSniffEngine.GetAdapterList: TStringList;
begin
  Result := F_Sniffer.Adapters;
end;

procedure TSniffEngine.SetPktThreshold(thres: Integer);
begin
  F_PktThreshold := thres;
  F_SniffHelper.PktThreshold := F_PktThreshold;
end;

function TSniffEngine.SetSniffAdapter(Index: Integer): boolean;
begin
  Result := False;
  If (Index >= F_Sniffer.Adapters.Count ) or (Index < 0) Then Exit;
  F_Sniffer.AdapterIndex := Index;
  Result := True;
end;

function TSniffEngine.Start: boolean;
begin
  Result := False;
  F_IsAutoStop := False;
  if F_Sniffer.IsSniffing Then Exit;
  if F_Sniffer.Activate(F_ErrMsg) Then begin
    F_Thread := TThreadPacketReader.Create(Self);
    F_Thread.FreeOnTerminate := True;//FALSE;
    //如果是FALSE，F_Optex会死锁！！导致读线程阻塞！！
    F_Thread.Resume;
    Result := True;
  end;
end;

function TSniffEngine.Stop: boolean;
begin
  Result := False;
  If F_IsAutoStop and Assigned(F_OnStop) Then begin
    F_OnStop(F_IsAutoStop);
    F_IsAutoStop := False;
    Exit;
  end;
  If not F_Sniffer.IsSniffing Then Exit;
  If F_Sniffer.DeActivate(F_ErrMsg) Then begin
    F_Thread.Terminate;
    //F_Thread.WaitFor;
    //F_Thread.Free;
    F_Thread := nil;
    Result := True;
  end;
  //Do Stop Events
end;

////////////////////////////////////////////////////////////////////////////////
{ TThreadPacketReader }
////////////////////////////////////////////////////////////////////////////////

constructor TThreadPacketReader.Create(SE: TSniffEngine);
begin
  F_ReadCount := 0;
  F_SniffEngine := SE;
  F_Optex := TJclOptex.Create(STR_READER_OPTEX);
  inherited Create(TRUE);
end;

destructor TThreadPacketReader.Destroy;
begin
  F_Optex.Free;
  inherited;
end;

procedure TThreadPacketReader.Execute;
begin
  While Not Terminated do
  begin
    if F_SniffEngine = nil then Exit;
    If not F_SniffEngine.F_Sniffer.IsSniffing then Exit;
    OutputPacketInfo;
  end;
end;

procedure TThreadPacketReader.OutputPacketInfo;
var
  pp: PPacketInfo;
  st: TSystemTime;
  p: pointer;
  I: integer;
begin
  F_Optex.Enter;
  try
    if (F_ReadCount >= F_SniffEngine.PktThreshold) and
      (F_SniffEngine.PktThreshold > 0) Then begin
      F_SniffEngine.IsAutoStop := True;  // friend member
      F_SniffEngine.F_SniffHelper.UpdatePktThreshold;     
      F_SniffEngine.Stop;
      F_ReadCount := 0;
    end else begin
      p := nil;
      p := F_SniffEngine.F_SniffHelper.GetPacketDataInReadOnly(F_SniffEngine.PacketCounts);
      if (p <> nil) then begin
        F_SniffEngine.PacketCounts := F_SniffEngine.PacketCounts + 1;
        Inc(F_ReadCount);
        GetLocalTime(st);
        pp := New(PPacketInfo);
        pp^.Length := PSniffData(p)^.Length;
        pp^.Data := p;  //PSniffData!! not Pure Data Pointer
        pp^.PacketNo := F_SniffEngine.PacketCounts;
        pp^.DataFlag  := '';
        pp^.TimeStamp := SystemTimeToStr(st) +'.'+ IntToStr(st.wMilliseconds);
        pp^.Descript := '';
        for I := 0 To 5 do begin
          pp^.SrcAddr[I]   := PETHERNET_HDR(PSniffData(pp^.Data)^.Buffer)^.Source[I];
          pp^.DstAddr[I]   := PETHERNET_HDR(PSniffData(pp^.Data)^.Buffer)^.Destination[I];
        end;
        pp^.Protocol  := GetEtherType(PETHERNET_HDR((PSniffData(pp^.Data)^.Buffer))^.Protocol);
        F_SniffEngine.PrintPacket(pp, F_SniffEngine.F_SniffHelper.GetMemoryUsage);
      end;
    end;
  finally
    F_Optex.Leave;
  end;
end;


end.
