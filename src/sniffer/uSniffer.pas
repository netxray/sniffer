unit uSniffer;

{///////////////////////////////////////////////////////////////////////////////

  unit desc:      定义监听对象组件
  unit author:    net_xray@hotmail.com
  created date:   2003/10/01

///////////////////////////////////////////////////////////////////////////////}

interface

uses
  Windows, Messages, SysUtils, Variants, Classes, Math,
  SyncObjs, JclDatetime, JclSysInfo, uWpCap, uWpCapImpl;//uWinPCap

type
  TSnifferThread = class;

  TSniffer = class
  private
    FIsSniffing : boolean;
    FAdapterIndex : integer;
    FDevNames, FDevDescs: TStringList;
    FThread : TSnifferThread;
    FVersion: string;
    FErrMsg: string;
    FPCap : Ppcap_t;
    procedure SetAdapterIndex(const Value: Integer);
    procedure ThreadTerminate(Sender: TObject);
  public
    OnPacket : Procedure(Data: Pointer; RecvBytes: Word) of Object;
    Constructor Create;
    Destructor Destroy; Override;
    Function Activate(var ErrMsg : String) : boolean;
    Function DeActivate(var ErrMsg : String) : boolean;
    //property
    property IsSniffing: boolean read FIsSniffing;
    property Adapters: TStringList read FDevNames;
    property AdapterIndex: integer read FAdapterIndex write SetAdapterIndex;
    property WpCapVersion: string read FVersion;
  end;


  //抓包线程
  TSnifferThread = class(TThread)
  private
    { Private declarations }
    Sniffer : TSniffer;
  protected
    Constructor Create(S: TSniffer);
    Destructor Destroy; override;
    procedure Execute; override;
    procedure SniffData;
  end;


implementation

constructor TSniffer.Create;
begin
  FVersion := 'unknow';
  FAdapterIndex := 0;
  FDevNames := TStringList.Create;
  FDevDescs := TStringList.Create;
  FPCAP := nil;
  FIsSniffing := FALSE;
  GetAdapters(FErrMsg, FDevNames, FDevDescs);
end;

function TSniffer.Activate(var ErrMsg: String): boolean;
begin
  Result := False;
  if FIsSniffing or (FPCap <> nil) then
    begin
      ErrMsg := 'Warning: Sniffer is working now!';
      Exit;
    end;

  FPCap := ActivatePCap(FDevNames.Strings[FAdapterindex], ErrMsg);
  if FPCap = nil then Exit;

  FVersion := GetWpCapVersion;
  if not Assigned(OnPacket) then
    begin
      ErrMsg:='No Packet Read Callback function assigned';
      exit;
    end;

  FThread := TSnifferThread.create(self);
  FThread.OnTerminate := ThreadTerminate;
  FThread.FreeOnTerminate := FALSE;
  FThread.resume;
  FIsSniffing := True;
  Result := True;
end;

function TSniffer.DeActivate(var ErrMsg: String): boolean;
begin
  Result := False;
	if not FIsSniffing then begin ErrMsg := 'Warning: sniffer not active.';Exit; end;
	if FThread = nil then begin ErrMsg := 'Warning: No Sniffer Thread to Stop.';Exit; end;

  FThread.Terminate;
  FThread.WaitFor;
  FThread.Free;
  FThread := nil;
  FIsSniffing := FALSE;
  
  DeActivatePCap(FPCap);
  Result := True;
end;

destructor TSniffer.Destroy;
var
  ErrMsg : String;
begin
  DeActivate(ErrMsg);
  FDevNames.Free;
  FDevNames := nil;
  FDevDescs.Free;
  FDevDescs := nil;
  inherited;
end;

procedure TSniffer.SetAdapterIndex(const Value: integer);
begin
  if (Value >- 1) and (Value < Adapters.Count) then
    FAdapterIndex := Value;
end;

procedure TSniffer.ThreadTerminate(Sender: tobject);
begin
  FIsSniffing := FALSE;
end;


{//////////////////////////////////////////////////////////////////////////////////////////////////}
{ TSnifferThread }
{//////////////////////////////////////////////////////////////////////////////////////////////////}

procedure CaptureCallBack(User: Pointer; const Header: PPacketHdr; const Data: PChar);
begin
  TSniffer(User).OnPacket(Data, Header.Len); //Header.Len --> actual length of packet
end;

constructor TSnifferThread.Create(S: TSniffer);
begin
  Sniffer := S;
  inherited Create(TRUE);
end;

destructor TSnifferThread.Destroy;
begin
  //
  inherited;
end;

procedure TSnifferThread.Execute;
begin
  { Place thread code here }
  if Sniffer = nil then exit;

  While Not Terminated do
    begin
      SniffData
    end;
end;

procedure TSnifferThread.SniffData;
begin
  SniffPacket(Sniffer.FPCAP, 0, CaptureCallBack, Pointer(Sniffer));
end;

end.
