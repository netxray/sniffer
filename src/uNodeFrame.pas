unit uNodeFrame;
{
  将 dst.ip / src.ip / protocol / dst.port / src.port / length / data pointer 形成IP Table
  每收到一个packet都检查这个IP Table，存在的将length更新，则计算出这个连接所有的数据量
  然后将同dst.ip/src.ip的同port的数据用一个链表指针管理，最后，可以通过这个链表指针还原
  出所有的数据流!
}

interface

uses 
  Windows, Messages, SysUtils, Classes, Graphics, Controls, Forms, Dialogs,
  StdCtrls, ComCtrls, JvListView, ExtCtrls, uCommon, uHoriWatch;

const
  MAX_USAGE_SIZE = 2048;

type

  TNodeFrame = class(TFrame)
    gbNode: TGroupBox;
    lvNodeList: TJvListView;
    GroupBox1: TGroupBox;
    TrafficPnl: TPanel;
  private
    { Private declarations }
    F_DrawTimer  : TTimer;
    F_Watch: THoriWatch;
    UsageBuf: array [1..MAX_USAGE_SIZE] of Byte;
    function GetTrafficItemIndex(Addr: PMAC2IP): integer;
    function AddTrafficItem(p: Pointer): boolean;
    function UpdTrafficItem(idx: integer; p: Pointer): boolean;
    procedure UpdateScope(Sender:TObject);
  public
    { Public declarations }
    constructor Create(AOwner: TComponent); override;
    destructor Destroy; override;
    procedure UpdateTraffic;
    //
  end;

implementation

uses
  uNodeTraffic;

{$R *.dfm}

{ TNodeFrame }

constructor TNodeFrame.Create(AOwner: TComponent);
begin
  inherited;
  //
  FillChar(UsageBuf[1], MAX_USAGE_SIZE, $FF);
  F_Watch           :=  THoriWatch.Create(Self);
  F_Watch.Parent    :=  TrafficPnl;
  F_Watch.Align     :=  alClient;
  F_Watch.Buffer    :=  @UsageBuf[MAX_USAGE_SIZE];
  F_Watch.LineColor :=  clYellow;
  F_DrawTimer           :=  TTimer.Create(SELF);
  F_DrawTimer.Enabled   :=  TRUE;
  F_DrawTimer.OnTimer   :=  UpdateScope;
  F_DrawTimer.Interval  :=  250;
end;

destructor TNodeFrame.Destroy;
begin
  //
  F_DrawTimer.Enabled := False;
  F_DrawTimer.Free;
  inherited;
end;

function TNodeFrame.GetTrafficItemIndex(Addr: PMAC2IP): integer;
var
  I: integer;
begin
  Result := -1;
  for I := 0 to lvNodeList.Items.Count - 1 do begin
    if CompareText(lvNodeList.Items.Item[I].SubItems.Strings[0], //IP address
      IPtoStr(Addr^.IP)) = 0 Then
    begin
      Result := I;
      Exit;
    end;
  end;
end;

function TNodeFrame.AddTrafficItem(p: Pointer): boolean;
var
  tmpItem: TListItem;
  count: Integer;
  ipaddr, nodename: string;
begin
  Result := False;
  count := lvNodeList.Items.Count + 1;
  ipaddr := IPtoStr(PTranNodeInfo(p)^.Addr.IP);
  //GetNameByIP(ipaddr, nodename);
  tmpItem := lvNodeList.Items.Add;
  with tmpItem do begin
    Caption := IntToStr(count);
    SubItems.Add(ipaddr);
    SubItems.Add(nodename);
    SubItems.Add(IntToStr(PtranNodeInfo(p)^.InBytes));
    SubItems.Add(IntToStr(PtranNodeInfo(p)^.OutBytes));
  end;
  Result := True;
end;

function TNodeFrame.UpdTrafficItem(idx: integer; p: Pointer): boolean;
begin
  with lvNodeList.Items.Item[idx] do begin
    SubItems.Strings[2] := IntToStr(PtranNodeInfo(p)^.InBytes);
    SubItems.Strings[3] := IntToStr(PtranNodeInfo(p)^.OutBytes);
  end;
  Result := True;
end;

procedure TNodeFrame.UpdateTraffic;
var
  I, count, Idx : integer;
  p: PTranNodeInfo;
begin
  //
  count := G_TranList.GetTransCount;
  For I := 0 To count - 1 do begin
    p := G_TranList.GetTransInfo(I);
    if p = nil then Continue;
    Idx := GetTrafficItemIndex(@(p^.Addr));
    if Idx = -1 then
      AddTrafficItem(p)
    else
      UpdTrafficItem(Idx, p);
  end;
end;

procedure TNodeFrame.UpdateScope(Sender: TObject);
begin
  UsageBuf[MAX_USAGE_SIZE]:=Random(100);
  Move(UsageBuf[2], UsageBuf[1], MAX_USAGE_SIZE-1);
  F_Watch.Invalidate;
end;

initialization
  RegisterClass( TNodeFrame );

end.
