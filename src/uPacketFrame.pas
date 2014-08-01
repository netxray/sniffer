unit uPacketFrame;

interface

uses
  Windows, Messages, SysUtils, Classes, Graphics, Controls, Forms, Dialogs,
  StdCtrls, ExtCtrls, Grids, ComCtrls,
  JvListView, TB2Item, TB2Dock, TB2Toolbar, TB2ExtItems, ToolWin, ImgList,
  uSniffHelper, uPacketAnaysis, uCommon, uProtoXml, JvExComCtrls, uHexDumpGrid;

type


  TPacketFrame = class(TFrame)
    lvPktList: TJvListView;
    Splitter1: TSplitter;
    Splitter2: TSplitter;
    TBView: TToolBar;
    TBPktView: TToolButton;
    TBProtoView: TToolButton;
    ImgLst: TImageList;
    tvProtocol: TTreeView;
    tbPrevPacket: TToolButton;
    tbNextPacket: TToolButton;
    ToolButton3: TToolButton;
    dgHexView: THexDumpGrid;
    procedure lvPktListClick(Sender: TObject);
    procedure lvPktListChange(Sender: TObject; Item: TListItem;
      Change: TItemChange);
    procedure tvProtocolCustomDrawItem(Sender: TCustomTreeView;
      Node: TTreeNode; State: TCustomDrawState; var DefaultDraw: Boolean);
    procedure tvProtocolDeletion(Sender: TObject; Node: TTreeNode);
    procedure TBPktViewClick(Sender: TObject);
    procedure TBProtoViewClick(Sender: TObject);
    procedure tvProtocolExit(Sender: TObject);
    procedure tvProtocolEnter(Sender: TObject);
    procedure tbPrevPacketClick(Sender: TObject);
    procedure tbNextPacketClick(Sender: TObject);
  private
    { Private declarations }
    F_IsEnter: boolean;
    F_IsHexView: boolean;
    F_IsPktView: boolean;
    F_Analyzer: TPacketAnalyzer;
    procedure ParsePacketInHexView(p: pointer);
    procedure ParsePacketInTreeView(p: pointer; pno: integer);
  public
    { Public declarations }
    constructor Create(AOwner: TComponent); override;
    destructor Destroy; override;
  end;

implementation

uses JclStrings;

{$R *.dfm}

procedure TPacketFrame.lvPktListClick(Sender: TObject);
var
  UserData: PSniffData;
begin
  If lvPktList.Selected = nil then Exit;
  ParsePacketInHexView(lvPktList.Selected.Data);
end;

procedure TPacketFrame.lvPktListChange(Sender: TObject; Item: TListItem;
  Change: TItemChange);
begin
  If Item.Data = nil then Exit;
  If F_IsHexView Then ParsePacketInHexView(Item.Data);
  If F_IsPktView Then ParsePacketInTreeView(Item.Data, StrToInt(Item.Caption));
end;

procedure TPacketFrame.ParsePacketInHexView(p: pointer);
var
  UserData: PSniffData;
begin
  // Print Hex Dump
  UserData := PSniffData(p);
  if (UserData = nil) or (UserData^.Buffer = nil) Then
  begin
    MessageBox(self.Handle, '读取数据时发生异常', '数据错误', MB_OK + MB_ICONWARNING);
    Exit;
  end;
  dgHexView.InitializeHexDump;
  dgHexView.SetData(UserData^.Buffer, UserData^.Length, UserData^.Length);
  dgHexView.SetSelection(0, 0);
  //Memory.Free;
end;

procedure TPacketFrame.ParsePacketInTreeView(p: pointer; pno: integer);
var
  UserData: PSniffData;
  I: integer;
begin
  // Print Hex Dump
  UserData := PSniffData(p);
  if (UserData = nil) or (UserData^.Buffer = nil) Then
  begin
    MessageBox(self.Handle, '读取数据时发生异常', '数据错误', MB_OK + MB_ICONWARNING);
    Exit;
  end;
  //vtProtoTree

  tvProtocol.Items.BeginUpdate;
  try
    tvProtocol.Items.Clear;
    F_Analyzer.ParsePacketInTreeView(UserData, pno);
    for I := 0 To tvProtocol.Items.Count - 1 do begin
      if tvProtocol.Items.Item[I].Level = 0 then begin
        tvProtocol.Items.Item[I].ImageIndex := 0;
        tvProtocol.Items.Item[I].StateIndex := 0;
        tvProtocol.Items.Item[I].SelectedIndex := 0;
      end else begin
        if tvProtocol.Items.Item[I].ImageIndex < 2 then begin
          tvProtocol.Items.Item[I].ImageIndex := 1;
          tvProtocol.Items.Item[I].StateIndex := 1;
          tvProtocol.Items.Item[I].SelectedIndex := 1;
        end
      end;
    end;
  finally
    tvProtocol.Items.EndUpdate;
  end;
  //tvProtocol.FullExpand;
end;

////////////////////////////////////////////////////////////////////////////////
constructor TPacketFrame.Create(AOwner: TComponent);
begin
  inherited;
  F_IsEnter := False;
  F_IsHexView := True;
  F_IsPktView := True;
  F_Analyzer := TPacketAnalyzer.Create;
  F_Analyzer.PrepareProtoTree(@tvProtocol);
  TBPktView.Down := True;
  TBProtoView.Down := True;
end;

destructor TPacketFrame.Destroy;
begin
  F_Analyzer.Destroy;
  inherited;
end;

procedure TPacketFrame.tvProtocolCustomDrawItem(Sender: TCustomTreeView;
  Node: TTreeNode; State: TCustomDrawState; var DefaultDraw: Boolean);
var
  no: PNodeObj;
begin
  no := Node.Data;
  if no = nil then Exit;
  Sender.Canvas.Font.Style := no^.FontStyle;
  if not F_IsEnter Then begin
    Sender.Canvas.Font.Color := no^.FontColor;
  end else if Node.Selected then begin
    Sender.Canvas.Font.Color := clWhite;
  end else begin
    Sender.Canvas.Font.Color := no^.FontColor;
  end;
end;

procedure TPacketFrame.tvProtocolDeletion(Sender: TObject;
  Node: TTreeNode);
begin
  Dispose(Node.Data);
end;

procedure TPacketFrame.TBPktViewClick(Sender: TObject);
begin
  F_IsHexView := TBPktView.Down;
  if not TBPktView.Down then begin
    dgHexView.Visible := false;
    Splitter1.Align := alBottom;
    Splitter1.Visible := false;
    lvPktList.Align := alClient;
  end else begin
    lvPktList.Align := alTop;
    lvPktList.Height := self.Height div 3;
    Splitter1.Visible := True;
    Splitter1.Align := alTop;
    dgHexView.Align := alClient;
    dgHexView.Visible := True;
  end;
end;

procedure TPacketFrame.TBProtoViewClick(Sender: TObject);
begin
  F_IsPktView := TBProtoView.Down;
  If not TBProtoView.Down then begin
    tvProtocol.Visible := false;
    Splitter2.Visible := false;
  end else begin
    tvProtocol.Visible := true;
    Splitter2.Visible := true;
  end;
end;

procedure TPacketFrame.tvProtocolExit(Sender: TObject);
begin
  F_IsEnter := False;
end;

procedure TPacketFrame.tvProtocolEnter(Sender: TObject);
begin
  F_IsEnter := True;
end;

procedure TPacketFrame.tbPrevPacketClick(Sender: TObject);
begin
  if lvPktList.Items.Count <= 0 then Exit;
  if lvPktList.Selected <> nil then begin
    if (lvPktList.Selected.Index - 1) < 0 then Exit;
    lvPktList.Selected := lvPktList.Items.Item[lvPktList.Selected.Index - 1];
    lvPktList.OnClick(sender);
    SendMessage(lvPktList.Handle, WM_VScroll, SB_LINEUP, 0);
  end;
end;

procedure TPacketFrame.tbNextPacketClick(Sender: TObject);
begin
  if lvPktList.Items.Count <= 0 then Exit;
  if lvPktList.Selected <> nil then begin
    if (lvPktList.Selected.Index + 1) > lvPktList.Items.Count then Exit;
    lvPktList.Selected := lvPktList.Items.Item[lvPktList.Selected.Index + 1];
    lvPktList.OnClick(sender);
    SendMessage(lvPktList.Handle, WM_VScroll, SB_LINEDOWN, 0);
  end;
end;

initialization
  RegisterClass( TPacketFrame );

end.
