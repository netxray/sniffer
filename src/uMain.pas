unit uMain;

{///////////////////////////////////////////////////////////////////////////////

  unit desc:      Main Unit
  unit author:    net_xray@hotmail.com
  created date:   2003/10/01

  bug:
  1. scalability 的作法，业务分段后由worker thread去做
  2. close时出现的exception

///////////////////////////////////////////////////////////////////////////////}

interface

uses
  Windows, Messages, SysUtils, Variants, Classes, Graphics, Controls, Forms,
  Dialogs, Menus, ExtCtrls, ComCtrls, StdCtrls, Tabs,
  TB2Item, ImgList, TB2Dock, TB2Toolbar, JvListView, JclSysInfo,
  JvEdit, JclStrings,
  uFrameHelper, USniffEngine, uSniffHelper, uCommon,
  xmldom, XMLIntf, msxmldom, XMLDoc, ToolWin;

type

  PListView = TJvListView;

  TfrmMain = class(TForm)
    TBTooBarDock: TTBDock;
    TBToolbar: TTBToolbar;
    TBImage: TTBImageList;
    TBEndCap: TTBItem;
    TBStartCap: TTBItem;
    TBSelAdapter: TTBItem;
    StatusBar: TStatusBar;
    pnlCaption: TPanel;
    mmMenu: TMainMenu;
    N1: TMenuItem;
    miOpen: TMenuItem;
    miSave: TMenuItem;
    miSaveAs: TMenuItem;
    N6: TMenuItem;
    miClose: TMenuItem;
    N7: TMenuItem;
    miExit: TMenuItem;
    S1: TMenuItem;
    miSelAdapter: TMenuItem;
    N10: TMenuItem;
    miStartCap: TMenuItem;
    miEndCap: TMenuItem;
    N14: TMenuItem;
    miSetFilter: TMenuItem;
    N13: TMenuItem;
    miHelp: TMenuItem;
    N17: TMenuItem;
    miAbout: TMenuItem;
    TabSet: TTabSet;
    spHeader1: TShape;
    Label1: TLabel;
    Label2: TLabel;
    Panel2: TPanel;
    spHeader2: TShape;
    Label3: TLabel;
    Label4: TLabel;
    Panel3: TPanel;
    Panel4: TPanel;
    Panel1: TPanel;
    btnStartCap: TButton;
    XMLDoc: TXMLDocument;
    procedure TabSetClick(Sender: TObject);
    procedure FormCreate(Sender: TObject);
    procedure TBSelAdapterClick(Sender: TObject);
    procedure FormClose(Sender: TObject; var Action: TCloseAction);
    procedure TBStartCapClick(Sender: TObject);
    procedure TBEndCapClick(Sender: TObject);
    procedure TBExitClick(Sender: TObject);
    procedure miAboutClick(Sender: TObject);
  private
    { Private declarations }
    F_IsSetAdapter: Boolean;
    F_MemSize : Integer;
    F_MemUsage: Integer;
    F_FrameHelper: TFrameHelper;
    F_SniffEngine: TSniffEngine;
    function LoadXmlConf: boolean;
    procedure EnableCapture;
    procedure DisableCapture;
    // callback 
    procedure PrintPacket(pp: PPacketInfo; mem: Integer);
    procedure OnSniffEngineStop(var AutoStop: boolean);
    procedure AddPacketToListView(pp: PPacketInfo);
    procedure UpdateCaptureInfo(pp: PPacketInfo; mem: Integer);
    function CreateSniffEngine: boolean;
  public
    { Public declarations }
  end;

var
  frmMain: TfrmMain;

implementation

uses
  uSelAdapter, uAbout, uProtoXml, 
  uPacketAnaysis;//, uNodeTraffic;

{$R *.dfm}

////////////////////////////////////////////////////////////////////////////////
// Initialization
////////////////////////////////////////////////////////////////////////////////
function TfrmMain.LoadXmlConf: boolean;
var
  ipconf, etconf, ptconf, p3conf: string;
  ProtoXml: TIPNumberCls;
begin
  ipconf := ExtractFilePath(Application.ExeName) + 'ipnumber.xml';
  etconf := ExtractFilePath(Application.ExeName) + 'etnumber.xml';
  ptconf := ExtractFilePath(Application.ExeName) + 'ptnumber.xml';
  p3conf := ExtractFilePath(Application.ExeName) + 'p3number.xml';
  if FileExists(ipconf) and FileExists(etconf) and
    FileExists(ptconf) and FileExists(p3conf) then begin
    XmlDoc.FileName := ipconf;
    G_ProtoXml := TIPNumberCls.Create;
    G_ProtoXml.ParseIPXml(XmlDoc);
    XmlDoc.FileName := etconf;
    G_ProtoXml.ParseETXml(XmlDoc);
    XmlDoc.FileName := ptconf;
    G_ProtoXml.ParsePTXml(XmlDoc);
    XmlDoc.FileName := p3conf;
    G_ProtoXml.ParseP3Xml(XmlDoc);
    Result := True;
    Exit;
  end;
  Result := False;
end;

procedure TfrmMain.FormCreate(Sender: TObject);
begin
  //G_Tranlist := TTranList.Create;
  // initialization
  if not LoadXmlConf then begin
    MessageBox(self.Handle, 'Loading Xml Config Failed. Please reinstall me now!', 'Warning', 
              MB_OK + MB_ICONERROR);
    Close;
  end;
  F_IsSetAdapter := False;
  F_MemSize := GetTotalPhysicalMemory div 10;
  //uses 1/10 memory from current system
  if not CreateSniffEngine then begin
    ShowMessage('Cannot found any Network Adapter in your machine!');
    Exit;
  end;
  F_FrameHelper := TFrameHelper.Create(Application);
  DisableCapture;
  TabSetClick(self);
  DoubleBuffered := True;
end;

function TfrmMain.CreateSniffEngine: boolean;
begin
  F_SniffEngine := TSniffEngine.Create;
  // prepare
  if (F_SniffEngine.GetAdapterList.Count <= 0) Then begin
    Result := False;
    Exit;
  end;
  F_SniffEngine.PrintPacket := PrintPacket;
  F_SniffEngine.OnStop := OnSniffEngineStop;
  Result := True;
end;

////////////////////////////////////////////////////////////////////////////////
// View Control
////////////////////////////////////////////////////////////////////////////////
procedure TfrmMain.TabSetClick(Sender: TObject);
begin
  //
  case TabSet.TabIndex of
    0: F_FrameHelper.ShowPacketFrame(self);
    1: F_FrameHelper.ShowNodeFrame(self);
    2: F_FrameHelper.ShowProtoFrame(self);
  end;
end;

procedure TfrmMain.TBSelAdapterClick(Sender: TObject);
var
  frmSelAdapter: TfrmSelAdapter;
begin
  //select adapter
  frmSelAdapter := TfrmSelAdapter.Create(self);
  try
    frmSelAdapter.cbxAdapterList.Items.Assign(F_SniffEngine.GetAdapterList);
    frmSelAdapter.ShowModal;
    if F_SniffEngine.SetSniffAdapter(frmSelAdapter.AdapterIndex) Then
    begin
      if frmSelAdapter.PktCapLimit > 0 then begin
        F_SniffEngine.PktThreshold := frmSelAdapter.PktCapLimit;
      end;
      F_IsSetAdapter := True;
      StatusBar.Panels.Items[1].Text := '[Network Card] ' +
        frmSelAdapter.cbxAdapterList.Items.Strings[frmSelAdapter.AdapterIndex];
      EnableCapture
    end
    else
      DisableCapture;
  finally
    frmSelAdapter.Free;
  end;
end;

procedure TfrmMain.EnableCapture;
begin
  StatusBar.Panels.Items[0].Text := 'Ready.';
  btnStartCap.Enabled := True;
  TBStartCap.Enabled := True;
  miStartCap.Enabled := True;
  TBEndCap.Enabled := False;
  miEndCap.Enabled := False;
  TBSelAdapter.Enabled := False;
  miSelAdapter.Enabled := False;
end;

procedure TfrmMain.DisableCapture;
begin
  StatusBar.Panels.Items[0].Text := 'Please select Network Card first.';
  btnStartCap.Enabled := False;
  TBStartCap.Enabled := False;
  miStartCap.Enabled := False;
  TBEndCap.Enabled := True;
  miEndCap.Enabled := True;
end;

procedure TfrmMain.TBStartCapClick(Sender: TObject);
begin
  // start capture
  TBEndCap.Enabled := True;
  miEndCap.Enabled := True;
  TBStartCap.Enabled := False;
  miStartCap.Enabled := False;
  btnStartCap.Enabled := False;
  TBSelAdapter.Enabled := False;
  miSelAdapter.Enabled := False;
  F_SniffEngine.Start;
end;

procedure TfrmMain.TBEndCapClick(Sender: TObject);
var
  cur: TCursor;
begin
  // stop capture
  cur := Screen.Cursor;
  Screen.Cursor := crHourGlass;
  try
    if F_IsSetAdapter Then begin
      miEndCap.Enabled := False;
      TBEndCap.Enabled := False;
      TBStartCap.Enabled := True;
      miStartCap.Enabled := True;
      btnStartCap.Enabled := True;
      TBSelAdapter.Enabled := True;
      miSelAdapter.Enabled := True;
      F_SniffEngine.Stop;
    end;
  finally
    Screen.Cursor := cur;
  end;
end;

////////////////////////////////////////////////////////////////////////////////
// CallBack
////////////////////////////////////////////////////////////////////////////////
procedure TfrmMain.PrintPacket(pp: PPacketInfo; mem: Integer);
begin
  AddPacketToListView(pp);//synchronize
  UpdateCaptureInfo(pp, mem);
end;

procedure TfrmMain.AddPacketToListView(pp: PPacketInfo);
var
//  pktList: TJvListView;
  pktItem: TListItem;
  inaddr, outaddr: PMAC2IP;
begin
  pktItem := F_FrameHelper.PacketFrame.lvPktList.Items.Add;
  with pktItem do begin
    Caption := (IntToStr(pp^.PacketNo));
    SubItems.Add(MACtoStr(pp^.SrcAddr));
    SubItems.Add(MACtoStr(pp^.DstAddr));
    SubItems.Add(pp^.DataFlag);
    SubItems.Add(IntToStr(pp^.Length));
    SubItems.Add(pp^.TimeStamp);
    SubItems.Add(G_ProtoXml.GetETProtoDesc(pp^.Protocol));
    SubItems.Add(pp^.Descript);
    Data := pp^.Data;//PSniffData;
  end;
  //
{
  // 好像只有用线程来做了
  inaddr := New(PMAC2IP);
  outaddr := New(PMAC2IP);
  try
    TPacketAnalyzer.ParsePacketAddrInfo(pp^.Data, inaddr, outaddr);
    G_TranList.AddTransInfo(inaddr, True, pp^.Length);
    G_TranList.AddTransInfo(outaddr, False, pp^.Length);
  finally
    Dispose(inaddr);
    Dispose(outaddr);
  end;
}
  SendMessage(F_FrameHelper.PacketFrame.lvPktList.Handle, WM_VScroll, SB_LINEDOWN, 0);
end;

procedure TfrmMain.UpdateCaptureInfo(pp: PPacketInfo; mem: Integer);
var
  t: integer;
begin
//  edtRcvPacket.Value := pp^.PacketNo;
//  edtFltPacket.Value := 0;
//  edtFilterInfo.Value := 0;
//  edtMemInfo.Value := mem;
  t := Round((mem / F_MemSize)*100);
//  pbMemUsage.Percent := t;
//  pbFilter.Percent := 0;
end;

procedure TfrmMain.OnSniffEngineStop(var AutoStop: boolean);
begin
  AutoStop := not AutoStop;
  If not AutoStop Then TBEndCap.Click;
end;

////////////////////////////////////////////////////////////////////////////////
// Finalization
////////////////////////////////////////////////////////////////////////////////
procedure TfrmMain.TBExitClick(Sender: TObject);
begin
  Close;
end;

procedure TfrmMain.FormClose(Sender: TObject; var Action: TCloseAction);
var
  I: integer;
begin
//  G_Tranlist.Destroy;
  try
    if Assigned(F_FrameHelper) then begin
      // avoid produce listview.onchange event when application exit.
      For I := 0 To F_FrameHelper.PacketFrame.lvPktList.Items.Count - 1 do
      begin
        F_FrameHelper.PacketFrame.lvPktList.Items.Item[I].Data := nil;
      end;
    end;
    if Assigned(F_SniffEngine) then F_SniffEngine.Destroy;
    if Assigned(G_ProtoXml) then G_ProtoXml.Destory;
  except
  end;
  Action := caFree;
end;

////////////////////////////////////////////////////////////////////////////////
// Other
////////////////////////////////////////////////////////////////////////////////
procedure TfrmMain.miAboutClick(Sender: TObject);
begin
  OKRightDlg.Show;
end;

end.
