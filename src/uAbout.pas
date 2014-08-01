unit uAbout;

interface

uses Windows, SysUtils, Classes, Graphics, Forms, Controls, StdCtrls,
  Buttons, ExtCtrls, jpeg, JvComponent; //, JvComputerInfo;

type
  TOKRightDlg = class(TForm)
    OKBtn: TButton;
    Panel1: TPanel;
    Image1: TImage;
    Bevel1: TBevel;
    Bevel2: TBevel;
    Label1: TLabel;
//    sysinfo: TJvComputerInfo;
    meSysInfo: TMemo;
    procedure OKBtnClick(Sender: TObject);
    procedure FormShow(Sender: TObject);
  private
    { Private declarations }
  public
    { Public declarations }
  end;

var
  OKRightDlg: TOKRightDlg;

implementation

uses uWinPcap;

{$R *.dfm}

procedure TOKRightDlg.OKBtnClick(Sender: TObject);
begin
  close;
end;

procedure TOKRightDlg.FormShow(Sender: TObject);
begin
//  with SysInfo do begin
//    meSysInfo.Text :=
//    'LoggedOnUser: ' + LoggedOnUser + #13#10 +
//    'ComputerName: ' + ComputerName + #13#10 +
//    'Username:     ' + Username + #13#10 +
//    'Company:      ' + Company + #13#10 +
//    'WorkGroup:    ' + WorkGroup + #13#10 + #13#10 +
//    'Windows Info: ' + #13#10 +
//    '  ' + ProductName + #13#10 +
//    '  ' + ProductID + #13#10 +
//    '-------------------------------' + #13#10 +
//    'Xray@Net (under construction)' + #13#10 +
//    'WinPCap '+GetWpCapVersion;
//  end;
end;

end.
