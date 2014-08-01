unit uSelAdapter;

interface

uses
  Windows, Messages, SysUtils, Variants, Classes, Graphics, Controls, Forms,
  Dialogs, StdCtrls, ComCtrls, JclRegistry, JvEdit;

type
  TfrmSelAdapter = class(TForm)
    cbxAdapterList: TComboBox;
    btnOK: TButton;
    btnCL: TButton;
    Label1: TLabel;
    cbxPktCapLimit: TCheckBox;
    udPktCapLimit: TUpDown;
    procedure btnOKClick(Sender: TObject);
    procedure btnCLClick(Sender: TObject);
    procedure cbxPktCapLimitClick(Sender: TObject);
    procedure FormShow(Sender: TObject);
  private
    { Private declarations }
    F_AdapterIndex : integer;
    F_PktCapLimit :  integer;
    function UpdateAdapterNameFromReg(DeviceList: TStrings): boolean;
  public
    { Public declarations }
    property AdapterIndex: integer read F_AdapterIndex;
    property PktCapLimit:  integer read F_PktCapLimit;
  end;

var
  frmSelAdapter: TfrmSelAdapter;

implementation

{$R *.dfm}

procedure TfrmSelAdapter.btnOKClick(Sender: TObject);
begin
  F_PktCapLimit := 0;
  F_AdapterIndex := cbxAdapterList.ItemIndex;
  If cbxPktCapLimit.Checked Then begin
//    if edtCapPktLimit.Value < 0 Then
//      F_PktCapLimit := 0//no limit
//    else
//      F_PktCapLimit := edtCapPktLimit.Value;
  end;
  if F_AdapterIndex >= 0 Then Close;
end;

procedure TfrmSelAdapter.btnCLClick(Sender: TObject);
begin
  F_AdapterIndex := -1;
  Close;
end;

procedure TfrmSelAdapter.cbxPktCapLimitClick(Sender: TObject);
begin
//  edtCapPktLimit.Enabled := cbxPktCapLimit.Checked;
  udPktCapLimit.Enabled := cbxPktCapLimit.Checked;
end;

function TfrmSelAdapter.UpdateAdapterNameFromReg(DeviceList: TStrings): boolean;
const
  REG_NETWORKCARDS = 'Software\Microsoft\Windows NT\CurrentVersion\NetworkCards';
var
  I, J: integer;
  Tmp, Desc, Name: string;
  CardList: TStringList;
begin
  CardList := TStringList.Create;
  try
    If (RegGetKeyNames(HKEY_LOCAL_MACHINE, REG_NETWORKCARDS, CardList)) Then
    begin
      For I:=0 To CardList.Count - 1 Do
      begin
        Tmp := REG_NETWORKCARDS + '\' + CardList.Strings[I];
        Name := RegReadString(HKEY_LOCAL_MACHINE, Tmp, 'ServiceName');
        Desc := RegReadString(HKEY_LOCAL_MACHINE, Tmp, 'Description');
        For J:=0 To DeviceList.Count - 1 Do
          If (Pos(Name, DeviceList.Strings[J]) <> 0) Then
          begin
            DeviceList.Strings[J] := Desc;
          end;
      end;
    end;
    Result := True;
    Exit;
  finally
    CardList.Free;
  end;
  Result := False;
end;

procedure TfrmSelAdapter.FormShow(Sender: TObject);
begin
  //cbxAdapterList.Items.Clear;
  UpdateAdapterNameFromReg(cbxAdapterList.Items);
end;

end.
