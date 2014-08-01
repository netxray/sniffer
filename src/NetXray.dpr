program NetXray;

uses
  Forms,
  uMain in 'uMain.pas' {frmMain},
  uPacketFrame in 'uPacketFrame.pas' {PacketFrame: TFrame},
  uFrameHelper in 'uFrameHelper.pas',
  uNodeFrame in 'uNodeFrame.pas' {NodeFrame: TFrame},
  uProtoFrame in 'uProtoFrame.pas' {ProtoFrame: TFrame},
  uNdis_def in 'sniffer\uNdis_def.pas',
  uPacket32 in 'sniffer\uPacket32.pas',
  uProtocolDef in 'sniffer\uProtocolDef.pas',
  uSniffer in 'sniffer\uSniffer.pas',
  uWinPCap in 'sniffer\uWinPCap.pas',
  uSniffHelper in 'uSniffHelper.pas',
  uSniffFilter in 'uSniffFilter.pas',
  uPacketAnaysis in 'uPacketAnaysis.pas',
  uSniffEngine in 'uSniffEngine.pas',
  uSelAdapter in 'uSelAdapter.pas' {frmSelAdapter},
  uCommon in 'uCommon.pas',
  uProtoXml in 'uProtoXml.pas',
  uAbout in 'uAbout.pas' {OKRightDlg},
  uNodeTraffic in 'uNodeTraffic.pas',
  uWpCap in 'sniffer\uWpCap.pas',
  uHoriWatch in 'uHoriWatch.pas',
  uWpCapImpl in 'uWpCapImpl.pas';

{$R *.res}

begin
  Application.Initialize;
  Application.Title := 'NetXray';
  Application.CreateForm(TfrmMain, frmMain);
  Application.CreateForm(TOKRightDlg, OKRightDlg);
  Application.Run;
end.
