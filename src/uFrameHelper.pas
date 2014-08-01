unit uFrameHelper;

interface

uses
  Windows, Messages, SysUtils, Variants, Classes, Graphics, Controls, Forms,
  uPacketFrame, uNodeFrame, uProtoFrame, uProtoXml;

type

  TFrameHelper = class
    private
      F_PktFrame: TPacketFrame;
      F_NodFrame: TNodeFrame;
      F_PrtFrame: TProtoFrame;
    public
      constructor Create(App: TApplication);
      destructor Destroy; override;
      function ShowPacketFrame(p: TObject): boolean;
      function ShowNodeFrame(p: TObject): boolean;
      function ShowProtoFrame(p: TObject): boolean;
      property PacketFrame : TPacketFrame read F_PktFrame;
      property NodeFrame : TNodeFrame read F_NodFrame;
      property ProtoFrame : TProtoFrame read F_PrtFrame;
  end;

  TPktFrmCls = class of TPacketFrame;
  TNodFrmCls = class of TNodeFrame;
  TPrtFrmCls = class of TProtoFrame;
  
const
  FRAME_PACKET      = 'PacketFrame';
  FRAME_PACKET_CLS  = 'TPacketFrame';
  FRAME_NODE        = 'NodeFrame';
  FRAME_NODE_CLS    = 'TNodeFrame';
  FRAME_PROTO       = 'ProtoFrame';
  FRAME_PROTO_CLS   = 'TProtoFrame';


implementation

{ TFrameHelper }

constructor TFrameHelper.Create(App: TApplication);
var
  tc3: TPrtFrmCls;
begin
  F_PktFrame := App.FindComponent(FRAME_PACKET) as TPacketFrame;
  F_NodFrame := App.FindComponent(FRAME_NODE) as TNodeFrame;
  F_PrtFrame := App.FindComponent(FRAME_PROTO) as TProtoFrame;
end;

destructor TFrameHelper.Destroy;
begin
  F_PktFrame.Free;
  F_NodFrame.Free;
  F_PrtFrame.Free;
  inherited;
end;

function TFrameHelper.ShowNodeFrame(p: TObject): boolean;
var
  tc1: TNodFrmCls;
begin
  Result := False;
  try
    if not Assigned(F_NodFrame) then begin
      tc1 := TNodFrmCls(FindClass(FRAME_NODE_CLS));
      F_NodFrame := tc1.Create(TComponent(p));
      with F_NodFrame do begin
        Parent := TWinControl(p);
        Align := alClient;
        Visible := True;
        BringToFront;
      end;
    end else begin
      F_NodFrame.Visible := True;
      F_NodFrame.BringToFront;
      if Assigned(F_PktFrame) then F_PktFrame.Visible := False;
      if Assigned(F_PrtFrame) then F_PrtFrame.Visible := False;
    end;
    Result := True;
  except
  end;
end;

function TFrameHelper.ShowPacketFrame(p: TObject): boolean;
var
  tc2: TPktFrmCls;
begin
  Result := False;
  try
    if not Assigned(F_PktFrame) then begin
      tc2 := TPktFrmCls(FindClass(FRAME_PACKET_CLS));
      F_PktFrame := tc2.Create(TComponent(p));
      with F_PktFrame do begin
        Parent := TWinControl(p);
        Align := alClient;
        Visible := True;
        BringToFront;
      end;
    end else begin
      F_PktFrame.Visible := True;
      F_PktFrame.BringToFront;
      if Assigned(F_NodFrame) then F_NodFrame.Visible := False;
      if Assigned(F_PrtFrame) then F_PrtFrame.Visible := False;
    end;
    Result := True;
  except
  end;
end;

function TFrameHelper.ShowProtoFrame(p: TObject): boolean;
var
  tc3: TPrtFrmCls;
begin
  Result := False;
  try
    if not Assigned(F_PrtFrame) then begin
      tc3 := TPrtFrmCls(FindClass(FRAME_PROTO_CLS));
      F_PrtFrame := tc3.Create(TComponent(p));
      with F_PrtFrame do begin
        Parent := TWinControl(p);
        Align := alClient;
        Visible := True;
        BringToFront;
      end;
    end else begin
      F_PrtFrame.Visible := True;
      F_PrtFrame.BringToFront;
      if Assigned(F_NodFrame) then F_NodFrame.Visible := False;
      if Assigned(F_PktFrame) then F_PktFrame.Visible := False;
    end;
    Result := True;
  except
  end;
end;

end.
