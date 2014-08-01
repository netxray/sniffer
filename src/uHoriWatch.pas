unit uHoriWatch;

interface

uses
  Windows, Messages, SysUtils, Classes, Graphics, Controls, Forms, Dialogs;

type
  THoriWatch = class(TCustomControl)
  private
    FLineColor: TColor;
    pBuf: PChar;
    procedure SetLineColor(Value: TColor);
  protected
    procedure CreateParams(var Params: TCreateParams); override;
    procedure Paint; override;
  public
    constructor Create(AOwner: TComponent); override;
    property Buffer: PChar read pBuf write pBuf;
  published
    property Align;
    property Color;
    property LineColor: TColor read FLineColor write SetLineColor;
  end;

implementation

constructor THoriWatch.Create(AOwner: TComponent);
begin
  inherited Create(AOwner);
  ControlStyle := [csReplicatable];
  Canvas.Brush.Color:=clGreen;
  Canvas.Brush.Style:=bsCross;
  Color := clBlack;
  Height := 0;
  Width := 0;
  DoubleBuffered := true;
end;

procedure THoriWatch.CreateParams(var Params: TCreateParams);
begin
  inherited CreateParams(Params);
  with Params do
  begin
    Style := Style and not WS_BORDER;
    ExStyle := ExStyle or WS_EX_CLIENTEDGE;
  end;
end;

procedure THoriWatch.Paint;
var i: integer;
    p: PChar;
begin
  Canvas.Lock;
  Canvas.Rectangle(-1, -1, Width, Height);
  p := Buffer;
  i := Width - 1;
  Canvas.MoveTo(i, ClientHeight * (100 - Ord(p^)) div 100);
  while i > 2 do begin
    if Ord(p^) > 100 then begin
      break;
    end;
    i := i - 2;
    Dec(p);
    if Ord(p^) > 100 then begin
      break;
    end;
    Canvas.LineTo(i - 1, ClientHeight * (100 - Ord(p^)) div 100);
  end;
  Canvas.Unlock;
end;

procedure THoriWatch.SetLineColor(Value: TColor);
begin
  if Value = FLineColor then Exit;
  FLineColor := Value;
  Canvas.Pen.Color := Value;
end;

end.
