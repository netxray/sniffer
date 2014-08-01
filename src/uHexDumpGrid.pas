unit uHexDumpGrid;

{
  @original author: Network Chemistry.
  @author: converted from c++ builder, by net_xray@hotmail.com
  @date:   2003/07/26
}

interface

uses
  Windows, SysUtils, Controls, Classes, Forms, Graphics, Grids, Types,
  Math, JclStrings, uHexCommon;

type
	//typedef void __fastcall (__closure *TOnSelectionChangedEvent)(System::TObject* Sender, int Index);
  TOnSelectionChangedEvent = procedure(Sender: TObject; Index: Integer) of object;

	THexDumpGrid = class(TCustomGrid)
	private
		//unsigned char *fData;
		fData       : PAnsiChar; //PByte;
		fDataLength : Integer;
		fMaxLength  : Integer;
		fEditIndex  : Integer; // Index of the nibble or character to edit. Whether it is a nibble or character depends on fEditHex.
		fEditHex    : Boolean;
    
		procedure ConstrainEditing;
	protected
		fSelectionStart		: Integer;
		fSelectionLength	: Integer;
		fReadOnly         : Boolean;
		fOnChange					: TNotifyEvent;
		fInactiveSelectedColor		  : TColor;
		fInactiveSelectedFontColor 	: TColor;
    fOnSelectionChanged			    : TOnSelectionChangedEvent;

		// Scroll the grid so that the selection is visible.
		procedure EnsureSelectionVisible;
		// Test if a cell is currently visible.
		function IsVisible(Cell: Integer): Boolean;
		
		//virtual void __fastcall DrawCell(int ACol, int ARow, const TRect &ARect, TGridDrawState AState);
	  procedure DrawCell(ACol, ARow: Longint; ARect: TRect; AState: TGridDrawState); override;
    {
			DYNAMIC procedure MouseDown(Controls::TMouseButton Button, Classes::TShiftState Shift, int X, int Y);
			DYNAMIC procedure MouseMove(Classes::TShiftState Shift, int X, int Y);
			DYNAMIC procedure MouseUp(Controls::TMouseButton Button, Classes::TShiftState Shift, int X, int Y);
			DYNAMIC procedure KeyDown(Word &Key, Classes::TShiftState Shift);
			DYNAMIC procedure KeyPress(char &Key);
		}
    procedure MouseDown(Button: TMouseButton; Shift: TShiftState; X, Y: Integer); override;
    procedure MouseMove(Shift: TShiftState; X, Y: Integer); override;
    procedure MouseUp(Button: TMouseButton; Shift: TShiftState; X, Y: Integer); override;
    procedure KeyDown(var Key: Word; Shift: TShiftState); override;
    procedure KeyPress(var Key: Char); override;

		//  void __fastcall MouseToCell(int X, int Y, int &ACol, int &ARow);
		procedure MouseToCell(X, Y : Integer; var ACol: Integer; var ARow: Integer);
	public
		//__fastcall THexDumpGrid(TComponent* Owner);
		//__fastcall THexDumpGrid(HWND ParentWindow);
		//virtual __fastcall ~THexDumpGrid() {};
    constructor Create(AOwner: TComponent); override;
    //constructor Create(ParentWindow: THandle); overload;
    destructor Destroy; override;

		//__fastcall SetParent(TWinControl* AParent);
    procedure SetParent(AParent:TWinControl); override;
		procedure InitializeHexDump;
		procedure SetData(AData: Pointer{PByte}; ALength, AMaxLength: Integer);
		
		procedure SetSelection(Start, Length: Integer);
		procedure SetSelectionStart(Value: Integer);
		procedure SetSelectionLength(Value: Integer);
		
		property DataLength: Integer Read fDataLength;
		property SelectionStart: Integer Read fSelectionStart Write SetSelectionStart;
		property SelectionLength: Integer Read fSelectionLength Write SetSelectionLength;
		
		property Canvas;
		property Col;
		property ColWidths;
		property EditorMode;
		property GridHeight;
		property GridWidth;
		property LeftCol;
		property Selection;
		property Row;
		property RowHeights;
		property TabStops;
		property TopRow;
	  
  published
		property ReadOnly: Boolean Read fReadOnly Write fReadOnly;
		property InactiveSelectedColor: TColor Read fInactiveSelectedColor Write fInactiveSelectedColor;
		property InactiveSelectedFontColor: TColor Read fInactiveSelectedFontColor Write fInactiveSelectedFontColor;
		
		property OnSelectionChanged : TOnSelectionChangedEvent Read fOnSelectionChanged Write fOnSelectionChanged;
		property OnChange: TNotifyEvent Read fOnChange Write fOnChange;
		
		property Align;
		property Anchors;
		property BiDiMode;
		property BorderStyle;
		property Color;
		property ColCount;
		property Constraints;
		property Ctl3D;
		property DefaultColWidth;
		property DefaultRowHeight;
		property DefaultDrawing;
		property DragCursor;
		property DragKind;
		property DragMode;
		property Enabled;
		property FixedColor;
		property FixedCols;
		property RowCount;
		property FixedRows;
		property Font;
		property GridLineWidth;
		property Options;
		property ParentBiDiMode;
		property ParentColor;
		property ParentCtl3D;
		property ParentFont;
		property ParentShowHint;
		property PopupMenu;
		property ScrollBars;
		property ShowHint;
		property TabOrder;
		property TabStop;
		property Visible;
		property VisibleColCount;
		property VisibleRowCount;
		property OnClick;
		property OnContextPopup;
		property OnDblClick;
		property OnDragDrop;
		property OnDragOver;
		property OnEndDock;
		property OnEndDrag;
		property OnEnter;
		property OnExit;
		property OnKeyDown;
		property OnKeyPress;
		property OnKeyUp;
		property OnMouseDown;
		property OnMouseMove;
		property OnMouseUp;
		property OnMouseWheelDown;
		property OnMouseWheelUp;
		property OnStartDock;
		property OnStartDrag;
	end;

const
  HORZ_MARGIN = 8;
  VERT_MARGIN = 2;
  BYTES_PER_ROW = 16;
  HEX_START = 2;
  TEXT_START = (2 + BYTES_PER_ROW + 1);

procedure Register;

implementation

{ THexDumpGrid }

procedure THexDumpGrid.ConstrainEditing;
begin
  if ( fEditIndex < 0 ) Then fEditIndex := 0;
  if ( fEditHex ) Then
  begin
    if fEditIndex > (fDataLength*2) Then fEditIndex := fDataLength*2-1;
    if fEditIndex = (fDataLength*2) Then
    begin
      if ( fDataLength < fMaxLength ) Then
        Inc(fDataLength)
      else
        fEditIndex := fDataLength*2-1;
    end;
    if ((fEditIndex/2) < fSelectionStart) or ((fEditIndex/2) >= (fSelectionStart + fSelectionLength)) Then
    begin
      if Assigned(fOnSelectionChanged) Then fOnSelectionChanged(self, fEditIndex div 2);
    end
  end
  else
  begin
    if fEditIndex > fDataLength Then fEditIndex := fDataLength - 1;
    if fEditIndex = fDataLength Then
    begin
      if fDataLength < fMaxLength Then
        Inc(fDataLength)
      else
        fEditIndex := fDataLength - 1;
    end;
    if (fEditIndex < fSelectionStart) or (fEditIndex >= (fSelectionStart + fSelectionLength)) Then
    begin
      if Assigned(fOnSelectionChanged) Then fOnSelectionChanged(self, fEditIndex);
    end;
  end;
end;

constructor THexDumpGrid.Create(AOwner: TComponent);
begin
  inherited Create(AOwner);
  InitializeHexDump;
end;

//constructor THexDumpGrid.Create(ParentWindow: THandle);
//begin
//  InitializeHexDump;
//end;

destructor THexDumpGrid.Destroy;
begin

  inherited;
end;

procedure THexDumpGrid.DrawCell(ACol, ARow: Integer; ARect: TRect;
  AState: TGridDrawState);
var
  OldBrushColor, OldFontColor, BackgroundColor, FontColor: TColor;
  Contents: AnsiString;
  SelRect: TRect;
  Index: Integer;
begin
  //inherited;

  OldBrushColor := Canvas.Brush.Color;
  OldFontColor := Canvas.Font.Color;
  Contents := '';
  SelRect := ARect;

  Canvas.Brush.Color := clWindow;
  Canvas.FillRect(ARect);

  if (fData = nil) or (fDataLength = 0) Then Exit;

  if Focused then
  begin
    BackgroundColor := clHighlight;
    FontColor := clHighlightText;
  end
  else
  begin
    BackgroundColor := InactiveSelectedColor;
    FontColor := InactiveSelectedFontColor;
  end;

  if ACol = 0 then
  begin
    // Draw the address.
    Canvas.Brush.Color := FixedColor;
    Canvas.Font.Color := Font.Color;
    Canvas.FillRect(ARect);
    
    Contents := Format('  %.4x:', [ARow * BYTES_PER_ROW]); //%4.4X
    Canvas.TextRect(ARect, ARect.Left, ARect.Top, Contents);
  end
  else
  begin
    if (ACol >= HEX_START) and (ACol < HEX_START + BYTES_PER_ROW) Then
    begin
      // We are drawing the hex.
      Index := (ARow * BYTES_PER_ROW) + ACol - HEX_START;
      if ( Index < fDataLength ) Then
      begin
        if (fSelectionLength > 0) and
          (Index >= fSelectionStart) and
          (Index < fSelectionStart + fSelectionLength) Then
        begin
          // Draw the cell as selected.
          Canvas.Brush.Color := BackgroundColor;
          Canvas.Font.Color := FontColor;
          if (Index = (fSelectionStart + fSelectionLength -1)) Then
          begin
            SelRect.Right := SelRect.Left + Canvas.TextWidth('AA');
          end;
          Canvas.FillRect(SelRect);
        end;
        //Contents.printf("%2.2X", fData[Index] );
        Contents := ' ';
        try
          Contents := ConvertChrToHex(fData[Index], false);
        except
          Contents := '';
        end;
        Canvas.TextRect(SelRect, ARect.Left, ARect.Top, Contents);

        // If we are focused, editable and an index is selected then show
        // the editable character.
        if (Focused and (not fReadOnly) and fEditHex and (fEditIndex/2 = Index)) Then
        begin
          SelRect := ARect;

          if (fEditIndex mod 2) = 1 Then
          begin
            SelRect.Left  := SelRect.Left + Canvas.TextWidth('0');
            SelRect.Right := SelRect.Left + Canvas.TextWidth('0');
          end
          else
            SelRect.Right := SelRect.Left + Canvas.TextWidth('0');
          InvertRect(Canvas.Handle, SelRect);
        end
      end
    end
    else if (ACol >= TEXT_START) and (ACol < TEXT_START + BYTES_PER_ROW) Then
    begin
      // We are drawing the text.
      Index := (ARow * BYTES_PER_ROW) + ACol - TEXT_START;
      if ( Index < fDataLength ) Then
      begin
        if (fSelectionLength > 0) and
          (Index >= fSelectionStart) and
          (Index < fSelectionStart + fSelectionLength) Then
        begin
          // Draw the cell as selected.
          Canvas.Brush.Color := BackgroundColor;
          Canvas.Font.Color := FontColor;
          Canvas.FillRect(ARect);
        end;
        //Contents.printf("%c", isprint(fData[Index])?fData[Index]:'.' );
        if CharIsPrintable(WideChar(fData[Index])) then
          Contents := fData[Index]
        else
          Contents := '.';
        Canvas.TextRect(ARect, ARect.Left, ARect.Top, Contents);

        // If we are focused, editable and an index is selected then show
        // the editable character.
        if (Focused and (not fReadOnly) and (not fEditHex) and (fEditIndex = Index)) Then
        begin
          InvertRect(Canvas.Handle, ARect);
        end
      end
    end
  end;

  Canvas.Brush.Color := OldBrushColor;
  Canvas.Font.Color := OldFontColor;
end;

procedure THexDumpGrid.EnsureSelectionVisible;
begin
  // We want to make as much of the selection visible as possible.
  // At a minimum, the first cell of the selection must be visible.

  if ( fSelectionLength <= 0 ) Then Exit;

  if ( IsVisible(fSelectionStart) ) Then
  begin
    // See if the end of the selection is visible.
    if ( not IsVisible(fSelectionStart + fSelectionLength) ) Then
    begin
      TopRow := fSelectionStart div BYTES_PER_ROW;
    end
  end
  else TopRow := fSelectionStart div BYTES_PER_ROW;
end;

procedure THexDumpGrid.InitializeHexDump;
begin
  InactiveSelectedColor := clHighlight;
  InactiveSelectedFontColor := clHighlightText;
  fData := nil;
  fDataLength := 0;
  fOnSelectionChanged := nil;
  fOnChange := nil;
  SetSelection(0, 0);
end;

function THexDumpGrid.IsVisible(Cell: Integer): Boolean;
begin
  Result := (Cell / BYTES_PER_ROW > TopRow) and
            ((Cell / BYTES_PER_ROW) < (TopRow + VisibleRowCount));
end;

procedure THexDumpGrid.KeyDown(var Key: Word; Shift: TShiftState);
begin
  if ReadOnly Then Exit;

  case (Key) of
    VK_UP: begin
      if fEditHex then
        fEditIndex := fEditIndex - (2 * BYTES_PER_ROW)
      else
        fEditIndex := fEditIndex - BYTES_PER_ROW;
    end;
    VK_DOWN: begin
      if fEditHex Then
        fEditIndex := fEditIndex + (2 * BYTES_PER_ROW)
      else
        fEditIndex := fEditIndex + BYTES_PER_ROW;
    end;
    VK_LEFT: begin
      Dec(fEditIndex);
    end;
    VK_RIGHT: begin
      Inc(fEditIndex);
    end;
    VK_TAB: begin
      fEditHex := NOT fEditHex;
    end;
  end;

  ConstrainEditing;
  Invalidate;
end;

procedure THexDumpGrid.KeyPress(var Key: Char);
var
  lc: Char;
  OldVal, NewVal : AnsiChar;
begin
  inherited KeyPress(Key);

  if ReadOnly Then Exit;

  if fEditHex Then
  begin
    lc := CharLower(Key);

    if ( ((lc >= '0') and (lc <= '9')) or ((lc >= 'a') and (lc <= 'f')) ) Then
    begin
      OldVal := fData[fEditIndex div 2];

      if (lc >= '0') and (lc <= '9') Then
        NewVal := AnsiChar(Chr(Ord(lc) - Ord('0')))
      else
        NewVal := AnsiChar(Chr(10 + (Ord(lc)-Ord('a'))));

      if ((fEditIndex mod 2) = 0 ) Then
        fData[fEditIndex div 2] := AnsiChar(Chr((Ord(NewVal) shl 4) OR (Ord(OldVal) AND $0F)))
      else
        fData[fEditIndex div 2] := AnsiChar(Chr((Ord(OldVal) AND $F0) OR (Ord(NewVal) AND $0F)));

      Inc(fEditIndex);
      if Assigned(fOnChange) Then fOnChange(self);
    end;
  end
  else
  begin
    fData[fEditIndex] := AnsiChar(Key);
    Inc(fEditIndex);
    if Assigned(fOnChange) Then fOnChange(self);
  end;

  ConstrainEditing;
  Invalidate;
end;

procedure THexDumpGrid.MouseDown(Button: TMouseButton; Shift: TShiftState;
  X, Y: Integer);
begin
  inherited MouseDown(Button, Shift, X, Y);

  if (not (csDesigning in ComponentState) and
     (CanFocus or (GetParentForm(self) = nil))) then
    SetFocus;
end;

procedure THexDumpGrid.MouseMove(Shift: TShiftState; X, Y: Integer);
begin
  inherited MouseMove(Shift, X, Y);
end;

procedure THexDumpGrid.MouseToCell(X, Y: Integer; var ACol, ARow: Integer);
var
  Coord: TGridCoord;
begin
  Coord := MouseCoord(X, Y);
  ACol := Coord.X;
  ARow := Coord.Y;
end;

procedure THexDumpGrid.MouseUp(Button: TMouseButton; Shift: TShiftState; X,
  Y: Integer);
var
  ACol, ARow, Index: Integer;
begin
  inherited MouseUp(Button, Shift, X, Y);

  MouseToCell(X, Y, ACol, ARow);
  if (ACol >= HEX_START) and (ACol < (HEX_START + BYTES_PER_ROW)) Then
  begin
    Index := ARow * BYTES_PER_ROW + ACol - HEX_START;
    fEditIndex := Index * 2;
    fEditHex := true;
  end
  else if (ACol >= TEXT_START) and (ACol < (TEXT_START + BYTES_PER_ROW )) Then
  begin
    Index := ARow * BYTES_PER_ROW + ACol - TEXT_START;
    fEditIndex := Index;
    fEditHex := false;
  end
  else begin
    SetSelection(0, 0);
    fEditIndex := -1;
    fEditHex := false;
    Index := -1;
  end;
  
  if Assigned(fOnSelectionChanged) Then fOnSelectionChanged(self, Index);
  
  Invalidate;
end;

procedure THexDumpGrid.SetData(AData: Pointer; ALength, AMaxLength: Integer);
begin
  fData := AData;//PChar(AData);
  fDataLength := ALength;
  fMaxLength := AMaxLength;

  RowCount := Ceil(ALength / BYTES_PER_ROW);

  if (fSelectionStart >= fDataLength) or
    ((fSelectionStart + fSelectionLength) > fDataLength) Then
  begin
    SetSelection(0, 0);
    fEditIndex := -1;
  end;
  Invalidate;
end;

procedure THexDumpGrid.SetParent(AParent: TWinControl);
var
  I, HexWidth, CharWidth: Integer;
begin
  inherited SetParent(AParent);
  if ( AParent <> nil ) Then
  begin
    // Configure the grid.
    ParentFont := false;
    Canvas.Font := Font;
    FixedCols := 1;
    FixedRows := 0;
    RowCount := 1;
    DefaultRowHeight := VERT_MARGIN + Canvas.TextHeight('0');
    ColCount := 1 + 1 + BYTES_PER_ROW + 1 + BYTES_PER_ROW;

    ColWidths[0] := HORZ_MARGIN + Canvas.TextWidth('0000:');
    ColWidths[1] := 20;
    HexWidth := HORZ_MARGIN + Canvas.TextWidth('00');
    For I := 0 To BYTES_PER_ROW - 1 do ColWidths[HEX_START + I] := HexWidth;
    ColWidths[2 + BYTES_PER_ROW] := 20;
    CharWidth := Canvas.TextWidth('X') + 1;
    For I := 0 To BYTES_PER_ROW - 1 do ColWidths[TEXT_START + I] := CharWidth;
  end;
end;

procedure THexDumpGrid.SetSelection(Start, Length: Integer);
begin
  if (Start <> fSelectionStart) or (Length <> fSelectionLength) Then
  begin
    fSelectionStart := Start;
    fSelectionLength := Length;
    Invalidate;
    EnsureSelectionVisible;
  end;
end;

procedure THexDumpGrid.SetSelectionLength(Value: Integer);
begin
  if (Value <> fSelectionLength) Then
  begin
    fSelectionLength := Value;
    Invalidate;
    EnsureSelectionVisible;
  end;
end;

procedure THexDumpGrid.SetSelectionStart(Value: Integer);
begin
  if (Value <> fSelectionStart) Then
  begin
    fSelectionStart := Value;
    Invalidate;
    EnsureSelectionVisible;
  end;
end;

procedure Register;
begin
  RegisterComponents('xray', [THexDumpGrid]);
end;

end.
