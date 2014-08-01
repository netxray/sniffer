unit uHexCommon;

interface

uses
  Windows, Messages, SysUtils, Classes, Graphics, Controls, Forms, grids;

  function ConvertHexToBin(aFrom, aTo: PChar; const aCount: Integer ;
                             const SwapNibbles: Boolean ; var BytesTranslated: Integer): PChar;
  function ConvertBinToHex(aFrom, aTo: PChar; const aCount: Integer ;
                             const SwapNibbles: Boolean): PChar;
  function ConvertChrToHex(aFrom: AnsiChar; const SwapNibbles: Boolean): string;

const
  HexCHL = '0123456789abcdef';
  HexCHU = '0123456789ABCDEF';
  HexCHA = HexCHL+HexCHU;

implementation

// translate a hexadecimal data representation ("a000 cc45 d3 42"...) to its binary values
function ConvertHexToBin(aFrom ,aTo: PChar; const aCount: Integer;
                           const SwapNibbles: Boolean; var BytesTranslated: Integer): PChar;
var
	lHi : Boolean;
	lCT : Integer;
	lBy : Byte;
	lNb : Char;
begin
	Result := aTo;
	BytesTranslated := 0;
	lHi := True;
	lBy := 0;
	for lCT := 0 to Pred(aCount) do
  begin
		if Pos(aFrom[lCT], HexCHA) <> 0 then
		begin
			lNB := UpCase(aFrom[lCT]);
			if lHi then
				lBY := ((Pos(lNB , HexCHU) - 1) * 16)
			else
				lBy := lBy or ((Pos(lNB, HexCHU) - 1));
			lHI := not lHI;
			if lHI then
			begin
				if SwapNibbles then
					aTo[BytesTranslated] := Char(((lBy and 15)*16) or ((lBy and $f0) shr 4))
				else
					aTo[BytesTranslated] := Char(lBY);
				Inc(BytesTranslated);
			end;
		end;
  end;
end;

// translate binary data to its hex representation
function ConvertBinToHex(aFrom, aTo: PChar; const aCount: Integer;
                           const SwapNibbles: Boolean): PChar;
var
	lCT : Integer;
	lBy : Byte;
	lCX : Integer;
begin
	Result := aTo;
	lCX := 0;
	for lCT := 0 to Pred (aCount) do
	begin
		lBy := Ord(aFrom[lCT]);
		if SwapNibbles then
		begin
			aTo[lCX] := UpCase(HexCHU[(lBY and 15) + 1]);
			aTo[lCX+1] := UpCase(HexCHU[(lBY shr 4) + 1])
		end
		else
		begin
			aTo[lCX+1] := UpCase(HexCHU[(lBY and 15) + 1]);
			aTo[lCX] := UpCase(HexCHU[(lBY shr 4) + 1])
		end;
		Inc(lCX , 2);
	end;
	aTO[lCX] := #0;
end;

function ConvertChrToHex(aFrom : AnsiChar; const SwapNibbles : Boolean ): string;
var
  lBy : Byte;
  aTo : array[0..1] of char;
begin
  lBy := Ord(aFrom);
  if SwapNibbles then
  begin
    aTo[0] := UpCase(HexCHU[(lBY and 15) + 1]);
    aTo[1] := UpCase(HexCHU[(lBY shr 4) + 1])
  end
  else
  begin
    aTo[1] := UpCase(HexCHU[(lBY and 15) + 1]);
    aTo[0] := UpCase(HexCHU[(lBY shr 4) + 1])
  end;
  Result := String(aTo);
end;

end.
