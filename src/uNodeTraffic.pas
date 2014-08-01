unit uNodeTraffic;

interface
uses
  Windows, WinSock, SysUtils, Classes,
  uCommon;

type

  // 在内存中建立一个动态的IP-MAC对应表
  PTranNodeInfo = ^TTranNodeInfo;
  TTranNodeInfo = record
    Addr:    TMAC2IP;
    Name:    string;   // node name
    InBytes: integer;  // bytes
    OutBytes:integer;
  end;

  TTranList = class
    private
      F_TranList: TThreadList;
    public
      constructor Create;
      destructor Destroy; override;
      procedure AddTransInfo(addr: PMAC2IP; InOrOut: boolean; bytes: integer);
      function GetTransInfo(ItemIdx: Integer): PTranNodeInfo;
      function GetTransCount: Integer;
  end;

var
  G_Tranlist: TTranList;

implementation

{ TTranList }

procedure TTranList.AddTransInfo(addr: PMAC2IP; InOrOut: boolean;
  bytes: integer);
var
  ni: PTranNodeInfo;
  I: integer;
begin
  if not IsValidMAC(addr^.MAC) then Exit;
  // is this address already exist? exist, update item
  try
    with F_TranList.LockList do begin
      For I:= 0 To Count - 1 do begin
        // check transmission path by source/destination ip
        if CompareIP(PTranNodeInfo(Items[I])^.Addr.IP, addr^.IP) then begin
          if InOrOut Then
            PTranNodeInfo(Items[I])^.InBytes := PTranNodeInfo(Items[I])^.InBytes + bytes
          else
            PTranNodeInfo(Items[I])^.OutBytes := PTranNodeInfo(Items[I])^.OutBytes + bytes;
          //update ip address
          if not IsValidIP(PTranNodeInfo(Items[I])^.Addr.IP) then begin
            PTranNodeInfo(Items[I])^.Addr.IP[0] := addr^.IP[0];
            PTranNodeInfo(Items[I])^.Addr.IP[1] := addr^.IP[1];
            PTranNodeInfo(Items[I])^.Addr.IP[2] := addr^.IP[2];
            PTranNodeInfo(Items[I])^.Addr.IP[3] := addr^.IP[3];
          end;
          Exit;
        end;
      end;
    end;
  finally
    F_TranList.UnlockList;
  end;
  // not exist, new item
  ni := New(PTranNodeInfo);
  ni^.InBytes := 0;
  ni^.OutBytes := 0;
  for I := 0 To 5 do begin
    ni^.Addr.MAC[I] := addr^.MAC[I];
    if I < 4 then ni^.Addr.IP[I] := addr^.IP[I];
  end;
  if InOrOut then
    ni^.InBytes := ni^.InBytes + bytes
  else
    ni^.OutBytes := ni^.OutBytes + bytes;
  //
  F_TranList.LockList.Add(ni);
end;

constructor TTranList.Create;
begin
  F_TranList := TThreadList.Create;
end;

destructor TTranList.Destroy;
var
  I: integer;
begin
  try
    For I := 0 To F_TranList.LockList.Count - 1 do
      Dispose(F_TranList.LockList.Items[I]);
  finally
    F_TranList.UnlockList;
  end;
  F_TranList.Free;
  inherited;
end;

function TTranList.GetTransCount: Integer;
begin
  try
    Result := F_TranList.LockList.Count;
  finally
    F_TranList.UnlockList;
  end;
end;

function TTranList.GetTransInfo(ItemIdx: Integer): PTranNodeInfo;
begin
  Result := nil;
  If (ItemIdx < 0) or (ItemIdx >= F_TranList.LockList.Count) Then Exit;
  try
    Result := F_TranList.LockList.Items[ItemIdx];
  finally
    F_TranList.UnlockList;
  end;
end;

end.
