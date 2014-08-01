unit uSniffFilter;

{///////////////////////////////////////////////////////////////////////////////

  unit desc:      定义监听器的过滤条件, 模拟BPF VM
  unit author:    net_xray@hotmail.com
  created date:   2003/10/06

///////////////////////////////////////////////////////////////////////////////}

interface

uses
  uPacket32;

type

  TSniffFilter = class
    private
      F_UseFilter : boolean;
      F_FiltPktCnt : Integer;
    public
      // packet filter
      function SetFilter(fp: Pbpf_program): boolean; overload;
      function SetFilter(str_exp: string): boolean; overload;
      //
      function IsDataPermit(Data: Pointer): boolean;
      //
      property UseFilter: Boolean read F_UseFilter;
      property FilteredPacketCount: Integer read F_FiltPktCnt;
  end;

implementation

{ TSniffFilter }

function TSniffFilter.IsDataPermit(Data: Pointer): boolean;
begin
  Result := True;
end;

function TSniffFilter.SetFilter(fp: Pbpf_program): boolean;
begin
  Result := True;
end;

function TSniffFilter.SetFilter(str_exp: string): boolean;
begin
  Result := True;
end;

end.
