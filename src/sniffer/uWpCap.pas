unit uWpCap;

interface

uses
  windows, winsock;

const
  DLL = 'wpcap.dll';

type
  // all function below, if success will return 0;

  Pbpf_u_int32 = ^Tbpf_u_int32;
  Tbpf_u_int32 = LongWord;

  Ppcap_t = ^Tpcap_t;
  Tpcap_t = integer;

  TTimeVal = packed record
  	tv_sec:   LongWord;
	  tv_usec:  LongWord;
  end;
  //struct pcap_pkthdr {
  //	struct timeval ts;	/* time stamp */
  //	bpf_u_int32 caplen;	/* length of portion present */
  //	bpf_u_int32 len;	/* length this packet (off wire) */
  //};
  Ppchar = ^PAnsiChar;
  PPpcap_pkthdr = ^Ppcap_pkthdr;
  Ppcap_pkthdr = ^Tpcap_pkthdr;
  Tpcap_pkthdr = packed record
  	ts:     TTimeVal;
	  caplen: Tbpf_u_int32;
  	len :   Tbpf_u_int32;
  end;

  //struct pcap_stat {
  //	u_int ps_recv;		/* number of packets received */
  //	u_int ps_drop;		/* number of packets dropped */
  //	u_int ps_ifdrop;	/* drops by interface XXX not yet supported */
  //#ifdef REMOTE
  //#ifdef WIN32
  ////	u_int bs_capt;		/* number of packets that reach the application */
  //#endif /* WIN32 */
  //	u_int ps_capt;		/* number of packets that reach the application; please get rid off the Win32 ifdef */
  //	u_int ps_sent;		/* number of packets sent by the server on the network */
	//  u_int ps_netdrop;	/* number of packets lost on the network */
  //#endif
  //};
  Ppcap_stat = ^Tpcap_stat;
  Tpcap_stat = packed record
    ps_recv:    LongWord;
    ps_drop:    LongWord;
    ps_ifdrop:  LongWord;
{$IFDEF REMOTE}
{$IFDEF WIN32}
    bs_capt:    LongWord;
{$ENDIF}
    ps_capt:    LongWord;
    ps_sent:    LongWord;
    ps_netdrop: LongWord;
{$ENDIF}
  end;

	//  //Structure for BIOCSETF.
	//struct bpf_program {
	//	u_int bf_len;
	//	struct bpf_insn *bf_insns;
	//};
  Pbpf_insn = ^Tbpf_insn;
  Tbpf_insn = packed record
    code : Word;
    jt   : Byte;
    jf   : Byte;
    k    : Integer;
  end;

  Pbpf_program = ^Tbpf_program;
  Tbpf_program = packed record
    bf_len  : LongWord;
    bf_insns: ^Tbpf_insn;
  end;

	//#ifndef _FILE_DEFINED
	//struct _iobuf {
	//        char *_ptr;
	//        int   _cnt;
	//        char *_base;
	//        int   _flag;
	//        int   _file;
	//        int   _charbuf;
	//        int   _bufsiz;
	//        char *_tmpfname;
	//};
	//typedef struct _iobuf FILE;
	//#define _FILE_DEFINED
	//#endif
  Pbpf_FILE = ^Tbpf_FILE;
  Tbpf_FILE = packed record
    _ptr:       PAnsiChar;
    _cnt:       integer;
    _base:      PAnsiChar;
    _flag:      integer;
    _file:      integer;
    _charbuf:   integer;
    _bufsiz:    integer;
    _tmpfname:  PAnsiChar;
  end;

  Tbpf_SOCKET = LongWord;

  Ppcap_dumper_t = ^Tpcap_dumper_t;
  Tpcap_dumper_t = integer; // gilgil

  Ppcap_addr_t = ^Tpcap_addr_t;
  Tpcap_addr_t = packed record
  	next: Ppcap_addr_t;
	  addr: PSockAddrIn; { address }
  	netmask: PSockAddrIn; { netmask for that address }
	  broadaddr: PSockAddrIn; { broadcast address for that address }
  	dstaddr: PSockAddrIn; { P2P destination address for that address }
  end;

  Ppcap_if_t = ^Tpcap_if_t;
  Pppcap_if_t = ^Ppcap_if_t;
  Tpcap_if_t = packed record
	  next: Ppcap_if_t;
	  name: PAnsiChar;
	  description: PAnsiChar;
	  address : Ppcap_addr_t;
	  flags: Tbpf_u_int32;
  end;


  //struct pcap_send_queue{
  //	u_int maxlen;		///< Maximum size of the the queue, in bytes.
                      ///This variable contains the size of the buffer field.
  //	u_int len;			///< Current size of the queue, in bytes.
  //	char *buffer;		///< Buffer containing the packets to be sent.
  //};
  Ppcap_send_queue = ^Tpcap_send_queue;
  Tpcap_send_queue = packed record
    maxlen, len: LongWord;
    buffer: PAnsiChar;
  end;

  //  struct pcap_etherent {
  //	  u_char addr[6];
  //	  char name[122];
  //  };
  Ppcap_ethernet = ^Tpcap_ethernet;
  Tpcap_ethernet = packed record
    addr: array[0..5] of UCHAR;
    name: array[0..121] of CHAR;
  end;

	//struct pcap_rmtauth
	//{
	//		\brief Type of the authentication required.

	//		In order to provide maximum flexibility, we can support different types
	//		of authentication based on the value of this 'type' variable. The currently
	//		supported authentication mathods are:
	//		- RPCAP_RMTAUTH_NULL: if the user does not provide an authentication method
	//		(this could enough if, for example, the RPCAP daemon allows connections
	//		from trusted hosts only)
	//		- RPCAP_RMTAUTH_PWD: if the user is willing to provide a valid
	//		username/password to authenticate itself on the remote machine. Username/
	//		password must be valid on the remote machine.

	//	int type;
	//		\brief Zero-terminated string containing the username that has to be
	//		used on the remote machine for authentication.
	//
	//		This field is meaningless in case of the RPCAP_RMTAUTH_NULL authentication
	//		and it can be NULL.

	//	char *username;
	//		\brief Zero-terminated string containing the password that has to be
	//		used on the remote machine for authentication.
	//
	//		This field is meaningless in case of the RPCAP_RMTAUTH_NULL authentication
	//		and it can be NULL.

	//	char *password;
	//};
  Ppcap_rmtauth = ^Tpcap_rmtauth;
  Tpcap_rmtauth = packed record
    m_type: integer;
    username: PAnsiChar;
    password: PAnsiChar;
  end;

  Pservent = ^Tservent;
  Tservent = packed record
    s_name:     PAnsiChar;
    s_aliases:  array of PAnsiChar;
    s_port:     short;
    s_proto:    PAnsiChar;
  end;

  //typedef void (*pcap_handler)(u_char *, const struct pcap_pkthdr *,
	//		     const u_char *);
  pcap_handler = procedure(user: PAnsiChar; handle: Ppcap_pkthdr;
                           const handle_buff: PAnsiChar); cdecl;

  {
  	char	*pcap_lookupdev(char *);
    Param:
      char* error_buf
    Return:
      char* adapter_names, memory allocate in this function
    Desc:
      Return the name of a network interface attached to the system, or NULL
      if none can be found.  The interface must be configured up; the
      lowest unit number is preferred; loopback is ignored.
  }
  function pcap_lookupdev(errbuf: PAnsiChar): PAnsiChar; cdecl external DLL;

  {
  	int	pcap_lookupnet(const char *, bpf_u_int32 *, bpf_u_int32 *, char *);
    Param:
    	register const char *device;
    	register bpf_u_int32 *netp, *maskp; //unsigned int
    	register char *errbuf;
  }
  function pcap_lookupnet(const device: PAnsiChar; netp, maskp: Pbpf_u_int32;
              errbuf: PAnsiChar): integer; cdecl external DLL;

  {
    pcap_t *pcap_open_live(const char *device, int snaplen, int promisc,
                            int to_ms, char *ebuf)
  }
	function pcap_open_live(const device: PAnsiChar; snaplen, promisc, to_ms: integer;
              ebuf: PAnsiChar): Ppcap_t; cdecl external DLL;
  
  {
    pcap_t *pcap_open_dead(int linktype, int snaplen)
  }
	function pcap_open_dead(linktype, snaplen: integer): Ppcap_t; cdecl external DLL;

  {
    pcap_t *pcap_open_offline(const char *fname, char *errbuf)
  }
	function pcap_open_offline(const fname: PAnsiChar; errbuf: PAnsiChar): Ppcap_t; cdecl external DLL;

  {
    void pcap_close(pcap_t *p)
  }  
	procedure pcap_close(p: Ppcap_t); cdecl external DLL;

  {
    int pcap_loop(pcap_t *p, int cnt, pcap_handler callback, u_char *user)
  }
	function pcap_loop(p: Ppcap_t; cnt: integer; callback: pcap_handler;
              user: PAnsiChar): integer; cdecl external DLL;

  {
    int pcap_dispatch(pcap_t *p, int cnt, pcap_handler callback, u_char *user)
  }
	function pcap_dispatch(p: Ppcap_t; cnt: integer; callback: pcap_handler;
              user: PAnsiChar): integer; cdecl external DLL;
  {
    const u_char *pcap_next(pcap_t *p, struct pcap_pkthdr *h)
  }
	function pcap_next(p: Ppcap_t; h: Ppcap_pkthdr): PAnsiChar; cdecl external DLL;

  {
    int pcap_stats(pcap_t *p, struct pcap_stat *ps)
  }
	function pcap_stats(p: Ppcap_t; ps: Ppcap_stat): integer; cdecl external DLL;

  {
    int pcap_setfilter(pcap_t *p, struct bpf_program *fp)
  }
	function pcap_setfilter(p: Ppcap_t; fp: Pbpf_program): integer; cdecl external DLL;

  {
  	// * NOTE: in the future, these may need to call platform-dependent routines,
	  // * e.g. on platforms with memory-mapped packet-capture mechanisms where
  	// * "pcap_read()" uses "select()" or "poll()" to wait for packets to arrive.
	  int pcap_getnonblock(pcap_t *p, char *errbuf)
  }
	function pcap_getnonblock(p: Ppcap_t; errbuf: PAnsiChar): integer; cdecl external DLL;

  {
    int pcap_setnonblock(pcap_t *p, int nonblock, char *errbuf)
  }  
	function pcap_setnonblock(p: Ppcap_t; nonblock: integer;
              errbuf: PAnsiChar): integer; cdecl external DLL;

  {
    void pcap_perror(pcap_t *p, char *prefix)
  }
	procedure pcap_perror(p: Ppcap_t; prefix: PAnsiChar); cdecl external DLL;
  
	// * Not all systems have strerror().
	//char *pcap_strerror(int errnum)
	function pcap_strerror(errnum: integer): PAnsiChar; cdecl external DLL;
  
  {
    char *pcap_geterr(pcap_t *p)
  }
	function pcap_geterr(p: Ppcap_t): PAnsiChar; cdecl external DLL;

  {
    int pcap_compile(pcap_t *p, struct bpf_program *program,
  	     char *buf, int optimize, bpf_u_int32 mask)
  }
	function pcap_compile(p: Ppcap_t; prg: Pbpf_program; buf: PAnsiChar;
              optimize: integer; mask: Tbpf_u_int32): integer; cdecl external DLL;

	// * entry point for using the compiler with no pcap open
	// * pass in all the stuff that is needed explicitly instead.
	//int pcap_compile_nopcap(int snaplen_arg, int linktype_arg,
	//		    struct bpf_program *program,
	//	     char *buf, int optimize, bpf_u_int32 mask)
	function pcap_compile_nopcap(snaplen_arg, linktype_arg: integer;
              prg: Pbpf_program; buf: PAnsiChar;
              optimize: integer; mask: Tbpf_u_int32): integer; cdecl external DLL;
  
	// * Clean up a "struct bpf_program" by freeing all the memory allocated
	// * in it.
	//void pcap_freecode(struct bpf_program *program)
	procedure	pcap_freecode(prg: Pbpf_program); cdecl external DLL;

  {
    int pcap_datalink(pcap_t *p)
  }  
	function pcap_datalink(p: Ppcap_t): integer; cdecl external DLL;

  {
    int pcap_list_datalinks(pcap_t *p, int **dlt_buffer)
  }
	function pcap_list_datalinks(p: Ppcap_t;
              var dlt_buffer: array of integer): integer; cdecl external DLL;

  {
    int pcap_set_datalink(pcap_t *p, int dlt)
  }
	function pcap_set_datalink(p: Ppcap_t; dlt: integer): integer; cdecl external DLL;
  
  {
    int pcap_datalink_name_to_val(const char *name)
  }
	function pcap_datalink_name_to_val(const name: PAnsiChar): integer; cdecl external DLL;

  {
    const char *pcap_datalink_val_to_name(int dlt)
  }
	function pcap_datalink_val_to_name(dlt: integer): PAnsiChar; cdecl external DLL;

  {
    int pcap_snapshot(pcap_t *p)
  }
	function pcap_snapshot(p: Ppcap_t): integer; cdecl external DLL;

  {
    int pcap_is_swapped(pcap_t *p)
  }
	function pcap_is_swapped(p: Ppcap_t): integer; cdecl external DLL;

  //int pcap_major_version(pcap_t *p)
	function pcap_major_version(p: Ppcap_t): integer; cdecl external DLL;
	function pcap_minor_version(p: Ppcap_t): integer; cdecl external DLL;
	
  //FILE *pcap_file(pcap_t *p)
  //int pcap_fileno(pcap_t *p)
	function pcap_file(p: Ppcap_t): Pbpf_FILE; cdecl external DLL;
	function pcap_fileno(p: Ppcap_t): integer; cdecl external DLL;
	
	// * Initialize so that sf_write() will output to the file named 'fname'.
	//pcap_dumper_t *pcap_dump_open(pcap_t *p, const char *fname)
	function pcap_dump_open(p: Ppcap_t; const fname: PAnsiChar): Ppcap_dumper_t; cdecl external DLL;
  
  //int pcap_dump_flush(pcap_dumper_t *p)
  //void pcap_dump_close(pcap_dumper_t *p)
	function pcap_dump_flush(p: Ppcap_dumper_t): integer; cdecl external DLL;
	procedure pcap_dump_close(p: Ppcap_dumper_t); cdecl external DLL;
  
  //* Output a packet to the initialized dump file.
  //void pcap_dump(u_char *user, const struct pcap_pkthdr *h, const u_char *sp)
  procedure	pcap_dump(user: PAnsiChar; const h: Ppcap_pkthdr; const sp: PAnsiChar); cdecl external DLL;
	
	// Get a list of all interfaces that are up and that we can open.
	// Returns -1 on error, 0 otherwise.
	// The list, as returned through "alldevsp", may be null if no interfaces
	// were up and could be opened.
	// 
	// Win32 implementation, based on WinPcap
	//int pcap_findalldevs(pcap_if_t **alldevsp, char *errbuf)
	function pcap_findalldevs(alldevsp: Pppcap_if_t; errbuf: PAnsiChar): integer; cdecl external DLL;

  //Free a list of interfaces.
  //void pcap_freealldevs(pcap_if_t *alldevs)
	procedure pcap_freealldevs(alldevs: Ppcap_if_t); cdecl external DLL;
	
	{* To avoid callback, this returns one packet at a time *}
  //int pcap_next_ex(pcap_t *p, struct pcap_pkthdr **pkt_header, u_char **pkt_data)
	function pcap_next_ex(p: Ppcap_t; pkt_header: PPpcap_pkthdr;
              pkt_data: PAnsiChar): integer; cdecl external DLL;
	
	{* XXX this guy lives in the bpf tree *}
	///*
	// * Execute the filter program starting at pc on the packet p
	// * wirelen is the length of the original packet
	// * buflen is the amount of data present
	// * For the kernel, p is assumed to be a pointer to an mbuf if buflen is 0,
	// * in all other cases, p is a pointer to a buffer and buflen is its size.
	// */
	//u_int
	//bpf_filter(pc, p, wirelen, buflen)
	//	register struct bpf_insn *pc;
	//	register u_char *p;
	//	u_int wirelen;
	//	register u_int buflen;
	function bpf_filter(pc: Pbpf_insn; p: PAnsiChar; wirelen,
            buflen: LongWord): LongWord; cdecl external DLL;

  //int	bpf_validate(struct bpf_insn *f, int len);
  function bpf_validate(f: Pbpf_insn; len: integer): integer; cdecl external DLL;

  //char *bpf_image(p, n)
	//struct bpf_insn *p;
	//int n;
  function bpf_image(p: Pbpf_insn; n: integer): PAnsiChar; cdecl external DLL;

  //void bpf_dump(struct bpf_program *p, int option)
  procedure bpf_dump(p: Pbpf_program; option: integer); cdecl external DLL;

	//int pcap_setbuff(pcap_t *p, int dim);
  function pcap_setbuff(p: Ppcap_t; dim: integer): integer; cdecl external DLL;

  //int pcap_setmode(pcap_t *p, int mode);
  function pcap_setmode(p: Ppcap_t; mode: integer): integer; cdecl external DLL;

	//int pcap_sendpacket(pcap_t *p, u_char *buf, int size);
  function pcap_sendpacket(p: Ppcap_t; buf: PAnsiChar; size: integer): integer; cdecl external DLL;

  //int pcap_setmintocopy(pcap_t *p, int size);
  function pcap_setmintocopy(p: Ppcap_t; size: integer): integer; cdecl external DLL;
	
  //Print out packets stored in the file initialized by sf_read_init().
  //If cnt > 0, return after 'cnt' packets, otherwise continue until eof.
  //
  //int pcap_offline_read(pcap_t *p, int cnt, pcap_handler callback, u_char *user)
  function pcap_offline_read(p: Ppcap_t; cnt: integer; callback: pcap_handler;
              user: PAnsiChar): integer; cdecl external DLL;

  //int pcap_read(pcap_t *p, int cnt, pcap_handler callback, u_char *user)
  function pcap_read(p: Ppcap_t; cnt: integer; callback: pcap_handler;
              user: PAnsiChar): integer; cdecl external DLL;
	
	//pcap_send_queue* pcap_sendqueue_alloc(u_int memsize);
  function pcap_sendqueue_alloc(memsize: LongWord): Ppcap_send_queue; cdecl external DLL;

  //void pcap_sendqueue_destroy(pcap_send_queue* queue);
  procedure pcap_sendqueue_destroy(queue: Ppcap_send_queue); cdecl external DLL;
  
	//int pcap_sendqueue_queue(pcap_send_queue* queue,
  //            const struct pcap_pkthdr *pkt_header, const u_char *pkt_data);
  function pcap_sendqueue_queue(queue: Ppcap_send_queue;
              const pkt_header: Ppcap_pkthdr;
              const pkt_data: PAnsiChar): integer; cdecl external DLL;
  
	//u_int pcap_sendqueue_transmit(pcap_t *p, pcap_send_queue* queue, int sync);
  function pcap_sendqueue_transmit(p: Ppcap_t; queue: Ppcap_send_queue;
              sync: integer): LongWord; cdecl external DLL;

	//HANDLE pcap_getevent(pcap_t *p);
  function pcap_getevent(p: Ppcap_t): THandle; cdecl external DLL;
  
	//struct pcap_stat *pcap_stats_ex(pcap_t *p);
  function pcap_stats_ex(p: Ppcap_t): Ppcap_stat; cdecl external DLL;
  
  //int pcap_setuserbuffer(pcap_t *p, int size);
	function pcap_setuserbuffer(p: Ppcap_t; size: integer): integer; cdecl external DLL;

	//int pcap_live_dump(pcap_t *p, char *filename, int maxsize, int maxpacks);
  function pcap_live_dump(p: Ppcap_t; filename: PAnsiChar; maxsize: integer;
              maxpacks: integer): integer;  cdecl external DLL;
              
	//int pcap_live_dump_ended(pcap_t *p, int sync);
  function pcap_live_dump_ended(p: Ppcap_t; sync: integer): integer; cdecl external DLL;
	
	
	//Make a copy of a BPF program and put it in the "fcode" member of
	//a "pcap_t".
	//If we fail to allocate memory for the copy, fill in the "errbuf"
	//member of the "pcap_t" with an error message, and return -1;
	//otherwise, return 0.
  
	//int install_bpf_program(pcap_t *p, struct bpf_program *fp)
	function install_bpf_program(p: Ppcap_t; fp: Pbpf_program): integer; cdecl external DLL;
  
	//struct	pcap_etherent *pcap_next_etherent(FILE *fp);
  function pcap_next_ethernet(fp: Pbpf_FILE): Ppcap_ethernet; cdecl external DLL;
	

{*!	\ingroup remote_func

	\brief It opens a generic source in order to capture / send (WinPcap only) traffic.
	
	The pcap_open() replaces all the pcap_open_xxx() functions with a single call.

	This function hides the differences between the different pcap_open_xxx() functions
	so that the programmer does not have to manage different opening function.
	In this way, the 'true' open function is decided according to the source type,
	which is included into the source string (in the form of source prefix).

	This function can rely on the pcap_createsrcstr() to create the string that keeps
	the capture device according to	the new syntax, and the pcap_parsesrcstr() for the
	other way round.

	\param source: zero-terminated string containing the source name to open.
	The source name has to include the format prefix according to the 
	syntax proposed by WinPcap. It cannot be NULL.
	On on Linux systems with 2.2 or later kernels, a device argument of "any"
	 (i.e. rpcap://any) can be used to capture packets from all interfaces.
	 <br>
	In case the pcap_createsrcstr() is not used, remember that the new source 
	syntax allows for these formats to be used in the pcap_open():
	- file://filename [we want to open a local file]
	- rpcap://host.foo.bar/adaptername [everything literal, no port number]
	- rpcap://host.foo.bar:1234/adaptername [everything literal, with port number]
	- rpcap://10.11.12.13/adaptername [IPv4 numeric, no port number]
	- rpcap://10.11.12.13:1234/adaptername [IPv4 numeric, with port number]
	- rpcap://[10.11.12.13]:1234/adaptername [IPv4 numeric with IPv6 format, with port number]
	- rpcap://[1:2:3::4]/adaptername [IPv6 numeric, no port number]
	- rpcap://[1:2:3::4]:1234/adaptername [IPv6 numeric, with port number]
	- rpcap://adaptername [local adapter, opened without using the RPCAP protocol]
	- adaptername [to open a local adapter; kept for compability, but it is strongly discouraged]
	- (NULL) [to open the first local adapter; kept for compability, but it is strongly discouraged]
	
	The following formats are not allowed:
	- rpcap:// [to open the first local adapter]
	- rpcap://hostname/ [to open the first remote adapter]

	\param snaplen: length of the packet that has to be retained.	
	For each packet received by the filter, only the first 'snaplen' bytes are stored 
	in the buffer and passed to the user application. For instance, snaplen equal to 
	100 means that only the first 100 bytes of each packet are stored.

  	\param flags: keeps several flags that can be needed for capturing packets.
	The allowed flags are the following:
	- PCAP_OPENFLAG_PROMISCUOUS: if the adapter has to go in promiscuous mode.		
	It is '1' if you have to open the adapter in promiscuous mode, '0' otherwise.
	Note that even if this parameter is false, the interface could well be in promiscuous
	mode for some other reason (for example because another capture process with 
	promiscuous mode enabled is currently using that interface).
	On on Linux systems with 2.2 or later kernels (that have the "any" device), this
	flag does not work on the "any" device; if an argument of "any" is supplied,
	the 'promisc' flag is ignored.
	- PCAP_OPENFLAG_SERVEROPEN_DP: it specifies who is responsible for opening the data
	connection in case of a remote capture (it means 'server open data path').
	If it is '1', it specifies if the data connection has to be intitiated 
	by the capturing device (which becomes like 'active'). If '0', the connection 
	will be initiated by the client workstation.
	This flag is used to overcome the problem of firewalls, which allow
	only outgoing connections. In that case, the capturing device can open
	a connection toward the client workstation in order to allow the
	data trasfer.
	In fact, the data connection is opened using a random port (while the
	control connection uses a standard port), so it is hard to configure
	a firewall to permit traffic on the data path.
	This flag is meaningless if the source is not a remote interface.
	Addictionally, it is meaningless if the data connection is done using
	the UDP protocol, since in this case the connection wil always be opened
	by the server.
	In these cases, it is simply ignored.
	- PCAP_OPENFLAG_UDP_DP: it specifies if the data trasfer (in case of a remote
	capture) has to be done with UDP protocol.
	If it is '1' if you want a UDP data connection, '0' if you want
	a TCP data connection; control connection is always TCP-based.
	A UDP connection is much lighter, but it does not guarantee that all
	the captured packets arrive to the client workstation. Moreover, 
	it could be harmful in case of network congestion.
	This flag is meaningless if the source is not a remote interface.
	In that case, it is simply ignored.

	\param read_timeout: read timeout in milliseconds.
	The read timeout is used to arrange that the read not necessarily return
	immediately when a packet is seen, but that it waits for some amount of 
	time to allow more packets to arrive and to read multiple packets from 
	the OS kernel in one operation. Not all platforms support a read timeout;
	on platforms that don't, the read timeout is ignored.

	\param auth: a pointer to a 'struct pcap_rmtauth' that keeps the information required to
	authenticate the user on a remote machine. In case this is not a remote capture, this
	pointer can be set to NULL.

	\param errbuf: a pointer to a user-allocated buffer which will contain the error
	in case this function fails. The pcap_open() and findalldevs() are the only two
	functions which have this parameter, since they do not have (yet) a pointer to a
	pcap_t structure, which reserves space for the error string. Since these functions
	do not have (yet) a pcap_t pointer (the pcap_t pointer is NULL in case of errors),
	they need an explicit 'errbuf' variable.
	'errbuf' may also be set to warning text when pcap_open_live() succeds; 
	to detect this case the caller should store a  zero-length string in  
	'errbuf' before calling pcap_open_live() and display the warning to the user 
	if 'errbuf' is no longer a zero-length string.

	\return A pointer to a 'pcap_t' which can be used as a parameter to the following
	calls (pcap_compile() and so on) and that specifies an opened WinPcap session. In case of 
	problems, it returns NULL and the 'errbuf' variable keeps the error message.

	\warning The source cannot be larger than PCAP_BUF_SIZE.
*}
	//pcap_t *pcap_open(const char *source, int snaplen, int flags,
  //            int read_timeout, struct pcap_rmtauth *auth, char *errbuf);
	function pcap_open(const source: PAnsiChar; snaplen, flags, read_timeout: integer;
              auth: Ppcap_rmtauth; errbuf: PAnsiChar): Ppcap_t; cdecl external DLL;

	//int pcap_createsrcstr(char *source, int type, const char *host,
  //            const char *port, const char *name, char *errbuf);
	function pcap_createsrcstr(source: PAnsiChar; itype: integer; const host: PAnsiChar;
              const port: PAnsiChar; const name: PAnsiChar;
              errbuf: PAnsiChar): integer; cdecl external DLL;

	//int pcap_parsesrcstr(const char *source, int *type, char *host,
  //            char *port, char *name, char *errbuf);
	function pcap_parsesrcstr(const source: PAnsiChar; var itype: integer;
              host, port, name, errbuf: PAnsiChar): integer; cdecl external DLL;

	//int pcap_findalldevs_ex(char *host, char *port, SOCKET sockctrl,
  //            struct pcap_rmtauth *auth, pcap_if_t **alldevs, char *errbuf);
	function pcap_findalldevs_ex(host, port: PAnsiChar; sockctrl: Tbpf_SOCKET;
              auth: Ppcap_rmtauth; alldevs: Pppcap_if_t;
              errbuf: PAnsiChar): integer; cdecl external DLL;

	//int pcap_remoteact_accept(const char *address, const char *port,
  //            const char *hostlist, char *connectinghost,
  //            struct pcap_rmtauth *auth, char *errbuf);
	function pcap_remoteact_accept(const address, port, hostlist: PAnsiChar;
              connectinghost: PAnsiChar; auth: Ppcap_rmtauth;
              errbuf: PAnsiChar): integer; cdecl external DLL;
              
	//int pcap_remoteact_list(char *hostlist, char sep, int size, char *errbuf);
  function pcap_remoteact_list(hostlist: PAnsiChar; sep: PAnsiChar; size: integer;
              errbuf: PAnsiChar): integer; cdecl external DLL;
  
	//int pcap_remoteact_close(const char *host, char *errbuf);
	function pcap_remoteact_close(const host: PAnsiChar;
              errbuf: PAnsiChar): integer; cdecl external DLL;
	//void pcap_remoteact_cleanup();
	procedure pcap_remoteact_cleanup(); cdecl external DLL;

	//int wsockinit();
	//void		endservent (void);
	//struct servent	*getservent (void);
  function wsockinit(): integer; cdecl external DLL;
  procedure endservent(); cdecl external DLL;

  //struct  servent {
  //      char    FAR * s_name;           /* official service name */
  //      char    FAR * FAR * s_aliases;  /* alias list */
  //      short   s_port;                 /* port # */
  //      char    FAR * s_proto;          /* protocol to use */
  //};
  function getservent():Pservent;  cdecl external DLL;
	
const
  RPCAP_RMTAUTH_NULL = 0;
  RPCAP_RMTAUTH_PWD = 1;


implementation

end.
