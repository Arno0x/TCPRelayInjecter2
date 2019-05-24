TCPRelayInjecter2
============

Author: [Arno0x](https://twitter.com/Arno0x0x).

As opposed to my first version of this project, this second version:
  - uses a completely different approach (no more CLR loading into the remote process, not necessary),
  - supports both 32 or 64 bits target process.
    
This tool is used to inject a "TCP Relay" managed assembly (*TcpRelay_x86.dll or TcpRelay_x64.dll*) into an unmanaged process. The relay is basically listening on a TCP port and relaying (*forwarding*) the received connection to another destination port, either locally (*localhost*) or, optionnaly, to a remote IP.

Note: TCPRelayInjecter only relays TCP connections.

Background and context
----------------

I created this tool in order to bypass Windows local firewall rules preventing some inbound connections I needed (*in order to perform some relay and/or get a MiTM position*). As a non-privileged user, firewall rules could not be modified or added.

The idea is to find a process running as the same standard (*non-privileged*) user **AND** allowed to receive any network connection, or at least the one we need. You can find such a process by analyzing the local FW rules:

`netsh advfirewall firewall show rule name=all`

From there we just have to inject a TCP Relay assembly in the process fulfilling your needs, passing it some arguments like a local port to listen to, a destination port and an optionnal destination IP to forward the traffic to.

Compile
----------------

The injecter comes in two flavors achieving exactly the same goal: there's a C++ version (`TcpRelayInjecter.cpp`) and there's a C# version (`TcpRelayInjecter.cs`). You only need to compile one of these two files. It might be easier though to compile the C# injecter as it doesn't require VisualStudio or any other C++ compiler, it just needs the `csc.exe` compiler which comes with the .Net framework installed with any recent Windows OS.

**Targetting 32 bits processes**:
  - You'll need the **32 bits version** of both the DLL and the injecter
  - Compile the DLL:
    *Refer to the comments in the headers of the `TcpRelay.cs`
    * Modify the .Net DLL to export the `EntryPoint` method as explained in the file header comments.
  - Compile the injecter either using `TcpRelayInjecter.cpp` or `TcpRelayInjecter.cs`. Refer to the file header comments for compilation instructions.
  
  

**Targetting 64 bits processes**:
  - You'll need the **64 bits version** of both the DLL and the injecter
  - Compile the DLL:
    * Refer to the comments in the headers of the `TcpRelay.cs`
    * Modify the .Net DLL to export the `EntryPoint` method as explained in the file header comments.
  - Compile the injecter either using `TcpRelayInjecter.cpp` or `TcpRelayInjecter.cs`. Refer to the file header comments for compilation instructions.

Usage
----------------

Prior to running the tool, ensure the binary files are all in the same path:
  - TcpRelayInjecter_x86.exe
  - TCPRelay_x86.dll
  
or

  - TcpRelayInjecter_x64.exe
  - TCPRelay_x64.dll

 Then use the following command line:

`TcpRelayInjecter_x86|x64.exe <target_process_name> <listening_port> <destination_port> [destination_IP]`

  - target_process_name: the name of the executable we want to inject the TCP Forwarder into
  - listening_port: the TCP port to use for listening for inbound connections
  - destination_port: the TCP port to which forward the traffic (typically another process would be listening on that port)
  - destination_IP: *Optionnal*,  the destination IP to which forward the traffic, if not specified, defaults to localhost