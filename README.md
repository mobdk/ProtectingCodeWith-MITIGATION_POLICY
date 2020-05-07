# ProtectingCodeWith-MITIGATION_POLICY

![example](https://github.com/mobdk/ObfuscateTest/blob/master/policy01.PNG)

Protect your code with a mitigation policy that prevent non Microsoft signed code to inject for inspection, this PoC shows the basic, FindUserPID search for logon srvhost PID, so we have permission.  

Compile: C:\Windows\Microsoft.NET\Framework64\v4.0.30319\csc.exe /platform:x64 /target:exe /unsafe policy.cs

policy.cs:

```
using System;
using System.Diagnostics;
using System.Runtime.InteropServices;
using System.Security.Principal;


public class Code
{
    static void Main(string[] args)
    {
       int ProcId = FindUserPID("svchost");
       const uint EXTENDED_STARTUPINFO_PRESENT = 0x00080000;
       // https://docs.microsoft.com/en-us/windows/win32/api/processthreadsapi/nf-processthreadsapi-updateprocthreadattribute
       const int PROC_THREAD_ATTRIBUTE_MITIGATION_POLICY = 0x00020007;
       const long PROCESS_CREATION_MITIGATION_POLICY_BLOCK_NON_MICROSOFT_BINARIES_ALWAYS_ON = 0x100000000000;

       var pInfo = new PROCESS_INFORMATION();
       var sInfoEx = new STARTUPINFOEX();
       sInfoEx.StartupInfo.cb = Marshal.SizeOf(sInfoEx);
       IntPtr lpValue = IntPtr.Zero;

       var lpSize = IntPtr.Zero;
       var result = InitializeProcThreadAttributeList(IntPtr.Zero, 1, 0, ref lpSize);
       sInfoEx.lpAttributeList = Marshal.AllocHGlobal(lpSize);
       result = InitializeProcThreadAttributeList(sInfoEx.lpAttributeList, 1, 0, ref lpSize);
       var parentHandle = Process.GetProcessById(ProcId).Handle;
       lpValue = Marshal.AllocHGlobal(IntPtr.Size);
       Marshal.WriteInt64(lpValue, PROCESS_CREATION_MITIGATION_POLICY_BLOCK_NON_MICROSOFT_BINARIES_ALWAYS_ON);
       result = UpdateProcThreadAttribute( sInfoEx.lpAttributeList, 0, (IntPtr) PROC_THREAD_ATTRIBUTE_MITIGATION_POLICY, lpValue, (IntPtr)IntPtr.Size, IntPtr.Zero, IntPtr.Zero);

       var pSec = new SECURITY_ATTRIBUTES();
       var tSec = new SECURITY_ATTRIBUTES();
       pSec.nLength = Marshal.SizeOf(pSec);
       tSec.nLength = Marshal.SizeOf(tSec);
       CreateProcess(/*"C:\\Windiows\\Tasks\\csharpshell64.exe"*/"C:\\Windows\\System32\\notepad.exe", null, ref pSec, ref tSec, false, EXTENDED_STARTUPINFO_PRESENT, IntPtr.Zero, null, ref sInfoEx, out pInfo);
       DeleteProcThreadAttributeList(sInfoEx.lpAttributeList);
       Marshal.FreeHGlobal(sInfoEx.lpAttributeList);
       Marshal.FreeHGlobal(lpValue);
       CloseHandle(pInfo.hProcess);
       CloseHandle(pInfo.hThread);
    }

    private static string GetProcessUser(Process process)
    {
        IntPtr processHandle = IntPtr.Zero;
        try
        {
            ZwOpenProcessToken(process.Handle, 8, out processHandle);
            WindowsIdentity wi = new WindowsIdentity(processHandle);
            string user = wi.Name;
            return user.Contains(@"\") ? user.Substring(user.IndexOf(@"\") + 1) : user;
        }
        catch
        {
            return null;
        }
        finally
        {
            if (processHandle != IntPtr.Zero)
            {
                CloseHandle(processHandle);
            }
        }
    }


    public static int FindUserPID(string procName)
    {
        string owner;
        Process proc;
        int foundPID = 0;
        Process[] processList = Process.GetProcesses();
        foreach (Process process in processList)
        {
            if (process.ProcessName == procName) {
                proc = Process.GetProcessById(process.Id);
                owner = GetProcessUser(proc);
                if (owner == Environment.UserName ) {
                    foundPID = process.Id;
                    break;
                }
          }
      }
      return foundPID;
    }

    [DllImport("kernel32.dll")]
    [return: MarshalAs(UnmanagedType.Bool)]
    static extern bool CreateProcess( string lpApplicationName, string lpCommandLine, ref SECURITY_ATTRIBUTES lpProcessAttributes, ref SECURITY_ATTRIBUTES lpThreadAttributes, bool bInheritHandles, uint dwCreationFlags, IntPtr lpEnvironment, string lpCurrentDirectory, [In] ref STARTUPINFOEX lpStartupInfo, out PROCESS_INFORMATION lpProcessInformation);

    [DllImport("kernel32.dll", SetLastError = true)]
    [return: MarshalAs(UnmanagedType.Bool)]
    private static extern bool UpdateProcThreadAttribute( IntPtr lpAttributeList, uint dwFlags, IntPtr Attribute, IntPtr lpValue, IntPtr cbSize, IntPtr lpPreviousValue, IntPtr lpReturnSize);

    [DllImport("kernel32.dll", SetLastError = true)]
    [return: MarshalAs(UnmanagedType.Bool)]
    private static extern bool InitializeProcThreadAttributeList( IntPtr lpAttributeList, int dwAttributeCount, int dwFlags, ref IntPtr lpSize);

    [DllImport("kernel32.dll", SetLastError = true)]
    [return: MarshalAs(UnmanagedType.Bool)]
    private static extern bool DeleteProcThreadAttributeList(IntPtr lpAttributeList);

    [DllImport("kernel32.dll", SetLastError = true)]
    static extern bool CloseHandle(IntPtr hObject);

    [DllImport("ntdll.dll", SetLastError = true)]
    public static extern bool ZwOpenProcessToken(IntPtr ProcessHandle, uint DesiredAccess, out IntPtr TokenHandle);

    [StructLayout(LayoutKind.Sequential, CharSet = CharSet.Unicode)]
    struct STARTUPINFOEX
    {
        public STARTUPINFO StartupInfo;
        public IntPtr lpAttributeList;
    }

    [StructLayout(LayoutKind.Sequential, CharSet = CharSet.Unicode)]
    struct STARTUPINFO
    {
        public Int32 cb;
        public string lpReserved;
        public string lpDesktop;
        public string lpTitle;
        public Int32 dwX;
        public Int32 dwY;
        public Int32 dwXSize;
        public Int32 dwYSize;
        public Int32 dwXCountChars;
        public Int32 dwYCountChars;
        public Int32 dwFillAttribute;
        public Int32 dwFlags;
        public Int16 wShowWindow;
        public Int16 cbReserved2;
        public IntPtr lpReserved2;
        public IntPtr hStdInput;
        public IntPtr hStdOutput;
        public IntPtr hStdError;
    }

    [StructLayout(LayoutKind.Sequential)]
    internal struct PROCESS_INFORMATION
    {
        public IntPtr hProcess;
        public IntPtr hThread;
        public int dwProcessId;
        public int dwThreadId;
    }

    [StructLayout(LayoutKind.Sequential)]
    public struct SECURITY_ATTRIBUTES
    {
        public int nLength;
        public IntPtr lpSecurityDescriptor;
        public int bInheritHandle;
    }
}

```
