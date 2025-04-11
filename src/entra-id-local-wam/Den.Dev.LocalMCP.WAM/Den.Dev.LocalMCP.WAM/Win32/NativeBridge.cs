using System.Runtime.InteropServices;

namespace Den.Dev.LocalMCP.WAM.Win32
{
    static partial class NativeBridge
    {
        [DllImport("user32.dll", ExactSpelling = true)]
        internal static extern nint GetAncestor(nint hwnd, GetAncestorFlags flags);

        [DllImport("kernel32.dll")]
        internal static extern nint GetConsoleWindow();


        [DllImport("ntdll.dll")]
        internal static extern int NtQueryInformationProcess(nint processHandle, int processInformationClass, ref PROCESS_BASIC_INFORMATION processInformation, int processInformationLength, out int returnLength);

        internal static int GetParentProcessId(int processId)
        {
            var process = System.Diagnostics.Process.GetProcessById(processId);
            var pbi = new PROCESS_BASIC_INFORMATION();
            int returnLength;
            int status = NtQueryInformationProcess(process.Handle, 0, ref pbi, Marshal.SizeOf(pbi), out returnLength);

            if (status != 0)
            {
                throw new InvalidOperationException($"NtQueryInformationProcess failed with status code {status}");
            }

            return pbi.InheritedFromUniqueProcessId.ToInt32();
        }
    }
}
