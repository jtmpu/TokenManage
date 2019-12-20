using System;
using System.Collections.Generic;
using System.Runtime.ConstrainedExecution;
using System.Runtime.InteropServices;
using System.Security;
using System.Text;

namespace TokenManage.API
{
    public class Kernel32
    {
        /// <summary>
        /// Retrieve the error code if a function fails.
        /// </summary>
        /// <returns></returns>
        [DllImport("kernel32.dll")]
        public static extern uint GetLastError();

        /// <summary>
        /// Retrieves pseudo handle to the current process.
        /// </summary>
        /// <returns></returns>
        [DllImport("kernel32.dll", ExactSpelling = true)]
        public static extern IntPtr GetCurrentProcess();

        [DllImport("kernel32.dll", ExactSpelling = true)]
        public static extern IntPtr GetCurrentThread();


        [DllImport("kernel32.dll", SetLastError = true)]
        [ReliabilityContract(Consistency.WillNotCorruptState, Cer.Success)]
        [SuppressUnmanagedCodeSecurity]
        [return: MarshalAs(UnmanagedType.Bool)]
        public static extern bool CloseHandle(IntPtr hObject);

        /// <summary>
        /// Retrieves a handle to a process.
        /// </summary>
        /// <param name="processAccess"></param>
        /// <param name="bInheritHandle"></param>
        /// <param name="processId"></param>
        /// <returns></returns>
        [DllImport("kernel32.dll", SetLastError = true)]
        public static extern IntPtr OpenProcess(
            ProcessAccessFlags processAccess,
            bool bInheritHandle,
            int processId);

        [DllImport("kernel32.dll", SetLastError = true)]
        public static extern IntPtr CreateNamedPipe(
            string lpName, 
            uint dwOpenMode,
            uint dwPipeMode, 
            uint nMaxInstances, 
            uint nOutBufferSize, 
            uint nInBufferSize,
            uint nDefaultTimeOut,
            IntPtr pipeSecurityDescriptor);

        [DllImport("kernel32.dll")]
        static extern bool ConnectNamedPipe(
            IntPtr hNamedPipe,
            IntPtr lpOverlapped);

        [DllImport("kernel32.dll", SetLastError = true)]
        private static extern bool DisconnectNamedPipe(
            IntPtr hHandle);


        [DllImport("kernel32.dll", EntryPoint = "CreateFile", SetLastError = true)]
        public static extern IntPtr CreateFile(
            String lpFileName,
            UInt32 dwDesiredAccess, 
            UInt32 dwShareMode,
            IntPtr lpSecurityAttributes,
            UInt32 dwCreationDisposition,
            UInt32 dwFlagsAndAttributes,
            IntPtr hTemplateFile);

        [DllImport("kernel32.dll", SetLastError = true)]
        public static extern bool WriteFile(
            IntPtr handle,
            byte[] buffer,
            uint count, 
            ref uint written, 
            IntPtr lpOverlapped);

        [DllImport("kernel32.dll", SetLastError = true)]
        public static extern IntPtr LocalFree(IntPtr hMem);

    }
}
