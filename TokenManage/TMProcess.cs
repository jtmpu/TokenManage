using System;
using System.Collections.Generic;
using System.Diagnostics;
using System.Runtime.InteropServices;
using System.Text;

namespace TokenManage
{
    public class TMProcess
    {

        private int pid;
        private string processTokenUser;
        private string processName;

        public TMProcess(Process process)
        {
            this.pid = process.Id;
            this.processName = process.ProcessName;
            this.processTokenUser = null;
        }

        public int GetProcessID()
        {
            return pid;
        }

        public String GetProcessName()
        {
            return processName;
        }

        public String GetProcessTokenUser()
        {
            if (this.processTokenUser != null)
                return this.processTokenUser;

            this.processTokenUser = "";

            IntPtr hProc = WinInterop.OpenProcess(ProcessAccessFlags.QueryInformation, false, this.pid);
            if (hProc == IntPtr.Zero)
            {
                return "";
            }

            IntPtr hToken;
            if(!WinInterop.OpenProcessToken(hProc, WinInterop.TOKEN_QUERY, out hToken))
            {
                return "";
            }

            uint tokenInfLength = 0;
            bool success;

            success = WinInterop.GetTokenInformation(hToken, TOKEN_INFORMATION_CLASS.TokenUser, IntPtr.Zero, tokenInfLength, out tokenInfLength);
            IntPtr tokenInfo = Marshal.AllocHGlobal(Convert.ToInt32(tokenInfLength));
            success = WinInterop.GetTokenInformation(hToken, TOKEN_INFORMATION_CLASS.TokenUser, tokenInfo, tokenInfLength, out tokenInfLength);

            this.processTokenUser = "";
            if (success)
            {
                TOKEN_USER tokenUser = (TOKEN_USER)Marshal.PtrToStructure(tokenInfo, typeof(TOKEN_USER));
                int length = Convert.ToInt32(WinInterop.GetLengthSid(tokenUser.User.Sid));
                byte[] sid = new byte[length];
                Marshal.Copy(tokenUser.User.Sid, sid, 0, length);

                StringBuilder sbUser = new StringBuilder();
                uint cchName = (uint)sbUser.Capacity;
                StringBuilder sbDomain = new StringBuilder();
                uint cchReferencedDomainName = (uint)sbDomain.Capacity;
                SID_NAME_USE peUse;
                if(WinInterop.LookupAccountSid(null, sid, sbUser, ref cchName, sbDomain, ref cchReferencedDomainName, out peUse))
                {
                    this.processTokenUser = $"{sbDomain.ToString()}\\{sbUser.ToString()}";
                }
                else
                {
                    this.processTokenUser = "";
                }
            }

            Marshal.FreeHGlobal(tokenInfo);
            return this.processTokenUser;
        }

        public static List<TMProcess> GetAllProcesses()
        {
            List<TMProcess> ret = new List<TMProcess>();
            Process[] processes = Process.GetProcesses();
            foreach(Process p in processes)
            {
                ret.Add(new TMProcess(p));
            }
            return ret;
        }
    }
}
