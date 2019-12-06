using System;
using System.Collections.Generic;
using System.Diagnostics;
using System.Linq;
using System.Runtime.InteropServices;
using System.Text;

namespace TokenManage
{
    public class TMProcess
    {

        private int pid;
        private string processTokenUser;
        private string processName;

        private TMProcess(Process process)
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

        /// <summary>
        /// Retrieves the user connected to a processes access token.
        /// This requires that the current access token is able to have 
        /// the QueryInformation and TOKEN_QUERY rights on the targeted 
        /// process.
        /// 
        /// Only retrieves this once, and this is cached after that.
        /// </summary>
        /// <returns></returns>
        public String GetProcessTokenUser()
        {
            if (this.processTokenUser != null)
                return this.processTokenUser;

            this.processTokenUser = String.Empty;
            IntPtr hProc = WinInterop.OpenProcess(ProcessAccessFlags.QueryInformation, false, this.pid);
            if (hProc == IntPtr.Zero)
            {
                Logger.GetInstance().Error($"Failed to open handle to process with PID: {pid}. OpenProcess failed with error code: {WinInterop.GetLastError()}");
                return processTokenUser;
            }

            IntPtr hToken;
            if(!WinInterop.OpenProcessToken(hProc, WinInterop.TOKEN_QUERY, out hToken))
            {
                Logger.GetInstance().Error($"Failed to open handle to process token. OpenProcessToken failed with error code: {WinInterop.GetLastError()}");
                return processTokenUser;
            }

            uint tokenInfLength = 0;
            bool success;

            success = WinInterop.GetTokenInformation(hToken, TOKEN_INFORMATION_CLASS.TokenUser, IntPtr.Zero, tokenInfLength, out tokenInfLength);
            IntPtr tokenInfo = Marshal.AllocHGlobal(Convert.ToInt32(tokenInfLength));
            success = WinInterop.GetTokenInformation(hToken, TOKEN_INFORMATION_CLASS.TokenUser, tokenInfo, tokenInfLength, out tokenInfLength);

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
                    Logger.GetInstance().Error($"Failed to retrieve user for process token. LookupAccountSid failed with error: {WinInterop.GetLastError()}");
                    this.processTokenUser = "";
                }
            }
            else
            {
                Logger.GetInstance().Error($"Failed to retreive token information for process token. GetTokenInformation failed with error: {WinInterop.GetLastError()}");
            }

            Marshal.FreeHGlobal(tokenInfo);
            return this.processTokenUser;
        }

        /// <summary>
        /// 
        /// </summary>
        /// <returns></returns>
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

        /// <summary>
        /// Gets a process based on its ID.
        /// </summary>
        /// <param name="pid"></param>
        /// <returns></returns>
        public static TMProcess GetProcessByID(int pid)
        {
            Process p = Process.GetProcessById(pid);
            if(p == null)
            {
                Logger.GetInstance().Error($"Failed to find process with PID: ${pid}");
                throw new Exception("Process could not be found.");
            }
            return new TMProcess(p);
        }

        /// <summary>
        /// Returns a list of processes with an access token connected to 
        /// the specified user.
        /// </summary>
        /// <param name="user"></param>
        /// <returns></returns>
        public static List<TMProcess> GetProcessByUser(string user)
        {
            var processes = GetAllProcesses();
            var ret = processes.Where(x => x.GetProcessTokenUser().ToLower().Contains(user.ToLower()));
            return ret.ToList();
        }

        public static List<TMProcess> GetProcessByName(string name)
        {
            var processes = Process.GetProcessesByName(name).ToList();
            return processes.Select(x => new TMProcess(x)).ToList();
        }
    }
}
