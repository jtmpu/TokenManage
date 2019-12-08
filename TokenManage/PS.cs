using System;
using System.Collections.Generic;
using System.Diagnostics;
using System.Text;
using TokenManage.Domain;
using TokenManage.Domain.AccessTokenInfo;
using TokenManage.API;

namespace TokenManage
{
    public class PS
    {
        public static String Whoami()
        {
            return String.Format(@"{0}\{1}", Environment.UserDomainName, Environment.UserName);
        }

        public static bool EnablePrivilege(string privilege)
        {
            LUID luid;
            if (!Advapi32.LookupPrivilegeValue(null, privilege, out luid))
            {
                return false;
            }

            IntPtr hProc = Kernel32.GetCurrentProcess();
            uint desiredAccess = Constants.TOKEN_QUERY | Constants.TOKEN_ADJUST_PRIVILEGES;
            IntPtr hToken;
            if (!Advapi32.OpenProcessToken(hProc, desiredAccess, out hToken))
            {
                return false;
            }

            TOKEN_PRIVILEGES newPriv = new TOKEN_PRIVILEGES();
            newPriv.PrivilegeCount = 1;
            newPriv.Privileges = new LUID_AND_ATTRIBUTES[1];
            newPriv.Privileges[0] = new LUID_AND_ATTRIBUTES();
            newPriv.Privileges[0].Luid = luid;
            newPriv.Privileges[0].Attributes = Constants.SE_PRIVILEGE_ENABLED;

            if (!Advapi32.AdjustTokenPrivileges(hToken, false, ref newPriv, 0, IntPtr.Zero, IntPtr.Zero))
            {
                return false;
            }
            return true;
        }

        public static void ListProcesses()
        {
            var processes = TMProcess.GetAllProcesses();
            foreach(var p in processes)
            {
                try
                {
                    var pHandle = TMProcessHandle.FromProcess(p, ProcessAccessFlags.QueryInformation);
                    var hToken = AccessTokenHandle.FromProcessHandle(pHandle, TokenAccess.TOKEN_QUERY);
                    var userInfo = AccessTokenUser.FromTokenHandle(hToken);
                    Console.WriteLine($"{p.ProcessId}, {p.ProcessName}, {userInfo.User}");

                } catch(Exception)
                {
                    continue;
                }
            }

        }
    }
}
