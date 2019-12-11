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
            var hProc = TMProcessHandle.GetCurrentProcessHandle();
            var hToken = AccessTokenHandle.FromProcessHandle(hProc);
            var user = AccessTokenUser.FromTokenHandle(hToken);
            return String.Format(@"{0}\{1}", user.Domain, user.Username);
        }

        #region Privileges

        public static void EnablePrivilege(string privilege)
        {
            SetPrivilege(privilege, true);
        }

        public static void DisablePrivilege(string privilege)
        {
            SetPrivilege(privilege, false);
        }

        public static void SetPrivilege(string privilege, bool enabled)
        {
            var hProc = TMProcessHandle.GetCurrentProcessHandle();
            var hToken = AccessTokenHandle.FromProcessHandle(hProc, TokenAccess.TOKEN_ADJUST_PRIVILEGES);

            var newPrivs = new List<ATPrivilege>();
            var attributes = (uint)(enabled ? Constants.SE_PRIVILEGE_ENABLED : Constants.SE_PRIVILEGE_DISABLED);
            newPrivs.Add(ATPrivilege.FromValues(privilege, attributes));

            AccessTokenPrivileges.AdjustTokenPrivileges(hToken, newPrivs);
        }

        #endregion

        /// <summary>
        /// Duplicates and impersonates the process token of the specified PID.
        /// This replaces the current thread token. Call RevertToSelf() to get back
        /// previous access token.
        /// </summary>
        /// <param name="pid"></param>
        public static void ImpersonateProcessToken(int pid)
        {
            var hProc = TMProcessHandle.FromProcessId(pid, ProcessAccessFlags.QueryInformation);
            var hToken = AccessTokenHandle.FromProcessHandle(hProc, TokenAccess.TOKEN_IMPERSONATE, TokenAccess.TOKEN_DUPLICATE);

            var hDuplicate = AccessTokenHandle.Duplicate(hToken, SECURITY_IMPERSONATION_LEVEL.SecurityImpersonation, 
                TOKEN_TYPE.TokenImpersonation, TokenAccess.TOKEN_ALL_ACCESS);

            if(!Advapi32.SetThreadToken(IntPtr.Zero, hDuplicate.GetHandle()))
            {
                Console.WriteLine($"{Kernel32.GetLastError()}");
            }
        }

        public static void RevertToSelf()
        {
            Advapi32.RevertToSelf();
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
                    Console.WriteLine($"{p.ProcessId}, {p.ProcessName}, {userInfo.Username}");

                } catch(Exception)
                {
                    continue;
                }
            }

        }
    }
}
