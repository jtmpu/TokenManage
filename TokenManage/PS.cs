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

        public static void EnablePrivilege(string privilege)
        {
            var hProc = TMProcessHandle.GetCurrentProcessHandle();
            var hToken = AccessTokenHandle.FromProcessHandle(hProc);

            var newPrivs = new List<ATPrivilege>();
            newPrivs.Add(ATPrivilege.FromValues(privilege, Constants.SE_PRIVILEGE_ENABLED));

            AccessTokenPrivileges.AdjustTokenPrivileges(hToken, newPrivs);
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
