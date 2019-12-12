﻿using System;
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

        /// <summary>
        /// Return access token information regarding current process.
        /// </summary>
        /// <returns></returns>
        public static String WhoisProcess()
        {
            var hProc = TMProcessHandle.GetCurrentProcessHandle();
            var hToken = AccessTokenHandle.FromProcessHandle(hProc);
            var user = AccessTokenUser.FromTokenHandle(hToken);
            return GetAccessTokenInfo(hToken);
        }

        /// <summary>
        /// Return access token information regarding current thread.
        /// </summary>
        /// <returns></returns>
        public static String WhoisThread()
        {
            var hThread = TMThreadHandle.GetCurrentThreadHandle();
            var hToken = AccessTokenHandle.FromThreadHandle(hThread);
            var user = AccessTokenUser.FromTokenHandle(hToken);
            return GetAccessTokenInfo(hToken);
        }

        private static string GetAccessTokenInfo(AccessTokenHandle hToken)
        {
            StringBuilder info = new StringBuilder();
            var user = AccessTokenUser.FromTokenHandle(hToken);
            var groups = AccessTokenGroups.FromTokenHandle(hToken);
            var privileges = AccessTokenPrivileges.FromTokenHandle(hToken);
            info.Append("[USERNAME]\n");
            info.Append("\n");
            info.Append($"{user.Domain}\\{user.Username}\n");
            info.Append("\n");
            info.Append("[GROUPS]");
            info.Append("\n");
            foreach (var group in groups.GetGroupEnumerator())
                info.Append($"{group.Domain}\\{group.Name}\n");
            info.Append("\n");
            info.Append("[PRIVILEGES]");
            info.Append("\n");
            foreach (var priv in privileges.GetPrivileges())
            {
                var enabled = priv.Attributes == Constants.SE_PRIVILEGE_ENABLED ? "Enabled" : "Disabled";
                info.Append($"{priv.Name}: {enabled}\n");

            }
            info.Append("\n");
            return info.ToString();
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
