using System;
using System.Collections.Generic;
using System.Diagnostics;
using System.Text;
using TokenManage.API;
using TokenManage.Domain;
using TokenManage.Domain.AccessTokenInfo;

namespace TokenManage.Logic
{
    public class TMProcessBuilder
    {

        /// <summary>
        /// A flag to determine if we attempt to enable all privileges for the token.
        /// </summary>
        public bool EnableAll { get; private set; }

        public String Application { get; private set; }

        public string CommandLine { get; private set; }

        public AccessTokenHandle TokenHandle { get; private set; }
        public bool SameSession { get; private set; }

        /// <summary>
        /// A flag to determine if we create with CreateProcessWithTokenW or CreateProcessAsUser
        /// </summary>
        public bool CreateWithImpersonate { get; private set; }

        public TMProcessBuilder UsingCredentials(string domain, string username, string password)
        {
            var token = AccessTokenHandle.FromLogin(username, 
                password, 
                domain, 
                API.LogonType.LOGON32_LOGON_INTERACTIVE, 
                API.LogonProvider.LOGON32_PROVIDER_DEFAULT);
            this.TokenHandle = token;
            return this;
        }

        public TMProcessBuilder UsingExistingProcessToken(int processId)
        {
            var hProc = TMProcessHandle.FromProcessId(processId);
            var hToken = AccessTokenHandle.FromProcessHandle(hProc, TokenAccess.TOKEN_DUPLICATE, TokenAccess.TOKEN_QUERY);
            var hDuplicate = hToken.DuplicatePrimaryToken();
            this.TokenHandle = hDuplicate;
            return this;
        }

        public TMProcessBuilder SetApplication(string application)
        {
            this.Application = application;
            return this;
        }

        public TMProcessBuilder SetCommandLine(string commandLine)
        {
            this.CommandLine = commandLine;
            return this;
        }

        public TMProcessBuilder WithCreateProcessWithToken()
        {
            this.CreateWithImpersonate = true;
            return this;
        }
        public TMProcessBuilder WithCreateProcessAsUser()
        {
            this.CreateWithImpersonate = false;
            return this;
        }


        /// <summary>
        /// Uses the CreateProcessWithTokenW function. This
        /// creates a new process and primary thread using an access token.
        /// This requires the privileges SE_IMPERSONATE_NAME.
        /// </summary>
        /// <returns></returns>
        private TMProcess CreateProcessWithToken()
        {
            this.ElevateProcess(PrivilegeConstants.SeImpersonatePrivilege);

            STARTUPINFO si = new STARTUPINFO();
            PROCESS_INFORMATION pi;
            if (!Advapi32.CreateProcessWithTokenW(this.TokenHandle.GetHandle(), LogonFlags.NetCredentialsOnly,
                this.Application, this.CommandLine, CreationFlags.NewConsole, IntPtr.Zero, @"C:\", ref si, out pi))
            {
                Logger.GetInstance().Error($"Failed to create shell. CreateProcessWithTokenW failed with error code: {Kernel32.GetLastError()}");
                throw new Exception();
            }

            return TMProcess.GetProcessById(pi.dwProcessId);
        }

        /// <summary>
        /// Uses the CreateProcessAsUser function. This
        /// creates a new process and primary thread using an access token.
        /// This requires the privileges SE_ASSIGNPRIMARYTOKEN and SE_INCREASE_QUOTA.
        /// </summary>
        /// <returns></returns>
        private TMProcess CreateProcessAsUser()
        {
            this.ElevateProcess(PrivilegeConstants.SeAssignPrimaryTokenPrivilege, PrivilegeConstants.SeIncreaseQuotaPrivilege);

            STARTUPINFO si = new STARTUPINFO();
            PROCESS_INFORMATION pi;
            SECURITY_ATTRIBUTES saProcessAttributes = new SECURITY_ATTRIBUTES();
            SECURITY_ATTRIBUTES saThreadAttributes = new SECURITY_ATTRIBUTES();
            if (!Advapi32.CreateProcessAsUser(this.TokenHandle.GetHandle(), this.Application, this.CommandLine, ref saProcessAttributes,
                ref saThreadAttributes, false, 0, IntPtr.Zero, null, ref si, out pi))
            { 
                Logger.GetInstance().Error($"Failed to create shell. CreateProcessAsUser failed with error code: {Kernel32.GetLastError()}");
                throw new Exception();
            }

            return TMProcess.GetProcessById(pi.dwProcessId);
        }

        public TMProcessBuilder EnableAllPrivileges()
        {
            this.EnableAll = true;
            return this;
        }

        private void EnablePrivileges()
        {
            foreach(var privName in Enum.GetNames(typeof(PrivilegeConstants)))
            {
                var privs = new List<ATPrivilege>();
                privs.Add(ATPrivilege.CreateEnabled(privName));
                try
                {
                    AccessTokenPrivileges.AdjustTokenPrivileges(this.TokenHandle, privs);
                }
                catch
                { 
                }
            }
        }

        public TMProcessBuilder EnsureSameSesssionId()
        {
            this.SameSession = true;
            return this;
        }
        
        private void SetSameSessionId()
        {
            var hCurrent = AccessTokenHandle.GetCurrentProcessTokenHandle();
            var currentSession = AccessTokenSessionId.FromTokenHandle(hCurrent);
            var targetSession = AccessTokenSessionId.FromTokenHandle(this.TokenHandle);
            if (currentSession.SessionId != targetSession.SessionId)
                AccessTokenSessionId.SetTokenSessionId(currentSession, this.TokenHandle);

            var tmp = AccessTokenSessionId.FromTokenHandle(TokenHandle);
            if (tmp.SessionId != currentSession.SessionId)
                Logger.GetInstance().Error($"Failed to set session id for token. {currentSession.SessionId} vs {tmp.SessionId}");
        }

        private void ElevateProcess(params PrivilegeConstants[] privs)
        {
            var hToken = AccessTokenHandle.GetCurrentProcessTokenHandle();
            var privileges = AccessTokenPrivileges.FromTokenHandle(hToken);

            foreach(var priv in privs)
            {
                if(!privileges.IsPrivilegeEnabled(priv))
                {
                    //Due to current bug, i can only adjust one privilege at a time.
                    var newPriv = new List<ATPrivilege>();
                    newPriv.Add(ATPrivilege.CreateEnabled(priv));
                    AccessTokenPrivileges.AdjustTokenPrivileges(hToken, newPriv);
                }
            }
        }

        public TMProcess Create()
        {
            if(this.EnableAll)
                this.EnablePrivileges();

            if(this.SameSession)
                this.SetSameSessionId();

            if (this.CreateWithImpersonate)
                return CreateProcessWithToken();
            else
                return CreateProcessAsUser();
        }
    }
}
