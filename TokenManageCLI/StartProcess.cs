using CommandLine;
using System;
using System.Linq;
using TokenManage;
using TokenManage.Domain;
using TokenManage.Domain.AccessTokenInfo;
using TokenManage.API;
using System.Collections.Generic;

namespace TokenManageCLI
{

    [Verb("start", HelpText = "Starts a new process")]
    public class StartProcessOptions : BaseOptions
    {
        [Option('p', "process", Required = false, HelpText = "ID of process to duplicate access token from.")]
        public int? ProcessID { get; set; }

        [Option('a', "application", Required = false, HelpText = @"Specify the application to run. Defaults to cmd.exe.")]
        public string ApplicationName { get; set; }

        [Option('c', "command", Required = false, Default = null, HelpText = "The command arguments to use.")]
        public string CommandLine { get; set; }

        [Option('s', "system", Required = false, Default = false, HelpText = "Automatically attempts to open a CMD shell running as NT AUTHORITY\\System")]
        public bool System { get; set; }

        [Option('n', "session", Required = false, HelpText = "Starts a process using the token connected to the specified session id.")]
        public uint SessionId { get; set; }
    }

    public class StartProcess
    {

        private ConsoleOutput console;
        private StartProcessOptions options;

        public StartProcess(StartProcessOptions options, ConsoleOutput console)
        {
            this.options = options;
            this.console = console;
        }


        public void Execute()
        {
            if(this.options.ProcessID.HasValue)
            {
                BorrowProcessToken(this.options.ProcessID.Value);
            }
            else if(this.options.System)
            {
                var processes = TMProcess.GetProcessByName("lsass");
                if(processes.Count == 0)
                {
                    console.Error("Failed to find LSASS process. That is weird.");
                    return;
                }
                else if(processes.Count > 1)
                {
                    console.Error("Found multiple LSASS processes. That is weird.");
                    return;
                }
                else
                {
                    var lsassProcess = processes.First();
                    BorrowProcessToken(lsassProcess.ProcessId);
                }
            }
            else
            {
                BorrowSessionToken(this.options.SessionId);
            }
        }

        public void BorrowSessionToken(uint sessionId)
        {
            var hToken = AccessTokenHandle.FromSessionId(sessionId);

            var hDuplicate = AccessTokenHandle.Duplicate(hToken, SECURITY_IMPERSONATION_LEVEL.SecurityImpersonation, TOKEN_TYPE.TokenPrimary, TokenAccess.TOKEN_ALL_ACCESS);
            
            STARTUPINFO si = new STARTUPINFO();
            PROCESS_INFORMATION pi;
            this.console.Debug($"Starting new process.");
            string applicationName = Environment.GetEnvironmentVariable("WINDIR") + @"\System32\cmd.exe";
            if (this.options.ApplicationName != null)
            {
                applicationName = this.options.ApplicationName;
            }
            this.console.Debug($"Starting with application: {applicationName}");

            if (!Advapi32.CreateProcessWithTokenW(hDuplicate.GetHandle(), LogonFlags.NetCredentialsOnly, applicationName, this.options.CommandLine, CreationFlags.NewConsole, IntPtr.Zero, @"C:\", ref si, out pi))
            {
                this.console.Error($"Failed to create shell. CreateProcessWithTokenW failed with error code: {Kernel32.GetLastError()}");
                return;
            }
        }

        public void BorrowProcessToken(int pid)
        {
            this.Elevate();

            var hProc = TMProcessHandle.FromProcessId(pid);
            var hToken = AccessTokenHandle.FromProcessHandle(hProc, TokenAccess.TOKEN_ALL_ACCESS);
            this.console.Debug($"Duplicating access token.");
            var hDuplicate = hToken.DuplicatePrimaryToken();

            STARTUPINFO si = new STARTUPINFO();
            PROCESS_INFORMATION pi;
            this.console.Debug($"Starting new process.");
            string applicationName = Environment.GetEnvironmentVariable("WINDIR") + @"\System32\cmd.exe";
            if (this.options.ApplicationName != null)
            {
                applicationName = this.options.ApplicationName;
            }
            this.console.Debug($"Starting with application: {applicationName}");
            SECURITY_ATTRIBUTES saProcessAttributes = new SECURITY_ATTRIBUTES();
            SECURITY_ATTRIBUTES saThreadAttributes = new SECURITY_ATTRIBUTES();
            if (!Advapi32.CreateProcessAsUser(hDuplicate.GetHandle(), applicationName, this.options.CommandLine, ref saProcessAttributes, 
                ref saThreadAttributes, false, 0, IntPtr.Zero, null, ref si, out pi))
            {
                this.console.Error($"Failed to create shell. CreateProcessAsUser failed with error code: {Kernel32.GetLastError()}");
            }

            this.Revert();
        }

        private void Elevate()
        {
            // 1. Enable debug privileges for our process.
            var hProc = TMProcessHandle.GetCurrentProcessHandle();
            var hToken = AccessTokenHandle.FromProcessHandle(hProc, TokenAccess.TOKEN_QUERY, TokenAccess.TOKEN_ADJUST_PRIVILEGES);
            var newPriv = new List<ATPrivilege>();
            newPriv.Add(ATPrivilege.FromValues(PrivilegeConstants.SeDebugPrivilege.ToString(), Constants.SE_PRIVILEGE_ENABLED));
            AccessTokenPrivileges.AdjustTokenPrivileges(hToken, newPriv);

            // 2. Retrieve impersonation token for a LocalSystem process.
            hProc = TMProcessHandle.FromProcess(TMProcess.GetProcessById(3644), ProcessAccessFlags.QueryInformation);
            hToken = AccessTokenHandle.FromProcessHandle(hProc, TokenAccess.TOKEN_IMPERSONATE, TokenAccess.TOKEN_DUPLICATE, TokenAccess.TOKEN_QUERY);
            if(!Advapi32.ImpersonateLoggedOnUser(hToken.GetHandle()))
            {
                this.console.Error($"Failed to impersonate local system. ImpersonateLoggedOnUser failed with error: {Kernel32.GetLastError()}");
                throw new Exception();
            }

            hToken = AccessTokenHandle.FromThreadHandle(TMThreadHandle.GetCurrentThreadHandle());
            newPriv = new List<ATPrivilege>();
            newPriv.Add(ATPrivilege.FromValues(PrivilegeConstants.SeTcbPrivilege.ToString(), Constants.SE_PRIVILEGE_ENABLED));
            AccessTokenPrivileges.AdjustTokenPrivileges(hToken, newPriv);


            hToken = AccessTokenHandle.FromThreadHandle(TMThreadHandle.GetCurrentThreadHandle());
            var user = AccessTokenUser.FromTokenHandle(hToken);
            console.WriteLine($"{user.Domain}\\{user.Username}");
            var privileges = AccessTokenPrivileges.FromTokenHandle(hToken);
            foreach (var priv in privileges.GetPrivileges())
            {
                console.WriteLine($"{priv.Name}: {priv.Attributes}");
            }
        }

        private void Revert()
        {
            if(!Advapi32.RevertToSelf())
            {
                this.console.Error($"Failed to revert to self. RevertToSelf failed with error: {Kernel32.GetLastError()}");
                throw new Exception();
            }
        }
    }
}
