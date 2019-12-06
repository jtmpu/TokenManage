using CommandLine;
using System;
using TokenManage;

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
            if (!this.options.ProcessID.HasValue)
            {
                this.console.Error($"Currently only works when you specify process id.");
                return;
            }

            int pid = this.options.ProcessID.Value;
            this.console.Debug($"Attempting to open handle to process with id {pid}");
            IntPtr hProc = WinInterop.OpenProcess(ProcessAccessFlags.QueryInformation, true, pid);
            if (hProc == IntPtr.Zero)
            {
                this.console.Error($"Cannot open handle to process. OpenProcess failed with error code: {WinInterop.GetLastError()}.");
                return;
            }
            this.console.Debug($"Successfully retrieved handle.");

            uint desiredAccess = WinInterop.TOKEN_IMPERSONATE;
            desiredAccess |= WinInterop.TOKEN_QUERY;
            desiredAccess |= WinInterop.TOKEN_DUPLICATE;
            desiredAccess |= WinInterop.TOKEN_ASSIGN_PRIMARY;
            IntPtr hToken;
            this.console.Debug($"Attempting to open handle to process token.");
            if (!WinInterop.OpenProcessToken(hProc, desiredAccess, out hToken))
            {
                this.console.Error($"Cannot open handle to process token. OpenProcessToken failed with error code: {WinInterop.GetLastError()}");
                return;
            }
            this.console.Debug($"Successfully retrieved handle.");

            IntPtr hDuplicate = IntPtr.Zero;
            SECURITY_ATTRIBUTES secAttr = new SECURITY_ATTRIBUTES();

            this.console.Debug($"Attempting to duplicate token.");
            if (!WinInterop.DuplicateTokenEx(hToken, WinInterop.TOKEN_ALL_ACCESS, ref secAttr, SECURITY_IMPERSONATION_LEVEL.SecurityImpersonation, TOKEN_TYPE.TokenPrimary, out hDuplicate))
            {
                this.console.Error($"Failed to duplicate token. DuplicateTokenEx failed with error code: {WinInterop.GetLastError()}");
                return;
            }
            this.console.Debug($"Successfully duplicated token.");

            STARTUPINFO si = new STARTUPINFO();
            PROCESS_INFORMATION pi;

            this.console.Debug($"Starting new process.");
            string applicationName = Environment.GetEnvironmentVariable("WINDIR") + @"\System32\cmd.exe";
            if (this.options.ApplicationName != null)
            {
                applicationName = this.options.ApplicationName;
            }
            this.console.Debug($"Starting with application: {applicationName}");

            if (!WinInterop.CreateProcessWithTokenW(hDuplicate, LogonFlags.NetCredentialsOnly, applicationName, this.options.CommandLine, CreationFlags.NewConsole, IntPtr.Zero, @"C:\", ref si, out pi))
            {
                this.console.Error($"Failed to create shell. CreateProcessWithTokenW failed with error code: {WinInterop.GetLastError()}");
                return;
            }

        }
    }
}
