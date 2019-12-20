using CommandLine;
using System;
using System.Linq;
using System.Diagnostics;
using TokenManage;
using TokenManage.Domain;
using TokenManage.Domain.AccessTokenInfo;
using TokenManage.API;
using System.Collections.Generic;
using TokenManage.Logic;
using System.Threading;

namespace TokenManageCLI
{

    [Verb("start", HelpText = "Starts a new process")]
    public class StartProcessOptions : BaseOptions
    {
        [Option('p', "process", Default = -1, Required = false, HelpText = "ID of process to duplicate access token from.")]
        public int ProcessID { get; set; }

        [Option('a', "application", Required = false, HelpText = @"Specify the application to run. Defaults to cmd.exe.")]
        public string ApplicationName { get; set; }

        [Option('c', "command", Required = false, Default = null, HelpText = "The command arguments to use.")]
        public string CommandLine { get; set; }

        [Option('s', "system", Required = false, Default = false, HelpText = "Automatically attempts to open a CMD shell running as NT AUTHORITY\\System")]
        public bool System { get; set; }

        [Option('n', "session", Required = false, HelpText = "Starts a process using the token connected to the specified session id.")]
        public uint SessionId { get; set; }

        [Option('u',"AsUser", Default = false, Required = false, HelpText = "Use CreateProcessAsUser (requiring SE_ASSIGNPRIMARYTOKEN and SE_INCREASEQUOTA). Otherwise, this uses CreateProcessWithTokenW (Requires SE_IMPERSONATE).")]
        public bool AsUser { get; set; }

        [Option('e', "enableall", Default = false, HelpText = "Ensure that all possible privileges are enabled.", Required = false)]
        public bool EnabledAllPossiblePrivileges { get; set; }

        [Option("samesession", Default = false, HelpText = "Ensure the access tokens have the same session id", Required = false)]
        public bool SameSessionId { get; set; }

        [Option('i', "interactive", Default = false, HelpText = "Attempt to use the current interactive shell instead of opening a new window.")]
        public bool Interactive { get; set; }

        [Option("nogui", Required = false, Default = false, HelpText = "Uses no GUI. This flag will not modify the DACL of the desktop for the targeted user, and won't show a GUI.")]
        public bool NoGUI { get; set; }
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
            if(this.options.ProcessID != -1)
            {
                this.InnerCreateProcess(this.options.ProcessID);
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
                    InnerCreateProcess(lsassProcess.ProcessId);
                }
            }
            else
            {
                throw new NotImplementedException();
            }
        }

        private void InnerCreateProcess(int processId)
        {
            var applicationName = @"C:\Windows\System32\cmd.exe";
            if (this.options.ApplicationName != null && this.options.ApplicationName != "")
                applicationName = this.options.ApplicationName;
            var builder = new TMProcessBuilder().
                SetApplication(applicationName).
                SetCommandLine(this.options.CommandLine).
                UsingExistingProcessToken(processId);

            if (this.options.EnabledAllPossiblePrivileges)
                builder.EnableAllPrivileges();

            if (this.options.SameSessionId)
                builder.EnsureSameSesssionId();

            if (this.options.NoGUI)
                builder.UseNoGUI();

            if (this.options.AsUser)
            {
                console.Debug("Starting with CreateProcessAsUser");
                builder.UsingCreateProcessAsUser();
            }
            else
            {
                console.Debug("Starting with CreateProcessWithTokenW");
                builder.UsingCreateProcessWithToken();
            }

            if (this.options.Interactive)
                builder.SetupInteractive();

            var tmProcess = builder.Create();

            if(this.options.Interactive)
            {
                // Attempt to attach to the processes STDin and STDout.
                console.WriteLine("[WIP]: Starting interactive shell... ");
            }


        }
    }
}
