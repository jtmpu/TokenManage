using CommandLine;
using System;
using System.Collections.Generic;
using System.Text;
using TokenManage;
using TokenManage.Domain;
using TokenManage.Domain.AccessTokenInfo;

namespace TokenManageCLI
{
    [Verb("token", HelpText = "Get information about an access token.")]
    public class TokenOptions : BaseOptions
    {
        [Option('p', "processid", Required = false, HelpText = "The process ID to show token info from")]
        public int? ProcessID { get; set; }

        [Option('c', "current", Required = false, HelpText = "Show information about current process access token.")]
        public bool Current { get; set; }

        [Option('u', "user", Required = false, HelpText = "Show user info")]
        public bool ShowUser { get; set; }

        [Option('g', "groups", Required = false, HelpText = "Show groups")]
        public bool ShowGroups { get; set; }

        [Option("logonsid", Required = false, HelpText = "Show logon SID")]
        public bool ShowLogonSid { get; set; }

        [Option("sessionid", Required = false, HelpText = "Show session ID")]
        public bool ShowSessionID { get; set; }

        [Option("privileges", Required = false, HelpText = "Show privileges")]
        public bool ShowPrivileges { get; set; }

        [Option('a', "all", Required = false, HelpText = "Show all available information")]
        public bool ShowAll { get; set; }
    }

    public class Token
    {
        private ConsoleOutput console;
        private TokenOptions options;

        public Token(TokenOptions options, ConsoleOutput console)
        {
            this.options = options;
            this.console = console;
        }

        public void Execute()
        {
            TMProcessHandle hProcess;
            if(this.options.ProcessID.HasValue)
            {
                hProcess = TMProcessHandle.FromProcessId(this.options.ProcessID.Value, TokenManage.API.ProcessAccessFlags.QueryInformation);
            }
            else
            {
                hProcess = TMProcessHandle.GetCurrentProcessHandle();
            }

            var hToken = AccessTokenHandle.FromProcessHandle(hProcess, TokenAccess.TOKEN_QUERY);

            if (this.options.ShowUser || this.options.ShowAll)
            {
                ShowUser(hToken);
            }
            if (this.options.ShowGroups || this.options.ShowAll)
            {
                ShowGroups(hToken);
            }

            if (this.options.ShowPrivileges || this.options.ShowAll)
            {
                ShowPrivileges(hToken);
            }

            if (this.options.ShowLogonSid || this.options.ShowAll)
            {
                ShowLogonSid(hToken);
            }

            if (this.options.ShowSessionID || this.options.ShowAll)
            {
                ShowSessionID(hToken);
            }

        }

        private void ShowUser(AccessTokenHandle hToken)
        {
            var user = AccessTokenUser.FromTokenHandle(hToken);
            console.WriteLine("[USERNAME]");
            console.WriteLine("");
            console.WriteLine($"{user.Domain}\\{user.Username}");
            console.WriteLine("");
        }

        private void ShowGroups(AccessTokenHandle hToken)
        {
            var groups = AccessTokenGroups.FromTokenHandle(hToken);
            console.WriteLine("[GROUPS]");
            console.WriteLine("");
            foreach (var group in groups.GetGroups())
            {
                var msg = $"{group.Domain}\\{group.Name}";
                console.WriteLine(msg);
            }
            console.WriteLine("");
        }

        private void ShowLogonSid(AccessTokenHandle hToken)
        {
            var logonSid = AccessTokenLogonSid.FromTokenHandle(hToken);
            console.WriteLine("[LOGON SID]");
            console.WriteLine("");
            foreach (var sid in logonSid.GetLogonSidStrings())
            {
                console.WriteLine(sid);
            }
            console.WriteLine("");
        }

        private void ShowSessionID(AccessTokenHandle hToken)
        {
            var sessionId = AccessTokenSessionId.FromTokenHandle(hToken);
            console.WriteLine("[SESSION ID]");
            console.WriteLine("");
            console.WriteLine(sessionId.SessionId.ToString());
            console.WriteLine("");

        }

        private void ShowPrivileges(AccessTokenHandle hToken)
        {
            var privileges = AccessTokenPrivileges.FromTokenHandle(hToken);
            console.WriteLine("[PRIVILEGES]");
            console.WriteLine("");
            foreach(var priv in privileges.GetPrivileges())
            {
                var enabledText = priv.IsEnabled() ? "Enabled" : "Disabled";
                console.WriteLine($"{priv.Name}: {enabledText}");
            }
            console.WriteLine("");
        }
    }
}
