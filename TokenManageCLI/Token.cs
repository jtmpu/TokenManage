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
        [Option('t', "tmp", Required = false, HelpText = "")]
        public bool ProcessID { get; set; }
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
            var hProcess = TMProcessHandle.GetCurrentProcessHandle();
            var hToken = AccessTokenHandle.FromProcessHandle(hProcess, TokenAccess.TOKEN_QUERY);
            var user = AccessTokenUser.FromTokenHandle(hToken);
            console.WriteLine(user.User);
            var groups = AccessTokenGroups.FromTokenHandle(hToken);
            foreach (var group in groups.GetGroups())
            {
                var msg = $"{group.Domain}\\{group.Name}, {group.Type.ToString()}";
                console.WriteLine(msg);
            }
            var logonSid = AccessTokenLogonSid.FromTokenHandle(hToken);
            foreach(var sid in logonSid.GetLogonSidStrings())
            {
                console.WriteLine(sid);
            }
        }
    }
}
