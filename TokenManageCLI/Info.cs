﻿using CommandLine;
using TokenManage;
using System;
using System.Collections.Generic;
using System.Text;
using System.Linq;
using TokenManage.Domain;
using TokenManage.Domain.AccessTokenInfo;
using TokenManage.API;

namespace TokenManageCLI
{
    [Verb("info", HelpText = "Retrieve information about access tokens")]
    public class InfoOptions : BaseOptions
    {

        [Option('l', "list", Required = false, HelpText = "List all available access tokens")]
        public bool ListTokens { get; set; }
        [Option('t', "test", Required = false, HelpText = "Test")]
        public bool Test { get; set; }

        [Option('p', "privilege", Required = false, HelpText = "List processes with this privilege enabled")]
        public string Privilege { get; set; }
        [Option("disabled", Default = false, Required = false, HelpText = "List processes with the privilege disabled" )]
        public bool Disabled { get; set;  }

    }
    public class Info
    {
        private InfoOptions options;
        private ConsoleOutput console;

        public Info(InfoOptions options, ConsoleOutput console)
        {
            this.options = options;
            this.console = console;
        }

        public void Execute()
        {
            if (options.ListTokens)
            {
                StringBuilder output = new StringBuilder();
                int padding = 2;
                int maxName = 0;
                int maxPid = 0;
                int maxUser = 0;


                var processes = TMProcess.GetAllProcesses();
                List<Tuple<string, string, string>> processesInfo = new List<Tuple<string, string, string>>();
                foreach(var p in processes)
                {
                    string username = "";
                    try
                    {
                        var pHandle = TMProcessHandle.FromProcess(p, ProcessAccessFlags.QueryInformation);
                        var tHandle = AccessTokenHandle.FromProcessHandle(pHandle, TokenAccess.TOKEN_QUERY);
                        var userInfo = AccessTokenUser.FromTokenHandle(tHandle);
                        var sessId = AccessTokenSessionId.FromTokenHandle(tHandle);
                        var logonId = AccessTokenLogonSid.FromTokenHandle(tHandle);
                        username = userInfo.Username + ":" + sessId.SessionId.ToString() + ":";
                        foreach (var sid in logonId.GetLogonSidStrings())
                            username += sid + ",";
                    }
                    catch(Exception)
                    {
                    }
                    processesInfo.Add(new Tuple<string, string, string>(p.ProcessId.ToString(), p.ProcessName, username));
                }


                foreach (var p in processesInfo)
                {
                    maxPid = Math.Max(maxPid, p.Item1.Length);
                    maxName = Math.Max(maxName, p.Item2.Length);
                    maxUser = Math.Max(maxUser, p.Item3.Length);
                }

                string name = "PROCESS";
                string pid = "PID";
                string user = "USER";

                output.Append(pid + "," + generateSpaces(maxPid + padding - pid.Length));
                output.Append(name + "," + generateSpaces(maxName + padding - name.Length));
                output.Append(user + "\n");

                var sorted = processesInfo.OrderBy(x => x.Item1).ToList();
                foreach (var p in sorted)
                {
                    string line = "";
                    line += p.Item1 +  ",";
                    line += generateSpaces(maxPid + padding - p.Item1.Length);
                    line += p.Item2 + ",";
                    line += generateSpaces(maxName + padding - p.Item2.Length);
                    line += p.Item3;
                    output.Append(line + "\n");
                }

                console.Write(output.ToString());
            }
            if(this.options.Privilege != null)
            {
                var processes = TMProcess.GetAllProcesses();
                foreach(var proc in processes)
                {
                    try
                    {
                        var hProc = TMProcessHandle.FromProcess(proc, ProcessAccessFlags.QueryInformation);
                        var hToken = AccessTokenHandle.FromProcessHandle(hProc, TokenAccess.TOKEN_QUERY);
                        var privileges = AccessTokenPrivileges.FromTokenHandle(hToken);
                        foreach(var priv in privileges.GetPrivileges())
                        {
                            if(priv.Name.ToLower().Contains(this.options.Privilege.ToLower()))
                            {
                                var attrib = this.options.Disabled ? Constants.SE_PRIVILEGE_DISABLED : Constants.SE_PRIVILEGE_ENABLED;
                                if (priv.Attributes == attrib)
                                {
                                    console.WriteLine($"FOUND: {proc.ProcessName} - {proc.ProcessId}");
                                }
                            }
                        }
                    }
                    catch
                    {

                    }
                }
            }
        }

        private string generateSpaces(int number)
        {
            string ret = "";
            for (int i = 0; i < number; i++)
                ret += " ";
            return ret;
        }
    }
}
