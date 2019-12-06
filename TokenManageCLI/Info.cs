using CommandLine;
using TokenManage;
using System;
using System.Collections.Generic;
using System.Text;
using System.Linq;

namespace TokenManageCLI
{
    [Verb("info", HelpText = "Retrieve information about access tokens")]
    public class InfoOptions : BaseOptions
    {

        [Option('l', "list", Required = false, HelpText = "List all available access tokens")]
        public bool ListTokens { get; set; }

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
                var processes = TMProcess.GetAllProcesses();
                StringBuilder output = new StringBuilder();
                int padding = 2;
                int maxName = 0;
                int maxPid = 0;
                int maxUser = 0;
                foreach (TMProcess p in processes)
                {
                    maxName = Math.Max(maxName, p.GetProcessName().Length);
                    maxPid = Math.Max(maxPid, p.GetProcessID().ToString().Length);
                    maxUser = Math.Max(maxUser, p.GetProcessTokenUser().Length);
                }

                string name = "PROCESS";
                string pid = "PID";
                string user = "USER";

                output.Append(pid + "," + generateSpaces(maxPid + padding - pid.Length));
                output.Append(name + "," + generateSpaces(maxName + padding - name.Length));
                output.Append(user + "\n");

                var sorted = processes.OrderBy(x => x.GetProcessID()).ToList();
                foreach (TMProcess p in sorted)
                {
                    string line = "";
                    line += p.GetProcessID().ToString() +  ",";
                    line += generateSpaces(maxPid + padding - p.GetProcessID().ToString().Length);
                    line += p.GetProcessName() + ",";
                    line += generateSpaces(maxName + padding - p.GetProcessName().Length);
                    line += p.GetProcessTokenUser();
                    output.Append(line + "\n");
                }

                console.Write(output.ToString());
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
