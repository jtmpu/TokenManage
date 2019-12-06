using CommandLine;
using System;
using System.Collections.Generic;
using System.Text;

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

        public Info(InfoOptions options, ConsoleOutput console)
        {

        }

        public void Execute()
        {

        }
    }
}
