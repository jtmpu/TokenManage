using System;
using TokenManage;
using CommandLine;
using System.Collections.Generic;

namespace TokenManageCLI
{
    class Program
    {


        static int Main(string[] args)
        {
            return Parser.Default.ParseArguments<StartProcessOptions, InfoOptions>(args)
                .MapResult(
                (StartProcessOptions opts) => RunStartProcess(opts),
                (InfoOptions opts) => RunInfo(opts),
                errs => 1);
        }

        public static int RunStartProcess(StartProcessOptions opts)
        {
            ConsoleOutput co = new ConsoleOutput(opts);
            StartProcess startProcess = new StartProcess(opts, co);
            try
            {
                startProcess.Execute();
                return 0;
            }
            catch
            {
                return 1;
            }
        }

        public static int RunInfo(InfoOptions opts)
        {
            ConsoleOutput co = new ConsoleOutput(opts);
            Info info = new Info(opts, co);
            try
            {
                info.Execute();
                return 0;
            }
            catch
            {
                return 1;
            }
        }
    }
}
