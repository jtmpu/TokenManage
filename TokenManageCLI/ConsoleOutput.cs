using System;
using TokenManage;
using System.Collections.Generic;
using System.Text;

namespace TokenManageCLI
{
    public class ConsoleOutput : IOutput
    {
        private bool verbose;
        private bool quiet;
        private bool debug;

        public ConsoleOutput(BaseOptions opts)
        {
            this.verbose = opts.Verbose;
            this.quiet = opts.Quiet;
            this.debug = opts.Debug;
        }

        public void Write(string message)
        {
            if (!this.quiet)
                Console.Write(message);
        }
        public void WriteLine(string message)
        {
            if (!this.quiet)
                Console.WriteLine(message);
        }

        public void Log(LogLevel level, string msg)
        {
            switch (level)
            {
                case LogLevel.INFO:
                    if (this.debug || this.verbose)
                        this.WriteLine("[+] INFO: " + msg);
                    break;
                case LogLevel.ERROR:
                    this.WriteLine("[!] ERROR: " + msg);
                    break;
                case LogLevel.DEBUG:
                    if (this.debug)
                        this.WriteLine("[+] DEBUG: " + msg);
                    break;
            }
        }

        public void Error(string msg)
        {
            this.Log(LogLevel.ERROR, msg);
        }

        public void Debug(string msg)
        {
            this.Log(LogLevel.DEBUG, msg);
        }

        public void Info(string msg)
        {
            this.Log(LogLevel.INFO, msg);
        }
    }
}
