using System;
using System.Collections.Generic;
using System.Text;

namespace TokenManageCLI
{

    public enum LOG
    {
        INFO,
        DEBUG,
        ERROR
    }
    public class ConsoleOutput
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

        public void Log(LOG level, string msg)
        {
            switch (level)
            {
                case LOG.INFO:
                    if (this.debug || this.verbose)
                        this.WriteLine("[+] INFO: " + msg);
                    break;
                case LOG.ERROR:
                    this.WriteLine("[!] ERROR: " + msg);
                    break;
                case LOG.DEBUG:
                    if (this.debug)
                        this.WriteLine("[+] DEBUG: " + msg);
                    break;
            }
        }
    }
}
