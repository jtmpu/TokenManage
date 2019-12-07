using System;
using System.Collections.Generic;
using System.Text;

namespace TokenManage.Exceptions
{
    public class OpenProcessException : Exception
    {
        public OpenProcessException(string message) : base(message)
        {
        }
    }
}
