using System;
using System.Collections.Generic;
using System.Text;

namespace TokenManage.Exceptions
{
    public class AuthenticationFailedException : Exception
    {
        public AuthenticationFailedException(string message) : base(message)
        {
        }
    }
}
