using System;
using System.Collections.Generic;
using System.Text;

namespace TokenManage.Exceptions
{
    class AdjustTokenPrivilegeException : Exception
    {
        public AdjustTokenPrivilegeException(string message) : base(message)
        {
        }
    }
}
