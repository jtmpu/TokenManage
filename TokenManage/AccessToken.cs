using System;
using System.Collections.Generic;
using System.Text;

namespace TokenManage
{
    public class AccessToken
    {
        private IntPtr hToken;

        public AccessToken(IntPtr hToken)
        {
            this.hToken = hToken;
        }


    }
}
