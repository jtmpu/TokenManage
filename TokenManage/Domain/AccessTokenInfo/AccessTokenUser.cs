using System;
using System.Collections.Generic;
using System.Runtime.InteropServices;
using System.Text;
using TokenManage.API;

namespace TokenManage.Domain.AccessTokenInfo
{
    public class AccessTokenUser
    {
        public string User { get; }

        private AccessTokenUser(string user)
        {
            this.User = user;
        }

        public static AccessTokenUser FromTokenHandle(AccessTokenHandle handle)
        {
            uint tokenInfLength = 0;
            bool success;

            IntPtr hToken = handle.GetHandle();

            success = Advapi32.GetTokenInformation(hToken, TOKEN_INFORMATION_CLASS.TokenUser, IntPtr.Zero, tokenInfLength, out tokenInfLength);
            IntPtr tokenInfo = Marshal.AllocHGlobal(Convert.ToInt32(tokenInfLength));
            success = Advapi32.GetTokenInformation(hToken, TOKEN_INFORMATION_CLASS.TokenUser, tokenInfo, tokenInfLength, out tokenInfLength);

            var accessTokenUser = "";
            if (success)
            {
                TOKEN_USER tokenUser = (TOKEN_USER)Marshal.PtrToStructure(tokenInfo, typeof(TOKEN_USER));
                int length = Convert.ToInt32(Advapi32.GetLengthSid(tokenUser.User.Sid));
                byte[] sid = new byte[length];
                Marshal.Copy(tokenUser.User.Sid, sid, 0, length);

                StringBuilder sbUser = new StringBuilder();
                uint cchName = (uint)sbUser.Capacity;
                StringBuilder sbDomain = new StringBuilder();
                uint cchReferencedDomainName = (uint)sbDomain.Capacity;
                SID_NAME_USE peUse;
                if (Advapi32.LookupAccountSid(null, sid, sbUser, ref cchName, sbDomain, ref cchReferencedDomainName, out peUse))
                {
                    accessTokenUser = $"{sbDomain.ToString()}\\{sbUser.ToString()}";
                }
                else
                {
                    Logger.GetInstance().Error($"Failed to retrieve user for access token. LookupAccountSid failed with error: {Kernel32.GetLastError()}");
                    accessTokenUser = "";
                }
            }
            else
            {
                Logger.GetInstance().Error($"Failed to retreive token information for access token. GetTokenInformation failed with error: {Kernel32.GetLastError()}");
            }

            Marshal.FreeHGlobal(tokenInfo);

            return new AccessTokenUser(accessTokenUser);
        }
    }
}
