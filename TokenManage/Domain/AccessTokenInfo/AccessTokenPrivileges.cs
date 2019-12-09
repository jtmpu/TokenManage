using System;
using System.Collections.Generic;
using System.Runtime.InteropServices;
using System.Text;
using TokenManage.API;
using TokenManage.Exceptions;

namespace TokenManage.Domain.AccessTokenInfo
{
    public class AccessTokenPrivileges
    {
        private List<ATPrivilege> privileges;

        private AccessTokenPrivileges(List<ATPrivilege> privileges)
        {
            this.privileges = privileges;
        }

        public List<ATPrivilege> GetPrivileges()
        {
            return this.privileges;
        }

        public static AccessTokenPrivileges FromTokenHandle(AccessTokenHandle handle)
        {
            uint tokenInfLength = 0;
            bool success;

            IntPtr hToken = handle.GetHandle();

            success = Advapi32.GetTokenInformation(hToken, TOKEN_INFORMATION_CLASS.TokenPrivileges, IntPtr.Zero, tokenInfLength, out tokenInfLength);
            IntPtr tokenInfo = Marshal.AllocHGlobal(Convert.ToInt32(tokenInfLength));
            success = Advapi32.GetTokenInformation(hToken, TOKEN_INFORMATION_CLASS.TokenPrivileges, tokenInfo, tokenInfLength, out tokenInfLength);

            if (success)
            {
                var parsedGroups = new List<ATGroup>();

                TOKEN_PRIVILEGES privileges = (TOKEN_PRIVILEGES)Marshal.PtrToStructure(tokenInfo, typeof(TOKEN_PRIVILEGES));

                var sidAndAttrSize = Marshal.SizeOf(new LUID_AND_ATTRIBUTES());
                var privs = new List<ATPrivilege>();
                for (int i = 0; i < privileges.PrivilegeCount; i++)
                {
                    var laa = (LUID_AND_ATTRIBUTES)Marshal.PtrToStructure(new IntPtr(tokenInfo.ToInt64() + i * sidAndAttrSize + 4), typeof(LUID_AND_ATTRIBUTES));

                    var pname = new StringBuilder();
                    int luidNameLen = 0;
                    IntPtr ptrLuid = Marshal.AllocHGlobal(Marshal.SizeOf(laa.Luid));
                    Marshal.StructureToPtr(laa.Luid, ptrLuid, true);

                    // Get length of name.
                    Advapi32.LookupPrivilegeName(null, ptrLuid, null, ref luidNameLen);
                    pname.EnsureCapacity(luidNameLen);

                    var privilegeName = "";
                    if(!Advapi32.LookupPrivilegeName(null, ptrLuid, pname, ref luidNameLen))
                    {
                        Logger.GetInstance().Error($"Failed to lookup privilege name. LookupPrivilegeName failed with error: {Kernel32.GetLastError()}");
                        privilegeName = "UNKNOWN";
                    }
                    else
                    {
                        privilegeName = pname.ToString();
                    }
                    Marshal.FreeHGlobal(ptrLuid);

                    privs.Add(new ATPrivilege(privilegeName, laa.Attributes));
                }


                Marshal.FreeHGlobal(tokenInfo);

                return new AccessTokenPrivileges(privs);
            }
            else
            {
                Marshal.FreeHGlobal(tokenInfo);
                Logger.GetInstance().Error($"Failed to retreive session id information for access token. GetTokenInformation failed with error: {Kernel32.GetLastError()}");
                throw new TokenInformationException();
            }
        }
    }

    public class ATPrivilege
    {
        public string Name { get; }
        public uint Attributes { get; }

        public ATPrivilege(string name, uint attributes)
        {
            this.Name = name;
            this.Attributes = attributes;
        }

        public bool IsEnabled()
        {
            return this.Attributes == Constants.SE_PRIVILEGE_ENABLED;
        }
    }
}
