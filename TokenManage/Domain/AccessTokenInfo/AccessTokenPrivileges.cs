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

                    privs.Add(ATPrivilege.FromValues(privilegeName, laa.Attributes));
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

        public static void AdjustTokenPrivileges(AccessTokenHandle hToken, AccessTokenPrivileges privileges)
        {
            AdjustTokenPrivileges(hToken, privileges.GetPrivileges());
        }

        /// <summary>
        /// Attempts to adjust the specified token's privileges. Only a list of the privileges which
        /// should be changed need to be specified.
        /// Throws an exceptions if the access token privilege adjustment fails.
        /// </summary>
        /// <param name="handle"></param>
        /// <param name="newPrivileges"></param>
        public static void AdjustTokenPrivileges(AccessTokenHandle hToken, List<ATPrivilege> newPrivileges)
        {
            if (newPrivileges.Count == 0)
                return;

            TOKEN_PRIVILEGES tpNew = new TOKEN_PRIVILEGES();
            tpNew.PrivilegeCount = newPrivileges.Count;
            tpNew.Privileges = new LUID_AND_ATTRIBUTES[newPrivileges.Count];
            for(int i = 0; i < newPrivileges.Count; i++)
            {
                LUID luid;
                if (!Advapi32.LookupPrivilegeValue(null, newPrivileges[i].Name, out luid))
                {
                    var msg = $"Failed to lookup LUID for {newPrivileges[i].Name}. LookupPrivilegeValue failed with error: {Kernel32.GetLastError()}";
                    Logger.GetInstance().Error(msg);
                    throw new AdjustTokenPrivilegeException(msg);
                }
                tpNew.Privileges[i] = new LUID_AND_ATTRIBUTES();
                tpNew.Privileges[i].Luid = luid;
                tpNew.Privileges[i].Attributes = newPrivileges[i].Attributes;
            }

            if (!Advapi32.AdjustTokenPrivileges(hToken.GetHandle(), false, ref tpNew, 0, IntPtr.Zero, IntPtr.Zero))
            {
                var msg = $"Failed to adjust token privileges. AdjustTokenPrivileges failed with error: {Kernel32.GetLastError()}";
                Logger.GetInstance().Error(msg);
                throw new AdjustTokenPrivilegeException(msg);
            }

            var err = Kernel32.GetLastError();
            if(err == Constants.ERROR_NOT_ALL_ASSIGNED)
            {
                Logger.GetInstance().Error("Not all privileges or groups referenced are assigned to the caller.");
            }
        }
    }

    public class ATPrivilege
    {
        public string Name { get; }
        public uint Attributes { get; }

        private ATPrivilege(string name, uint attributes)
        {
            this.Name = name;
            this.Attributes = attributes;
        }

        public bool IsEnabled()
        {
            return this.Attributes == Constants.SE_PRIVILEGE_ENABLED;
        }

        public static ATPrivilege FromValues(string name, uint attributes)
        {
            return new ATPrivilege(name, attributes);
        }
    }
}
