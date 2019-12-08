using System;
using System.Collections.Generic;
using System.Runtime.InteropServices;
using System.Text;
using TokenManage.Exceptions;

namespace TokenManage.Domain.AccessTokenInfo
{
    public class AccessTokenLogonSid
    {
        private string[] sidStrings;
        private int[] sidAttributes;
        private IntPtr[] sidPtrs;

        private AccessTokenLogonSid(string[] sidStrings, int[] sidAttributes, IntPtr[] sidPtrs)
        {
            this.sidStrings = sidStrings;
            this.sidAttributes = sidAttributes;
            this.sidPtrs = sidPtrs;
        }

        public List<String> GetLogonSidStrings()
        {
            return new List<string>(sidStrings);
        }

        public List<int> GetLogonSidAttributes()
        {
            return new List<int>(sidAttributes);
        }

        public List<IntPtr> GetLogonSids()
        {
            return new List<IntPtr>(sidPtrs);
        }

        public Dictionary<String, int> GetLogonSidDict()
        {
            var ret = new Dictionary<string, int>();
            for(int i = 0; i < sidStrings.Length; i++)
            {
                ret.Add(sidStrings[i], sidAttributes[i]);
            }
            return ret;
        }

        /// <summary>
        /// Apparently, this cannot be done, and always returns the error
        /// code 87.
        /// </summary>
        /// <param name="logonSid"></param>
        /// <param name="handle"></param>
        public static void SetTokenLogonSid(AccessTokenLogonSid logonSid, AccessTokenHandle handle)
        {
            TOKEN_GROUPS tokenGroups = new TOKEN_GROUPS();
            var ptrs = logonSid.GetLogonSids();
            var attributes = logonSid.GetLogonSidAttributes();
            tokenGroups.GroupCount = (uint)ptrs.Count;
            tokenGroups.Groups = new SID_AND_ATTRIBUTES[tokenGroups.GroupCount];
            for(int i = 0; i < tokenGroups.GroupCount; i++)
            {
                tokenGroups.Groups[i] = new SID_AND_ATTRIBUTES();
                tokenGroups.Groups[i].Sid = ptrs[i];
                tokenGroups.Groups[i].Attributes = attributes[i];
            }

            var size = Marshal.SizeOf(tokenGroups);
            var tgPtr = Marshal.AllocHGlobal(size);
            Marshal.StructureToPtr(tokenGroups, tgPtr, true);

            if(!WinInterop.SetTokenInformation(handle.GetHandle(), TOKEN_INFORMATION_CLASS.TokenLogonSid, tgPtr, size))
            {
                Marshal.FreeHGlobal(tgPtr);
                Logger.GetInstance().Error($"Failed to set new logon sid for token. SetTokenInformation failed with error: {WinInterop.GetLastError()}");
                throw new TokenInformationException();
            }

            Marshal.FreeHGlobal(tgPtr);
        }

        public static AccessTokenLogonSid FromTokenHandle(AccessTokenHandle handle)
        {

            uint tokenInfLength = 0;
            bool success;

            IntPtr hToken = handle.GetHandle();

            success = WinInterop.GetTokenInformation(hToken, TOKEN_INFORMATION_CLASS.TokenLogonSid, IntPtr.Zero, tokenInfLength, out tokenInfLength);
            IntPtr tokenInfo = Marshal.AllocHGlobal(Convert.ToInt32(tokenInfLength));
            success = WinInterop.GetTokenInformation(hToken, TOKEN_INFORMATION_CLASS.TokenLogonSid, tokenInfo, tokenInfLength, out tokenInfLength);


            if (success)
            {
                TOKEN_GROUPS logonSid = (TOKEN_GROUPS)Marshal.PtrToStructure(tokenInfo, typeof(TOKEN_GROUPS));

                string[] sids = new string[logonSid.GroupCount];
                IntPtr[] sidPtrs = new IntPtr[logonSid.GroupCount];
                int[] attributes = new int[logonSid.GroupCount];

                for(int i = 0; i < logonSid.GroupCount; i++)
                {
                    string sidStr;
                    if(WinInterop.ConvertSidToStringSid(logonSid.Groups[i].Sid, out sidStr))
                    {
                        sids[i] = sidStr;
                    }
                    else
                    {
                        Logger.GetInstance().Error("Failed to retrieve SID-string for token LogonSession.");
                    }
                    sidPtrs[i] = logonSid.Groups[i].Sid;
                    attributes[i] = logonSid.Groups[i].Attributes;
                    Logger.GetInstance().Debug(sidStr);
                }
                Marshal.FreeHGlobal(tokenInfo);
                return new AccessTokenLogonSid(sids, attributes, sidPtrs);
            }
            else
            {
                Marshal.FreeHGlobal(tokenInfo);
                Logger.GetInstance().Error($"Failed to retreive session id information for access token. GetTokenInformation failed with error: {WinInterop.GetLastError()}");
                throw new TokenInformationException();
            }
        }
    }
}
