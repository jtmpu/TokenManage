using System;
using System.Collections.Generic;
using System.Runtime.InteropServices;
using System.Text;
using TokenManage.Exceptions;

namespace TokenManage.Domain.AccessTokenInfo
{
    public class AccessTokenSessionId
    {
        public int SessionId { get; }

        private AccessTokenSessionId(int sessionId)
        {
            this.SessionId = sessionId;
        }

        public static AccessTokenSessionId FromTokenHandle(AccessTokenHandle handle)
        {
            uint tokenInfLength = 0;
            bool success;

            IntPtr hToken = handle.GetHandle();

            success = WinInterop.GetTokenInformation(hToken, TOKEN_INFORMATION_CLASS.TokenSessionId, IntPtr.Zero, tokenInfLength, out tokenInfLength);
            IntPtr tokenInfo = Marshal.AllocHGlobal(Convert.ToInt32(tokenInfLength));
            success = WinInterop.GetTokenInformation(hToken, TOKEN_INFORMATION_CLASS.TokenSessionId, tokenInfo, tokenInfLength, out tokenInfLength);
            
            Int32 sessionId = -1;
            if (success)
            {
                sessionId = Marshal.ReadInt32(tokenInfo);
            }
            else
            {
                Logger.GetInstance().Error($"Failed to retreive session id information for access token. GetTokenInformation failed with error: {WinInterop.GetLastError()}");
                throw new TokenInformationException();
            }

            Marshal.FreeHGlobal(tokenInfo);

            return new AccessTokenSessionId(sessionId);
        }

        public static AccessTokenSessionId FromValue(int sessionId)
        {
            return new AccessTokenSessionId(sessionId);
        }

        public static void SetTokenSessionId(AccessTokenSessionId sessionId, AccessTokenHandle handle)
        {
            var sessionIdPtr = Marshal.AllocHGlobal(4);
            Marshal.Copy(BitConverter.GetBytes(sessionId.SessionId), 0, sessionIdPtr, 4);
            if (!WinInterop.SetTokenInformation(handle.GetHandle(), TOKEN_INFORMATION_CLASS.TokenSessionId, sessionIdPtr, 4))
            {
                Logger.GetInstance().Error($"Failed to set session id to: {sessionId.SessionId}. SetTokenInformation failed with error code: {WinInterop.GetLastError()}");
                throw new TokenInformationException();
            }
        }
    }
}
