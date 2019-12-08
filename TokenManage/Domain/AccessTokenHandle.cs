using System;
using System.Collections.Generic;
using System.Linq;
using System.Text;
using TokenManage.Exceptions;

namespace TokenManage.Domain
{
    public enum TokenAccess
    {
        TOKEN_ASSIGN_PRIMARY = 0x0001,
        TOKEN_DUPLICATE = 0x0002,
        TOKEN_IMPERSONATE = 0x0004,
        TOKEN_QUERY = 0x0008,
        TOKEN_QUERY_SOURCE = 0x0010,
        TOKEN_ADJUST_PRIVILEGES = 0x0020,
        TOKEN_ADJUST_GROUPS = 0x0040,
        TOKEN_ADJUST_DEFAULT = 0x0080,
        TOKEN_ADJUST_SESSIONID = 0x0100,
        STANDARD_RIGHTS_REQUIRED = 0x000F0000,
        STANDARD_RIGHTS_READ = 0x00020000,
        TOKEN_READ = (STANDARD_RIGHTS_READ | TOKEN_QUERY),
        TOKEN_ALL_ACCESS = (STANDARD_RIGHTS_REQUIRED | TOKEN_ASSIGN_PRIMARY |
            TOKEN_DUPLICATE | TOKEN_IMPERSONATE | TOKEN_QUERY | TOKEN_QUERY_SOURCE |
            TOKEN_ADJUST_PRIVILEGES | TOKEN_ADJUST_GROUPS | TOKEN_ADJUST_DEFAULT |
            TOKEN_ADJUST_SESSIONID)
}

    public class AccessTokenHandle
    {
        private readonly TokenAccess[] tokenAccess;
        private IntPtr handle;


        private AccessTokenHandle(IntPtr handle, params TokenAccess[] access)
        {
            this.handle = handle;
            this.tokenAccess = access;
        }

        ~AccessTokenHandle()
        {
            if (!WinInterop.CloseHandle(handle))
                Logger.GetInstance().Error($"Failed to remove access token handle.");
        }

        public bool OpenedWithAccess(TokenAccess access)
        {
            return this.tokenAccess.Contains(access);
        }

        public IntPtr GetHandle()
        {
            return handle;
        }

        public static AccessTokenHandle FromProcessHandle(TMProcessHandle process, params TokenAccess[] desiredAccess)
        {
            var defaultAccess = TokenAccess.TOKEN_ALL_ACCESS;
            uint combinedAccess = (uint)defaultAccess;
            if(desiredAccess.Length > 0)
                combinedAccess = (uint)(new List<TokenAccess>(desiredAccess).Aggregate((x,y) => x | y));

            IntPtr tokenHandle;

            Logger.GetInstance().Debug($"Attemping to open handle to process access token.");
            if(!WinInterop.OpenProcessToken(process.Handle, combinedAccess, out tokenHandle))
            {
                Logger.GetInstance().Error($"Failed to retrieve handle to processes access token.");
                throw new OpenProcessTokenException();
            }
            Logger.GetInstance().Debug($"Successfully opened handle to process access token.");


            if (desiredAccess.Length > 0)
                return new AccessTokenHandle(tokenHandle, desiredAccess);
            else
                return new AccessTokenHandle(tokenHandle, defaultAccess);
        }

        public static AccessTokenHandle FromLogin(
            string username, 
            string password, 
            string domain, 
            LogonType logonType = LogonType.LOGON32_LOGON_INTERACTIVE, 
            LogonProvider logonProvider = LogonProvider.LOGON32_PROVIDER_DEFAULT)
        {

            IntPtr hToken;
            Logger.GetInstance().Debug($"Authenticating with {domain}\\{username}");
            if (!WinInterop.LogonUser(username, domain, password, (int)logonType, (int)logonProvider, out hToken))
            {
                Logger.GetInstance().Error($"Authentication failed for user {domain}\\{username}. LogonUser failed with error code: {WinInterop.GetLastError()}");
                throw new AuthenticationFailedException($"Failed to authenticate user {domain}\\{username}. LogonUser failed with error code: {WinInterop.GetLastError()}");
            }
            else
            {
                Logger.GetInstance().Debug($"Successfully authenticated {domain}\\{username}");
            }

            return new AccessTokenHandle(hToken, TokenAccess.TOKEN_ALL_ACCESS);
        }

        public static AccessTokenHandle Duplicate(AccessTokenHandle originalToken, SECURITY_IMPERSONATION_LEVEL impersonationLevel, 
            TOKEN_TYPE tokenType, params TokenAccess[] desiredAccess)
        {
            var defaultAccess = TokenAccess.TOKEN_ALL_ACCESS;
            uint combinedAccess = (uint)defaultAccess;
            if (desiredAccess.Length > 0)
                combinedAccess = (uint)(new List<TokenAccess>(desiredAccess).Aggregate((x, y) => x | y));

            SECURITY_ATTRIBUTES secAttr = new SECURITY_ATTRIBUTES();
            IntPtr newToken;
            Logger.GetInstance().Debug($"Attempting to duplicate token.");
            if (!WinInterop.DuplicateTokenEx(originalToken.GetHandle(), combinedAccess, ref secAttr, impersonationLevel, tokenType, out newToken))
            {
                Logger.GetInstance().Error($"Failed to duplicate token. DuplicateTokenEx failed with error code: {WinInterop.GetLastError()}");
                throw new DuplicateTokenException();
            }
            Logger.GetInstance().Debug($"Successfully duplicated token.");

            if (desiredAccess.Length > 0)
                return new AccessTokenHandle(newToken, desiredAccess);
            else
                return new AccessTokenHandle(newToken, defaultAccess);
        }

        /// <summary>
        /// Retrieves a handle to the primary token connected to a session ID.
        /// </summary>
        /// <param name="sessionId"></param>
        /// <returns></returns>
        public static AccessTokenHandle FromSessionId(uint sessionId)
        {
            IntPtr hToken;
            if(!WinInterop.WTSQueryUserToken(sessionId, out hToken))
            {
                Logger.GetInstance().Error($"Failed to retrieve the primary access token for session '{sessionId}'. WTSQueryUserToken failed with error: {WinInterop.GetLastError()}");
                throw new OpenProcessTokenException();
            }
            return new AccessTokenHandle(hToken, TokenAccess.TOKEN_ALL_ACCESS);
        }
    }
}
