// ------------------------------------------------------------------------------
// Copyright (c) 2014 Microsoft Corporation
// 
// Permission is hereby granted, free of charge, to any person obtaining a copy
//  of this software and associated documentation files (the "Software"), to deal
//  in the Software without restriction, including without limitation the rights
//  to use, copy, modify, merge, publish, distribute, sublicense, and/or sell
//  copies of the Software, and to permit persons to whom the Software is
//  furnished to do so, subject to the following conditions:
// 
// The above copyright notice and this permission notice shall be included in
//  all copies or substantial portions of the Software.
// 
// THE SOFTWARE IS PROVIDED "AS IS", WITHOUT WARRANTY OF ANY KIND, EXPRESS OR
//  IMPLIED, INCLUDING BUT NOT LIMITED TO THE WARRANTIES OF MERCHANTABILITY,
//  FITNESS FOR A PARTICULAR PURPOSE AND NONINFRINGEMENT. IN NO EVENT SHALL THE
//  AUTHORS OR COPYRIGHT HOLDERS BE LIABLE FOR ANY CLAIM, DAMAGES OR OTHER
//  LIABILITY, WHETHER IN AN ACTION OF CONTRACT, TORT OR OTHERWISE, ARISING FROM,
//  OUT OF OR IN CONNECTION WITH THE SOFTWARE OR THE USE OR OTHER DEALINGS IN
//  THE SOFTWARE.
// ------------------------------------------------------------------------------

using System.Security;

namespace Microsoft.Live
{
    using System;
    using System.Collections.Generic;
    using System.Diagnostics;
    using System.Globalization;
    using System.Linq;
    using System.Text;
    using System.Threading.Tasks;
    using System.Web;
    
    /// <summary>
    /// LiveAuthClientCore class provides the core implementation of authentication/authorization logic
    /// behind the public LiveAuthClient class
    /// </summary>
    internal class LiveAuthClientCore
    {
        private readonly LiveAuthClient publicAuthClient;
        private readonly string clientId;
        private readonly IRefreshTokenHandler refreshTokenHandler;
        private LiveLoginResult loginStatus;
        private RefreshTokenInfo refreshTokenInfo;
        private TaskCompletionSource<LiveLoginResult> initTask;
        private TaskCompletionSource<LiveConnectSession> codeExchangeTask;
        private IEnumerable<string> initScopes;
        private LiveAuthClient.ClientLog m_cll;

        public void RegisterClientLog(LiveAuthClient.ClientLog cll)
        {
            m_cll = cll;
            Log(null, "LiveAuthClientCore(RegisterClientLog)");
        }

        void Log(object crid, string s)
        {
            if (m_cll != null)
                m_cll(crid, s);
        }

        /// <summary>
        /// Initializes a new instance of the LiveAuthClientCore class.
        /// </summary>
        public LiveAuthClientCore(
            string clientId,
            IRefreshTokenHandler refreshTokenHandler,
            LiveAuthClient authClient)
        {
            Debug.Assert(!string.IsNullOrEmpty(clientId));
            Debug.Assert(authClient != null);

            this.clientId = clientId;
            this.refreshTokenHandler = refreshTokenHandler;
            this.publicAuthClient = authClient;
        }

        /// <summary>
        /// Initializes the LiveAuthClient instance by trying to retrieve an access token using refresh token
        /// provided by the app via the IRefreshTokenHandler instance.
        /// </summary>
        public Task<LiveLoginResult> InitializeAsync(IEnumerable<string> scopes, object crid)
        {
            // We don't allow InitializeAsync or ExchangeAuthCodeAsync to be invoked concurrently.
            if (this.initTask != null)
                {
                Log(crid, "concurrent calls to InitializeAsync and ExchangeAuthCodeAsync");
                throw new InvalidOperationException(ErrorText.ExistingAuthTaskRunning);
            }

            var task = new TaskCompletionSource<LiveLoginResult>();
            this.initTask = task;
            this.initScopes = scopes;

            if (this.loginStatus != null)
                {
                Log(this.loginStatus.CorrelationID, "Already have loginStatus; calling OnInitCompleted. This is a PAIRED LOG. PART 1: Existing CorrelationID");
                Log(crid, "Already have loginStatus; calling OnInitCompleted. This is a PAIRED LOG. PART 2: New CorrelationID");
                // We have a result already, then return this one.
                this.OnInitCompleted(null);
            }
            else
            {
                this.loginStatus = new LiveLoginResult(LiveConnectSessionStatus.Unknown, null);
                this.loginStatus.CorrelationID = crid;
                this.TryRefreshToken(crid);
            }

            return task.Task;
        }

        /// <summary>
        /// Exchange authentication code for access token.
        /// </summary>
        /// <param name="AuthenticationCode">The authentication code the app received from Microsoft authorization server during user authentication and authorization process.</param>
        /// <returns></returns>
        public Task<LiveConnectSession> ExchangeAuthCodeAsync(string authenticationCode, object crid)
        {
            Debug.Assert(!string.IsNullOrEmpty(authenticationCode));

            // We don't allow InitializeAsync or ExchangeAuthCodeAsync to be invoked concurrently.
            if (this.codeExchangeTask != null)
            {
                throw new InvalidOperationException(ErrorText.ExistingAuthTaskRunning);
            }

            this.codeExchangeTask = new TaskCompletionSource<LiveConnectSession>();

            this.ExchangeCodeForToken(authenticationCode, crid);

            return this.codeExchangeTask.Task;
        }
        
        /// <summary>
        /// Generates a consent URL that includes a set of provided parameters.
        /// </summary>
        public string GetLoginUrl(IEnumerable<string> scopes, string redirectUrl, DisplayType display, ThemeType theme, string locale, string state)
        {
            return LiveAuthUtility.BuildAuthorizeUrl(this.clientId, redirectUrl, scopes, ResponseType.Code, display, theme, locale, state);
        }

        internal bool CanRefreshToken
        {
            get
            {
                return this.refreshTokenHandler != null;
            }
        }

        internal void TryRefreshToken(object crid)
        {
            this.TryRefreshToken(null, crid);
        }


        internal void TryRefreshToken(Action<LiveLoginResult> completionCallback, object crid)
        {
            Log(crid, "Entering TryRefreshToken");

            LiveLoginResult result = new LiveLoginResult(LiveConnectSessionStatus.Unknown, null);
            result.CorrelationID = crid;

            if (this.refreshTokenHandler != null)
            {
                if (this.refreshTokenInfo == null)
                    {
                    Log(crid, "Need to retrieve refresh token");
                    this.refreshTokenHandler.RetrieveRefreshTokenAsync().ContinueWith(t =>
                    {
                        this.refreshTokenInfo = t.Result;
                        this.RefreshToken(completionCallback, crid);

                    });
                    return;
                }

                this.RefreshToken(completionCallback, crid);
                return;
            }

            this.OnRefreshTokenCompleted(result, completionCallback);
        }

        private void RefreshToken(Action<LiveLoginResult> completionCallback, object crid)
        {
            Log(crid, "RefreshToken ENTER");

            if (this.refreshTokenInfo != null)
                {
                Log(crid, "Calling RefreshTokenAsync");
                LiveAuthRequestUtility.RefreshTokenAsync(
                        this.clientId,
                        null,
                        LiveAuthUtility.BuildDesktopRedirectUrl(),
                        this.refreshTokenInfo.RefreshToken,
                        null /*scopes*/,
                        m_cll,
                        crid
                    ).ContinueWith(t =>
                    {
                        this.OnRefreshTokenCompleted(t.Result, completionCallback);
                    });
            }
            else
            {
                LiveLoginResult result = new LiveLoginResult(LiveConnectSessionStatus.Unknown, null);
                result.CorrelationID = crid;
                this.OnRefreshTokenCompleted(result, completionCallback);
            }
        }

        private void OnRefreshTokenCompleted(LiveLoginResult result, Action<LiveLoginResult> completionCallback)
        {
            Log(result?.CorrelationID, "OnRefreshTokenCompleted ENTER");
            if (completionCallback != null)
            {
                Log(result?.CorrelationID, "About to UpdateSession");
                this.UpdateSession(result);
                Log(result?.CorrelationID, "About to call completionCallback");
                completionCallback(result);
            }
            else
                {
                Log(result?.CorrelationID, "completionCallback == null");
                this.OnInitCompleted(result);
            }
        }

        private void UpdateSession(LiveLoginResult result)
        {
            Debug.Assert(result != null);

            if (result.Session != null)
            {
                // Set the AuthClient that is needed when refreshing a token.
                result.Session.AuthClient = this.publicAuthClient;

                // We have a new session, update the public property
                this.loginStatus = result;
                this.publicAuthClient.Session = result.Session;

                if (this.refreshTokenHandler != null &&
                    !string.IsNullOrEmpty(result.Session.RefreshToken))
                {
                    RefreshTokenInfo refreshInfo = new RefreshTokenInfo(result.Session.RefreshToken);
                    this.refreshTokenHandler.SaveRefreshTokenAsync(refreshInfo);
                }
            }
            else if (this.loginStatus.Status == LiveConnectSessionStatus.Unknown && 
                result.Status == LiveConnectSessionStatus.NotConnected)
            {
                this.loginStatus = result;
            }
        }

        private void OnInitCompleted(LiveLoginResult authResult)
        {
            Log(authResult?.CorrelationID, "OnInitCompleted");
            authResult = this.ValidateSessionInitScopes(authResult);
            Log(authResult?.CorrelationID, "Calling updatesession");
            this.UpdateSession(authResult);

            Debug.Assert(this.loginStatus != null);
            Log(authResult?.CorrelationID, "Firing Pending PropertyChanged events");
            this.publicAuthClient.FirePendingPropertyChangedEvents();
            

            if (authResult != null && authResult.Error != null)
            {
                Log(authResult?.CorrelationID, String.Format("error: {0}", authResult.Error.Message));
                this.initTask.SetException(authResult.Error);
            }
            else
            {
                Log(authResult?.CorrelationID, "Setting result for loginstatus");
                this.initTask.SetResult(this.loginStatus);
            }

            this.initTask = null;
        }

        private LiveLoginResult ValidateSessionInitScopes(LiveLoginResult loginResult)
        {
            if (loginResult.Session != null && this.initScopes != null)
            {
                if (!LiveAuthUtility.IsSubsetOfScopeRange(this.initScopes, loginResult.Session.Scopes))
                {
                    loginResult = new LiveLoginResult(LiveConnectSessionStatus.NotConnected, null);
                }

                this.initScopes = null;
            }

            return loginResult;
        }

        private void ExchangeCodeForToken(string authorizationCode, object crid)
        {
            Task<LiveLoginResult> task = LiveAuthRequestUtility.ExchangeCodeForTokenAsync(
                this.clientId, 
                null, 
                LiveAuthUtility.BuildDesktopRedirectUrl(), 
                authorizationCode,
                crid);
            task.ContinueWith((Task<LiveLoginResult> t) =>
                {
                t.Result.CorrelationID = crid;
                this.OnExchangeCodeCompleted(t.Result);
            });
        }

        private void OnExchangeCodeCompleted(LiveLoginResult authResult)
        {
            this.UpdateSession(authResult);

            Debug.Assert(this.loginStatus != null);
            this.publicAuthClient.FirePendingPropertyChangedEvents();
            if (authResult != null && authResult.Error != null)
            {
                this.codeExchangeTask.SetException(authResult.Error);
            }
            else
            {
                this.codeExchangeTask.SetResult(authResult.Session);
            }

            this.codeExchangeTask = null;
        }        
    }
}
