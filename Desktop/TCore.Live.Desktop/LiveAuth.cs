using System;
using System.Collections.Generic;
using System.ComponentModel;
using System.Linq;
using System.Reflection.Emit;
using System.Text;
using System.Threading.Tasks;
using System.Windows.Forms;
using System.Windows.Forms.VisualStyles;
using Microsoft.Live;
using Microsoft.Live.Operations;
using TCore.Logging;

namespace TCore.Live.Desktop
{
    public delegate void SessionChangedCallback(CorrelationID crid);
    public delegate void OnAuthComplete(bool fSuccess, string sError, CorrelationID crid, LiveConnectSession lcs);

    public class LiveUserInfo_Emails
    {
        private string m_sPreferred;
        private string m_sAccount;

        public string preferred { get { return m_sPreferred; } set { m_sPreferred = value; } }
        public string account { get { return m_sAccount; } set { m_sAccount = value; } }
    }

    public class LiveUserInfo
    {
        private string m_sId;
        private string m_sName;
        private string m_sFirstName;
        private string m_sLastName;
        private string m_sLink;
        private LiveUserInfo_Emails m_luie;

        public string id { get { return m_sId; } set { m_sId = value; } }
        public string name { get { return m_sName; } set { m_sName = value; } }
        public string first_name { get { return m_sFirstName; } set { m_sFirstName = value; } }
        public string last_name { get { return m_sLastName; } set { m_sLastName = value; } }
        public string link { get { return m_sLink; } set { m_sLink = value; } }
        public LiveUserInfo_Emails emails { get { return m_luie; } set { m_luie = value; } }
    }

    public class AuthResult
    {
        public AuthResult(Uri resultUri, CorrelationID crid)
        {
            string[] queryParams = resultUri.Query.TrimStart('?').Split('&');
            CorrelationIDFoo = crid;
            foreach (string param in queryParams)
                {
                string[] kvp = param.Split('=');
                switch (kvp[0])
                    {
                    case "code":
                        this.AuthorizeCode = kvp[1];
                        break;
                    case "error":
                        this.ErrorCode = kvp[1];
                        break;
                    case "error_description":
                        this.ErrorDescription = Uri.UnescapeDataString(kvp[1]);
                        break;
                    }
                }
        }

        public string AuthorizeCode { get; private set; }
        public string ErrorCode { get; private set; }
        public string ErrorDescription { get; private set; }
        public CorrelationID CorrelationIDFoo { get; set; }
    }

    public class LiveAuth : IRefreshTokenHandler
    {
        private LiveAuthForm m_lafSigninForm;
        private string m_sClientID;
        private LiveAuthClient liveAuthClient;
        private LiveConnectClient liveConnectClient;
        private RefreshTokenInfo m_oRefreshTokenInfo;
        private SessionChangedCallback m_scc;
        private LiveAuthClient.ClientLog m_cll;
        private List<string> m_plsAuthScopes;

        public void RegisterClientLog(LiveAuthClient.ClientLog cll)
        {
            m_cll = cll;
            LogSz(null, "LiveAuth(RegisterClientLog)");
            liveAuthClient?.RegisterClientLog(m_cll);
        }

        void LogSz(object crid, string s)
        {
            m_cll?.Invoke(crid, s);
        }

        public void RegisterSessionChangedCallback(SessionChangedCallback scc)
        {
            m_scc = scc;
        }

        public bool IsLoggedIn()
        {
            if (AuthSession == null)
                return false;

            return true;
        }

        public async Task<LiveUserInfo> CurrentUserAsync(object crid)
        {
            if (!IsLoggedIn())
                return null;

            LiveOperationResult rslt = await liveConnectClient.GetAsync("me", crid);
            dynamic meData = rslt.Result;

            LiveUserInfo lui = new LiveUserInfo();
            lui.name = meData.name;
            lui.first_name = meData.first_name;
            lui.last_name = meData.last_name;
            lui.id = meData.id;
            lui.link = meData.link;
            lui.emails = new LiveUserInfo_Emails();
            lui.emails.account = meData.emails.account;
            lui.emails.preferred = meData.emails.preferred;

            return lui;
        }
        private LiveAuthClient AuthClient
        {
            get
                {
                if (liveAuthClient == null)
                    {
                    this.AuthClient = new LiveAuthClient(m_sClientID, this);
                    this.AuthClient.RegisterClientLog(m_cll);
                    }

                return this.liveAuthClient;
                }
            set
                {
                if (this.liveAuthClient != null)
                    {
                    this.liveAuthClient.PropertyChanged -= this.liveAuthClient_PropertyChanged;
                    }

                this.liveAuthClient = value;
                this.liveAuthClient.RegisterClientLog(m_cll);

                if (this.liveAuthClient != null)
                    {
                    this.liveAuthClient.PropertyChanged += this.liveAuthClient_PropertyChanged;
                    }

                this.liveConnectClient = null;
                }
        }

        public LiveConnectSession AuthSession
        {
            get
                {
                return this.AuthClient.Session;
                }
        }

        private void liveAuthClient_PropertyChanged(object sender, PropertyChangedEventArgs e)
        {
            if (e.PropertyName == "Session")
                {
                if (m_scc != null)
                    m_scc(null); // sadly I don't have a correlation ID to propagate throught he propertychanged events...hopefully we don't see many of these!
                }
        }

        public LiveAuth(string sClientID)
        {
            m_sClientID = sClientID;
            m_plsAuthScopes = new List<string>();
            m_plsAuthScopes.Add("wl.signin");
            m_plsAuthScopes.Add("wl.offline_access");
        }

        public void AddAuthScopes(string[] rgs)
        {
            m_plsAuthScopes.AddRange(rgs);
        }

        public void AddAuthScopes(string s)
        {
            m_plsAuthScopes.Add(s);
        }

        private OnAuthComplete m_oac;

        void OnAuthFormClosed(object sender, FormClosedEventArgs e)
        {
            CleanupAuthForm();
        }

        public void StartSignin(OnAuthComplete oac, CorrelationID crid)
        {
            if (m_lafSigninForm == null)
                {
                string sUrlStart = AuthClient.GetLoginUrl(m_plsAuthScopes.ToArray());
                string endUrl = "https://login.live.com/oauth20_desktop.srf";

                LogSz(crid, "StartSignin: InitializeAsync");

                Task<LiveLoginResult> tllr = AuthClient.InitializeAsync(m_plsAuthScopes.ToArray(), crid);

                LogSz(crid, "Executed InitializeAsync; Waiting for result.");
                try
                    {
                    tllr.Wait();
                    }
                catch
                    {
                    }
                if (tllr.Status == TaskStatus.RanToCompletion && tllr.Result.Status == LiveConnectSessionStatus.Connected)
                    {
                    LogSz(crid, "Wait complete, RanToComplete, Connected");
                    liveConnectClient = new LiveConnectClient(tllr.Result.Session);
                    oac(true, null, crid, liveConnectClient.Session);
                    return;
                    }
                LogSz(crid, String.Format("Wait complete, not connected: {0}, {1}", tllr.Status.ToString(),
                                    tllr.Result.Status.ToString()));

                m_oac = oac;
                m_lafSigninForm = new LiveAuthForm(
                    sUrlStart,
                    endUrl,
                    this.OnAuthCompleted,
                    crid);
                m_lafSigninForm .FormClosed += OnAuthFormClosed;
                m_lafSigninForm .ShowDialog();
                }
        }

        private WebBrowser m_wbSignOut;

        public void Signout(CorrelationID crid)
        {
            if (m_wbSignOut == null)
                {
                m_wbSignOut = new WebBrowser();
                m_wbSignOut.Location = new System.Drawing.Point(647, 22);
                m_wbSignOut.MinimumSize = new System.Drawing.Size(20, 20);
                m_wbSignOut.Name = "signOutWebBrowser";
                m_wbSignOut.Size = new System.Drawing.Size(26, 25);
                m_wbSignOut.TabIndex = 1;
                m_wbSignOut.Visible = false;
                }

            m_wbSignOut.Navigate(AuthClient.GetLogoutUrl());
            AuthClient = null;

            if (m_scc != null)
                m_scc(crid);
        }

        private void CleanupAuthForm()
        {
            if (m_lafSigninForm != null)
                {
                m_lafSigninForm.Dispose();
                m_lafSigninForm = null;
                m_oac = null;
                }
        }

        private void OnRefreshTokenOperationCompleted(LiveLoginResult result)
        {
            switch (result.Status)
            {
                case LiveConnectSessionStatus.Connected:
                    LogSz(result?.CorrelationID, "OnRefreshTokenOperationCompleted: new live connection client");
                    liveConnectClient = new LiveConnectClient(result.Session);
                    if (m_scc != null)
                        m_scc((CorrelationID)result?.CorrelationID); 
                    break;
                case LiveConnectSessionStatus.Unknown:
                    // Once we know the user is unknown, we clear the session and fail the operation. 
                    // On Windows Blue, the user may disconnect the Microsoft account. 
                    // We ensure we are not allowing app to continue to access user's data after the user disconnects the account.
                    LogSz(result?.CorrelationID, String.Format("OnRefreshTokenOperationCompleted: Unknown"));
                    liveConnectClient = null;
                    if (m_scc != null)
                        m_scc((CorrelationID)result?.CorrelationID); 
//                    var error = new LiveConnectException(ApiOperation.ApiClientErrorCode, ResourceHelper.GetString("UserNotLoggedIn"));
                    return;
            }

        }

        public bool Refresh(object crid)
        {
            if (liveAuthClient != null)
                return liveAuthClient.RefreshToken(OnRefreshTokenOperationCompleted, crid);
            
            return false;
        }

        private async void OnAuthCompleted(AuthResult result)
        {
            OnAuthComplete oac = m_oac;

            CleanupAuthForm();
            if (result.AuthorizeCode != null)
                {
                try
                    {
                    LiveConnectSession session = await this.AuthClient.ExchangeAuthCodeAsync(result.AuthorizeCode, result?.CorrelationIDFoo);
                    liveConnectClient = new LiveConnectClient(session);
                    LiveOperationResult meRs = await this.liveConnectClient.GetAsync("me", result.CorrelationIDFoo);
                    dynamic meData = meRs.Result;
                    // this.meNameLabel.Text = meData.name;

                    //LiveDownloadOperationResult meImgResult = await this.liveConnectClient.DownloadAsync("me/picture");
                    //this.mePictureBox.Image = Image.FromStream(meImgResult.Stream);
                    }
                catch (LiveAuthException aex)
                    {
                    if (oac != null)
                        oac(false, "Failed to retrieve access token. Error: " + aex.Message, result.CorrelationIDFoo, null);
                    return;
                    }
                catch (LiveConnectException cex)
                    {
                    if (oac != null)
                        oac(false, "Failed to retrieve the user's data. Error: " + cex.Message, result.CorrelationIDFoo, null);
                    return;
                    }
                if (oac != null)
                    oac(true, null, result.CorrelationIDFoo, liveConnectClient.Session);
                }
            else
                {
                if (oac != null)
                    oac(false, string.Format("Error received. Error: {0} Detail: {1}", result.ErrorCode,
                                             result.ErrorDescription), result.CorrelationIDFoo, null);
                }
        }

        public void SetRefreshToken(string sRefreshToken)
        {
            if (String.IsNullOrEmpty(sRefreshToken))
                {
                m_oRefreshTokenInfo = null;
                }
            else
                {
                m_oRefreshTokenInfo = new RefreshTokenInfo(sRefreshToken);
                }
        }

        public string RefreshToken { get { return m_oRefreshTokenInfo.RefreshToken; } }

        Task IRefreshTokenHandler.SaveRefreshTokenAsync(RefreshTokenInfo tokenInfo)
        {
            // Note: 
            // 1) In order to receive refresh token, wl.offline_access scope is needed.
            // 2) Alternatively, we can persist the refresh token.
            return Task.Factory.StartNew(() =>
            {
                this.m_oRefreshTokenInfo = tokenInfo;
            });
        }

        Task<RefreshTokenInfo> IRefreshTokenHandler.RetrieveRefreshTokenAsync()
        {
            return Task.Factory.StartNew<RefreshTokenInfo>(() =>
            {
                return this.m_oRefreshTokenInfo;
            });
        }
    }
}
