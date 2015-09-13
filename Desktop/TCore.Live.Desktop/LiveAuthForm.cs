using System;
using System.Collections.Generic;
using System.ComponentModel;
using System.Data;
using System.Drawing;
using System.Linq;
using System.Text;
using System.Threading.Tasks;
using System.Windows.Forms;
using TCore.Logging;

namespace TCore.Live.Desktop
{
    public delegate void AuthCompletedCallback(AuthResult result);


    public partial class LiveAuthForm : Form
    {
        private readonly string startUrl;
        private readonly string endUrl;
        private CorrelationID crid;
        private readonly AuthCompletedCallback callback;

        public LiveAuthForm(string startUrl, string endUrl, AuthCompletedCallback callback, CorrelationID crid)
        {
            this.startUrl = startUrl;
            this.endUrl = endUrl;
            this.callback = callback;
            this.crid = crid;
            InitializeComponent();
        }

        private void LiveAuthForm_Load(object sender, EventArgs e)
        {
            this.webBrowser.Navigated += WebBrowser_Navigated;
            this.webBrowser.Navigate(this.startUrl);

        }

        private void WebBrowser_Navigated(object sender, WebBrowserNavigatedEventArgs e)
        {
            if (this.webBrowser.Url.AbsoluteUri.StartsWith(this.endUrl))
                {
                if (this.callback != null)
                    {
                    this.callback(new AuthResult(this.webBrowser.Url, crid));
                    }
                }
        }
    }
}
