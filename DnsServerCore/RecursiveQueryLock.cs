using DnsServer.Core.Net.Dns;

namespace DnsServer.Core
{
    public class RecursiveQueryLock
    {
        #region variables

        #endregion

        #region public

        public void SetComplete(DnsDatagram response)
        {
            if (!Complete)
            {
                Complete = true;
                Response = response;
            }
        }

        #endregion

        #region properties

        public bool Complete { get; private set; }

        public DnsDatagram Response { get; private set; }

        #endregion
    }
}