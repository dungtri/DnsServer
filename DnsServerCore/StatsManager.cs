using System;
using System.Net;
using DnsServer.Core.Net.Dns;

namespace DnsServer.Core
{
    public enum StatsResponseType
    {
        NoError = 0,
        ServerFailure = 1,
        NameError = 2,
        Refused = 3,
        Blocked = 4
    }

    public class StatsManager : IDisposable
    {
        #region variables

        readonly LogManager _log;

        const int MAINTENANCE_TIMER_INITIAL_INTERVAL = 60000;
        const int MAINTENANCE_TIMER_INTERVAL = 60000;

        #endregion

        #region constructor

        public StatsManager(LogManager log)
        {
            _log = log;
        }

        #endregion

        #region IDisposable

        private bool _disposed = false;
        private readonly object _disposeLock = new object();

        protected virtual void Dispose(bool disposing)
        {
            lock (_disposeLock)
            {
                if (_disposed)
                    return;

                if (disposing)
                {
                    // TODO: Dispose resources

                }

                _disposed = true;
            }
        }

        public void Dispose()
        {
            Dispose(true);
        }

        #endregion

        
        #region public

        public void Update(DnsDatagram response, IPAddress clientIpAddress)
        {
            StatsResponseType responseType;
            bool cacheHit;

            if ("blocked".Equals(response.Tag))
            {
                responseType = StatsResponseType.Blocked;
                cacheHit = true;
            }
            else
            {
                switch (response.Header.RCODE)
                {
                    case DnsResponseCode.NoError:
                        responseType = StatsResponseType.NoError;
                        break;

                    case DnsResponseCode.ServerFailure:
                        responseType = StatsResponseType.ServerFailure;
                        break;

                    case DnsResponseCode.NameError:
                        responseType = StatsResponseType.NameError;
                        break;

                    case DnsResponseCode.Refused:
                        responseType = StatsResponseType.Refused;
                        break;

                    default:
                        return;
                }

                cacheHit = ("cacheHit".Equals(response.Tag));
            }

            if (response.Header.QDCOUNT > 0)
                Update(response.Question[0], responseType, cacheHit, clientIpAddress);
            else
                Update(new DnsQuestionRecord("", DnsResourceRecordType.ANY, DnsClass.IN), responseType, cacheHit, clientIpAddress);
        }

        public void Update(DnsQuestionRecord query, StatsResponseType responseType, bool cacheHit, IPAddress clientIpAddress)
        {
            // TODO:
        }

        #endregion
    }
}
