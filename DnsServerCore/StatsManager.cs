/*
Technitium DNS Server
Copyright (C) 2019  Shreyas Zare (shreyas@technitium.com)

This program is free software: you can redistribute it and/or modify
it under the terms of the GNU General Public License as published by
the Free Software Foundation, either version 3 of the License, or
(at your option) any later version.

This program is distributed in the hope that it will be useful,
but WITHOUT ANY WARRANTY; without even the implied warranty of
MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
GNU General Public License for more details.

You should have received a copy of the GNU General Public License
along with this program.  If not, see <http://www.gnu.org/licenses/>.

*/

using System;
using System.Collections.Concurrent;
using System.Collections.Generic;
using System.IO;
using System.Net;
using System.Text;
using System.Threading;
using TechnitiumLibrary.IO;
using TechnitiumLibrary.Net;
using TechnitiumLibrary.Net.Dns;

namespace DnsServerCore
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
