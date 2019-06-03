using System.Collections.Generic;
using DnsServer.Core.Net.Dns;

namespace DnsServer.Core
{
    public class ResolverDnsCache : DnsCache
    {
        const uint NEGATIVE_RECORD_TTL = 300u;
        const uint MINIMUM_RECORD_TTL = 0u;
        const uint SERVE_STALE_TTL = 7 * 24 * 60 * 60; //7 days serve stale ttl as per draft-ietf-dnsop-serve-stale-04

        #region variables

        protected readonly Zone _cacheZoneRoot;

        #endregion

        #region constructor

        public ResolverDnsCache(Zone cacheZoneRoot)
            : base(NEGATIVE_RECORD_TTL, MINIMUM_RECORD_TTL, SERVE_STALE_TTL)
        {
            _cacheZoneRoot = cacheZoneRoot;
        }

        #endregion

        #region public

        public override DnsDatagram Query(DnsDatagram request)
        {
            return _cacheZoneRoot.Query(request);
        }

        protected override void CacheRecords(ICollection<DnsResourceRecord> resourceRecords)
        {
            _cacheZoneRoot.SetRecords(resourceRecords);
        }

        #endregion
    }
}