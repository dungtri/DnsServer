using DnsServer.Core.Net.Dns;

namespace DnsServer.Core
{
    public class ResolverPrefetchDnsCache : ResolverDnsCache
    {
        #region variables

        readonly DnsQuestionRecord _prefetchQuery;

        #endregion

        #region constructor

        public ResolverPrefetchDnsCache(Zone cacheZoneRoot, DnsQuestionRecord prefetchQuery)
            : base(cacheZoneRoot)
        {
            _prefetchQuery = prefetchQuery;
        }

        #endregion

        #region public

        public override DnsDatagram Query(DnsDatagram request)
        {
            if (_prefetchQuery.Equals(request.Question[0]))
                return _cacheZoneRoot.QueryCacheGetClosestNameServers(request); //return closest name servers so that the recursive resolver queries them to refreshes cache instead of returning response from cache

            return _cacheZoneRoot.Query(request);
        }

        #endregion
    }
}