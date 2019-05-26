using System;
using System.Collections.Generic;
using System.Net;

namespace DnsServerCore.Configuration
{
    public class DnsSettings
    {
        public string ServerDomain { get; set; }
        public IPAddress[] LocalAddresses { get; set; }
        public bool AllowRecursion { get; set; }
        public bool AllowRecursionOnlyForPrivateNetworks { get; set; }
        public bool LogEnabled { get; set; }
        public bool LogQueryEnabled { get; set; }
        public bool PreferIPv6 { get; set; }
        
        public CachePrefetch CachePrefetch { get; set; }

        public Proxy Proxy { get; set; }
        public List<Uri> BlockListUrls { get; set; }


        // TODO: Forwarders

        public bool EnableDnsOverHttp { get; set; }
        public bool EnableDnsOverTls { get; set; }
        public bool EnableDnsOverHttps { get; set; }

        public DnsSettings()
        {
            ServerDomain = Environment.MachineName.ToLower();

            LocalAddresses = new IPAddress[] { IPAddress.Any, IPAddress.IPv6Any };

        }
    }
}
