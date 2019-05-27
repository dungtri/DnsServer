using System.Net;
using DnsServerCore.Net.Proxy;

namespace DnsServerCore.Configuration
{
    public class Proxy
    {
        public NetProxyType ProxyType { get; set; }
        public string Address { get; set; }
        public int Port { get; set; }
        public NetworkCredential Credential { get; set; }
    }
}