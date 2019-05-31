using System;
using Xunit;

namespace DnsServer.Tests
{
    public class DnsServerTests
    {
        [Fact]
        public void Test1()
        {
            var server = new Core.DnsServer();
        }
    }
}
