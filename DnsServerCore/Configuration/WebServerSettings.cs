using System;
using System.Collections.Generic;
using System.Text;

namespace DnsServerCore.Configuration
{
    public class WebServerSettings
    {
        public int Port { get; set; }

        public WebServerSettings()
        {
            Port = 5380;
        }
    }
}
