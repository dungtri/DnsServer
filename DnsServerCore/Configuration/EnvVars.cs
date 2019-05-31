namespace DnsServer.Core.Configuration
{
    public static class EnvVars
    {
        private const string PREFIX = "DNS_";
        public const string CONFIG_FOLDER = PREFIX + nameof(CONFIG_FOLDER);
        public const string LOG_ENABLED = PREFIX + nameof(LOG_ENABLED);
        public const string LOG_QUERY_ENABLED = PREFIX + nameof(LOG_QUERY_ENABLED);
        public const string IPV6_ENABLED = PREFIX + nameof(IPV6_ENABLED);
    }
}