namespace DnsServerCore.Configuration
{
    public class CachePrefetch
    {
        public int Eligibility { get; set; }
        public int Trigger { get; set; }
        public int SampleIntervalInMinutes { get; set; }
        public int SampleEligibilityHitsPerHour { get; set; }
    }
}