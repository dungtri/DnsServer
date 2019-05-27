using System;

namespace DnsServerCore
{
    public class InvalidTokenDnsWebServiceException : DnsWebServiceException
    {
        #region constructors

        public InvalidTokenDnsWebServiceException()
            : base()
        { }

        public InvalidTokenDnsWebServiceException(string message)
            : base(message)
        { }

        public InvalidTokenDnsWebServiceException(string message, Exception innerException)
            : base(message, innerException)
        { }

        protected InvalidTokenDnsWebServiceException(System.Runtime.Serialization.SerializationInfo info, System.Runtime.Serialization.StreamingContext context)
            : base(info, context)
        { }

        #endregion
    }
}