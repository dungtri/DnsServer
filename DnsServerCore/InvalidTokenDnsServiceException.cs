using System;

namespace DnsServer.Core
{
    public class InvalidTokenDnsServiceException : DnsServiceException
    {
        #region constructors

        public InvalidTokenDnsServiceException()
            : base()
        { }

        public InvalidTokenDnsServiceException(string message)
            : base(message)
        { }

        public InvalidTokenDnsServiceException(string message, Exception innerException)
            : base(message, innerException)
        { }

        protected InvalidTokenDnsServiceException(System.Runtime.Serialization.SerializationInfo info, System.Runtime.Serialization.StreamingContext context)
            : base(info, context)
        { }

        #endregion
    }
}