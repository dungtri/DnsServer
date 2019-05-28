using System;

namespace DnsServerCore
{
    public class DnsServiceException : Exception
    {
        #region constructors

        public DnsServiceException()
            : base()
        { }

        public DnsServiceException(string message)
            : base(message)
        { }

        public DnsServiceException(string message, Exception innerException)
            : base(message, innerException)
        { }

        protected DnsServiceException(System.Runtime.Serialization.SerializationInfo info, System.Runtime.Serialization.StreamingContext context)
            : base(info, context)
        { }

        #endregion
    }
}