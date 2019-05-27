using System;

namespace DnsServerCore
{
    public class DnsWebServiceException : Exception
    {
        #region constructors

        public DnsWebServiceException()
            : base()
        { }

        public DnsWebServiceException(string message)
            : base(message)
        { }

        public DnsWebServiceException(string message, Exception innerException)
            : base(message, innerException)
        { }

        protected DnsWebServiceException(System.Runtime.Serialization.SerializationInfo info, System.Runtime.Serialization.StreamingContext context)
            : base(info, context)
        { }

        #endregion
    }
}