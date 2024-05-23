using System;
using System.Globalization;
using System.Net;
using Rebex.Net;

namespace Rebex.Proxy
{
	/// <summary>
	/// Available protocols.
	/// </summary>
	public enum BindingType
	{
		NoTLS = 0,
		TLStoTLS,
		FromTLS,
		ToTLS,
		ToSMTP,
	}

	/// <summary>
	/// Holds information about port binding.
	/// </summary>
	public class ProxyBinding
	{
		public BindingType BindingType { get; private set; }
		public TlsVersion InboundTlsVersions { get; private set; }
		public TlsVersion OutboundTlsVersions { get; private set; }
		public EndPoint Source { get; private set; }
		public EndPoint Target { get; private set; }

		public int SourcePort
		{
			get
			{
				var ip = Source as IPEndPoint;
				if (ip != null)
					return ip.Port;
				var dns = Source as DnsEndPoint;
				if (dns != null)
					return dns.Port;
				return 0;
			}
		}

		public ProxyBinding(BindingType type, int sourcePort, string targetAddress, int targetPort, TlsVersion inVersions, TlsVersion outVersions)
		{
			if (targetAddress == null)
				throw new ArgumentNullException(nameof(targetAddress));

			BindingType = type;
			Source = new IPEndPoint(IPAddress.Any, sourcePort);
			Target = new MyDnsEndPoint(targetAddress, targetPort);
			InboundTlsVersions = inVersions;
			OutboundTlsVersions = outVersions;
		}

		public void DisableTls13()
		{
			InboundTlsVersions &= ~TlsVersion.TLS13;
			OutboundTlsVersions &= ~TlsVersion.TLS13;
		}

		private class MyDnsEndPoint : DnsEndPoint
		{
			public MyDnsEndPoint(string host, int port)
				: base(host, port)
			{
			}

			public override string ToString()
			{
				return string.Format(CultureInfo.InvariantCulture, "{0}:{1}", Host, Port);
			}
		}
	}
}
