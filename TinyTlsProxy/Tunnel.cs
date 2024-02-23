using System;
using System.Net;
using System.Net.Sockets;
using System.Threading;
using Rebex.Net;
using Rebex.Security.Certificates;

namespace Rebex.Proxy
{
	/// <summary>
	/// Represents tunnel between client (inbound connection) and server (outbound connection).
	/// </summary>
	public class Tunnel
	{
		private const int BUFFER_SIZE = 64 * 1024;
		private static readonly TimeSpan CLOSE_TIMEOUT = TimeSpan.FromSeconds(5);
		private static readonly TimeSpan CLOSE_FAST_TIMEOUT = TimeSpan.FromMilliseconds(500);

		private static int _nextId;

		private readonly object _sync;
		private readonly int _id;
		private readonly CancellationToken _cancellation;
		private readonly TunnelLogWriter _logger;

		private IDataProvider _inbound;
		private IDataProvider _outbound;
		private ManualResetEventSlim _inForwarder;
		private ManualResetEventSlim _outForwarder;
		private bool _isClosed;

		private bool IsStopped { get { return _isClosed || _cancellation.IsCancellationRequested; } }

		public int Id { get { return _id; } }

		public Action<int> OnClosing { get; set; }

		public ProxyBinding Binding { get; private set; }

		public EndPoint InboundEndpoint { get; private set; }

		public EndPoint OutboundEndpoint { get; private set; }

		public Tunnel(ProxyBinding binding, ILogWriter logWriter, CancellationToken cancellationToken)
		{
			Binding = binding ?? throw new ArgumentNullException(nameof(binding));

			_sync = new object();
			_id = Interlocked.Increment(ref _nextId);
			_logger = (logWriter != null) ? new TunnelLogWriter(logWriter, Id) : null;
			_cancellation = cancellationToken;
		}

		public void Open(Socket inboundSocket, int timeout, CertificateChain serverCertificate)
		{
			InboundEndpoint = inboundSocket.RemoteEndPoint;
			
			string insecurity = (Binding.InboundTlsVersions == TlsVersion.None) ? "unsecure" : Binding.InboundTlsVersions.ToString().Replace(" ", "");
			string outsecurity = (Binding.OutboundTlsVersions == TlsVersion.None) ? "unsecure" : Binding.OutboundTlsVersions.ToString().Replace(" ", "");

			Log(LogLevel.Info,
				$"Starting tunnel ({InboundEndpoint}) --'{insecurity}'--> ({Binding.SourcePort}) --'{outsecurity}'--> ({Binding.Target}).");

			var inbound = new TlsServerSocket(inboundSocket);
			_inbound = new TlsSocketDataProvider(inbound, BUFFER_SIZE);

			inbound.LogWriter = _logger.GetSpecific("IN");
			inbound.Timeout = timeout;
			inbound.Parameters.Version = Binding.InboundTlsVersions;
			inbound.Parameters.Entity = TlsConnectionEnd.Server;
			inbound.Parameters.Certificate = serverCertificate;

			if (Binding.InboundTlsVersions != TlsVersion.None)
			{
				inbound.Negotiate();
			}

			var outbound = new TlsClientSocket();
			_outbound = (Binding.BindingType == BindingType.ToSMTP)
				? (IDataProvider)new SmtpExplicitDataProvider(outbound, BUFFER_SIZE)
				: (IDataProvider)new TlsSocketDataProvider(outbound, BUFFER_SIZE);

			outbound.LogWriter = _logger.GetSpecific("OUT");
			outbound.Timeout = timeout;
			outbound.Parameters.Version = Binding.OutboundTlsVersions;
			outbound.Parameters.Entity = TlsConnectionEnd.Client;
			outbound.Connect(Binding.Target);
			OutboundEndpoint = _outbound.RemoteEndpoint;

			if (Binding.OutboundTlsVersions != TlsVersion.None && Binding.BindingType != BindingType.ToSMTP)
			{
				outbound.Negotiate();
			}

			Log(LogLevel.Debug, $"Tunnel established ({InboundEndpoint}) --'{insecurity}'--> ({Binding.SourcePort}) --'{outsecurity}'--> ({OutboundEndpoint}).");
		}

		public void Close(bool fast)
		{
			lock (_sync)
			{
				if (_isClosed)
					return;

				_isClosed = true;
			}

			Log(LogLevel.Info, "Closing tunnel ({0}) --({1})--> ({2}).", InboundEndpoint, Binding.SourcePort, OutboundEndpoint ?? Binding.Target);

			try
			{
				_inbound?.Close(_inForwarder, fast ? CLOSE_FAST_TIMEOUT : CLOSE_TIMEOUT);
			}
			catch (Exception ex)
			{
				Log(LogLevel.Debug, "Error while closing inbound tunnel: {0}", ex);
			}

			try
			{
				_outbound?.Close(_outForwarder, fast ? CLOSE_FAST_TIMEOUT : CLOSE_TIMEOUT);
			}
			catch (Exception ex)
			{
				Log(LogLevel.Debug, "Error while closing outbound tunnel: {0}", ex);
			}

			try { _inForwarder?.Dispose(); }
			catch { }

			try { _outForwarder?.Dispose(); }
			catch { }

			OnClosing?.Invoke(Id);

			Log(LogLevel.Debug, "Tunnel from {0} closed.", InboundEndpoint);
		}

		public void Start()
		{
			if (!IsStopped)
			{
				_inbound.BeginReceive(GetReadCallback(_inbound, _outbound, "IN --> OUT", _inForwarder = new ManualResetEventSlim(false)));
				_outbound.BeginReceive(GetReadCallback(_outbound, _inbound, "IN <-- OUT", _outForwarder = new ManualResetEventSlim(false)));
			}
		}

		private AsyncCallback GetReadCallback(IDataProvider reader, IDataProvider writer, string direction, ManualResetEventSlim forwarderDone)
		{
			AsyncCallback callback = null;
			callback = ar =>
			{
				bool close = true;
				try
				{
					int readCount = reader.EndReceive(ar);
					if (readCount == 0 || IsStopped)
						return;

					Log(LogLevel.Debug, "Forwarding {0} {1} bytes.", direction, readCount);

					writer.Send(reader.Buffer, 0, readCount);

					reader.BeginReceive(callback);

					close = false;
				}
				catch (SocketException ex)
				{
					if (!IsStopped && ex.SocketErrorCode != SocketError.TimedOut)
					{
						Log(LogLevel.Error, ex.ToString());
					}
				}
				catch (TlsException ex)
				{
					if (!IsStopped && ex.Status != NetworkSessionExceptionStatus.Timeout)
					{
						Log(LogLevel.Error, ex.ToString());
					}
				}
				catch (Exception ex)
				{
					if (!IsStopped)
					{
						Log(LogLevel.Error, ex.ToString());
					}
				}
				finally
				{
					if (close)
					{
						try { forwarderDone.Set(); }
						catch { }
						Log(LogLevel.Debug, "Forwarding {0} finished.", direction);
						Close(fast: false);
					}
				}
			};
			return callback;
		}

		private void Log(LogLevel level, string format, params object[] args)
		{
			var log = _logger;
			if (log != null)
			{
				Log(level, string.Format(format, args));
			}
		}

		private void Log(LogLevel level, string message)
		{
			var log = _logger;
			if (log != null)
			{
				try { log.Write(level, typeof(Tunnel), Id, "INFO", message); }
				catch { }
			}
		}

		private class TunnelLogWriter : LogWriterBase
		{
			readonly ILogWriter _logger;
			readonly int _id;
			readonly string _area;

			public TunnelLogWriter(ILogWriter logger, int tunnelId, string area = null)
			{
				_logger = logger ?? throw new ArgumentNullException(nameof(logger));
				Level = logger.Level;
				_id = tunnelId;
				_area = area;
			}

			public override void Write(LogLevel level, Type objectType, int objectId, string area, string message)
			{
				_logger.Write(level, typeof(Tunnel), _id, _area ?? area, message);
			}

			public override void Write(LogLevel level, Type objectType, int objectId, string area, string message, byte[] buffer, int offset, int length)
			{
				_logger.Write(level, typeof(Tunnel), _id, _area ?? area, message, buffer, offset, length);
			}

			public TunnelLogWriter GetSpecific(string area)
			{
				return new TunnelLogWriter(_logger, _id, area);
			}
		}
	}
}
