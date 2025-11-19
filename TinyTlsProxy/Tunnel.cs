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
		private readonly int _timeout;

		private IDataProvider _inbound;
		private IDataProvider _outbound;
		private ManualResetEventSlim _inForwarder;
		private ManualResetEventSlim _outForwarder;
		private Timer _timer;
		private bool _isClosed;

		private bool IsStopped { get { return _isClosed || _cancellation.IsCancellationRequested; } }

		public int Id { get { return _id; } }

		public Action<int> OnClosing { get; set; }

		public ProxyBinding Binding { get; private set; }

		public EndPoint InboundEndpoint { get; private set; }

		public EndPoint OutboundEndpoint { get; private set; }

		public Tunnel(ProxyBinding binding, IProxySettings settings, ILogWriter logWriter, CancellationToken cancellationToken)
		{
			Binding = binding ?? throw new ArgumentNullException(nameof(binding));

			_sync = new object();
			_id = Interlocked.Increment(ref _nextId);
			_logger = (logWriter != null) ? new TunnelLogWriter(logWriter, Id) : null;
			_cancellation = cancellationToken;
			_timeout = settings.TimeoutMilliseconds;
		}

		public void Open(Socket inboundSocket, IProxySettings settings)
		{
			InboundEndpoint = inboundSocket.RemoteEndPoint;

			string insecurity = (Binding.InboundTlsVersions == TlsVersion.None) ? "unsecure" : Binding.InboundTlsVersions.ToString().Replace(" ", "");
			string outsecurity = (Binding.OutboundTlsVersions == TlsVersion.None) ? "unsecure" : Binding.OutboundTlsVersions.ToString().Replace(" ", "");

			Log(LogLevel.Info,
				$"Starting tunnel ({InboundEndpoint}) --'{insecurity}'--> ({Binding.SourcePort}) --'{outsecurity}'--> ({Binding.Target}).");

			var sni = settings.SNI;
			bool preserveSNI = Binding.BindingType == BindingType.TLStoTLS && string.IsNullOrEmpty(sni);

			var inbound = new TlsServerSocket(inboundSocket);
			_inbound = new TlsSocketDataProvider(inbound, BUFFER_SIZE);

			inbound.LogWriter = _logger.GetSpecific("IN");
			inbound.Timeout = settings.TimeoutMilliseconds;
			inbound.Parameters.Version = Binding.InboundTlsVersions;
			inbound.Parameters.Entity = TlsConnectionEnd.Server;
			inbound.Parameters.Certificate = settings.ServerCertificate;
			if (settings.WeakCiphers)
			{
				inbound.Parameters.AllowedSuites |= TlsCipherSuite.Weak;
			}
			if (settings.InsecureCiphers)
			{
				inbound.Parameters.AllowedSuites |= TlsCipherSuite.Vulnerable;
				inbound.Parameters.AllowVulnerableSuites = true;
			}
			if (preserveSNI)
			{
				inbound.ClientHelloReceived += (s, e) =>
				{
					if (!string.IsNullOrEmpty(e.ServerName))
						sni = e.ServerName;
				};
			}

			if (Binding.InboundTlsVersions != TlsVersion.None)
			{
				inbound.Negotiate();
			}

			var outbound = new TlsClientSocket();
			_outbound = (Binding.BindingType == BindingType.ToSMTP)
				? (IDataProvider)new SmtpExplicitDataProvider(outbound, BUFFER_SIZE)
				: (IDataProvider)new TlsSocketDataProvider(outbound, BUFFER_SIZE);

			outbound.LogWriter = _logger.GetSpecific("OUT");
			outbound.Timeout = settings.TimeoutMilliseconds;
			outbound.Parameters.Version = Binding.OutboundTlsVersions;
			outbound.Parameters.Entity = TlsConnectionEnd.Client;
			if (settings.WeakCiphers)
			{
				outbound.Parameters.AllowedSuites |= TlsCipherSuite.Weak;
			}
			if (settings.InsecureCiphers)
			{
				outbound.Parameters.AllowedSuites |= TlsCipherSuite.Vulnerable;
				outbound.Parameters.AllowVulnerableSuites = true;
			}
			if (!string.IsNullOrEmpty(sni))
			{
				outbound.Parameters.CommonName = sni;
			}
			if (settings.ValidationOptions != ProxyValidationOptions.None)
			{
				outbound.ValidatingCertificate += (s, e) =>
				{
					if (settings.ValidationOptions.HasFlag(ProxyValidationOptions.AcceptAll))
					{
						LogWithArea(LogLevel.Info, "OUT", $"!!! Skipping certificate validation !!!");
						e.Accept();
					}
					else
					{
						ValidationOptions op = 0;
						if (settings.ValidationOptions.HasFlag(ProxyValidationOptions.SkipRevCheck))
							op |= ValidationOptions.SkipRevocationCheck;
						if (settings.ValidationOptions.HasFlag(ProxyValidationOptions.IgnoreTimeCheck))
							op |= ValidationOptions.IgnoreTimeNotValid;
						LogWithArea(LogLevel.Debug, "OUT", $"Applying certificate validation options ({op}).");
						var r = e.CertificateChain.Validate(e.ServerName, op);
						if (r.Valid)
							e.Accept();
						else
							e.Reject(r.Status);
					}
				};
			}

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

			try { _timer?.Dispose(); }
			catch { }

			try { _inbound?.Shutdown(); }
			catch (Exception ex)
			{
				Log(LogLevel.Debug, "Error while shutting down inbound tunnel: {0}", ex);
			}

			try { _outbound?.Shutdown(); }
			catch (Exception ex)
			{
				Log(LogLevel.Debug, "Error while shutting down outbound tunnel: {0}", ex);
			}

			// give forwarder routine chance to finish before closing the socket forcefully
			try { _inForwarder?.Wait(fast ? CLOSE_FAST_TIMEOUT : CLOSE_TIMEOUT); } catch { }
			try { _outForwarder?.Wait(fast ? CLOSE_FAST_TIMEOUT : CLOSE_TIMEOUT); } catch { }

			try { _inbound?.Close(); }
			catch (Exception ex)
			{
				Log(LogLevel.Debug, "Error while closing inbound tunnel: {0}", ex);
			}

			try { _outbound?.Close(); }
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
				_inbound.Timeout = Timeout.Infinite;
				_outbound.Timeout = Timeout.Infinite;
				_timer = new Timer(TimerTick, null, _timeout, period: Timeout.Infinite);
				_inbound.BeginReceive(GetReadCallback(_inbound, _outbound, "IN --> OUT", _inForwarder = new ManualResetEventSlim(false)));
				_outbound.BeginReceive(GetReadCallback(_outbound, _inbound, "IN <-- OUT", _outForwarder = new ManualResetEventSlim(false)));
			}
		}

		private void TimerTick(object state)
		{
			if (IsStopped)
				return;

			Log(LogLevel.Info, "Tunnel timed out.");
			Close(fast: false);
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

					// data received, reschedule timeout
					_timer.Change(_timeout, period: Timeout.Infinite);

					Log(LogLevel.Debug, "Forwarding {0} {1} bytes.", direction, readCount);

					writer.Send(reader.Buffer, 0, readCount);

					reader.BeginReceive(callback);

					close = false;
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
				LogWithArea(level, "INFO", message);
			}
		}

		private void LogWithArea(LogLevel level, string area, string message)
		{
			var log = _logger;
			if (log != null)
			{
				try { log.Write(level, typeof(Tunnel), Id, area, message); }
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
