using System;
using System.Collections.Generic;
using System.Net.Sockets;
using System.Threading;

namespace Rebex.Proxy
{
	/// <summary>
	/// Main TLS Proxy class.
	/// </summary>
	public class TlsProxy : IDisposable
	{
		private const string TLS_PROXY_RUNNING = "TLS Proxy is already running.";
		private const string TLS_PROXY_NOT_RUNNING = "TLS Proxy is not running.";
		private const string TLS_PROXY_STOPPING = "TLS Proxy is currently being stopped.";

		private const int MAX_CONNECTIONS = 50;

		private readonly object _sync;
		private readonly IProxySettings _settings;
		private readonly ProxyBinding[] _bindings;
		private readonly Dictionary<int, Socket> _listeners;
		private readonly Dictionary<int, Tunnel> _tunnels;

		private CancellationTokenSource _cancellation;
		private bool _isClosed;

		public bool IsRunning { get { return _cancellation != null; } }

		public ILogWriter LogWriter { get; set; }

		public TlsProxy(IProxySettings settings)
		{
			if (settings == null)
				throw new ArgumentNullException(nameof(settings));

			_sync = new object();
			_settings = settings;
			_bindings = settings.Bindings ?? new ProxyBinding[0];
			_listeners = new Dictionary<int, Socket>();
			_tunnels = new Dictionary<int, Tunnel>();
		}

		private void CheckDisposed()
		{
			if (_isClosed)
				throw new ObjectDisposedException(GetType().Name);
		}

		public void Start()
		{
			lock (_sync)
			{
				CheckDisposed();
				var cancellation = _cancellation;
				if (cancellation == null)
				{
					_cancellation = new CancellationTokenSource();
				}
				else if (cancellation.IsCancellationRequested)
				{
					throw new InvalidOperationException(TLS_PROXY_STOPPING);
				}
				else
				{
					throw new InvalidOperationException(TLS_PROXY_RUNNING);
				}
			}

			foreach (var binding in _bindings)
			{
				StartListener(binding, _cancellation.Token);
			}
		}

		public void Stop()
		{
			lock (_sync)
			{
				CheckDisposed();
				var cancellation = _cancellation;
				if (cancellation == null)
				{
					throw new InvalidOperationException(TLS_PROXY_NOT_RUNNING);
				}
				else if (cancellation.IsCancellationRequested)
				{
					throw new InvalidOperationException(TLS_PROXY_STOPPING);
				}
				else
				{
					cancellation.Cancel();
				}
			}

			StopProxy();
		}

		void IDisposable.Dispose()
		{
			lock (_sync)
			{
				if (_isClosed)
					return;
				_isClosed = true;

				var cancellation = _cancellation;
				if (cancellation == null || cancellation.IsCancellationRequested)
					return;
				cancellation.Cancel();
			}

			StopProxy();
		}

		private void StopProxy()
		{
			try
			{
				Log(LogLevel.Info, "Stopping proxy ...");

				foreach (var listener in _listeners.Values)
				{
					try { listener.Close(); }
					catch { } // we are stopping TLS proxy, we don't need to process close exceptions
				}
				_listeners.Clear();

				lock (_sync)
				{
					foreach (var tunnel in _tunnels.Values)
					{
						try { tunnel.Close(fast: true); }
						catch { } // we are stopping TLS proxy, we don't need to process close exceptions
					}
					_tunnels.Clear();
				}
			}
			finally
			{
				_cancellation = null;

				Log(LogLevel.Info, "Proxy stopped.");
			}
		}

		private void StartListener(ProxyBinding binding, CancellationToken cancellation)
		{
			var listener = new Socket(AddressFamily.InterNetwork, SocketType.Stream, ProtocolType.Tcp);

			_listeners.Add(binding.SourcePort, listener);

			Log(LogLevel.Info, "Listening at {0} (forwarding to {1}) ...", binding.Source, binding.Target);

			listener.Bind(binding.Source);
			listener.Listen(MAX_CONNECTIONS);

			var acceptCallback = GetAcceptSocketCallback(listener, binding, cancellation);
			listener.BeginAccept(acceptCallback, null);
		}

		private AsyncCallback GetAcceptSocketCallback(Socket listener, ProxyBinding binding, CancellationToken cancellation)
		{
			AsyncCallback callback = null;
			callback = ar =>
			{
				Socket socket = null;
				try
				{
					socket = listener.EndAccept(ar);
				}
				catch (ObjectDisposedException ex)
				{
					if (!cancellation.IsCancellationRequested)
					{
						Log(LogLevel.Error, "Error while accepting connection: {0}", ex);
					}
					return;
				}
				finally
				{
					if (!cancellation.IsCancellationRequested)
					{
						listener.BeginAccept(callback, null);
					}
				}

				int tunnelId = 0;
				try
				{
					StartTunnel(socket, binding, cancellation, out tunnelId);
				}
				catch (Exception ex)
				{
					if (!cancellation.IsCancellationRequested)
					{
						if (tunnelId > 0)
							Log(LogLevel.Error, "Error while starting tunnel({1}): {0}", ex, tunnelId);
						else
							Log(LogLevel.Error, "Error while starting tunnel: {0}", ex);
					}
				}
			};
			return callback;
		}

		private void StartTunnel(Socket inboundSocket, ProxyBinding binding, CancellationToken cancellation, out int tunnelId)
		{
			bool close = true;
			Tunnel tunnel = null;
			try
			{
				Log(LogLevel.Debug, "Connection from {0} accepted on {1}.", inboundSocket.RemoteEndPoint, inboundSocket.LocalEndPoint);

				tunnel = new Tunnel(binding, _settings, LogWriter, cancellation);
				tunnelId = tunnel.Id;
				tunnel.OnClosing = id =>
				{
					if (!cancellation.IsCancellationRequested)
					{
						lock (_sync)
						{
							_tunnels.Remove(id);
						}
					}
				};

				tunnel.Open(inboundSocket, _settings);
				inboundSocket = null;

				tunnel.Start();

				lock (_sync)
				{
					if (!cancellation.IsCancellationRequested)
					{
						_tunnels.Add(tunnel.Id, tunnel);
						close = false;
					}
				}
			}
			finally
			{
				if (inboundSocket != null)
					inboundSocket.Close();

				if (close && tunnel != null)
					tunnel.Close(fast: true);
			}
		}

		private void Log(LogLevel level, string format, params object[] args)
		{
			var log = LogWriter;
			if (log != null)
			{
				Log(level, string.Format(format, args));
			}
		}

		private void Log(LogLevel level, string message)
		{
			var log = LogWriter;
			if (log != null)
			{
				log.Write(level, typeof(TlsProxy), 0, "INFO", message);
			}
		}
	}
}
