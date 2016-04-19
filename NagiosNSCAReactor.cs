using System;
using System.Collections.Generic;
using System.Linq;
using System.Net;
using System.Timers;
using Nagios.NSCA.Client;
using Seq.Apps;
using Seq.Apps.LogEvents;

namespace Seq.App.NagiosNCSA
{
    [SeqApp("Nagios NSCA",
        Description = "Sends passive checks to Nagios using the NSCA protocol",
        AllowReprocessing = false)]
    public class NagiosNCSAReactor : Reactor, IDisposable, ISubscribeTo<LogEventData>
    {
        [SeqAppSetting(
            DisplayName = "Nagios Server Endpoint Address",
            HelpText = "The endpoint (IP address or DNS record) on which the Nagios server is listening for incoming NSCA messages.",
            InputType = SettingInputType.Text)]
        public string NagiosEndpoint { get; set; }

        [SeqAppSetting(
            DisplayName = "Nagios Server Endpoint Port",
            HelpText = "The port where the endpoint is listening. The default NSCA port is 5667.",
            InputType = SettingInputType.Integer)]
        public int NagiosEndpointPort { get; set; }

        [SeqAppSetting(
            DisplayName = "Hostname",
            HelpText = "The hostname that hosts the service in the Nagios configuration. This should correspond to the name of the host configured in Nagios.",
            InputType = SettingInputType.Text)]
        public string Hostname { get; set; }

        [SeqAppSetting(
            DisplayName = "Service Name",
            HelpText = "The name of the service. This should correspond to the name of the service configured in Nagios.",
            InputType = SettingInputType.Text)]
        public string ServiceName { get; set; }

        [SeqAppSetting(
            DisplayName = "NSCA Encryption Type",
            HelpText = "The encryption used by the NSCA endpoint. Currently supported encryption: None, Xor, TripleDES, Rijndael128, Rijndael192, Rijndael256",
            InputType = SettingInputType.Text)]
        public string NSCAEncryptionType { get; set; }

        [SeqAppSetting(
            DisplayName = "NSCA Password",
            HelpText = "The password that is being used to protect the NSCA endpoint",
            InputType = SettingInputType.Password,
            IsOptional = true)]
        public string NSCAPassword { get; set; }

        [SeqAppSetting(
            DisplayName = "Seq Error level is Nagios Critical level",
            HelpText = "If checked: if an event with level Error is received it will send a Critical level message to Nagios. If unchecked: if an event with level Error is received it will send a Warning level message to Nagios. (FYI: Seq warning = Nagios warning & Seq Fatal = Nagios Critical)",
            InputType = SettingInputType.Checkbox)]
        public bool ErrorIsCritical { get; set; }

        [SeqAppSetting(
            DisplayName = "Message Interval",
            HelpText = "The interval, in seconds, between sending messages to the endpoint. Nagios can be configured to fail if there has been no message from a passive check in x time, this option should be smaller than the freshness threshold configured for this check.",
            InputType = SettingInputType.Integer)]
        public int MessageInterval { get; set; }

        [SeqAppSetting(
            DisplayName = "Nagios Level On No Event",
            HelpText = "The level that should be send to Nagios when no event has been received within the interval. Supported Nagios levels: OK, Warning, Critical, Unknown",
            InputType = SettingInputType.Text)]
        public string LogLevelOnNoOkEvent { get; set; }


        [SeqAppSetting(
            DisplayName = "AutoRecovery Time",
            HelpText = "The time, in seconds, before sending an OK after a warning or worst log level has occurred.",
            InputType = SettingInputType.Integer)]
        public int AutoRecoveryTime { get; set; }

        [SeqAppSetting(
            DisplayName = "Debug Mode",
            HelpText = "Log to Seq to debug any problems with this App",
            InputType = SettingInputType.Checkbox)]
        public bool DebugMode { get; set; }

        private Timer _messageIntervalTimer;
        private readonly object _messageIntervalTimerLock = new object();

        private bool _eventReceivedDuringInterval = false;
        private readonly List<LogHistoryEntry> _history = new List<LogHistoryEntry>(); 

        private NSCAEncryptionType _encryptionType;
        private Level _logLevelOnNoOkEvent;

        protected override void OnAttached()
        {
            base.OnAttached();

            if (DebugMode) Log.Debug("Running OnAttach method. Trying to attach Nagios NSCA Reactor with the following settings: {NagiosEndpoint}, {NagiosEndpointPort}, {HostName}, {ServiceName}, {NSCAEncryptionType}, {HasPasswordSet}, {ErrorIsCritical}, {OKInterval}, {LogLevelOnNoOKEvent}, {AutoRecoveryTime}", NagiosEndpoint, NagiosEndpointPort, Hostname, ServiceName, NSCAEncryptionType, !String.IsNullOrWhiteSpace(NSCAPassword), ErrorIsCritical, MessageInterval, LogLevelOnNoOkEvent, AutoRecoveryTime);

            // Try to resolve the endpoint but don't actually save the result. 
            // We want to resolve the DNS for every log entry because this might be a very long lived application where a DNS change might occur
            try
            {
                var dnsResult = Dns.GetHostAddresses(NagiosEndpoint);
                if (!dnsResult.Any())
                {
                    throw new ArgumentException(String.Format("DNS entry ({0}) doesn't resolve to an IP address", NagiosEndpoint));
                }
                if (DebugMode) Log.Information("DNS hostname lookup of {NagiosEndpoint} resolves to {DnsResult}", NagiosEndpoint, dnsResult);
            }
            catch (Exception ex)
            {
                throw new ArgumentException(String.Format("The Nagios endpoint ({0}) could not be resolved to an IP address", NagiosEndpoint), ex);
            }

            if (!Enum.TryParse(NSCAEncryptionType, out _encryptionType))
                throw new ArgumentException(String.Format("Invalid NSCA Encryption Type: {0}! Please choose a supported encryption type! (See help text for supported encryption types)", NSCAEncryptionType));
            else
                if (DebugMode) Log.Information("{NSCAEncryptionType} parsed to {NSCAEncryptionTypeParsed}", NSCAEncryptionType, _encryptionType);

            if (!Enum.TryParse(LogLevelOnNoOkEvent, out _logLevelOnNoOkEvent))
                throw new ArgumentException("Invalid Nagios message level! Please choose a supported Nagios level! (See help text for supported Nagios levels)");
            else
                if (DebugMode) Log.Information("{LogLevelOnNoOkEvent} parsed to {LogLevelOnNoOkEventParsed}", LogLevelOnNoOkEvent, _logLevelOnNoOkEvent);

            if (MessageInterval < 1)
            {
                throw new ArgumentException("The OK Interval should be 1 or higher");
            }

            if (AutoRecoveryTime < 1)
            {
                throw new ArgumentException("The AutoRecoveryTime be 1 or higher");
            }

            if (DebugMode) Log.Information("Sending an OK message to Nagios to indicate successful initialization");
            ComposeAndSendNSCAMessage("Nagios NSCA Seq App is successfully initialized");

            if (DebugMode) Log.Information("Starting OK Interval timer with an interval of: {OkInterval} seconds", MessageInterval);

            lock (_messageIntervalTimerLock) {
                _messageIntervalTimer = new Timer(MessageInterval*1000);
                _messageIntervalTimer.Elapsed += OnMessageIntervalIntervalElapse;
                _messageIntervalTimer.AutoReset = false;
                _messageIntervalTimer.Start();
            }
        }

        public void On(Event<LogEventData> evt)
        {
            switch (evt.Data.Level)
            {
                case LogEventLevel.Verbose:
                case LogEventLevel.Debug:
                case LogEventLevel.Information:
                    OkTypeEventReceived(evt.Data);
                    break;
                case LogEventLevel.Warning:
                case LogEventLevel.Error:
                case LogEventLevel.Fatal:
                    NokTypeEventReceived(evt.Data);
                    break;
                default:
                    throw new ArgumentOutOfRangeException();
            }
        }

        private void OkTypeEventReceived(LogEventData evt)
        {
            _eventReceivedDuringInterval = true;
        }

        private void NokTypeEventReceived(LogEventData evt)
        {
            if (DebugMode) Log.Information("Received an event classified as NOT OK. {EventId} - {LogLevel}", evt.Id, evt.Level);

            lock (_messageIntervalTimerLock)
            {
                _messageIntervalTimer.Stop();
            }

            _eventReceivedDuringInterval = false;
            var message = String.Format("{0} - [{1}] - {2}", evt.LocalTimestamp, evt.Level, evt.RenderedMessage);
            var expirationTicks = DateTimeOffset.Now.AddSeconds(AutoRecoveryTime).Ticks;
            _history.Add(new LogHistoryEntry(expirationTicks, evt.Level, message));

            ComposeAndSendNSCAMessage();

            lock (_messageIntervalTimerLock)
            {
                _messageIntervalTimer.Start();
            }
        }

        private void OnMessageIntervalIntervalElapse(object sender, ElapsedEventArgs elapsedEventArgs)
        {
            if (DebugMode) Log.Information("The OK interval has been triggered. Has there been an OK event? {OkTypeEventReceivedDuringInterval}", _eventReceivedDuringInterval);

            lock (_messageIntervalTimerLock)
            {
                _messageIntervalTimer.Stop();
            }

            ComposeAndSendNSCAMessage();

            _eventReceivedDuringInterval = false;

            lock (_messageIntervalTimerLock)
            {
                _messageIntervalTimer.Start();
            }
        }

        //private void AutoRecoveryTimeElapsed(object sender, ElapsedEventArgs elapsedEventArgs)
        //{
        //    if (DebugMode) Log.Information("The AutoRecovery timer has expired.");

        //    lock (_messageIntervalTimerLock)
        //    {
        //        _messageIntervalTimer.Stop();
        //    }

        //    ComposeAndSendNSCAMessage(String.Format("It has been {0} seconds since the last log item that was not OK. Resetting status to OK.", AutoRecoveryTime));

        //    _errorLevel = null;
        //    _errorMessage = null;

        //    lock (_messageIntervalTimerLock)
        //    {
        //        _messageIntervalTimer.Start();
        //    }
        //}

        private void ComposeAndSendNSCAMessage(string optionalOkMessageOverride = null)
        {
            Level level = Level.Unknown;
            string message;
            var ticksNow = DateTimeOffset.Now.Ticks;

            if (DebugMode)
            {
                Log.Information("Now: {ticks}, Number of events in history: {EventsInHistory}. Events that will be deleted this run: {RemoveEventCount}, First expiry ticks in history: {expiryticks}",
                    ticksNow,
                    _history.Count,
                    _history.Count(x => x.ExpirationTicks <= ticksNow),
                    _history.Any() ? _history.Min(x => x.ExpirationTicks).ToString() : "-none-");
            }

            _history.RemoveAll(x => x.ExpirationTicks <= ticksNow);

            var worstLogEntry = _history
                .OrderByDescending(x => x.SeqLogLevel) // Worst log level
                .ThenByDescending(x => x.ExpirationTicks) // Last entry of the worst log level availible
                .FirstOrDefault();

            if (worstLogEntry != null)
            {
                if (DebugMode) Log.Information("Last event of the worst level in history: {ExpiryTicks}, {LogLevel}, {Message}", worstLogEntry.ExpirationTicks, worstLogEntry.SeqLogLevel, worstLogEntry.Message);

                message = worstLogEntry.Message;

                if (worstLogEntry.SeqLogLevel == LogEventLevel.Fatal || (ErrorIsCritical && worstLogEntry.SeqLogLevel == LogEventLevel.Error))
                {
                    level = Level.Critical;
                }
                else
                {
                    level = Level.Warning;
                }
            }
            else
            {
                if (!_eventReceivedDuringInterval)
                {
                    message = optionalOkMessageOverride ?? String.Format("There has been no log entry in the last {0} seconds", MessageInterval);
                    level = _logLevelOnNoOkEvent;
                }
                else
                {
                    message = optionalOkMessageOverride ?? String.Format("Received log entries in the last {0} seconds", MessageInterval);
                    level = Level.OK;
                }
            }

            if (DebugMode) Log.Information("Message send with level: {NagiosLevel} and message: {NagiosMessage}", level, message);

            NSCASettings settings = new NSCASettings()
            {
                EncryptionType = _encryptionType,
                NSCAAddress = Dns.GetHostAddresses(NagiosEndpoint).First().ToString(),
                Password = NSCAPassword ?? "",
                Port = NagiosEndpointPort
            };
            if (DebugMode) Log.Information("DNS hostname lookup (just before sending a message) of {NagiosEndpoint} resolves to {DnsResult}", NagiosEndpoint, settings.NSCAAddress);

            var client = new NSCAClientSender(settings);
            client.SendPassiveCheck(level, Hostname, ServiceName, message);
        }

        public void Dispose()
        {
            _messageIntervalTimer.Stop();
            _messageIntervalTimer.Elapsed -= OnMessageIntervalIntervalElapse;
            _messageIntervalTimer.Dispose();
        }

        private class LogHistoryEntry
        {
            public LogHistoryEntry(long expirationTicks, LogEventLevel seqLogLevel, string message)
            {
                ExpirationTicks = expirationTicks;
                SeqLogLevel = seqLogLevel;
                Message = message;
            }

            public long ExpirationTicks { get; private set; }
            public LogEventLevel SeqLogLevel { get; private set; }
            public string Message { get; private set; }
        }
    }
}
