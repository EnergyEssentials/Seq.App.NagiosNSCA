using System;
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

        private Timer _autoRecoveryTimer;
        private readonly object _autoRecoveryTimerLock = new object();

        private bool _eventReceivedDuringInterval = false;
        private string _errorMessage = null;
        private Level? _errorLevel = null;

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
            SendNSCAMessage(Level.OK, "Nagios NSCA Seq App is successfully initialized");

            if (DebugMode) Log.Information("Starting OK Interval timer with an interval of: {OkInterval} seconds", MessageInterval);

            lock (_messageIntervalTimerLock) {
                _messageIntervalTimer = new Timer(MessageInterval*1000);
                _messageIntervalTimer.Elapsed += OnMessageIntervalIntervalElapse;
                _messageIntervalTimer.AutoReset = false;
                _messageIntervalTimer.Start();
            }

            lock (_autoRecoveryTimerLock) {
                _autoRecoveryTimer = new Timer(AutoRecoveryTime*1000);
                _autoRecoveryTimer.Elapsed += AutoRecoveryTimeElapsed;
                _autoRecoveryTimer.AutoReset = false;
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
            _errorMessage = String.Format("{0} - [{1}] - {2}", evt.LocalTimestamp, evt.Level, evt.RenderedMessage);

            switch (evt.Level)
            {
                case LogEventLevel.Warning:
                    _errorLevel = Level.Warning;
                    break;
                case LogEventLevel.Error:
                    _errorLevel = ErrorIsCritical ? Level.Critical : Level.Warning;
                    break;
                case LogEventLevel.Fatal:
                    _errorLevel = Level.Critical;
                    break;
                default:
                    throw new InvalidOperationException("Unexpected NOK event level: " + evt.Level);
            }

            SendNSCAMessage(_errorLevel.Value, _errorMessage);

            lock (_autoRecoveryTimerLock)
            {
                if (_autoRecoveryTimer.Enabled)
                    _autoRecoveryTimer.Stop();

                _autoRecoveryTimer.Start();
            }

            lock (_messageIntervalTimerLock)
            {
                _messageIntervalTimer.Stop();
            }
        }

        private void OnMessageIntervalIntervalElapse(object sender, ElapsedEventArgs elapsedEventArgs)
        {
            if (DebugMode) Log.Information("The OK interval has been triggered. Has there been an OK event? {OkTypeEventReceivedDuringInterval}", _eventReceivedDuringInterval);

            lock (_messageIntervalTimerLock)
            {
                _messageIntervalTimer.Stop();
            }

            if (!_errorLevel.HasValue)
            {
                if (!_eventReceivedDuringInterval)
                {
                    var message = String.Format("There has been no log entry in the last {0} seconds", MessageInterval);
                    SendNSCAMessage(_logLevelOnNoOkEvent, message);
                }
                else
                {
                    var message = String.Format("Everything OK: received log entries in the last {0} seconds", MessageInterval);
                    SendNSCAMessage(Level.OK, message);
                }
            }
            else
            {
                SendNSCAMessage(_errorLevel.Value, _errorMessage);
            }

            _eventReceivedDuringInterval = false;

            lock (_messageIntervalTimerLock)
            {
                _messageIntervalTimer.Start();
            }
        }

        private void AutoRecoveryTimeElapsed(object sender, ElapsedEventArgs elapsedEventArgs)
        {
            if (DebugMode) Log.Information("The AutoRecovery timer has expired.");

            var message = String.Format("It has been {0} seconds since the last log item that was not OK. Resetting status to OK.", AutoRecoveryTime);
            SendNSCAMessage(Level.OK, message);

            _errorLevel = null;
            _errorMessage = null;

            lock (_messageIntervalTimerLock)
            {
                _messageIntervalTimer.Start();
            }
        }

        private void SendNSCAMessage(Level level, string message)
        {
            NSCASettings settings = new NSCASettings()
            {
                EncryptionType = _encryptionType, NSCAAddress = Dns.GetHostAddresses(NagiosEndpoint).First().ToString(), Password = NSCAPassword ?? "", Port = NagiosEndpointPort
            };
            if (DebugMode) Log.Information("DNS hostname lookup (just before sending a message) of {NagiosEndpoint} resolves to {DnsResult}", NagiosEndpoint, settings.NSCAAddress);

            var client = new NSCAClientSender(settings);

            if (DebugMode) Log.Information("Message send with level: {NagiosLevel} and message: {NagiosMessage}", level, message);
            client.SendPassiveCheck(level, Hostname, ServiceName, message);
        }

        public void Dispose()
        {
            _messageIntervalTimer.Stop();
            _messageIntervalTimer.Elapsed -= OnMessageIntervalIntervalElapse;
            _messageIntervalTimer.Dispose();

            _autoRecoveryTimer.Stop();
            _autoRecoveryTimer.Elapsed -= AutoRecoveryTimeElapsed;
            _autoRecoveryTimer.Dispose();
        }
    }
}
