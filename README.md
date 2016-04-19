# Seq.App.NagiosNSCA [![Build status](https://ci.appveyor.com/api/projects/status/bd9lg37vskj6x00j/branch/master?svg=true)](https://ci.appveyor.com/project/yoricksmeets/seq-app-nagiosnsca/branch/master)

Seq App: Sends passive checks to Nagios using the NSCA protocol

## Features

* Supports None, Xor, TripleDES, Rijndael128, Rijndael192, Rijndael256 encryption for the NSCA endpoint
* Heartbeat to Nagios - Configurable interval to send OK messages from Seq to Nagios
* Heartbeat to Seq - Configurable log level to send a different status to Nagios if there have been no log entries during the heartbeat interval (i.e. Unknown)
* Auto-Reset interval - Resume sending OK messages after a configured interval has elapsed (timer will reset every Warning/Error/Fatal message that is sent to Nagios)
* Debug mode for troubleshooting connectivity issues

## Used projects

* Nagios NSCA Client project: https://github.com/robertmircea/nagios-nsca-client
