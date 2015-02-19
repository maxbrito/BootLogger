-- Summary --

This code permits to compile a generic Windows driver
that will log to a text file the boot drivers and
services launched during the startup phase of Windows.


-- Installing --

To Install the driver on a Windows machine:
1) Select appropriate driver file (32 or 64 bit) on Windows explorer
2) Rename (for e.g.) BootLogger64.sys to BootLogger.sys 
3) Place the driver on the %windowsdir%\System32\Drivers folder

4) Run the BootLogger_Install.reg to add the registry keys
5) Reboot

6) For x64 Windows 7 and above press F8 and select "Disable driver
signature enforcement". Optionally, compile the drivers with a 
digital signature
to permit this driver to be loaded by recent Windows editions


-- Uninstalling --

To remove the driver:
1) Delete HKEY_LOCAL_MACHINE\SYSTEM\CurrentControlSet\services\BootLogger
2) Delete the BootLoogsys file from c:\Windows\System32\drivers


-- Customization / log report --

- The log report will be placed on c:\BootLog
- For each computer boot, a new log with a time stamp is created
- To track specific events on boot, use this page as reference:
	http://en.wikipedia.org/wiki/Windows_NT_startup_process

It is possible to change the default folder where the reports
are placed. Look inside this registry key:
HKEY_LOCAL_MACHINE\System\CurrentControlSet\services\BootLogger

The driver will log each call to a executable. It is possible
to deduce it's current stage of booting by observing which
executables are launched. For example, SMSS.exe called means
that the boot and service drivers were already booted. An entry
for winlogon.exe means the login screen is now visible to the
end user. A call to Explorer.exe or proquota.exe means that the
user has completed a login with success and that the desktop is
being launched.

Due to the nature of parallel and diverse nature of the processes
being launched during the startup operation, Windows does not
provide a definition of "boot complete". For example, some
applications such as Skype continue to run in the background after
being launched. Another suggested approach is to monitor the
CPU activity and detect a moment of less throtle but this would
fail on older computers and on cases where the end-user begins to
operate the machine before the startup processes complete their
typical processing.


-- Compiling --

To build the solution you require WDK, preferably 7600.1. 
You can also try VS2012, but it doesn't build drivers for the XP platform 
(actually it doesn't matter much, since driver will still work on XP, but it might be tricky sometimes)
 
This is the build process using WDK:
1) Select appropriate build environment (you can 
find this in the Start menu). The aim is Win7, 
Release, x86 or x64 (binaries built with this 
environment will work on both XP and 8, as well 
as on any other OS between)

2) Navigate to solution directory, "cd" inside bin folder
3) Launch build command
4) Done!


-- Compatibility --

This driver was tested on:
- Windows XP SP3
- Windows 7 SP1 x86
- Windows 8.1 x64
- Windows 10 x64 technical preview

Other Windows versions *should* work, please test and
provide us the feedback.


-- Feedback --

Something not working? Improvements?

Feedback is welcome. Please contact the author
using nuno.brito@triplecheck.de or @nn81 through
twitter.

For additional contacts: http://triplecheck.net

-- License ---

Copyright (c) 2015 by Nuno Brito, TripleCheck

This software is made available free of charge, under
the European Public Licence (EUPL) terms, version 1.1
or above. Files not containing a statement of license
on their headers should be considered as refering to
the EUPL terms, unless expressed otherwise.

You may not use, convey or distribute this work except in 
compliance with the conditions expressed in the licence.

You may obtain a copy of the EUPL 1.1 Licence at:
	https://joinup.ec.europa.eu/software/page/eupl

