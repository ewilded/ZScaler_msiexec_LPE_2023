This is my proof of concept for the Local Privilege Escalation via MSI installer (DLL hijacking race condition) in ZScaler Client Connect, version 3.7.2.18 (Windows).

The issue was addressed by the vendor in late 2023 without a CVE, in the meantime Microsoft has introduced a change in the way environmental variables are handled by msiexec processes running as SYSTEM (forced the TEMP value to be C:\Windows\SystemTemp, which is not accessible to regular users), effectively killing a significant number of msiexec-based LPEs such as this one.

Publishing this for educational purposes.

It was possible for regular users to trigger the installer in "repair" mode, by issuing the following command:
msiexec.exe /fa PATH_TO_INSTALLER_FILE.msi

That triggered the msiexec service, which automatically unpacks Zscaler-windows-3.7.2.18-installer-64.exe into a dynamically created directory C:\ZSAMSInstaller and runs it as NT AUTHORITY/SYSTEM.

The process then dynamically created a directory in C:\Users\kate\AppData\Local\Temp (whereas "kate" is the user who triggered the process) with "BRL0000" prefix, followed by 4 characters representing a hexadecimal number, for example C:\Users\kate\AppData\Local\Temp\BRL000019f0.

Then it dynamically unpacked 10 different DLL files into that directory and loaded them, executing their code as NT AUTHORITY/SYSTEM. The DLL files had ".tmp" extensions and started with the "BR" prefix, followed by 4 characters representing a hexadecimal number, for example BRF2BC.tmp.

Since AppData\Local\Temp directory is owned by a regular user, and the dynamically created BRL* directory inherited those permissions, it was possible for the regular user to interfere with the contents of the directory, for example by overwriting the dynamically generated DLL files.
That created a race condition. If the regular user managed to pick up DLL file names as they were created, they could attempt to overwrite them with their own file. If they managed to perform the replacement in the correct (very narrow) time window - right after the original file was written by the installer and the file descriptor was already closed, but before the installer called LoadLibrary() on it, they could get their own DLL file executed as NT AUTHORITY/SYSTEM, creating a Local Privilege Escalation.
Usually these kinds of race conditions are exploited using opportunistic locks and directory hardlinks, however in this case the not fully predictable directory name and file names, along with multiple write operations, made this approach questionable.
Thus, I decided to implement the exploit without using those mechanisms. 
Instead, I employed the use of FindFirstChangeNotification() WinAPI function to detect the creation of the temporary directory. Once that happens, without setting any further notification traps, the directory is immediately scanned for files starting with BR* prefix. The first file picked is targeted for replacement.
The exploit is very simple - it attempts to overwrite the first known file as soon as its name is known.
Successful exploitation requires multiple attempts (it is very unlikely that the race condition will be won at the right time in first attempt). With the version I have attached, I had to perform about 5 attempts until I hit the right time window.

To perform exploitation, the POC executable had to be in the same directory as the DLL we wanted to inject. It expects the DLL to be under "raw.dll" name.
We run it manually, providing the path to the MSI file as the only argument, like this: "ZScaler_LPE.exe PATH_TO_INSTALLER_FILE.msi". The MSI file must match the one the current version was installed from (can be the one from C:\Windows\Installer directory).

Remember, this will not work on recent versions of ZScaler Client Connect, neither on recent versions of Windows.

Demo:
https://hackingiscool.pl/content/images/download/when_race_condition_is_won_after_several_attempts.mp4
