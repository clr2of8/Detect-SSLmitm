# Detect-SSLmitm

This PowerShell script will determine if your connection to external servers over HTTPS is being decrypted by an intercepting proxy such as the internet proxies commonly found in corporate environments. It does this by comparing the SSL intermediate certificate being used for your connection to the true/known SSL certificate for the server.

Kudos to [@malcomvetter](https://twitter.com/malcomvetter) for the idea to write this script and for some improvement tips.

## Usage

Load the PowerShell Module functions from the Windows command prompt as follows:

```
powershell -exec bypass
Import-Module .\Detect-SSLmitm.ps1
```

Determine which sites (in the url list) are being decrypted by an intercepting proxy:

```
Detect-SSLmitm
```

The Output looks like this:

![Example Usage](https://github.com/clr2of8/Detect-SSLmitm/raw/master/images/Usage.png)



If you would like to configure which sites are checked, open the script and edit the "Uris" list near the bottom, then call the following function.

```
Get-GoldenHashes
```

Note, it is important to generate the Golden certificate hashes from a network location known to not decrypt SSL traffic, otherwise you will get false positives.
