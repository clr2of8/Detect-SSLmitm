$goldenHashes = @{
	"www.linkedin.com"  =  "1FB86B1168EC743154062E8C9CC5B171A4B7CCB4";
	"www.whitehouse.gov"  =  "1FB86B1168EC743154062E8C9CC5B171A4B7CCB4";
	"www.facebook.com"  =  "A031C46782E6E6C662C2C87C76DA9AA62CCABD8E";
	"mail.google.com"  =  "A6120FC0B4664FAD0B3B6FFD5F7A33E561DDB87D";
	"www.google.com"  =  "A6120FC0B4664FAD0B3B6FFD5F7A33E561DDB87D";
	"www.usbank.com"  =  "CC136695639065FAB47074D28C55314C66077E90";
	"www.twitter.com"  =  "7E2F3A4F8FE8FA8A5730AECA029696637E986F3F";
	"www.costco.com"  =  "FF67367C5CD4DE4AE18BCCE1D70FDABD7C866135";
}

function Detect-SSLmitm {

	foreach ($uri in $goldenHashes.Keys)
	{
		$hash = Get-CertHash -Uri "https://$uri"
		if ($hash -eq $goldenHashes[$uri])
		{
			Write-Host -ForegroundColor Green "[*] Certificate hash for $uri matches expected value. No SSL man-in-the-middle detected."
		}
		else {
			Write-Host -ForegroundColor Red "SSL man-in-the-middle detected for $uri"
		}
	}
}

# Get-CertHash function modifed from https://stackoverflow.com/questions/22233702/how-to-download-the-ssl-certificate-from-a-website-using-powershell
function Get-CertHash
{
    PARAM (
        [Uri]$Uri
    )

    if (-Not ($uri.Scheme -eq "https"))
    {
        Write-Error "You can only get keys for https addresses"
        return
    }

	[Net.ServicePointManager]::SecurityProtocol = [Net.SecurityProtocolType]::Tls12
    $request = [System.Net.HttpWebRequest]::Create($uri)
	$request.Proxy.Credentials = [System.Net.CredentialCache]::DefaultNetworkCredentials

    try
    {
        #Make the request but ignore (dispose it) the response, since we only care about the service point
        $request.GetResponse().Dispose()
    }
    catch [System.Net.WebException]
    {
        if ($_.Exception.Status -eq [System.Net.WebExceptionStatus]::TrustFailure)
        {
            #We ignore trust failures, since we only want the certificate, and the service point is still populated at this point
        }
        else
        {
            #Let other exceptions bubble up, or write-error the exception and return from this method
            throw
        }
    }

    #The ServicePoint object should now contain the Certificate for the site.
    $servicePoint = $request.ServicePoint
	# Build the Chain from this certificate so we can pull the secondary (intermediate) CA
	$chain = New-Object -TypeName System.Security.Cryptography.X509Certificates.X509Chain
	$success = $chain.Build($servicePoint.Certificate)
	$intermediateCert = $chain.ChainElements[1].Certificate
	$hash = $intermediateCert.GetCertHashString()
	return $hash
	
}

$Uris = @(
	"www.google.com"
	"mail.google.com"
	"www.whitehouse.gov"
    "www.costco.com"
	"www.facebook.com"
	"www.usbank.com"
	"www.twitter.com"
	"www.linkedin.com"
)

function Get-GoldenHashes
{
	$certHashes = @{}

	foreach ($uri in $Uris) {
        Write-Output "Getting golden certificate hash for $uri"
		$hash = Get-CertHash -Uri "https://$uri"
		$certHashes.add($uri, $hash )
	
	}

	# print out the hash table for easy copy and paste back into this script as the $goldenHashes variable
    Write-Host -ForegroundColor Green "[*] Done, now copy and paste these golden hashes into the goldenHashes array at the top of this script."
	$certHashes.Keys | % { "`t""$_""  =  ""$($certHashes.Item($_))"";" }
}