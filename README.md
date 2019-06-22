## YAWAST [![Gem Version](https://badge.fury.io/rb/yawast.svg)](https://badge.fury.io/rb/yawast)

**The YAWAST Antecedent Web Application Security Toolkit**

_Important: This refers to the Ruby version of YAWAST, which is no longer supported. The original wiki documentation is reproduced below._

YAWAST is an application meant to simplify initial analysis and information gathering for penetration testers and security auditors. It performs basic checks in these categories:

* TLS/SSL - Versions and cipher suites supported; common issues.
* Information Disclosure - Checks for common information leaks.
* Presence of Files or Directories - Checks for files or directories that could indicate a security issue.
* Common Vulnerabilities
* Missing Security Headers

This is meant to provide a easy way to perform initial analysis and information discovery. It's not a full testing suite, and it certainly isn't Metasploit. The idea is to provide a quick way to perform initial data collection, which can then be used to better target further tests. It is especially useful when used in conjunction with Burp Suite (via the `--proxy` parameter).

Please see [the wiki](https://github.com/adamcaudill/yawast/wiki) for full documentation.

### Installing

YAWAST is packaged as a Ruby Gem & Docker container to make installing it as easy as possible. Details are available [on the wiki](https://github.com/adamcaudill/yawast/wiki/Installation).

The simplest options to install are:

As a Gem: `gem install yawast`

Via Docker: `docker pull adamcaudill/yawast`

It's strongly recommended that you review the [installation](https://github.com/adamcaudill/yawast/wiki/Installation) documentation, to make sure you have the proper dependencies.

### Tests

The following tests are performed:

* *(Generic)* User Enumeration via Password Reset Form Response Differences
* *(Generic)* User Enumeration via Password Reset Form Timing Differences
* *(Generic)* Info Disclosure: X-Powered-By header present
* *(Generic)* Info Disclosure: X-Pingback header present
* *(Generic)* Info Disclosure: X-Backend-Server header present
* *(Generic)* Info Disclosure: X-Runtime header present
* *(Generic)* Info Disclosure: Via header present
* *(Generic)* Info Disclosure: PROPFIND Enabled
* *(Generic)* TRACE Enabled
* *(Generic)* X-Frame-Options header not present
* *(Generic)* X-Content-Type-Options header not present
* *(Generic)* Content-Security-Policy header not present
* *(Generic)* Public-Key-Pins header not present
* *(Generic)* Referrer-Policy header not present
* *(Generic)* Feature-Policy header not present
* *(Generic)* X-XSS-Protection disabled header present
* *(Generic)* SSL: HSTS not enabled
* *(Generic)* Source Control: Common source control directories present
* *(Generic)* Presence of crossdomain.xml or clientaccesspolicy.xml
* *(Generic)* Presence of sitemap.xml
* *(Generic)* Presence of WS_FTP.LOG
* *(Generic)* Presence of RELEASE-NOTES.txt
* *(Generic)* Presence of readme.html
* *(Generic)* Presence of CHANGELOG.txt
* *(Generic)* Missing cookie flags (Secure, HttpOnly, and SameSite)
* *(Generic)* Search for 14,405 common files (via `--files`) & 21,332 common directories (via `--dir`)
* *(Apache)* Info Disclosure: Module listing enabled
* *(Apache)* Info Disclosure: Server version
* *(Apache)* Info Disclosure: OpenSSL module version
* *(Apache)* Presence of /server-status
* *(Apache)* Presence of /server-info
* *(Apache Tomcat)* Presence of Tomcat Manager
* *(Apache Tomcat)* Presence of Tomcat Host Manager
* *(Apache Tomcat)* Tomcat Manager Weak Password
* *(Apache Tomcat)* Tomcat Host Manager Weak Password
* *(Apache Tomcat)* Tomcat version detection via invalid HTTP verb
* *(Apache Tomcat)* Tomcat version detection via File Not Found
* *(Apache Tomcat)* Tomcat PUT RCE (CVE-2017-12617)
* *(Apache Tomcat)* Tomcat Windows RCE (CVE-2019-0232)
* *(Apache Struts)* Sample files which may be vulnerable
* *(Nginx)* Info Disclosure: Server version
* *(Nginx)* Info Disclosure: Server status
* *(IIS)* Info Disclosure: Server version
* *(ASP.NET)* Info Disclosure: ASP.NET version
* *(ASP.NET)* Info Disclosure: ASP.NET MVC version
* *(ASP.NET)* Presence of Trace.axd
* *(ASP.NET)* Presence of Elmah.axd
* *(ASP.NET)* Debugging Enabled
* *(PHP)* Info Disclosure: PHP version
* *(Rails)* File Content Disclosure: CVE-2019-5418
* *(WordPress)* Version detection
* *(WordPress)* WP-JSON User Enumeration

CMS Detection:

* Generic (Generator meta tag) *[Real detection coming as soon as I get around to it...]*

SSL Information:

* Certificate details
* Certificate chain
* Supported ciphers
* Maximum requests using 3DES in a single connection
* DNS CAA records

Checks for the following SSL issues are performed:

*Note: By default, YAWAST uses SSL Labs, meaning this is a small subset of issues detected.*

* Expired Certificate
* Self-Signed Certificate
* MD5 Signature
* SHA1 Signature
* RC4 Cipher Suites
* Weak (< 128 bit) Cipher Suites
* SWEET32
* 64-bit Serial Numbers ([details](https://adamcaudill.com/2019/03/09/tls-64bit-ish-serial-numbers-mass-revocation/))

Certain DNS information is collected:

* IP Addresses
* IP Owner/Network (via [api.iptoasn.com](https://api.iptoasn.com/))
* TXT Records
* MX Records
* NS Records
* CAA Records (with CNAME chasing)
* Common Subdomains (2,354 subdomains) - optional, via `--subdomains`
* SRV Records - optional, via `--srv`

In addition to these tests, certain basic information is also displayed, such as IPs (and the PTR record for each IP), HTTP HEAD request, and others.

### Usage

The most common usage scenario is as simple as:

`yawast scan <url1> <url2>`

Detailed [usage information](https://github.com/adamcaudill/yawast/wiki/Usage-&-Parameters) is available on the wiki.

### Sample

Sample output for a [scan](https://github.com/adamcaudill/yawast/wiki/Sample-Output) and [TLS-specific](https://github.com/adamcaudill/yawast/wiki/Scanning-TLS-(SSL)) checks are on the wiki.

### Special Thanks

* [AppSec Consulting](https://www.appsecconsulting.com/) - Generously providing time to improve this tool.
* [SecLists](https://github.com/danielmiessler/SecLists) - Various lists are based on the resources collected by this project.

# Original Wiki Documentation

### Installing

The simplest method to install is to use the RubyGem installer:

`gem install yawast`

This allows for simple updates (`gem update yawast`) and makes it easy to ensure that you are always using the latest version.

YAWAST requires Ruby 2.3+, and is tested on Mac OSX, Linux, and Windows. YAWAST is tested against Ruby 2.3.5, 2.4.2, 2.6.0.

*Note:* There are additional dependencies required for certain scanning features starting with YAWAST 0.7.0; see the "Enhanced Vulnerability Scanner" section below for details.

#### Docker

YAWAST can be run inside a docker container.

```
docker pull adamcaudill/yawast && docker run --rm adamcaudill/yawast scan <url> ...
```

This is the recommended option, especially if you need to perform the SWEET32 test (`--tdessessioncount`), due to OpenSSL dropping support for the 3DES cipher suites.

If you would like to capture the JSON output via the `--output=` option, you will need to use a slightly different command. The following example is for macOS, Linux, etc., for Windows, you will need to modify the command. The following mounts the current directory to the Docker image, so that it can write the JSON file: 

```
$ docker pull adamcaudill/yawast && docker run -v `pwd`/:/data/output/ --rm adamcaudill/yawast scan <url> --output=./output/
```

#### Kali Rolling

To install on Kali, just run `gem install yawast` - all of the dependencies are already installed. *Note:* The version of OpenSSL used with Kali doesn't support 3DES cipher suites, so some tests, such as SWEET32 do not work. If you need these tests to work, using the Docker image is the recommended solution.

#### Ubuntu

To install YAWAST, you first need to install a couple packages via `apt-get`:

```
sudo apt-get install ruby ruby-dev
sudo gem install yawast
```

#### macOS

The version of Ruby shipped with macOS is too old, so the recommended solution is to use RVM:

```
gpg --keyserver hkp://keys.gnupg.net --recv-keys 409B6B1796C275462A1703113804BB82D39DC0E3
\curl -sSL https://get.rvm.io | bash -s stable
source ~/.rvm/scripts/rvm
rvm install 2.4
rvm use 2.4 --default
gem install yawast
```

#### Windows

To install on Windows, you need to first install Ruby. This can be done easily with the latest version of [RubyInstaller](https://rubyinstaller.org/downloads/). Once Ruby is installed, YAWAST can be installed via `gem install yawast` as normal.

### Enhanced Vulnerability Scanner

Starting in YAWAST version 0.7.0, there is a new vulnerability scanner that performs tests that aren't possible using Ruby alone. To accomplish this, the new vulnerability scanner uses Chrome via Selenium, which adds a few additional dependencies:

* Google Chrome
* [ChromeDriver](https://sites.google.com/a/chromium.org/chromedriver/)

#### macOS

ChromeDriver can be installed via `brew` using the following commands:

```
brew tap homebrew/cask
brew cask install chromedriver
```

#### Linux

ChromeDriver for Linux can be install using the following commands; please make sure that you are using the latest stable release from the [ChromeDriver](https://sites.google.com/a/chromium.org/chromedriver/) web site.

```
wget https://chromedriver.storage.googleapis.com/73.0.3683.68/chromedriver_linux64.zip
unzip chromedriver_linux64.zip
sudo mv chromedriver /usr/bin/chromedriver
sudo chown root:root /usr/bin/chromedriver
sudo chmod +x /usr/bin/chromedriver
```

#### Windows

You can easily install ChromeDriver on Windows via a package manager such as [Chocolatey](https://chocolatey.org/docs/installation) using the following command:
 
```
choco install chromedriver
```

## OpenSSL & 3DES Compatibility

In recent releases, OpenSSL has disabled the 3DES cipher suites, which creates the following issues:

### SWEET32 Test Fails

The SWEET32 test relies on being able to send requests using a 3DES cipher suite, which when OpenSSL is compiled without 3DES support, this test files.

At the moment, the easiest work around for this issue is to use the [docker container](https://github.com/adamcaudill/yawast/wiki/Installation#docker) which includes a version of OpenSSL that's properly configured.


### Commands & Parameters

* Standard scan: `yawast scan <url> [--internalssl] [--tdessessioncount] [--nossl] [--nociphers] [--dir] [--dirrecursive] [--dirlistredir] [--files] [--srv] [--subdomains] [--proxy localhost:8080] [--cookie SESSIONID=12345] [--nodns]`
* HEAD-only scan: `yawast head <url> [--internalssl] [--tdessessioncount] [--nossl] [--nociphers] [--proxy localhost:8080] [--cookie SESSIONID=12345]`
* SSL information: `yawast ssl <url> [--internalssl] [--tdessessioncount] [--nociphers]`
* DNS Information: `yawast dns <url>`
* CMS detection: `yawast cms <url> [--proxy localhost:8080] [--cookie SESSIONID=12345]`

For detailed information, just call `yawast -h` to see the help page. To see information for a specific command, call `yawast -h <command>` for full details. Here is an example, the details for the options to the `scan` command:

```
  OPTIONS:
        
    --nossl 
        Disables SSL checks
        
    --nociphers 
        Disables check for supported ciphers (only with --internalssl)
        
    --internalssl 
        Disable SSL Labs integration
        
    --tdessessioncount 
        Counts the number of messages that can be sent in a single session
        
    --dir 
        Enables directory search
        
    --dirrecursive 
        Recursive directory search (only with --dir)
        
    --dirlistredir 
        Show 301 redirects (only with --dir)
        
    --files 
        Performs a search for a large list of common files
        
    --srv 
        Scan for known SRV DNS Records
        
    --subdomains 
        Search for Common Subdomains
        
    --proxy STRING 
        HTTP Proxy Server (such as Burp Suite)
        
    --cookie STRING 
        Session cookie
        
    --nodns 
        Disable DNS checks
```

### Using with Zap / Burp Suite

By default, Burp Suite's proxy listens on localhost at port 8080, to use YAWAST with Burp Suite (or any proxy for that matter), just add this to the command line:

`--proxy localhost:8080`

### Authenticated Testing

For authenticated testing, YAWAST allows you to specify a cookie to be passed via the `--cookie` parameter.

`--cookie SESSIONID=1234567890`

### About The Output

You'll notice that most lines begin with a letter in a bracket, this is to tell you how to interpret the result at a glance. There are four possible values:

* `[I]` - This indicates that the line is informational, and doesn't necessarily indicate a security issue.
* `[W]` - This is a Warning, which means that it could be an issue, or could expose useful information. These need to be evaluated on a case-by-case basis to determine the impact.
* `[V]` - This is a Vulnerability, it indicates an issue that is known to be an issue, and needs to be addressed.
* `[E]` - This indicates that an error occurred, sometimes these are serious and indicate an issue with your environment, the target server, or the application. In other cases, they may just be informational to let you know that something didn't go as planned.

The indicator used may change over time based on new research or better detection techniques. In all cases, results should be carefully evaluated within the context of the application, how it's used, and what threats apply. The indicator is guidance, a hint if you will, it's up to you to determine the real impact.

## Scanning TLS (SSL)

YAWAST includes two modes for performing checks against TLS configurations, one uses [SSL Labs](https://www.ssllabs.com/) (default), which includes a very detailed analysis of the system. For cases where SSL Labs can't be used, YAWAST also includes an internal scanner (`--internalssl`) which includes basic configuration checks.

### SWEET32 Testing

The [SWEET32](https://adamcaudill.com/2016/09/15/testing-sweet32-yawast/) test works with both modes, and doesn't rely on external components. Details on how this test works, and its limitations are explained at the above link.

### Tests Performed


SSL Information:

* Certificate details
* Certificate chain
* Supported ciphers
* Maximum requests using 3DES in a single connection
* DNS CAA records

Checks for the following SSL issues are performed:

* Expired Certificate
* Self-Signed Certificate
* MD5 Signature
* SHA1 Signature
* RC4 Cipher Suites
* Weak (< 128 bit) Cipher Suites
* SWEET32

## Internal Mode

To use the custom internal TLS / SSL scanner (which uses your copy of OpenSSL), simply pass `--internalssl` on the command line. Here is a sample of the output generated by this tester.

```
[I] Found X509 Certificate:
[I] 		Issued To: sni67677.cloudflaressl.com / 
[I] 		Issuer: COMODO ECC Domain Validation Secure Server CA 2 / COMODO CA Limited
[I] 		Version: 2
[I] 		Serial: 167670175484361448885961646389808341945
[I] 		Subject: /OU=Domain Control Validated/OU=PositiveSSL Multi-Domain/CN=sni67677.cloudflaressl.com
[I] 		Expires: 2017-07-02 23:59:59 UTC
[I] 		Signature Algorithm: ecdsa-with-SHA256
[I] 		Key: EC-prime256v1
[I] 			Key Hash: 26c91946d32c2e664dd4c131ffd2b11bd6270331
[I] 		Extensions:
[I] 			authorityKeyIdentifier = keyid:40:09:61:67:F0:BC:83:71:4F:DE:12:08:2C:6F:D4:D4:2B:76:3D:96, 
[I] 			subjectKeyIdentifier = D0:F8:D6:82:36:B5:5C:AC:2D:9A:8E:7B:D9:D5:E6:99:38:B6:8C:FE
[I] 			keyUsage = critical, Digital Signature
[I] 			basicConstraints = critical, CA:FALSE
[I] 			extendedKeyUsage = TLS Web Server Authentication, TLS Web Client Authentication
[I] 			certificatePolicies = Policy: 1.3.6.1.4.1.6449.1.2.2.7,   CPS: https://secure.comodo.com/CPS, Policy: 2.23.140.1.2.1, 
[I] 			crlDistributionPoints = , Full Name:,   URI:http://crl.comodoca4.com/COMODOECCDomainValidationSecureServerCA2.crl, 
[I] 			authorityInfoAccess = CA Issuers - URI:http://crt.comodoca4.com/COMODOECCDomainValidationSecureServerCA2.crt, OCSP - URI:http://ocsp.comodoca4.com, 
[I] 		Alternate Names:
[I] 			sni67677.cloudflaressl.com
[I] 			*.adamcaudill.com
[I] 			adamcaudill.com
[I] 		Hash: 06746b606927dab24f9b339329639151112c9363
			https://censys.io/certificates?q=06746b606927dab24f9b339329639151112c9363
			https://crt.sh/?q=06746b606927dab24f9b339329639151112c9363

[I] Certificate: Chain
[I] 		Issued To: sni67677.cloudflaressl.com / 
[I] 			Issuer: COMODO ECC Domain Validation Secure Server CA 2 / COMODO CA Limited
[I] 			Expires: 2017-07-02 23:59:59 UTC
[I] 			Key: EC-prime256v1
[I] 			Signature Algorithm: ecdsa-with-SHA256
[I] 			Hash: 06746b606927dab24f9b339329639151112c9363

[I] 		Issued To: COMODO ECC Domain Validation Secure Server CA 2 / COMODO CA Limited
[I] 			Issuer: COMODO ECC Certification Authority / COMODO CA Limited
[I] 			Expires: 2029-09-24 23:59:59 UTC
[I] 			Key: EC-prime256v1
[I] 			Signature Algorithm: ecdsa-with-SHA384
[I] 			Hash: 75cfd9bc5cefa104ecc1082d77e63392ccba5291

[I] 		Issued To: COMODO ECC Certification Authority / COMODO CA Limited
[I] 			Issuer: AddTrust External CA Root / AddTrust AB
[I] 			Expires: 2020-05-30 10:48:38 UTC
[I] 			Key: EC-secp384r1
[I] 			Signature Algorithm: sha384WithRSAEncryption
[I] 			Hash: ae223cbf20191b40d7ffb4ea5701b65fdc68a1ca


		Qualys SSL Labs: https://www.ssllabs.com/ssltest/analyze.html?d=adamcaudill.com&hideResults=on

Supported Ciphers (based on your OpenSSL version):
	Checking for TLSv1 suites (98 possible suites)
[I] 		Version: TLSv1  	Bits: 256	Cipher: ECDHE-ECDSA-AES256-SHA
[I] 		Version: TLSv1  	Bits: 128	Cipher: ECDHE-ECDSA-AES128-SHA
[W] 		Version: TLSv1  	Bits: 112	Cipher: ECDHE-ECDSA-DES-CBC3-SHA
	Checking for TLSv1_2 suites (98 possible suites)
[I] 		Version: TLSv1.2	Bits: 256	Cipher: ECDHE-ECDSA-AES256-GCM-SHA384
[I] 		Version: TLSv1.2	Bits: 256	Cipher: ECDHE-ECDSA-AES256-SHA384
[I] 		Version: TLSv1.2	Bits: 256	Cipher: ECDHE-ECDSA-AES256-SHA
[I] 		Version: TLSv1.2	Bits: 128	Cipher: ECDHE-ECDSA-AES128-GCM-SHA256
[I] 		Version: TLSv1.2	Bits: 128	Cipher: ECDHE-ECDSA-AES128-SHA256
[I] 		Version: TLSv1.2	Bits: 128	Cipher: ECDHE-ECDSA-AES128-SHA
	Checking for TLSv1_1 suites (98 possible suites)
[I] 		Version: TLSv1.1	Bits: 256	Cipher: ECDHE-ECDSA-AES256-SHA
[I] 		Version: TLSv1.1	Bits: 128	Cipher: ECDHE-ECDSA-AES128-SHA
	Checking for SSLv3 suites (98 possible suites)

[I] HSTS: Enabled (strict-transport-security: max-age=15552000; preload)
```

## SSL Labs Mode

The default mode is to use the SSL Labs API, which makes all users bound by their [terms and conditions](https://www.ssllabs.com/downloads/Qualys_SSL_Labs_Terms_of_Use.pdf), and obviously results in the domain you are scanning being sent to them.

This mode is the most comprehensive, and contains far more data than the Internal Mode. Unless there is a good reason to use the Internal Mode, this is what you should use.

```
Beginning SSL Labs scan (this could take a minute or two)
[SSL Labs] This assessment service is provided free of charge by Qualys SSL Labs, subject to our terms and conditions: https://www.ssllabs.com/about/terms.html
.............................

	SSL Labs: https://www.ssllabs.com/ssltest/analyze.html?d=adamcaudill.com&hideResults=on

[I] IP: 104.28.27.55 - Grade: A+

	Certificate Information:
[I] 		Subject: CN=sni67677.cloudflaressl.com, OU=PositiveSSL Multi-Domain, OU=Domain Control Validated
[I] 		Common Names: sni67677.cloudflaressl.com
[I] 		Alternative names:
[I] 			sni67677.cloudflaressl.com
[I] 			*.adamcaudill.com
[I] 			adamcaudill.com
[I] 		Not Before: 2017-07-26T00:00:00+00:00
[I] 		Not After: 2018-02-01T23:59:59+00:00
[I] 		Key: EC 256 (RSA equivalent: 3072)
[I] 		Public Key Hash: 045a733405a4046b5bcc8abbd1e1cbd1d1d3b55c
[I] 		Version: 2
[I] 		Serial: 77574794376740264441751965250081500687
[I] 		Issuer: CN=COMODO ECC Domain Validation Secure Server CA 2, O=COMODO CA Limited, L=Salford, ST=Greater Manchester, C=GB
[I] 		Signature algorithm: SHA256withECDSA
[I] 		Extended Validation: No (Domain Control)
[I] 		Certificate Transparency: No
[I] 		OCSP Must Staple: false
[I] 		Revocation information: CRL information available
[I] 		Revocation information: OCSP information available
[I] 		Revocation status: certificate not revoked
[I] 		Extensions:
[I] 			authorityKeyIdentifier = keyid:40:09:61:67:F0:BC:83:71:4F:DE:12:08:2C:6F:D4:D4:2B:76:3D:96, 
[I] 			subjectKeyIdentifier = D0:F8:D6:82:36:B5:5C:AC:2D:9A:8E:7B:D9:D5:E6:99:38:B6:8C:FE
[I] 			keyUsage = critical, Digital Signature
[I] 			basicConstraints = critical, CA:FALSE
[I] 			extendedKeyUsage = TLS Web Server Authentication, TLS Web Client Authentication
[I] 			certificatePolicies = Policy: 1.3.6.1.4.1.6449.1.2.2.7,   CPS: https://secure.comodo.com/CPS, Policy: 2.23.140.1.2.1, 
[I] 			crlDistributionPoints = , Full Name:,   URI:http://crl.comodoca4.com/COMODOECCDomainValidationSecureServerCA2.crl, 
[I] 			authorityInfoAccess = CA Issuers - URI:http://crt.comodoca4.com/COMODOECCDomainValidationSecureServerCA2.crt, OCSP - URI:http://ocsp.comodoca4.com, 
[I] 		Hash: 2cf22bbb21e5a3eaa042feadc8fbc86ff0d3b1e1
			https://censys.io/certificates?q=2cf22bbb21e5a3eaa042feadc8fbc86ff0d3b1e1
			https://crt.sh/?q=2cf22bbb21e5a3eaa042feadc8fbc86ff0d3b1e1

[I] 		Certificate Chains:
		  Path 1:
[I] 			CN=sni67677.cloudflaressl.com, OU=PositiveSSL Multi-Domain, OU=Domain Control Validated
[I] 			  Signature: SHA256withECDSA  Key: EC-256
[I] 			  https://crt.sh/?q=2cf22bbb21e5a3eaa042feadc8fbc86ff0d3b1e1
[I] 			CN=COMODO ECC Domain Validation Secure Server CA 2, O=COMODO CA Limited, L=Salford, ST=Greater Manchester, C=GB
[I] 			  Signature: SHA384withECDSA  Key: EC-256
[I] 			  https://crt.sh/?q=75cfd9bc5cefa104ecc1082d77e63392ccba5291
[I] 			CN=COMODO ECC Certification Authority, O=COMODO CA Limited, L=Salford, ST=Greater Manchester, C=GB
[I] 			  Signature: SHA384withECDSA  Key: EC-384
[I] 			  https://crt.sh/?q=9f744e9f2b4dbaec0f312c50b6563b8e2d93c311
		  Path 2:
[I] 			CN=sni67677.cloudflaressl.com, OU=PositiveSSL Multi-Domain, OU=Domain Control Validated
[I] 			  Signature: SHA256withECDSA  Key: EC-256
[I] 			  https://crt.sh/?q=2cf22bbb21e5a3eaa042feadc8fbc86ff0d3b1e1
[I] 			CN=COMODO ECC Domain Validation Secure Server CA 2, O=COMODO CA Limited, L=Salford, ST=Greater Manchester, C=GB
[I] 			  Signature: SHA384withECDSA  Key: EC-256
[I] 			  https://crt.sh/?q=75cfd9bc5cefa104ecc1082d77e63392ccba5291
[I] 			CN=COMODO ECC Certification Authority, O=COMODO CA Limited, L=Salford, ST=Greater Manchester, C=GB
[I] 			  Signature: SHA384withRSA  Key: EC-384
[I] 			  https://crt.sh/?q=ae223cbf20191b40d7ffb4ea5701b65fdc68a1ca
[I] 			CN=AddTrust External CA Root, OU=AddTrust External TTP Network, O=AddTrust AB, C=SE
[I] 			  Signature: SHA1withRSA  Key: RSA-2048
[I] 			  https://crt.sh/?q=02faf3e291435468607857694df5e45b68851868

	Configuration Information:
		Protocol Support:
[I] 			TLS 1.0
[I] 			TLS 1.1
[I] 			TLS 1.2
[I] 			TLS 1.3

		Named Group Support:
[I] 			x25519 256
[I] 			secp256r1 256
[I] 			secp384r1 384
[I] 			secp224r1 224
[I] 			secp521r1 521

		Cipher Suite Support:
[I] 			TLS 1.0
[I] 			  TLS_ECDHE_ECDSA_WITH_AES_128_CBC_SHA               - 128-bits - ECDH-256 / x25519 (3072 equivalent)
[I] 			  TLS_ECDHE_ECDSA_WITH_AES_256_CBC_SHA               - 256-bits - ECDH-256 / x25519 (3072 equivalent)
[I] 			TLS 1.1
[I] 			  TLS_ECDHE_ECDSA_WITH_AES_128_CBC_SHA               - 128-bits - ECDH-256 / x25519 (3072 equivalent)
[I] 			  TLS_ECDHE_ECDSA_WITH_AES_256_CBC_SHA               - 256-bits - ECDH-256 / x25519 (3072 equivalent)
[I] 			TLS 1.2
[I] 			  TLS_ECDHE_ECDSA_WITH_AES_128_GCM_SHA256            - 128-bits - ECDH-256 / x25519 (3072 equivalent)
[I] 			  OLD_TLS_ECDHE_ECDSA_WITH_CHACHA20_POLY1305_SHA256  - 256-bits - ECDH-256 / x25519 (3072 equivalent)
[I] 			  TLS_ECDHE_ECDSA_WITH_CHACHA20_POLY1305_SHA256      - 256-bits - ECDH-256 / x25519 (3072 equivalent)
[I] 			  TLS_ECDHE_ECDSA_WITH_AES_128_CBC_SHA               - 128-bits - ECDH-256 / x25519 (3072 equivalent)
[I] 			  TLS_ECDHE_ECDSA_WITH_AES_128_CBC_SHA256            - 128-bits - ECDH-256 / x25519 (3072 equivalent)
[I] 			  TLS_ECDHE_ECDSA_WITH_AES_256_GCM_SHA384            - 256-bits - ECDH-256 / x25519 (3072 equivalent)
[I] 			  TLS_ECDHE_ECDSA_WITH_AES_256_CBC_SHA               - 256-bits - ECDH-256 / x25519 (3072 equivalent)
[I] 			  TLS_ECDHE_ECDSA_WITH_AES_256_CBC_SHA384            - 256-bits - ECDH-256 / x25519 (3072 equivalent)
[I] 			TLS 1.3
[I] 			  TLS_AES_128_GCM_SHA256                             - 128-bits - ECDH-256 / x25519 (3072 equivalent)
[I] 			  TLS_AES_256_GCM_SHA384                             - 256-bits - ECDH-256 / x25519 (3072 equivalent)
[I] 			  TLS_CHACHA20_POLY1305_SHA256                       - 256-bits - ECDH-256 / x25519 (3072 equivalent)

		Handshake Simulation:
[W] 			Android 2.3.7                - Simulation Failed
[I] 			Android 4.0.4                - TLS 1.0 - TLS_ECDHE_ECDSA_WITH_AES_128_CBC_SHA - ECDH-256 / secp256r1 (3072 equivalent)
[I] 			Android 4.1.1                - TLS 1.0 - TLS_ECDHE_ECDSA_WITH_AES_128_CBC_SHA - ECDH-256 / secp256r1 (3072 equivalent)
[I] 			Android 4.2.2                - TLS 1.0 - TLS_ECDHE_ECDSA_WITH_AES_128_CBC_SHA - ECDH-256 / secp256r1 (3072 equivalent)
[I] 			Android 4.3                  - TLS 1.0 - TLS_ECDHE_ECDSA_WITH_AES_128_CBC_SHA - ECDH-256 / secp256r1 (3072 equivalent)
[I] 			Android 4.4.2                - TLS 1.2 - TLS_ECDHE_ECDSA_WITH_AES_128_GCM_SHA256 - ECDH-256 / secp256r1 (3072 equivalent)
[I] 			Android 5.0.0                - TLS 1.2 - OLD_TLS_ECDHE_ECDSA_WITH_CHACHA20_POLY1305_SHA256 - ECDH-256 / secp256r1 (3072 equivalent)
[I] 			Android 6.0                  - TLS 1.2 - OLD_TLS_ECDHE_ECDSA_WITH_CHACHA20_POLY1305_SHA256 - ECDH-256 / secp256r1 (3072 equivalent)
[I] 			Android 7.0                  - TLS 1.2 - TLS_ECDHE_ECDSA_WITH_CHACHA20_POLY1305_SHA256 - ECDH-256 / x25519 (3072 equivalent)
[I] 			Baidu Jan 2015               - TLS 1.0 - TLS_ECDHE_ECDSA_WITH_AES_128_CBC_SHA - ECDH-256 / secp256r1 (3072 equivalent)
[I] 			BingPreview Jan 2015         - TLS 1.2 - TLS_ECDHE_ECDSA_WITH_AES_128_GCM_SHA256 - ECDH-256 / secp256r1 (3072 equivalent)
[W] 			Chrome 49 / XP SP3           - Simulation Failed
[I] 			Chrome 57 / Win 7            - TLS 1.3 - TLS_AES_128_GCM_SHA256 - ECDH-256 / x25519 (3072 equivalent)
[I] 			Firefox 31.3.0 ESR / Win 7   - TLS 1.2 - TLS_ECDHE_ECDSA_WITH_AES_128_GCM_SHA256 - ECDH-256 / secp256r1 (3072 equivalent)
[I] 			Firefox 47 / Win 7           - TLS 1.2 - TLS_ECDHE_ECDSA_WITH_AES_128_GCM_SHA256 - ECDH-256 / secp256r1 (3072 equivalent)
[I] 			Firefox 49 / XP SP3          - TLS 1.2 - TLS_ECDHE_ECDSA_WITH_AES_128_GCM_SHA256 - ECDH-256 / secp256r1 (3072 equivalent)
[I] 			Firefox 53 / Win 7           - TLS 1.3 - TLS_AES_128_GCM_SHA256 - ECDH-256 / x25519 (3072 equivalent)
[I] 			Googlebot Feb 2015           - TLS 1.2 - TLS_ECDHE_ECDSA_WITH_AES_128_GCM_SHA256 - ECDH-256 / secp256r1 (3072 equivalent)
[W] 			IE 6 / XP                    - Simulation Failed
[I] 			IE 7 / Vista                 - TLS 1.0 - TLS_ECDHE_ECDSA_WITH_AES_128_CBC_SHA - ECDH-256 / secp256r1 (3072 equivalent)
[W] 			IE 8 / XP                    - Simulation Failed
[I] 			IE 8-10 / Win 7              - TLS 1.0 - TLS_ECDHE_ECDSA_WITH_AES_128_CBC_SHA - ECDH-256 / secp256r1 (3072 equivalent)
[I] 			IE 11 / Win 7                - TLS 1.2 - TLS_ECDHE_ECDSA_WITH_AES_128_GCM_SHA256 - ECDH-256 / secp256r1 (3072 equivalent)
[I] 			IE 11 / Win 8.1              - TLS 1.2 - TLS_ECDHE_ECDSA_WITH_AES_128_GCM_SHA256 - ECDH-256 / secp256r1 (3072 equivalent)
[I] 			IE 10 / Win Phone 8.0        - TLS 1.0 - TLS_ECDHE_ECDSA_WITH_AES_128_CBC_SHA - ECDH-256 / secp256r1 (3072 equivalent)
[I] 			IE 11 / Win Phone 8.1        - TLS 1.2 - TLS_ECDHE_ECDSA_WITH_AES_128_GCM_SHA256 - ECDH-256 / secp256r1 (3072 equivalent)
[I] 			IE 11 / Win Phone 8.1 Update - TLS 1.2 - TLS_ECDHE_ECDSA_WITH_AES_128_GCM_SHA256 - ECDH-256 / secp256r1 (3072 equivalent)
[I] 			IE 11 / Win 10               - TLS 1.2 - TLS_ECDHE_ECDSA_WITH_AES_128_GCM_SHA256 - ECDH-256 / secp256r1 (3072 equivalent)
[I] 			Edge 13 / Win 10             - TLS 1.2 - TLS_ECDHE_ECDSA_WITH_AES_128_GCM_SHA256 - ECDH-256 / secp256r1 (3072 equivalent)
[I] 			Edge 13 / Win Phone 10       - TLS 1.2 - TLS_ECDHE_ECDSA_WITH_AES_128_GCM_SHA256 - ECDH-256 / secp256r1 (3072 equivalent)
[W] 			Java 6u45                    - Simulation Failed
[I] 			Java 7u25                    - TLS 1.0 - TLS_ECDHE_ECDSA_WITH_AES_128_CBC_SHA - ECDH-256 / secp256r1 (3072 equivalent)
[I] 			Java 8u31                    - TLS 1.2 - TLS_ECDHE_ECDSA_WITH_AES_128_GCM_SHA256 - ECDH-256 / secp256r1 (3072 equivalent)
[W] 			OpenSSL 0.9.8y               - Simulation Failed
[I] 			OpenSSL 1.0.1l               - TLS 1.2 - TLS_ECDHE_ECDSA_WITH_AES_128_GCM_SHA256 - ECDH-256 / secp256r1 (3072 equivalent)
[I] 			OpenSSL 1.0.2e               - TLS 1.2 - TLS_ECDHE_ECDSA_WITH_AES_128_GCM_SHA256 - ECDH-256 / secp256r1 (3072 equivalent)
[I] 			Safari 5.1.9 / OS X 10.6.8   - TLS 1.0 - TLS_ECDHE_ECDSA_WITH_AES_128_CBC_SHA - ECDH-256 / secp256r1 (3072 equivalent)
[I] 			Safari 6 / iOS 6.0.1         - TLS 1.2 - TLS_ECDHE_ECDSA_WITH_AES_128_CBC_SHA - ECDH-256 / secp256r1 (3072 equivalent)
[I] 			Safari 6.0.4 / OS X 10.8.4   - TLS 1.0 - TLS_ECDHE_ECDSA_WITH_AES_128_CBC_SHA - ECDH-256 / secp256r1 (3072 equivalent)
[I] 			Safari 7 / iOS 7.1           - TLS 1.2 - TLS_ECDHE_ECDSA_WITH_AES_128_CBC_SHA - ECDH-256 / secp256r1 (3072 equivalent)
[I] 			Safari 7 / OS X 10.9         - TLS 1.2 - TLS_ECDHE_ECDSA_WITH_AES_128_CBC_SHA - ECDH-256 / secp256r1 (3072 equivalent)
[I] 			Safari 8 / iOS 8.4           - TLS 1.2 - TLS_ECDHE_ECDSA_WITH_AES_128_CBC_SHA - ECDH-256 / secp256r1 (3072 equivalent)
[I] 			Safari 8 / OS X 10.10        - TLS 1.2 - TLS_ECDHE_ECDSA_WITH_AES_128_CBC_SHA - ECDH-256 / secp256r1 (3072 equivalent)
[I] 			Safari 9 / iOS 9             - TLS 1.2 - TLS_ECDHE_ECDSA_WITH_AES_128_GCM_SHA256 - ECDH-256 / secp256r1 (3072 equivalent)
[I] 			Safari 9 / OS X 10.11        - TLS 1.2 - TLS_ECDHE_ECDSA_WITH_AES_128_GCM_SHA256 - ECDH-256 / secp256r1 (3072 equivalent)
[I] 			Safari 10 / iOS 10           - TLS 1.2 - TLS_ECDHE_ECDSA_WITH_AES_128_GCM_SHA256 - ECDH-256 / secp256r1 (3072 equivalent)
[I] 			Safari 10 / OS X 10.12       - TLS 1.2 - TLS_ECDHE_ECDSA_WITH_AES_128_GCM_SHA256 - ECDH-256 / secp256r1 (3072 equivalent)
[I] 			Apple ATS 9 / iOS 9          - TLS 1.2 - TLS_ECDHE_ECDSA_WITH_AES_128_GCM_SHA256 - ECDH-256 / secp256r1 (3072 equivalent)
[I] 			Yahoo Slurp Jan 2015         - TLS 1.2 - TLS_ECDHE_ECDSA_WITH_AES_128_GCM_SHA256 - ECDH-256 / secp256r1 (3072 equivalent)
[I] 			YandexBot Jan 2015           - TLS 1.2 - TLS_ECDHE_ECDSA_WITH_AES_128_GCM_SHA256 - ECDH-256 / secp256r1 (3072 equivalent)

		Protocol & Vulnerability Information:
[I] 			DROWN: No
[I] 			Secure Renegotiation: secure renegotiation supported
[I] 			POODLE (SSL): No
[I] 			POODLE (TLS): No
[I] 			Downgrade Prevention: Yes
[I] 			Compression: No
[I] 			Heartbleed: No
[I] 			OpenSSL CCS (CVE-2014-0224): No
[I] 			OpenSSL Padding Oracle (CVE-2016-2107): No
[I] 			Forward Secrecy: Yes (all simulated clients)
[I] 			OCSP Stapling: Yes
[I] 			FREAK: No
[I] 			Logjam: No
[I] 			DH public server param (Ys) reuse: No
[I] 			Protocol Intolerance: No

Confirming your OpenSSL supports 3DES cipher suites...
TLS Session Request Limit: Checking number of requests accepted using 3DES suites...

[I] TLS Session Request Limit: Server does not support 3DES cipher suites
```

## Sample Output

Below is an example of the output from a typical `scan` with YAWAST - using `scan` - the normal go-to option, here's what you get when scanning my website:

```
$ yawast scan https://adamcaudill.com --tdessessioncount --dir --files --srv --subdomains
__   _____  _    _  ___   _____ _____ 
\ \ / / _ \| |  | |/ _ \ /  ___|_   _|
 \ V / /_\ \ |  | / /_\ \\ `--.  | |  
  \ /|  _  | |/\| |  _  | `--. \ | |  
  | || | | \  /\  / | | |/\__/ / | |  
  \_/\_| |_/\/  \/\_| |_/\____/  \_/  

YAWAST v0.6.0.beta5 - The YAWAST Antecedent Web Application Security Toolkit
 Copyright (c) 2013-2017 Adam Caudill <adam@adamcaudill.com>
 Support & Documentation: https://github.com/adamcaudill/yawast
 Ruby 2.2.4-p230; OpenSSL 1.0.2j  26 Sep 2016 (x86_64-darwin16)
 Latest Version: YAWAST v0.5.2 is the officially supported version, please update.

Scanning: https://adamcaudill.com/

DNS Information:
[I] 		104.28.27.55 (N/A)
[I] 			US - CLOUDFLARENET - CloudFlare, Inc.
			https://www.shodan.io/host/104.28.27.55
			https://censys.io/ipv4/104.28.27.55
[I] 		104.28.26.55 (N/A)
[I] 			US - CLOUDFLARENET - CloudFlare, Inc.
			https://www.shodan.io/host/104.28.26.55
			https://censys.io/ipv4/104.28.26.55
[I] 		2400:CB00:2048:1::681C:1A37 (N/A)
[I] 			US - CLOUDFLARENET - CloudFlare, Inc.
			https://www.shodan.io/host/2400:cb00:2048:1::681c:1a37
[I] 		2400:CB00:2048:1::681C:1B37 (N/A)
[I] 			US - CLOUDFLARENET - CloudFlare, Inc.
			https://www.shodan.io/host/2400:cb00:2048:1::681c:1b37
[I] 		TXT: v=spf1 mx a ptr include:_spf.google.com ~all
[I] 		TXT: brave-ledger-verification=0262b8f382f60074e0131f65243fa7caba48b15eb664ec8d0d3e0b3a26a45b47
[I] 		TXT: google-site-verification=QTO_7Q7UXmrUIwieJliLTXV3XuQdqNvTPVcug_TwH0w
[I] 		MX: aspmx5.googlemail.com (30) - 74.125.131.26 (US - GOOGLE - Google Inc.)
[I] 		MX: aspmx4.googlemail.com (30) - 108.177.96.26 (US - GOOGLE - Google Inc.)
[I] 		MX: aspmx3.googlemail.com (30) - 108.177.15.27 (US - GOOGLE - Google Inc.)
[I] 		MX: alt2.aspmx.l.google.com (20) - 108.177.15.27 (US - GOOGLE - Google Inc.)
[I] 		MX: aspmx2.googlemail.com (30) - 209.85.203.26 (US - GOOGLE - Google Inc.)
[I] 		MX: alt1.aspmx.l.google.com (20) - 209.85.203.27 (US - GOOGLE - Google Inc.)
[I] 		MX: aspmx.l.google.com (10) - 74.125.141.27 (US - GOOGLE - Google Inc.)
[I] 		NS: hal.ns.cloudflare.com - 173.245.59.174 (US - CLOUDFLARENET - CloudFlare, Inc.)
[I] 		NS: vera.ns.cloudflare.com - 173.245.58.147 (US - CLOUDFLARENET - CloudFlare, Inc.)
[I] 		SRV: _bittorrent._tcp.adamcaudill.com: example.com:1 - 93.184.216.34 (US - EDGECAST - MCI Communications Services, Inc. d/b/a Verizon Business)
[I] 		A: www.adamcaudill.com: 104.28.27.55 (US - CLOUDFLARENET - CloudFlare, Inc.)
[I] 		A: www.adamcaudill.com: 104.28.26.55 (US - CLOUDFLARENET - CloudFlare, Inc.)
[I] 		CAA (adamcaudill.com): 0 iodef "mailto:adam@adamcaudill.com"
[I] 		CAA (adamcaudill.com): 0 issue "letsencrypt.org"
[I] 		CAA (adamcaudill.com): 0 issue "globalsign.com"
[I] 		CAA (adamcaudill.com): 0 issue "comodoca.com"
[I] 		CAA (adamcaudill.com): 0 issue "digicert.com"
[I] 		CAA (com): No Records Found

[I] HEAD:
[I] 		date: Sun, 22 Oct 2017 14:56:30 GMT
[I] 		content-type: text/html; charset=UTF-8
[I] 		connection: close
[I] 		set-cookie: __cfduid=0123456789abcdef; expires=Mon, 22-Oct-18 14:56:29 GMT; path=/; domain=.adamcaudill.com; HttpOnly; Secure
[I] 		vary: Accept-Encoding,Cookie
[I] 		last-modified: Fri, 13 Oct 2017 19:39:19 GMT
[I] 		x-content-type-options: nosniff
[I] 		x-frame-options: sameorigin
[I] 		pragma: public
[I] 		cache-control: public, max-age=86400
[I] 		cf-cache-status: REVALIDATED
[I] 		expires: Mon, 23 Oct 2017 14:56:30 GMT
[I] 		strict-transport-security: max-age=15552000; preload
[I] 		server: cloudflare-nginx
[I] 		cf-ray: 0123456789abcdef-MIA

[I] NOTE: Server appears to be Cloudflare; WAF may be in place.

[I] X-Frame-Options Header: sameorigin
[I] X-Content-Type-Options Header: nosniff
[W] Content-Security-Policy Header Not Present
[W] Public-Key-Pins Header Not Present

[I] Cookies:
[I] 		__cfduid=0123456789abcdef; expires=Mon, 22-Oct-18 14:56:29 GMT; path=/; domain=.adamcaudill.com; HttpOnly; Secure
[W] 			Cookie missing SameSite flag


Beginning SSL Labs scan (this could take a minute or two)
[SSL Labs] This assessment service is provided free of charge by Qualys SSL Labs, subject to our terms and conditions: https://www.ssllabs.com/about/terms.html
.............................

	SSL Labs: https://www.ssllabs.com/ssltest/analyze.html?d=adamcaudill.com&hideResults=on

[I] IP: 104.28.27.55 - Grade: A+

	Certificate Information:
[I] 		Subject: CN=sni67677.cloudflaressl.com, OU=PositiveSSL Multi-Domain, OU=Domain Control Validated
[I] 		Common Names: sni67677.cloudflaressl.com
[I] 		Alternative names:
[I] 			sni67677.cloudflaressl.com
[I] 			*.adamcaudill.com
[I] 			adamcaudill.com
[I] 		Not Before: 2017-07-26T00:00:00+00:00
[I] 		Not After: 2018-02-01T23:59:59+00:00
[I] 		Key: EC 256 (RSA equivalent: 3072)
[I] 		Public Key Hash: 045a733405a4046b5bcc8abbd1e1cbd1d1d3b55c
[I] 		Version: 2
[I] 		Serial: 77574794376740264441751965250081500687
[I] 		Issuer: CN=COMODO ECC Domain Validation Secure Server CA 2, O=COMODO CA Limited, L=Salford, ST=Greater Manchester, C=GB
[I] 		Signature algorithm: SHA256withECDSA
[I] 		Extended Validation: No (Domain Control)
[I] 		Certificate Transparency: No
[I] 		OCSP Must Staple: false
[I] 		Revocation information: CRL information available
[I] 		Revocation information: OCSP information available
[I] 		Revocation status: certificate not revoked
[I] 		Extensions:
[I] 			authorityKeyIdentifier = keyid:40:09:61:67:F0:BC:83:71:4F:DE:12:08:2C:6F:D4:D4:2B:76:3D:96, 
[I] 			subjectKeyIdentifier = D0:F8:D6:82:36:B5:5C:AC:2D:9A:8E:7B:D9:D5:E6:99:38:B6:8C:FE
[I] 			keyUsage = critical, Digital Signature
[I] 			basicConstraints = critical, CA:FALSE
[I] 			extendedKeyUsage = TLS Web Server Authentication, TLS Web Client Authentication
[I] 			certificatePolicies = Policy: 1.3.6.1.4.1.6449.1.2.2.7,   CPS: https://secure.comodo.com/CPS, Policy: 2.23.140.1.2.1, 
[I] 			crlDistributionPoints = , Full Name:,   URI:http://crl.comodoca4.com/COMODOECCDomainValidationSecureServerCA2.crl, 
[I] 			authorityInfoAccess = CA Issuers - URI:http://crt.comodoca4.com/COMODOECCDomainValidationSecureServerCA2.crt, OCSP - URI:http://ocsp.comodoca4.com, 
[I] 		Hash: 2cf22bbb21e5a3eaa042feadc8fbc86ff0d3b1e1
			https://censys.io/certificates?q=2cf22bbb21e5a3eaa042feadc8fbc86ff0d3b1e1
			https://crt.sh/?q=2cf22bbb21e5a3eaa042feadc8fbc86ff0d3b1e1

[I] 		Certificate Chains:
		  Path 1:
[I] 			CN=sni67677.cloudflaressl.com, OU=PositiveSSL Multi-Domain, OU=Domain Control Validated
[I] 			  Signature: SHA256withECDSA  Key: EC-256
[I] 			  https://crt.sh/?q=2cf22bbb21e5a3eaa042feadc8fbc86ff0d3b1e1
[I] 			CN=COMODO ECC Domain Validation Secure Server CA 2, O=COMODO CA Limited, L=Salford, ST=Greater Manchester, C=GB
[I] 			  Signature: SHA384withECDSA  Key: EC-256
[I] 			  https://crt.sh/?q=75cfd9bc5cefa104ecc1082d77e63392ccba5291
[I] 			CN=COMODO ECC Certification Authority, O=COMODO CA Limited, L=Salford, ST=Greater Manchester, C=GB
[I] 			  Signature: SHA384withECDSA  Key: EC-384
[I] 			  https://crt.sh/?q=9f744e9f2b4dbaec0f312c50b6563b8e2d93c311
		  Path 2:
[I] 			CN=sni67677.cloudflaressl.com, OU=PositiveSSL Multi-Domain, OU=Domain Control Validated
[I] 			  Signature: SHA256withECDSA  Key: EC-256
[I] 			  https://crt.sh/?q=2cf22bbb21e5a3eaa042feadc8fbc86ff0d3b1e1
[I] 			CN=COMODO ECC Domain Validation Secure Server CA 2, O=COMODO CA Limited, L=Salford, ST=Greater Manchester, C=GB
[I] 			  Signature: SHA384withECDSA  Key: EC-256
[I] 			  https://crt.sh/?q=75cfd9bc5cefa104ecc1082d77e63392ccba5291
[I] 			CN=COMODO ECC Certification Authority, O=COMODO CA Limited, L=Salford, ST=Greater Manchester, C=GB
[I] 			  Signature: SHA384withRSA  Key: EC-384
[I] 			  https://crt.sh/?q=ae223cbf20191b40d7ffb4ea5701b65fdc68a1ca
[I] 			CN=AddTrust External CA Root, OU=AddTrust External TTP Network, O=AddTrust AB, C=SE
[I] 			  Signature: SHA1withRSA  Key: RSA-2048
[I] 			  https://crt.sh/?q=02faf3e291435468607857694df5e45b68851868

	Configuration Information:
		Protocol Support:
[I] 			TLS 1.0
[I] 			TLS 1.1
[I] 			TLS 1.2
[I] 			TLS 1.3

		Named Group Support:
[I] 			x25519 256
[I] 			secp256r1 256
[I] 			secp384r1 384
[I] 			secp224r1 224
[I] 			secp521r1 521

		Cipher Suite Support:
[I] 			TLS 1.0
[I] 			  TLS_ECDHE_ECDSA_WITH_AES_128_CBC_SHA               - 128-bits - ECDH-256 / x25519 (3072 equivalent)
[I] 			  TLS_ECDHE_ECDSA_WITH_AES_256_CBC_SHA               - 256-bits - ECDH-256 / x25519 (3072 equivalent)
[I] 			TLS 1.1
[I] 			  TLS_ECDHE_ECDSA_WITH_AES_128_CBC_SHA               - 128-bits - ECDH-256 / x25519 (3072 equivalent)
[I] 			  TLS_ECDHE_ECDSA_WITH_AES_256_CBC_SHA               - 256-bits - ECDH-256 / x25519 (3072 equivalent)
[I] 			TLS 1.2
[I] 			  TLS_ECDHE_ECDSA_WITH_AES_128_GCM_SHA256            - 128-bits - ECDH-256 / x25519 (3072 equivalent)
[I] 			  OLD_TLS_ECDHE_ECDSA_WITH_CHACHA20_POLY1305_SHA256  - 256-bits - ECDH-256 / x25519 (3072 equivalent)
[I] 			  TLS_ECDHE_ECDSA_WITH_CHACHA20_POLY1305_SHA256      - 256-bits - ECDH-256 / x25519 (3072 equivalent)
[I] 			  TLS_ECDHE_ECDSA_WITH_AES_128_CBC_SHA               - 128-bits - ECDH-256 / x25519 (3072 equivalent)
[I] 			  TLS_ECDHE_ECDSA_WITH_AES_128_CBC_SHA256            - 128-bits - ECDH-256 / x25519 (3072 equivalent)
[I] 			  TLS_ECDHE_ECDSA_WITH_AES_256_GCM_SHA384            - 256-bits - ECDH-256 / x25519 (3072 equivalent)
[I] 			  TLS_ECDHE_ECDSA_WITH_AES_256_CBC_SHA               - 256-bits - ECDH-256 / x25519 (3072 equivalent)
[I] 			  TLS_ECDHE_ECDSA_WITH_AES_256_CBC_SHA384            - 256-bits - ECDH-256 / x25519 (3072 equivalent)
[I] 			TLS 1.3
[I] 			  TLS_AES_128_GCM_SHA256                             - 128-bits - ECDH-256 / x25519 (3072 equivalent)
[I] 			  TLS_AES_256_GCM_SHA384                             - 256-bits - ECDH-256 / x25519 (3072 equivalent)
[I] 			  TLS_CHACHA20_POLY1305_SHA256                       - 256-bits - ECDH-256 / x25519 (3072 equivalent)

		Handshake Simulation:
[W] 			Android 2.3.7                - Simulation Failed
[I] 			Android 4.0.4                - TLS 1.0 - TLS_ECDHE_ECDSA_WITH_AES_128_CBC_SHA - ECDH-256 / secp256r1 (3072 equivalent)
[I] 			Android 4.1.1                - TLS 1.0 - TLS_ECDHE_ECDSA_WITH_AES_128_CBC_SHA - ECDH-256 / secp256r1 (3072 equivalent)
[I] 			Android 4.2.2                - TLS 1.0 - TLS_ECDHE_ECDSA_WITH_AES_128_CBC_SHA - ECDH-256 / secp256r1 (3072 equivalent)
[I] 			Android 4.3                  - TLS 1.0 - TLS_ECDHE_ECDSA_WITH_AES_128_CBC_SHA - ECDH-256 / secp256r1 (3072 equivalent)
[I] 			Android 4.4.2                - TLS 1.2 - TLS_ECDHE_ECDSA_WITH_AES_128_GCM_SHA256 - ECDH-256 / secp256r1 (3072 equivalent)
[I] 			Android 5.0.0                - TLS 1.2 - OLD_TLS_ECDHE_ECDSA_WITH_CHACHA20_POLY1305_SHA256 - ECDH-256 / secp256r1 (3072 equivalent)
[I] 			Android 6.0                  - TLS 1.2 - OLD_TLS_ECDHE_ECDSA_WITH_CHACHA20_POLY1305_SHA256 - ECDH-256 / secp256r1 (3072 equivalent)
[I] 			Android 7.0                  - TLS 1.2 - TLS_ECDHE_ECDSA_WITH_CHACHA20_POLY1305_SHA256 - ECDH-256 / x25519 (3072 equivalent)
[I] 			Baidu Jan 2015               - TLS 1.0 - TLS_ECDHE_ECDSA_WITH_AES_128_CBC_SHA - ECDH-256 / secp256r1 (3072 equivalent)
[I] 			BingPreview Jan 2015         - TLS 1.2 - TLS_ECDHE_ECDSA_WITH_AES_128_GCM_SHA256 - ECDH-256 / secp256r1 (3072 equivalent)
[W] 			Chrome 49 / XP SP3           - Simulation Failed
[I] 			Chrome 57 / Win 7            - TLS 1.3 - TLS_AES_128_GCM_SHA256 - ECDH-256 / x25519 (3072 equivalent)
[I] 			Firefox 31.3.0 ESR / Win 7   - TLS 1.2 - TLS_ECDHE_ECDSA_WITH_AES_128_GCM_SHA256 - ECDH-256 / secp256r1 (3072 equivalent)
[I] 			Firefox 47 / Win 7           - TLS 1.2 - TLS_ECDHE_ECDSA_WITH_AES_128_GCM_SHA256 - ECDH-256 / secp256r1 (3072 equivalent)
[I] 			Firefox 49 / XP SP3          - TLS 1.2 - TLS_ECDHE_ECDSA_WITH_AES_128_GCM_SHA256 - ECDH-256 / secp256r1 (3072 equivalent)
[I] 			Firefox 53 / Win 7           - TLS 1.3 - TLS_AES_128_GCM_SHA256 - ECDH-256 / x25519 (3072 equivalent)
[I] 			Googlebot Feb 2015           - TLS 1.2 - TLS_ECDHE_ECDSA_WITH_AES_128_GCM_SHA256 - ECDH-256 / secp256r1 (3072 equivalent)
[W] 			IE 6 / XP                    - Simulation Failed
[I] 			IE 7 / Vista                 - TLS 1.0 - TLS_ECDHE_ECDSA_WITH_AES_128_CBC_SHA - ECDH-256 / secp256r1 (3072 equivalent)
[W] 			IE 8 / XP                    - Simulation Failed
[I] 			IE 8-10 / Win 7              - TLS 1.0 - TLS_ECDHE_ECDSA_WITH_AES_128_CBC_SHA - ECDH-256 / secp256r1 (3072 equivalent)
[I] 			IE 11 / Win 7                - TLS 1.2 - TLS_ECDHE_ECDSA_WITH_AES_128_GCM_SHA256 - ECDH-256 / secp256r1 (3072 equivalent)
[I] 			IE 11 / Win 8.1              - TLS 1.2 - TLS_ECDHE_ECDSA_WITH_AES_128_GCM_SHA256 - ECDH-256 / secp256r1 (3072 equivalent)
[I] 			IE 10 / Win Phone 8.0        - TLS 1.0 - TLS_ECDHE_ECDSA_WITH_AES_128_CBC_SHA - ECDH-256 / secp256r1 (3072 equivalent)
[I] 			IE 11 / Win Phone 8.1        - TLS 1.2 - TLS_ECDHE_ECDSA_WITH_AES_128_GCM_SHA256 - ECDH-256 / secp256r1 (3072 equivalent)
[I] 			IE 11 / Win Phone 8.1 Update - TLS 1.2 - TLS_ECDHE_ECDSA_WITH_AES_128_GCM_SHA256 - ECDH-256 / secp256r1 (3072 equivalent)
[I] 			IE 11 / Win 10               - TLS 1.2 - TLS_ECDHE_ECDSA_WITH_AES_128_GCM_SHA256 - ECDH-256 / secp256r1 (3072 equivalent)
[I] 			Edge 13 / Win 10             - TLS 1.2 - TLS_ECDHE_ECDSA_WITH_AES_128_GCM_SHA256 - ECDH-256 / secp256r1 (3072 equivalent)
[I] 			Edge 13 / Win Phone 10       - TLS 1.2 - TLS_ECDHE_ECDSA_WITH_AES_128_GCM_SHA256 - ECDH-256 / secp256r1 (3072 equivalent)
[W] 			Java 6u45                    - Simulation Failed
[I] 			Java 7u25                    - TLS 1.0 - TLS_ECDHE_ECDSA_WITH_AES_128_CBC_SHA - ECDH-256 / secp256r1 (3072 equivalent)
[I] 			Java 8u31                    - TLS 1.2 - TLS_ECDHE_ECDSA_WITH_AES_128_GCM_SHA256 - ECDH-256 / secp256r1 (3072 equivalent)
[W] 			OpenSSL 0.9.8y               - Simulation Failed
[I] 			OpenSSL 1.0.1l               - TLS 1.2 - TLS_ECDHE_ECDSA_WITH_AES_128_GCM_SHA256 - ECDH-256 / secp256r1 (3072 equivalent)
[I] 			OpenSSL 1.0.2e               - TLS 1.2 - TLS_ECDHE_ECDSA_WITH_AES_128_GCM_SHA256 - ECDH-256 / secp256r1 (3072 equivalent)
[I] 			Safari 5.1.9 / OS X 10.6.8   - TLS 1.0 - TLS_ECDHE_ECDSA_WITH_AES_128_CBC_SHA - ECDH-256 / secp256r1 (3072 equivalent)
[I] 			Safari 6 / iOS 6.0.1         - TLS 1.2 - TLS_ECDHE_ECDSA_WITH_AES_128_CBC_SHA - ECDH-256 / secp256r1 (3072 equivalent)
[I] 			Safari 6.0.4 / OS X 10.8.4   - TLS 1.0 - TLS_ECDHE_ECDSA_WITH_AES_128_CBC_SHA - ECDH-256 / secp256r1 (3072 equivalent)
[I] 			Safari 7 / iOS 7.1           - TLS 1.2 - TLS_ECDHE_ECDSA_WITH_AES_128_CBC_SHA - ECDH-256 / secp256r1 (3072 equivalent)
[I] 			Safari 7 / OS X 10.9         - TLS 1.2 - TLS_ECDHE_ECDSA_WITH_AES_128_CBC_SHA - ECDH-256 / secp256r1 (3072 equivalent)
[I] 			Safari 8 / iOS 8.4           - TLS 1.2 - TLS_ECDHE_ECDSA_WITH_AES_128_CBC_SHA - ECDH-256 / secp256r1 (3072 equivalent)
[I] 			Safari 8 / OS X 10.10        - TLS 1.2 - TLS_ECDHE_ECDSA_WITH_AES_128_CBC_SHA - ECDH-256 / secp256r1 (3072 equivalent)
[I] 			Safari 9 / iOS 9             - TLS 1.2 - TLS_ECDHE_ECDSA_WITH_AES_128_GCM_SHA256 - ECDH-256 / secp256r1 (3072 equivalent)
[I] 			Safari 9 / OS X 10.11        - TLS 1.2 - TLS_ECDHE_ECDSA_WITH_AES_128_GCM_SHA256 - ECDH-256 / secp256r1 (3072 equivalent)
[I] 			Safari 10 / iOS 10           - TLS 1.2 - TLS_ECDHE_ECDSA_WITH_AES_128_GCM_SHA256 - ECDH-256 / secp256r1 (3072 equivalent)
[I] 			Safari 10 / OS X 10.12       - TLS 1.2 - TLS_ECDHE_ECDSA_WITH_AES_128_GCM_SHA256 - ECDH-256 / secp256r1 (3072 equivalent)
[I] 			Apple ATS 9 / iOS 9          - TLS 1.2 - TLS_ECDHE_ECDSA_WITH_AES_128_GCM_SHA256 - ECDH-256 / secp256r1 (3072 equivalent)
[I] 			Yahoo Slurp Jan 2015         - TLS 1.2 - TLS_ECDHE_ECDSA_WITH_AES_128_GCM_SHA256 - ECDH-256 / secp256r1 (3072 equivalent)
[I] 			YandexBot Jan 2015           - TLS 1.2 - TLS_ECDHE_ECDSA_WITH_AES_128_GCM_SHA256 - ECDH-256 / secp256r1 (3072 equivalent)

		Protocol & Vulnerability Information:
[I] 			DROWN: No
[I] 			Secure Renegotiation: secure renegotiation supported
[I] 			POODLE (SSL): No
[I] 			POODLE (TLS): No
[I] 			Downgrade Prevention: Yes
[I] 			Compression: No
[I] 			Heartbleed: No
[I] 			OpenSSL CCS (CVE-2014-0224): No
[I] 			OpenSSL Padding Oracle (CVE-2016-2107): No
[I] 			Forward Secrecy: Yes (all simulated clients)
[I] 			OCSP Stapling: Yes
[I] 			FREAK: No
[I] 			Logjam: No
[I] 			DH public server param (Ys) reuse: No
[I] 			Protocol Intolerance: No

Confirming your OpenSSL supports 3DES cipher suites...
TLS Session Request Limit: Checking number of requests accepted using 3DES suites...

[I] TLS Session Request Limit: Server does not support 3DES cipher suites

[I] HSTS: Enabled (strict-transport-security: max-age=15552000; preload)
[I] HSTS Preload: Chrome - false; Firefox - false; Tor - false
SSL-Session:
    Protocol  : TLSv1.2
    Cipher    : ECDHE-ECDSA-AES128-GCM-SHA256
    Session-ID: FFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFF
    Session-ID-ctx: 
    Master-Key: FFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFF
    Key-Arg   : None
    PSK identity: None
    PSK identity hint: None
    SRP username: None
    TLS session ticket lifetime hint: 64800 (seconds)
    TLS session ticket:
    0000 - ff ff ff ff ff ff ff ff-ff ff ff ff ff ff ff ff   ................
    0010 - ff ff ff ff ff ff ff ff-ff ff ff ff ff ff ff ff   ................
    0020 - ff ff ff ff ff ff ff ff-ff ff ff ff ff ff ff ff   ................
    0030 - ff ff ff ff ff ff ff ff-ff ff ff ff ff ff ff ff   ................
    0040 - ff ff ff ff ff ff ff ff-ff ff ff ff ff ff ff ff   ................
    0050 - ff ff ff ff ff ff ff ff-ff ff ff ff ff ff ff ff   ................
    0060 - ff ff ff ff ff ff ff ff-ff ff ff ff ff ff ff ff   ................
    0070 - ff ff ff ff ff ff ff ff-ff ff ff ff ff ff ff ff   ................
    0080 - ff ff ff ff ff ff ff ff-ff ff ff ff ff ff ff ff   ................
    0090 - ff ff ff ff ff ff ff ff-ff ff ff ff ff ff ff ff   ................
    00a0 - ff ff ff ff ff ff ff ff-ff ff ff ff ff ff ff ff   ................
    00b0 - ff ff ff ff ff ff ff ff-ff ff ff ff ff ff ff ff   ................
    00c0 - ff ff ff ff ff ff ff ff-ff ff ff ff ff ff ff ff   ................

    Start Time: 1508684351
    Timeout   : 300 (sec)
    Verify return code: 20 (unable to get local issuer certificate)

[W] '/readme.html' found: https://adamcaudill.com/readme.html


Checking for common files (this will take a few minutes)...
[I] '/favicon.ico' found: https://adamcaudill.com/favicon.ico
[I] '/keybase.txt' found: https://adamcaudill.com/keybase.txt
[I] '/license.txt' found: https://adamcaudill.com/license.txt
[I] '/robots.txt' found: https://adamcaudill.com/robots.txt
[I] '/sitemap_index.xml' found: https://adamcaudill.com/sitemap_index.xml
[I] '/tools' found: https://adamcaudill.com/tools
[I] '/wp-config.php' found: https://adamcaudill.com/wp-config.php
[I] '/wp-cron.php' found: https://adamcaudill.com/wp-cron.php
[I] '/wp-links-opml.php' found: https://adamcaudill.com/wp-links-opml.php
[I] '/wp-json' found: https://adamcaudill.com/wp-json
[I] '/wp-load.php' found: https://adamcaudill.com/wp-load.php
[I] '/wp-login.php' found: https://adamcaudill.com/wp-login.php
[I] '/wp-json/wp/v2/users' found: https://adamcaudill.com/wp-json/wp/v2/users
[I] '/wp-json/wp/v2/posts' found: https://adamcaudill.com/wp-json/wp/v2/posts

[I] Allow HTTP Verbs (OPTIONS): GET,HEAD,POST,OPTIONS

Searching for common directories...
[I] 	Found: 'https://adamcaudill.com//'
[I] 	Found: 'https://adamcaudill.com/0000/'
[I] 	Found: 'https://adamcaudill.com/2006/'
[I] 	Found: 'https://adamcaudill.com/2003/'
[I] 	Found: 'https://adamcaudill.com/2005/'
[I] 	Found: 'https://adamcaudill.com/2007/'
[I] 	Found: 'https://adamcaudill.com/2004/'
[I] 	Found: 'https://adamcaudill.com/2008/'
[I] 	Found: 'https://adamcaudill.com/2009/'
[I] 	Found: 'https://adamcaudill.com/2011/'
[I] 	Found: 'https://adamcaudill.com/2012/'
[I] 	Found: 'https://adamcaudill.com/2016/'
[I] 	Found: 'https://adamcaudill.com/2014/'
[I] 	Found: 'https://adamcaudill.com/2010/'
[I] 	Found: 'https://adamcaudill.com/2013/'
[I] 	Found: 'https://adamcaudill.com/2015/'
[I] 	Found: 'https://adamcaudill.com/2017/'
[I] 	Found: 'https://adamcaudill.com/ABOUT/'
[I] 	Found: 'https://adamcaudill.com/ARCHIVES/'
[I] 	Found: 'https://adamcaudill.com/About/'
[I] 	Found: 'https://adamcaudill.com/Archives/'
[I] 	Found: 'https://adamcaudill.com/BLOG/'
[I] 	Found: 'https://adamcaudill.com/Blog/'
[I] 	Found: 'https://adamcaudill.com/Photo/'
[I] 	Found: 'https://adamcaudill.com/Resume/'
[I] 	Found: 'https://adamcaudill.com/TOOLS/'
[I] 	Found: 'https://adamcaudill.com/Tools/'
[I] 	Found: 'https://adamcaudill.com/about/'
[I] 	Found: 'https://adamcaudill.com/archives/'
[I] 	Found: 'https://adamcaudill.com/blog/'
[I] 	Found: 'https://adamcaudill.com/feed/'
[I] 	Found: 'https://adamcaudill.com/pgp/'
[I] 	Found: 'https://adamcaudill.com/photo/'
[I] 	Found: 'https://adamcaudill.com/reading/'
[I] 	Found: 'https://adamcaudill.com/resume/'
[I] 	Found: 'https://adamcaudill.com/speaking/'
[I] 	Found: 'https://adamcaudill.com/tools/'
[I] 	Found: 'https://adamcaudill.com/wp-content/'

[I] Meta Generator: WordPress 4.8.2
Scan complete (00:51:05 seconds).
```



