# TSforge for Windows 7 build 6469

## Introduction

**[Windows 7 build 6469](https://betawiki.net/wiki/Windows_7_build_6469)** is the earliest available build of [Windows 7](https://betawiki.net/wiki/Windows_7), which was compiled on October 2nd, 2007, and uploaded to [BetaArchive](https://betawiki.net/wiki/BetaArchive) *(later taken down)* on April 26th, 2011. 

**You can download this build from [archive.org](https://archive.org/details/6469.1.071002-1531-x-86fre-client-en-us-gb-1-culxfre-en-dvd).**

Running this build requires the hardware clock to be set to a date between October 2, 2007 *(its compile date)* and April 4, 2008, when its timebomb expires and the system becomes effectively unusable.

Due to its earliness, this build identifies itself as [Windows Vista](https://betawiki.net/wiki/Windows_Vista) in most areas. Curiously, the EULA refers to this build as "Microsoft Windows Vista Service Pack 1", implying that this build was forked from an early Windows Vista Service Pack 1 build, which we’ll see reflected heavily in this build’s activation system.

The goal of this project is to port over MASSGRAVE's [TSforge](https://github.com/massgravel/TSforge) *(with both its ZeroCID and KMS4k methods)* to this specific build, allowing permanent *or effectively infinite* activation.

## A Meaningless Goal
### Background

Windows activation is managed by a subsystem called the Software Protection Platform (SPP). SPP stores information about the activation state in files called the "physical store" and "token store". The physical store's contents are cryptographically protected and integrity-checked by `sppsvc`/`spsys`, preventing users from easily modifying it.

The physical store for **Windows 7 build 6469** is found at `C:\Windows\System32\7B296FB0-376B-497e-B012-9C450E1B7327-2-0.C7483456-A289-439d-8115-601632D005A0` and `C:\Windows\System32\7B296FB0-376B-497e-B012-9C450E1B7327-2-1.C7483456-A289-439d-8115-601632D005A0`, similar to where Windows Vista's physical store is located.

Normally, accessing the physical store on this build *(and on Windows Vista in general)* isn’t really possible, because `spsys.sys`, a key driver used by the Software Protection Platform (SPP), holds a permanent handle on it. Unlike later versions of Windows, Vista doesn’t provide any built-in way for SlSvc *(renamed to **sppsvc** in this build)* to tell the driver to unload, so there’s no straightforward method to free that handle.

However, thanks to the work of [@InvoxiPlayGames](https://github.com/InvoxiPlayGames) on [vistaspctl](https://github.com/InvoxiPlayGames/vistaspctl), and its later integration into TSforge, this limitation is effectively bypassed, revealing that the underlying SPP loader driver exposes a set of unused `ioctls` that let you manually start and stop the protection driver without relying on SlSvc. In practice, this means the driver can be safely paused long enough to access the physical store and then restarted afterward, something that would otherwise be impossible on Vista.

With this information, the next step was to try porting [ZeroCID](https://massgrave.dev/tsforge#zerocid) *(and later on KMS4k)* to build 6469. It didn’t take long to realize that this build had its own set of complications, making this harder than initially anticipated.

### Vista Meets 7

Windows 7 build 6469 presented a unique challenge because it's a transitional build with characteristics of both Windows Vista and Windows 7. This meant that the existing ZeroCID *(and KMS4k)* implementations for Vista and 7 in TSforge simply wouldn't work. 

Research revealed the following:

- The physical store uses **Vista's structure** (no key namespace in blocks)
  
- The cryptography uses **Vista's salted SHA-1** (not Windows 7's HMAC)
  
- Internally, the data format uses Windows 7's CRC blocks (`CRCBlockModern`)
 
- The timer structure uses **Vista's simple format** (16 bytes instead of Windows 7's 32 bytes)

For KMS4k:
 
- The KMS paths follow Windows 7's convention `msft:spp/kms/bind/2.0/...`

With this information in hand, it was only a matter of changing things around to make ZeroCID functional.

### Making It Work

The implementation required several specific changes to handle Windows 7 build 6469's hybrid nature:

- **Unified the IID hash generation:** Build 6469 uses the same SHA-256 hashing as Windows 7 (full 32 bytes) rather than Vista's truncated 16-byte version.

- **Updated product key data handling:** The code now checks for `SppPkeyShortAuthenticator` *(from Windows 7)* first before falling back to `PKeyBasicInfo` *(from Vista)*, as build 6469 stores key data using the newer format.

- **Used Windows 7's phone activation version:** Changed from conditional versioning to always use phone version `"7.0"` and index by `pkeyId` rather than `actId`.

With these changes, `TSforge.exe /ver vista /zcid` **successfully activates Windows 7 build 6469 permanently**.

<div align="center">
<img width="800" height="600" alt="image" src="https://github.com/user-attachments/assets/1c6be4b1-0bfa-483f-a3ed-a712bbbf9345" />

<em>Figure 1: Windows 7 build 6469 activated permanently using ZeroCID.</em>

<img width="800" height="600" alt="image" src="https://github.com/user-attachments/assets/cc607a22-56a6-42cb-b486-2d7a7b7e3e8e" />

<em>Figure 2: `slmgr /dli` showing the activation status of Windows.</em>
</div>

These tests were all conducted using Windows Vista Business as the installed edition.

#### The following retail Generic Keys can be used to install this build, and subsequently activated using ZeroCID:

Edition|EditionID|Generic Key|Key Type
----|----|----|----
Business|Business|4D2XH-PRBMM-8Q22B-K8BM3-MRW4W|Retail
Business N|BusinessN|76884-QXFY2-6Q2WX-2QTQ8-QXX44|Retail
Enterprise|Enterprise|YQPQV-RW8R3-XMPFG-RXG9R-JGTVF|Retail
Enterprise N|EnterpriseN|Q7J9R-G63R4-BFMHF-FWM9R-RWDMV|Retail
Home Basic|HomeBasic|RCG7P-TX42D-HM8FM-TCFCW-3V4VD|Retail
Home Basic N|HomeBasicN|HY2VV-XC6FF-MD6WV-FPYBQ-GFJBT|Retail
Home Premium|HomePremium|X9HTF-MKJQQ-XK376-TJ7T4-76PKF|Retail
Home Premium N|HomePremiumN|KJ6TP-PF9W2-23T3Q-XTV7M-PXDT2|Retail
Starter|Starter|X9PYV-YBQRV-9BXWV-TQDMK-QDWK4|Retail
Ultimate|Ultimate|VMCB9-FDRV6-6CDQM-RV23K-RP8F7|Retail
Ultimate N|UltimateN|CVX38-P27B4-2X8BT-RXD4J-V7CKX|Retail

## Time Is Infinite

Using [KMS4k](https://massgrave.dev/tsforge#kms4k), fake cached KMS server response data is directly written to the trusted store. Unlike via normal KMS emulators, this method can arbitrarily set the activation expiration up to a maximum of 2,147,483,640 (2³¹ − 8) minutes, or 4083 years.

This allows for offline KMS activation that is effectively infinite for all practical purposes.

### From Vista to 7, and Back Again

Since ZeroCID already forced me to reverse the hybrid licensing behavior in build 6469, getting KMS4k running afterwards wasn’t especially painful, as most of the digging had already been done. And, just like previous research indicated, the KMS object paths ended up matching Windows 7’s format exactly: `msft:spp/kms/bind/2.0/...`.

However, the original Vista KMS4k code used an entirely different approach, writing raw binary data with length prefixes instead of using variable bags. Build 6469 needed the Windows 7 approach: a proper variable bag containing three `CRCBlockModern` blocks (KMS response, `msft:rm/algorithm/hwid/4.0`, and `SppBindingLicenseData`).

#### The key implementation changes were:

- Modified the Vista code path to create a VariableBag with `CRCBlockModern` blocks instead of raw binary data, matching Windows 7's structure while using Vista's simpler `VistaTimer` *(16 bytes instead of 32)*.

- Fixed variable bag serialization to properly encode blocks based on their actual type. The original code assumed Vista versions only used `CRCBlockVista`, but build 6469 needed `CRCBlockModern` blocks to serialize correctly even when using `PSVersion.Vista`.

- Used Windows 7's KMS paths (`msft:spp/kms/bind/2.0/store` and `msft:spp/kms/bind/2.0/timer`) instead of Vista's old paths, while maintaining Vista's physical store structure.

The solution was validated by comparing physical store dumps before and after a KMS activation using [vlmcsd](https://github.com/Wind4/vlmcsd), ensuring the data matched the exact format build 6469 expected.

After these changes, `TSforge.exe /ver vista /kms4k` successfully activates build 6469 with an effectively infinite expiration.

<div align="center">
<img width="800" height="600" alt="image" src="https://github.com/user-attachments/assets/0d5df8e2-ce5d-4581-9f4e-03a9afcf0d7b" />

<em>Windows 7 build 6469 activated with a volume activation expiration of 2,147,480,760 minutes using KMS4k.</em>

#### The following Generic Volume License Keys (GVLKs) can be used to install this build, and subsequently activated using KMS4k:

Edition|EditionID|Generic Volume License Key
----|----|----
Enterprise|Enterprise|VKK3X-68KWM-X2YGT-QR4M6-4BWMV
Business|Business|YFKBB-PQJJV-G996G-VWGXY-2V3X8
BusinessN|BusinessN|HMBQG-8H2RH-C77VX-27R82-VMQBT
EnterpriseN|EnterpriseN|VTC42-BM838-43QHV-84HX6-XJXKV

</div>

## Usage

Activating **[Windows 7 build 6469](https://betawiki.net/wiki/Windows_7_build_6469)** using this fork of [TSforge](https://github.com/massgravel/TSforge) is simple and involves the same steps one would take to activate Vista with TSforge.

*You'll need to follow the [build instructions](https://github.com/lava1879/TSforge?tab=readme-ov-file#build-instructions) first in order to obtain ready to use, built binaries.* 

1. Open the folder containing the binaries in an elevated command prompt.
2. Copy over **[System.Core.dll](https://gofile.io/d/eqx0eW)** to the folder containing the binaries.
3. Run `TSforge.exe /ver vista /zcid` for ZeroCID, or `TSforge.exe /ver vista /kms4k` for KMS4k.
4. **Windows 7 build 6469 should now be activated** using either activation method you used. `slmgr /dlv` can be used to check the activation status and its details.

This fork of TSforge is very unlikely to work on any other build of Windows. If you're interested in activating anything other beta builds or any Windows build in general, refer to [Microsoft Activation Scripts](https://massgrave.dev/).

## FAQ

### What should I do if I see a "Windows license is expired" message?

This build requires the system clock to be set between October 2, 2007 *(its compile date)* and April 4, 2008. Once the timebomb expires, Windows will display this message at login, effectively rendering the system unusable.

### How can I get help with activation or related issues?

You can create a new issue on the project repository, and I’ll investigate it.

### Why would anyone activate this build?

While it's pointless, activating it can be interesting for enthusiasts. This build offers a unique glimpse into early Windows 7 development, and allowed me to experiment with TSforge’s ZeroCID and KMS4k activation techniques on Windows 7's very first known build.

### How can I learn more about TSforge, its team and its inner workings?

You can check out [TSforge's GitHub repository](https://github.com/massgravel/TSforge), [its blog post](https://massgrave.dev/blog/tsforge), or [its documentation in MAS](https://massgrave.dev/tsforge).

## License

The project is licensed under the terms of the [GNU General Public License v3.0](LICENSE).
