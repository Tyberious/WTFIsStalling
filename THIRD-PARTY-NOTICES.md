# Third-party notices

WTFIsStalling itself is MIT licensed (see `LICENSE`). This file lists material from other projects
that is included in it, and the terms that material comes under.

## LOLDrivers

Portions of the hardware-access driver knowledge base in `src/hwaccess.rs` are derived from the
**LOLDrivers** project, <https://github.com/magicsword-io/LOLDrivers>, © the LOLDrivers
contributors, licensed under the **Apache License, Version 2.0**. A copy of that license is included
at [`licenses/Apache-2.0.txt`](licenses/Apache-2.0.txt).

The data has been modified: driver file names, vendor names and product names were extracted,
reformatted, edited and merged with information from other sources (Microsoft's vulnerable-driver
blocklist, CVE records, vendor advisories and upstream project source trees), and rows the project
could not corroborate were dropped. Rows in `src/hwaccess.rs` that rest on LOLDrivers (or on
Eclypsium's Screwed-Drivers list) are marked `Source::Catalog` and are described in the report as
coming from a community catalog rather than from a first-party source.

**No hashes and no binary samples from LOLDrivers are included.** Only names of drivers, vendors and
products are used. LOLDrivers' `drivers/*.bin` files are vulnerable or malicious driver binaries, and
shipping any of them — or their hashes — inside a consumer diagnostic tool would be both
irresponsible and a reliable way to get this tool flagged by antivirus software.

The LOLDrivers repository has no `NOTICE` file (checked 2026-09-21), so Apache-2.0 section 4(d) does
not apply; this section satisfies 4(a), 4(b) and 4(c).

*Note, not legal advice: a table of bare file names and vendor names may well carry no copyright at
all in some jurisdictions (in the United States, see* Feist v. Rural Telephone*). Complying with
Apache-2.0 anyway costs nothing and removes the question.*

## Other sources used, which are not licensed material

These are cited in the source comments but are facts read from published documents, not code or data
copied from them:

- The **PresentMon** project, <https://github.com/GameTechDev/PresentMon> (MIT), used in
  `src/gputrace/` as a second source for which Microsoft-Windows-DxgKrnl event IDs, versions and
  keywords mean what, and for the fact that Windows 11 added the `Present` keyword to the
  vertical-blank events. No PresentMon code was copied or adapted; the event IDs and keyword values
  it records are the same facts the provider's own manifest states on any Windows PC
  (`wevtutil gp Microsoft-Windows-DxgKrnl /ge`).
- Microsoft's recommended driver block rules and the `DriverPolicy_Enforced.xml` inside
  <https://aka.ms/VulnerableDriverBlockList>
- CVE records from MITRE's CVE Services API
- CERT/CC vulnerability notes
- Vendor advisories and vendor documentation (ASUS/Cisco Talos, Core Security, SecureAuth, Dell,
  FinalWire, WhirlwindFX)
- Upstream project source trees and READMEs (LibreHardwareMonitor, FanControl, OpenRGB, PawnIO)
- Eclypsium's Screwed-Drivers list, <https://github.com/eclypsium/Screwed-Drivers>
- Microsoft Learn, the Intel and AMD architecture manuals, the ACPI and UEFI PI specifications, and
  the Linux kernel's own documentation
