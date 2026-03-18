# Abandoned Open-Source Packages and Unfixed Vulnerabilities

This brief focuses on a practical question for an AI-agent security project: what happens when widely used packages become under-maintained or effectively abandoned while vulnerabilities remain open.

## 1. How many critical open-source packages have no active maintainer?

There is **no single authoritative global count** for "critical packages with no active maintainer" across all ecosystems.

What we do have are strong proxy signals:

- The Linux Foundation's **Census III** found that among the **top 50 non-npm OSS projects**, **17%** had **one developer** responsible for more than **80% of commits** in 2023, **40%** had only **one or two developers** doing >80% of commits, and **81%** had **10 or fewer developers** accounting for >80% of commits. That is not the same as "unmaintained," but it shows how many critical projects are one illness, burnout event, or account compromise away from effective abandonment.
- Tidelift's 2024 maintainer survey found **44% of maintainers describe themselves as solo maintainers** and **60% are unpaid**.
- Recent CVE records show real packages already in this state. For example:
  - **`libxslt`** was described in 2025 advisories as having **no active maintainer** while multiple security issues remained unfixed.
  - **`wabt`** CVEs published in 2025 state that the project had **no active maintainer at the moment**.

## 2. Famous incidents

- **XZ Utils backdoor (2024):** an attacker socially engineered their way into a critical compression library used throughout Linux distributions and cloud infrastructure. The incident became the clearest recent example of how maintainer overload and thin stewardship can become a national-scale supply-chain risk.
- **event-stream (npm, 2018):** a popular but lightly maintained package was handed to a new maintainer, who later shipped a malicious dependency (`flatmap-stream`) targeting cryptocurrency wallets.
- **left-pad (npm, 2016):** not a vulnerability incident, but a canonical example of ecosystem fragility: one tiny package removal broke large parts of the JavaScript ecosystem.
- **Heartbleed / OpenSSL (2014):** the bug was in a massively deployed project that was notoriously underfunded before the incident, which helped trigger major new funding efforts such as the Core Infrastructure Initiative.
- **Log4Shell (2021):** not an "abandoned package" case, but it demonstrated how a defect in one open-source component can create global emergency patching pressure across governments and industry.

## 3. What is the current funding gap for open-source maintenance?

Again, there is **no universally accepted current global dollar figure** for the maintenance funding gap.

The best current factual picture is:

- Harvard researchers estimated open source creates about **$8.8 trillion in demand-side value** while the **supply-side replacement cost** is about **$4.15 billion**. That is not the same as the maintenance gap, but it shows a huge mismatch between economic dependence and what it would cost to sustain the code.
- Tidelift's 2024 survey found **60% of maintainers are still unpaid**, despite increased security obligations.
- OpenForum Europe proposed an **EU Sovereign Tech Fund budget of at least EUR 350 million over seven years** to address security and sustainability gaps in critical open source.

Bottom line: the gap is clearly at least **hundreds of millions of euros/dollars in public-policy proposals**, and likely much larger in economic terms, but no trusted live global ledger exists.

## 4. What tools exist today, and what do they *not* do?

### Tools that exist

- **OSV / OSV-Scanner:** maps packages and versions to known vulnerabilities.
- **GitHub Advisory Database + Dependabot:** detects vulnerable dependencies and opens upgrade PRs when a fixed version exists.
- **SCA tools** such as Snyk, Mend, Socket, osv-scanner, Trivy, Grype, and `cve-bin-tool`: inventory dependencies and match them to known advisories.
- **OpenSSF Scorecard:** evaluates project security hygiene signals such as branch protection, CI hardening, token permissions, signed releases, and fuzzing.
- **Sigstore / Cosign / Rekor:** signs and verifies artifacts and records transparency logs.
- **SLSA:** provides a framework for build provenance and supply-chain integrity.
- **SBOM tooling** such as Syft, SPDX, and CycloneDX generators: enumerate components so organizations know what they shipped.

### What they do *not* do well today

- They usually **do not fix vulnerabilities when no maintainer is present**.
- They usually **do not backport patches** across abandoned branches.
- They usually **do not prove exploitability in your exact runtime**; most match known vulnerable versions.
- They usually **do not handle "no patch exists" well** beyond surfacing the alert and suggesting compensating controls.
- They usually **do not take over release engineering**, governance, or ownership transfer for orphaned packages.
- They usually **do not verify long-term package health** beyond metadata and repo heuristics.

That gap is where autonomous fixing agents could matter: not just detection, but patch synthesis, test repair, backporting, and release-ready remediation for packages that have lost active stewardship.

## 5. What are the most common types of vulnerabilities?

Using GitHub Advisory Database 2024 counts, the most common weakness classes in package advisories were:

1. **Cross-site scripting (CWE-79): 936 advisories**
2. **Exposure of sensitive information (CWE-200): 320**
3. **Path traversal (CWE-22): 259**
4. **Improper input validation (CWE-20): 202**
5. **Code injection (CWE-94): 188**
6. **SQL injection (CWE-89): 181**
7. **CSRF (CWE-352): 161**
8. **Improper access control (CWE-284): 153**
9. **Uncontrolled resource consumption / DoS (CWE-400): 149**
10. **Improper authentication (CWE-287): 124**

For lower-level packages written in C/C++, memory-safety bugs also remain common in abandoned or weakly maintained projects, including:

- out-of-bounds read/write
- use-after-free
- memory corruption
- type confusion

## 6. How many packages have known unfixed CVEs right now?

There is **no trustworthy global live count of packages with known unfixed CVEs across all open-source ecosystems**.

What can be said factually:

- GitHub said in 2025 that its Advisory Database has **over 22,000 reviewed advisories**, and that **for every year, nearly all of the advisories have a patch**. That implies the "no patch" set is a minority, but still non-zero.
- GitHub also documents that advisory records can have **"Patched versions: None"**, which is the common state for abandoned-package cases.
- Current examples include:
  - **`quill`** (`CVE-2021-3163`): GitHub Advisory lists **Patched versions: None**.
  - **`wabt`** (`CVE-2025-15411`, `CVE-2025-15412`): Debian tracker lists the package as **unfixed**.
  - **`libxslt`** 2025 advisories explicitly describe **multiple unfixed vulnerabilities** while the project had **no active maintainer**.

For a hackathon pitch, the most accurate phrasing is:

> There is no authoritative cross-ecosystem live count, but thousands of package advisories exist, a measurable minority have no patch, and real packages with unfixed CVEs and no active maintainer are present today.

## 7. What did the White House Executive Order on Software Security (EO 14028) mandate?

**EO 14028** ("Improving the Nation's Cybersecurity," May 12, 2021) required major federal action on the software supply chain. In practice, it mandated or triggered:

- **NIST guidance** for secure software development practices, which became the basis for the **Secure Software Development Framework (SSDF)** and related procurement guidance.
- A federal push toward **Software Bills of Materials (SBOMs)** so agencies and vendors can identify included components.
- A definition of **"critical software"** and follow-on guidance on which products fall into that category.
- New **security criteria for software sold to the federal government**, later operationalized through OMB memoranda and secure software attestation requirements.
- Stronger incident logging, breach reporting, and broader modernization measures for federal cybersecurity.

EO 14028 did **not** directly create a permanent federal maintainer-of-last-resort program for abandoned OSS. It increased disclosure, inventory, and development-process requirements, but left a practical remediation gap when projects lack active maintainers.

## 8. What is CISA's role in open-source security?

CISA's role has become much more explicit since 2023.

According to CISA's **Open Source Software Security Roadmap**, its four priorities are:

1. **Establish CISA's role in supporting OSS security**
2. **Drive visibility into OSS usage and risks**
3. **Reduce risks to the federal government**
4. **Harden the broader OSS ecosystem**

In practice, CISA now:

- coordinates vulnerability disclosure through its **Coordinated Vulnerability Disclosure (CVD)** program, including for **open source software**
- participates in the **CVE Program** and can assign CVEs in its role as a **CNA of Last Resort**
- pushes **SBOM** adoption and software transparency
- partners with **OpenSSF** and package ecosystems on security guidance, including principles for package repository security
- publishes strategy and guidance for federal OSS risk management

CISA is therefore a **coordinator, standards enabler, risk-reduction agency, and federal consumer of OSS security practices**. It is not the maintainer of most projects, and it typically does not patch abandoned packages itself.

## Takeaways for an AI-agent project

- The hardest operational gap is **not detection**; it is **remediation when nobody owns the package anymore**.
- The ecosystem has good tools for **finding** vulnerable dependencies and weaker tools for **safely repairing abandoned ones**.
- A credible autonomous-fix system should focus on:
  - finding "no patch" or "unfixed" advisories
  - generating minimal patches
  - running tests and building reproducers
  - backporting fixes to vulnerable release lines
  - producing SBOM / provenance / signed artifacts for downstream adopters

## Sources

- Linux Foundation Research, **Census III of Free and Open Source Software** (2024): <https://www.linuxfoundation.org/hubfs/LF%20Research/lfr_censusiii_120424a.pdf>
- GitHub Security Lab, **GitHub Advisory Database by the numbers** (2025): <https://github.blog/security/github-advisory-database-by-the-numbers-known-security-vulnerabilities-and-what-you-can-do-about-them/>
- GitHub Docs, **About global security advisories**: <https://docs.github.com/en/enterprise-server@3.15/code-security/concepts/vulnerability-reporting-and-management/about-global-security-advisories>
- OSV.dev: <https://osv.dev/>
- Tidelift, **2024 State of the Open Source Maintainer Report** summary: <https://www.businesswire.com/news/home/20240917030299/en/Tidelift-Study-Reveals-Paid-Open-Source-Maintainers-Do-Significantly-More-Critical-Security-and-Maintenance-Work-Than-Unpaid-Maintainers/>
- Tidelift, **XZ backdoor hack** analysis: <https://tidelift.com/resources/xz-backdoor-hack>
- Harvard Business School researchers on OSS economic value, summarized here: <https://www.heise.de/en/news/Harvard-study-Open-source-has-an-economic-value-of-8-8-trillion-dollars-10322643.html>
- OpenForum Europe, **EU Sovereign Tech Fund proposal**: <https://openforumeurope.org/investing-in-open-source-sustainability-and-security-ofes-proposal-for-an-eu-sovereign-tech-fund/>
- Debian Security Tracker, **wabt CVEs**: <https://security-tracker.debian.org/tracker/CVE-2025-15411>, <https://security-tracker.debian.org/tracker/CVE-2025-15412>
- FreeBSD VuXML, **libxslt unmaintained with multiple unfixed vulnerabilities**: <https://vuxml.freebsd.org/freebsd/b0a3466f-5efc-11f0-ae84-99047d0a6bcc.html>
- GitHub Advisory for **quill / CVE-2021-3163**: <https://github.com/advisories/GHSA-4943-9vgg-gr5r>
- The White House, **Executive Order 14028: Improving the Nation's Cybersecurity**: <https://www.whitehouse.gov/briefing-room/presidential-actions/2021/05/12/executive-order-on-improving-the-nations-cybersecurity/>
- NIST, **Software Security in Supply Chains: Open Source Software Controls**: <https://www.nist.gov/itl/executive-order-14028-improving-nations-cybersecurity/software-security-supply-chains-open>
- NIST, **Critical Software Definition**: <https://www.nist.gov/itl/executive-order-improving-nations-cybersecurity/critical-software-definition>
- CISA, **Open Source Software Security Roadmap**: <https://www.cisa.gov/resources-tools/resources/cisa-open-source-software-security-roadmap>
- CISA, **Open Source Security**: <https://www.cisa.gov/opensource>
- CISA, **Coordinated Vulnerability Disclosure Program**: <https://www.cisa.gov/resources-tools/programs/coordinated-vulnerability-disclosure-program>
