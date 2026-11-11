# Breach data notes for RQ2 (a): are internal or external threats more common?

Compiled 2026-11-09. Updated 2026-11-10 after review: the Ponemon/DTEX negligent share now uses the figure the full report prints, and the HHS data is marked as context only. Figures marked "(derived)" were calculated from counts printed in the primary source. Figures marked "(not verified from primary source)" come only from press coverage or vendor summaries.

## In short

In forensic breach caseloads, external actors clearly cause most data breaches. The 2026 Verizon DBIR (22,345 breaches with a known actor, incidents from 1 Nov 2024 to 31 Oct 2025) attributes 88% of breaches to external actors and 12% to internal actors. The internal figure includes honest mistakes as well as malice. The internal share moves a lot from year to year (34% in the 2019 DBIR, 35% in 2024, 18% in 2025, 12% in 2026). The DBIR itself explains these swings mostly by changes in who contributes data and how much mandatory-disclosure data it receives, not by a real change in insider behaviour. The internal share is also much higher in some sectors (Public Administration 44%, Healthcare 19% to 30%). HHS OCR data on large US healthcare breaches (81% hacking/IT incidents in 2024) is context only, not evidence for RQ2: HHS classifies breaches by type, not by who caused them, so a hacking incident can still involve an insider and an access or disclosure breach can be an outsider. Survey-based insider studies (Ponemon/DTEX) do not measure prevalence share at all: they only survey organisations that already had insider incidents, so they cannot answer "which is more common". IBM's survey of 600 breached organisations finds malicious insider attacks are the costliest initial vector (USD 4.92M), not the most common. Proportionate claim: **external threats account for most confirmed breaches in the best available datasets, but insiders (mostly through error) are a persistent minority whose measured share depends heavily on sector and on how breaches get reported.**

---

## 1. Verizon 2026 Data Breach Investigations Report (19th edition)

**Citation:** Verizon Business, *2026 Data Breach Investigations Report*, 2026. PDF: https://www.verizon.com/business/resources/T453/reports/2026-dbir-data-breach-investigations-report.pdf (landing page https://www.verizon.com/business/resources/reports/dbir/). Page numbers below are the printed page numbers, which match the PDF page numbers.

**Confirmed that a 2026 edition exists.** Verizon announced it in May 2026 (press release: https://www.verizon.com/about/news/breach-industry-wide-dbir-finds).

### Figures

| Measure | Value | Where |
|---|---|---|
| Incidents analysed | "more than 31,000" (31,860 to 31,861 in figure and table n values) | p. 5; Fig. 41 p. 38; Table 3 |
| Confirmed breaches | "more than 22,000" (22,624 in pattern figures) | p. 5; Fig. 40 p. 38 |
| Countries | 145 | p. 5 |
| Time window | Incidents from 1 Nov 2024 to 31 Oct 2025 | p. 8; Appendix A p. 111 |
| Breaches with known actor (Fig. 22 n) | 22,345 | p. 23 |
| External actors | 88% of breaches | p. 23 |
| Internal actors | 12% of breaches ("a decline from last year's 18%") | p. 23 |
| Partner and Multiple | Not given as numbers in the text: "relatively uncommon and barely moved the needle" | p. 23 |
| Internal actor varieties | End-users 75%, System administrators 19% (Fig. 24, n=1,000) | p. 24 |
| Human element | Present in 62% of breaches (60% the year before) | p. 12 |
| Miscellaneous Errors pattern | 1,757 incidents, 1,750 breaches, about 7.7% of 22,624 breaches (derived); actors Internal 100% | p. 56 |
| Privilege Misuse pattern | 1,141 incidents, 766 breaches, about 3.4% of 22,624 breaches (derived); actors Internal 100%, External 1%, Multiple 1% | p. 58 |
| Third-party involvement | 48% of breaches (press release) | press release |
| Sampling error | Maximum confidence +/- 0.7% (incidents), +/- 0.9% (breaches) | p. 112 |

Percentages can add up to more than 100% because one breach can involve more than one actor category (Appendix A, p. 111).

### Sector breakdown (breaches, 2026 DBIR)

| Sector | External | Internal | Page |
|---|---|---|---|
| Educational Services | 78% | 22% | p. 82 |
| Financial and Insurance | 88% | 12% | p. 84 |
| Healthcare | 81% | 19% | p. 86 |
| Manufacturing | 95% | 5% | p. 88 |
| Public Administration | 56% | 44% | p. 90 |

### Definitions (p. 24, citing verisframework.org/actors.html)

- **External:** "originate from sources outside of the organization and its network of partners", including criminal groups, lone hackers, **former employees** and government entities. "Typically, no trust or privilege is implied."
- **Internal:** "originating from within the organization": full-time employees, independent contractors, interns and other staff. "Insiders are trusted and privileged."
- **Partner:** any third party with a business relationship (suppliers, vendors, hosting providers, outsourced IT). An attacker who uses a partner as a vector does not make the partner the actor. "The partner has to initiate the incident."
- **Multiple:** any combination of the above (p. 23).
- The 12% internal figure covers "both unintentional errors and deliberate actions" (p. 24). The report says many internal cases are "mistakes, Misconfigurations, or creative shortcuts" without malicious intent.

### What it measures and how

A forensic and contributed-case dataset, not a survey. Cases come from (1) Verizon's own paid forensic investigations, (2) partners recording cases directly in VERIS, and (3) partners' own data converted into VERIS (p. 111). An incident needs at least seven VERIS fields filled in (or must be a DDoS attack) and at least one known threat action. Incidents affecting individuals that cannot be tied to an organisation are excluded (p. 111).

### Caveats stated by the DBIR itself

- "We make no claim that the findings of this report are representative of all data breaches in all organizations at all times ... it is still a sample ... bias still exists." (p. 111)
- "Many breaches go unreported ... Many more are as yet unknown by the victim." (p. 112)
- Sampling bias: "it is clear that we conduct biased sampling. For instance, some breaches, such as those publicly disclosed, are more likely to enter our corpus, while others, such as classified breaches, are less likely." (p. 112)
- Common breach types such as ransomware "might end up being overrepresented due to the vast availability of samples." (p. 112)
- Confirmation bias: the whole dataset is used for exploratory analysis, so specific hypotheses cannot be tested; it is "a sample of convenience" (p. 112).
- "Unknown" values are treated as unmeasured and left out of sample sizes (p. 111), so the actor shares are shares of breaches where the actor was known.
- Public Administration's high internal share comes with a context note that Verizon receives a lot of government incident data through mandatory reporting (p. 90).
- The report does not say in so many words that internal actors are under-reported. But the 2024 DBIR (below) explicitly linked the jump in internal actors to new mandatory-disclosure contributors. That suggests insider errors are under-counted when such data is missing.

## 2. Verizon 2025 DBIR (for comparison)

**Citation:** Verizon Business, *2025 Data Breach Investigations Report*, 2025. PDF: https://www.verizon.com/business/resources/T453/reports/2025-dbir-data-breach-investigations-report.pdf

| Measure | Value | Where |
|---|---|---|
| Incidents analysed | 22,052 | p. 5 |
| Confirmed breaches | 12,195 | p. 5 |
| Countries | 139 | p. 5 |
| Time window | 1 Nov 2023 to 31 Oct 2024 | p. 8 |
| Breaches with known actor (Fig. 18 n) | 12,063 | p. 22 |
| External actor breaches | n=9,754, about 81% (derived from Fig. 19 n / Fig. 18 n) | p. 22 |
| Internal actor breaches | n=2,199, about 18% (derived from Fig. 20 n / Fig. 18 n); the 2026 DBIR confirms "last year's 18%" | p. 22; 2026 DBIR p. 23 |
| Inside internal breaches | Miscellaneous Errors to Privilege Misuse "roughly 2 to 1" | p. 22 |
| Human element | "around 60%" | p. 11, p. 20 |
| Third-party involvement | Doubled from 15% to 30% | p. 11 |
| Miscellaneous Errors | 1,476 incidents, 1,449 breaches, about 11.9% of breaches (derived) | p. 60 |
| Privilege Misuse | 825 incidents, 757 breaches, about 6.2% of breaches (derived) | p. 62 |
| Healthcare actors | External 67%, Internal 30%, Partner 4%, Multiple 1% | p. 77 |
| EMEA region | External 71%, Internal 29% | p. 98 |

The headline percentages in the 2025 Figure 18 are shown only as a graphic; the text extraction did not include them. The 81% and 18% above are derived from the n values printed with Figures 18 to 20.

## 3. Verizon DBIR trend (older editions)

| Edition | Data window | Incidents / breaches | External | Internal | Partner | Multiple | Source |
|---|---|---|---|---|---|---|---|
| 2019 | 2018 caseload | 41,686 / 2,013 | 69% | 34% | 2% | 5% | 2019 DBIR p. 5, Fig. 4 |
| 2023 | 2022 caseload | (not checked) | (not checked) | 20% | | | as stated in 2024 DBIR p. 15 |
| 2024 | 1 Nov 2022 to 31 Oct 2023 | 30,458 / 10,626 (94 countries) | 65% | 35% | | | 2024 DBIR p. 5, p. 15 |
| 2025 | 1 Nov 2023 to 31 Oct 2024 | 22,052 / 12,195 | about 81% (derived) | about 18% (derived) | | | 2025 DBIR p. 22 |
| 2026 | 1 Nov 2024 to 31 Oct 2025 | about 31,860 / about 22,600 | 88% | 12% | | | 2026 DBIR p. 23 |

The 2024 DBIR (p. 15) explains its 35% internal figure: "in part because of improved breach collection processes and the onboarding of new data contributors documenting mandatory breach disclosures, it is finally time for Internal actors to shine." It adds that "73% of those Internal actor breaches were in the Miscellaneous Errors pattern." The 2025 DBIR (p. 22) says the internal increase was "due to an uptick of Error breaches, but those are back in line percentage-wise." So the swings in the internal share mostly track error breaches and contributor mix.

## 4. Ponemon Institute / DTEX Systems, Cost of Insider Risks Global Report

**Citation (latest):** Ponemon Institute and DTEX Systems, *2026 Cost of Insider Risks Global Report*, Feb. 2026. Press release: https://www.dtex.ai/newsroom/press-releases/insider-risk-costs-rise-as-ai-creates-new-blind-spots/ ; report page: https://ponemon.dtex.ai/ . The full report PDF sits behind a form. The negligent share below was checked against Figure 1 of the full report; the other 2026 figures still come from the press release until they are checked against it too.

| Measure | 2026 edition (2025 data) | 2025 edition (2024 data) |
|---|---|---|
| Average annual cost of insider incidents per organisation | USD 19.5M | USD 17.4M |
| Organisations / respondents | 354 organisations, 8,750 IT and IT security practitioners | 349 organisations, 8,306 practitioners |
| Regions | North America, EMEA, Asia-Pacific | same |
| Insider incidents per organisation | 25.4 | (not checked) |
| Negligent / careless insiders | 3,970 of 7,490 incidents, 53% (full report, Fig. 1); 13.8 incidents per org, USD 10.3M per year, about USD 747,107 per incident (press release) | 55% of incidents |
| Malicious insiders | 27% of incidents, USD 4.7M (not verified from primary source; from IT Brief coverage) | 25% of incidents |
| Outsmarted insiders (credential theft) | (not given in press release) | 20% of incidents |
| Time to contain | 67 days | 81 days |
| Total insider incidents | 7,490 (full report, Fig. 1) | (not checked) |
| Fieldwork | Two months ending September 2025 | (not checked) |

2025 edition figures come from the DTEX press release of 25 Feb 2025: https://www.dtex.ai/newsroom/press-releases/2025-ponemon-insider-threat-report-release

**What it measures:** the cost and count of insider incidents inside organisations that took part. Participants are organisations that "experienced one or more material events caused by an insider" (2026 press release). That means the sample is chosen because it has insider incidents.

**Method:** interview-based survey run by Ponemon, sponsored by DTEX, a vendor of insider risk products.

**Why 53% and not a derived figure:** an earlier version of this note divided the per-organisation averages (13.8 / 25.4, about 54%). The full report prints the count directly (3,970 of 7,490 in Figure 1) [13], so that figure is used. The two do not match exactly because 7,490 incidents across 354 organisations is about 21.2 per organisation, not 25.4; the press release average may use a different base. Use the Figure 1 count.

**Caveats:** The study cannot give an internal versus external prevalence share: it does not count external incidents, and the sample is chosen on the outcome. "Insider" here includes negligence and compromised (outsmarted) employees, which the DBIR would partly classify as external (for example, credential theft by an outside attacker). The sponsor has a commercial interest in the topic.

## 5. IBM and Ponemon Institute, Cost of a Data Breach Report

**Citation (figures used):** IBM Security and Ponemon Institute, *Cost of a Data Breach Report 2025*, July 2025. Copy read: https://www.bakerdonelson.com/webfiles/Publications/20250822_Cost-of-a-Data-Breach-Report-2025.pdf (a republished copy of the IBM report; official page https://www.ibm.com/reports/data-breach).

**Newer edition:** IBM released the 2026 report on 29 July 2026 (global average cost USD 4.99M, per the IBM report page). Its full PDF is behind a form, and I found no insider-specific 2026 figures. So the 2025 figures are used below.

| Measure | Value | Where |
|---|---|---|
| Sample | 600 organisations breached between March 2024 and February 2025; 3,470 interviews | p. 3; methodology p. 28 to 29 (PDF pages) |
| Malicious insider: average cost | USD 4.92M, highest of all initial vectors for the second year running | p. 4; Fig. 9 |
| Malicious insider: time to identify and contain | 194 + 66 = 260 days (second longest) | Fig. 10 |
| Malicious insider: share of breaches | Plotted in Fig. 9 but not printed as a number in the text (not verified from primary source) | Fig. 9 |
| Most common initial vectors | Phishing 16% (USD 4.80M), third-party vendor and supply chain compromise 15% (USD 4.91M) | Fig. 9 text |
| Insider error: average cost | USD 3.62M | Fig. 9 |
| Root cause of breach | Malicious or criminal attack 51%, human error 26%, IT failure 23% | Fig. 11 |
| Global average breach cost | USD 4.44M | p. 4 |

**What it measures:** the cost of breaches at organisations that had one, and how those breaches were distributed across initial vectors and root causes.

**Method:** an interview-based survey with activity-based costing. It is not a forensic caseload. Participating organisations are recruited by Ponemon.

**Caveats:** "Malicious or criminal attack" (51%) mixes insiders and outsiders ("whether launched within or outside an organization"). The 26% "human error" is an internal, non-malicious cause. A rough reading is that most breaches start with an external attack and about a quarter start with staff error. But IBM does not publish a clean external versus internal split in the text.

## 6. US HHS Office for Civil Rights, breaches of unsecured protected health information

**Citation:** U.S. Department of Health and Human Services, Office for Civil Rights, *Annual Report to Congress on Breaches of Unsecured Protected Health Information for Calendar Year 2024*. URL: https://www.hhs.gov/sites/default/files/breach-report-to-congress-2024.pdf . The HHS site returned HTTP 403 to automated download, so the figures below come from secondary summaries and are **not verified from primary source**.

| Measure | CY2024 | CY2022 |
|---|---|---|
| Large breaches (500 or more individuals) | 663 | 626 |
| Individuals affected (large breaches) | 242,908,056 | 41,747,613 |
| Hacking/IT incidents, share of large breaches | 81% (99.45% of affected individuals) | 74% |
| Unauthorized access/disclosure, share of large breaches | (not found) | 22% |
| Small breaches (fewer than 500) | 74,299 reports | 63,966 reports |
| Unauthorized access/disclosure, share of small breaches | "more common" (no %) | 93% |

Sources: Paubox (10 June 2026) for CY2024: https://www.paubox.com/blog/ocr-reports-242-million-records-exposed-in-2024 ; HIPAA Journal for CY2022: https://www.hipaajournal.com/ocr-reports-to-congress-on-hipaa-compliance-and-data-breaches/

**What it measures:** breaches that HIPAA-covered entities must report by law, classified by breach type (not by actor).

**Use in the report: context only.** These figures show which kinds of breach dominate one regulated sector. They are not evidence for RQ2, which asks about threat actors, so the report must not cite the 81% as support for external threats being more common.

**Caveats:** "Hacking/IT incident" is a breach type, not an actor; it is often external, but "unauthorized access/disclosure" mixes insider error, insider snooping and some outsider cases. The split between large and small breaches matters a lot: large breaches are mostly hacking, while the many small ones (mostly misdirected paper or email) are mostly unauthorized access or disclosure, which is often insider error. Mandatory reporting makes this dataset much more complete for small error breaches than voluntary datasets.

## 7. Not used

ENISA Threat Landscape was not consulted in detail for this note. It describes threat types rather than giving an internal versus external breach share, so it would add little to RQ2 (a).

---

## Comparison table

| Source | Year (data) | Method | Unit | Sample | Internal / insider figure | External figure |
|---|---|---|---|---|---|---|
| Verizon DBIR 2026 | 2026 (Nov 2024 to Oct 2025) | Forensic and contributed caseload, VERIS coded | Confirmed breaches | 22,345 breaches with known actor, 145 countries | 12% (errors and malice) | 88% |
| Verizon DBIR 2025 | 2025 (Nov 2023 to Oct 2024) | Same | Confirmed breaches | 12,063 with known actor | about 18% (derived) | about 81% (derived) |
| Verizon DBIR 2024 | 2024 (Nov 2022 to Oct 2023) | Same | Confirmed breaches | 10,626 breaches | 35% (73% of these were errors) | 65% |
| Verizon DBIR 2019 | 2019 (2018) | Same | Confirmed breaches | 2,013 breaches | 34% | 69% |
| DBIR 2026, Healthcare | 2026 | Same | Healthcare breaches | 1,438 breaches | 19% | 81% |
| DBIR 2026, Public Administration | 2026 | Same | Public sector breaches | (see p. 90) | 44% | 56% |
| IBM Cost of a Data Breach | 2025 (Mar 2024 to Feb 2025) | Interview survey | Breached organisations | 600 orgs | Human error root cause 26%; malicious insider cost USD 4.92M (share not printed) | Not split; malicious or criminal 51% includes insiders |
| Ponemon/DTEX Cost of Insider Risks | 2026 (2025) | Interview survey of orgs with insider events | Insider incidents | 354 orgs, 8,750 respondents | 53% of insider incidents negligent (3,970 of 7,490, Fig. 1); 27% malicious (not verified from primary source) | Not measured |
| HHS OCR breach reports | CY2024 | Mandatory regulatory reporting | Reported HIPAA breaches | 663 large breaches | Not measured (breach types, not actors); unauthorized access/disclosure dominates small breaches (93% in CY2022) | Not measured; context only: hacking/IT is 81% of large breaches (not verified from primary source) |

## Why they differ

1. **Breach versus incident versus organisation.** The DBIR counts confirmed breaches (data disclosure). IBM counts breached organisations and their costs. Ponemon/DTEX counts insider incidents, many of which never become breaches. These are different units, so their percentages cannot be compared directly.
2. **Survey versus forensic caseload versus regulatory filing.** DBIR data comes from incident responders, law enforcement and other contributors, so it over-represents breaches that trigger an investigation or a public disclosure (ransomware especially). Surveys depend on what respondents know and choose to report. Regulatory data (HHS OCR) captures many small error breaches that voluntary sources miss.
3. **Sample selection.** Ponemon/DTEX only includes organisations that already had insider incidents, so it cannot estimate how common insiders are compared with outsiders. The DBIR calls its own data "a sample of convenience".
4. **Definitions of insider.** The DBIR counts both errors and malice as internal, but classes former employees as external. It also counts an outside attacker using stolen employee credentials as external. Ponemon/DTEX counts "outsmarted" (credential-theft) employees as an insider category. IBM separates "malicious insider" (an initial vector) from "human error" (a root cause). The same event can therefore be internal in one study and external in another.
5. **Sector mix.** Internal shares are much higher in sectors with mandatory reporting and heavy paper or email handling (Public Administration 44%, Healthcare 19% to 30% in the DBIR). A dataset weighted towards those sectors will show more insiders.
6. **Contributor mix over time.** The DBIR's own internal share moved from 20% to 35% to 18% to 12% across four editions. The report attributes this mainly to new mandatory-disclosure contributors and the volume of ransomware cases, not to a real change in insider behaviour.
7. **Detection.** Insider misuse is hard to detect (the DBIR says such cases are "frequently the hardest to catch") and is often handled internally without disclosure. So any breach-based count probably under-counts malicious insiders.

## What this lets the report claim (and not claim)

**Can claim (with sources):**
- In the largest forensic breach dataset available, external actors are involved in most confirmed breaches: 88% in the 2026 DBIR, and consistently between about 65% and 88% in recent editions [1], [2], [3].
- Internal actors are a consistent minority of confirmed breaches, roughly one in eight to one in three depending on the year [1], [3], [4]. Most of these are errors (misdelivery, misconfiguration), not malice [1], [3].
- Deliberate insider misuse (Privilege Misuse) is a small share of breaches: about 3% (2026) to 6% (2025) [1], [2].
- When malicious insider breaches do happen, they are among the costliest and slowest to contain (USD 4.92M, 260 days in IBM 2025) [5].
- The insider share is sector-dependent and higher in Public Administration and Healthcare [1], [2].

**Should not claim:**
- That external threats are more common "in all organisations" or "globally" as a measured fact. The DBIR explicitly rejects that its data is representative [1].
- That "insiders cause X% of all breaches" using Ponemon/DTEX figures. That study measures cost and incident counts inside organisations chosen because they had insider events [6], [13].
- A precise trend (for example, "insider threats fell by a third from 2025 to 2026"). The year-to-year swings in the DBIR mostly reflect changes in the data sources [1], [3].
- That HHS OCR data shows external threats are more common. HHS counts breach types (hacking/IT, unauthorized access or disclosure), not threat actors [8].
- That external attacks are always more harmful. Per breach, malicious insiders are the costliest vector in IBM's data [5].

**Suggested proportionate wording:** "Published breach data indicates that external threats are more common than internal ones: the 2026 Verizon DBIR attributes 88% of the 22,345 breaches it analysed to external actors and 12% to internal actors [1]. However, the internal share varies widely between years (12% to 35% since 2024) and sectors (up to 44% in public administration), and most internal cases are errors rather than malicious acts. These figures come from non-representative samples, and malicious insiders are likely under-reported, so they show which threat is more frequently observed in reported breaches, not the true prevalence in all organisations."

---

## References (IEEE style)

[1] Verizon Business, "2026 Data Breach Investigations Report," Verizon, Basking Ridge, NJ, USA, 2026. [Online]. Available: https://www.verizon.com/business/resources/T453/reports/2026-dbir-data-breach-investigations-report.pdf

[2] Verizon Business, "2025 Data Breach Investigations Report," Verizon, Basking Ridge, NJ, USA, 2025. [Online]. Available: https://www.verizon.com/business/resources/T453/reports/2025-dbir-data-breach-investigations-report.pdf

[3] Verizon Business, "2024 Data Breach Investigations Report," Verizon, Basking Ridge, NJ, USA, 2024. [Online]. Available: https://www.verizon.com/business/resources/T453/reports/2024-dbir-data-breach-investigations-report.pdf

[4] Verizon, "2019 Data Breach Investigations Report," Verizon, 2019. [Online]. Available: https://www.verizon.com/business/resources/reports/2019-data-breach-investigations-report.pdf

[5] IBM Security and Ponemon Institute, "Cost of a Data Breach Report 2025," IBM Corp., Armonk, NY, USA, Jul. 2025. [Online]. Available: https://www.ibm.com/reports/data-breach

[6] DTEX Systems, "Insider risk costs hit $19.5M USD per year as AI creates new blind spots," press release on the Ponemon Institute and DTEX "2026 Cost of Insider Risks Global Report," Feb. 24, 2026. [Online]. Available: https://www.dtex.ai/newsroom/press-releases/insider-risk-costs-rise-as-ai-creates-new-blind-spots/

[7] DTEX Systems, "Ponemon cybersecurity report: Insider risk management enabling early breach detection and mitigation," press release on the "2025 Cost of Insider Risks Global Report," Feb. 25, 2025. [Online]. Available: https://www.dtex.ai/newsroom/press-releases/2025-ponemon-insider-threat-report-release

[8] U.S. Department of Health and Human Services, Office for Civil Rights, "Annual Report to Congress on Breaches of Unsecured Protected Health Information for Calendar Year 2024," HHS, Washington, DC, USA. [Online]. Available: https://www.hhs.gov/sites/default/files/breach-report-to-congress-2024.pdf

[9] F. Amod, "OCR reports 242 million records exposed in 2024," Paubox, Jun. 10, 2026. [Online]. Available: https://www.paubox.com/blog/ocr-reports-242-million-records-exposed-in-2024

[10] Verizon, "Vulnerability exploitation top breach entry point, 2026 industry-wide DBIR finds," press release, May 2026. [Online]. Available: https://www.verizon.com/about/news/breach-industry-wide-dbir-finds

[11] "Insider risk costs soar as AI reshapes workplace data," IT Brief Australia, Feb. 25, 2026. [Online]. Available: https://itbrief.com.au/story/insider-risk-costs-soar-as-ai-reshapes-workplace-data

[12] "OCR reports to Congress on HIPAA compliance and data breaches," HIPAA Journal, Feb. 22, 2024. [Online]. Available: https://www.hipaajournal.com/ocr-reports-to-congress-on-hipaa-compliance-and-data-breaches/

[13] Ponemon Institute and DTEX Systems, "2026 Cost of Insider Risks Global Report," Feb. 2026. [Online]. Available: https://ponemon.dtex.ai/ (full report behind a form; Figure 1 gives the negligent share)
