# A Formally Verified Semantic Intrusion Detection System for Automotive CAN XL Networks

This repository accompanies the IEEE-accepted research paper *A Formally Verified Semantic Intrusion Detection System for Automotive CAN XL Networks*. It provides the synthesizable SystemVerilog RTL implementation of the proposed semantic intrusion detection system (IDS), its white-box SystemVerilog Assertion (SVA) checkers, and the Synopsys VC Formal Tcl script used for formal property verification.

The proposed design addresses semantic security in CAN XL networks through three hierarchical security levels: Service Data Unit Type (SDT)-based semantic interpretation, Virtual CAN Network Identifier (VCID)-based domain binding, and domain-specific authorization of outer services and individual inner PDUs. The IDS further enforces configuration consistency, payload-stream validity, stateful domain ownership, and timing requirements. Detected violations are accumulated as security evidence and reported through a contextual incident interface. Persistent state updates are permitted only after violation-free frame completion.

## 1. Architecture

<!-- Optional system model (Figure 1 of the paper): upload system-model.png to the repository root and uncomment the following line.
![System model of the proposed CAN XL semantic IDS](system-model.png)
-->

<!-- Internal architecture (Figure 2 of the paper): upload architecture.png to the repository root and uncomment the following two lines.
![Internal architecture of the proposed semantic IDS](architecture.png)
*Internal architecture of the proposed CAN XL semantic IDS.*
-->

The IDS processes one frame at a time, accepting receiver-provided metadata before the corresponding payload stream. Its architecture combines:

- **Level 1 — SDT-based semantic interpretation:** selects the native or multi-PDU semantic class and the method for extracting the outer service identifier from the Acceptance Field (AF).
- **Level 2 — VCID-based domain binding:** requires exactly one matching domain binding with a consistent configuration generation and establishes the applicable service-rule and state-storage ranges.
- **Level 3 — Domain-specific authorization:** evaluates the outer service against the selected domain's rules, including Priority ID (PID), declared payload length, SEC indication, and receiver-provided CANsec status. Each inner PDU in a multi-PDU frame is independently authorized within the outer-frame context.
- **Stateful ownership and timing protection:** validates state addresses, domain ownership, and minimum transmission intervals before preparing a pending state update.
- **Payload-stream validation and multi-PDU parsing:** checks accepted byte counts, byte-enable masks, abort conditions, and inner-PDU structure using a research-defined 8-byte header.
- **Frame finalization and incident reporting:** combines accumulated frame and parser evidence, commits pending state only for clean authorized frames, and reports detected violations with their associated frame context.

The IDS consumes receiver-provided metadata and CANsec status; it does not implement the CAN XL physical layer or independently perform cryptographic verification. Native payload bodies are treated as opaque. The inner-PDU header format is defined for this research implementation.

<img width="634" height="433" alt="CAN-XL_IDS" src="https://github.com/user-attachments/assets/13a0404a-87cc-4310-bdf4-832210b8b5e8" />


## 2. Repository contents

The three source files are kept in the repository root because the Tcl script analyzes both SystemVerilog files by relative filename.

| File | Purpose |
| --- | --- |
| [`canxl-IDS-rtl.sv`](canxl-IDS-rtl.sv) | Shared semantic types and configuration structures, state store, streaming multi-PDU parser, and top-level semantic IDS pipeline. |
| [`canxl-IDS-formal-sva.sv`](canxl-IDS-formal-sva.sv) | Bound white-box formal checkers, independent reference models, assertions, assumptions, and reachability cover properties. |
| [`canxl-IDS.tcl`](canxl-IDS.tcl) | VC Formal FPV setup, source analysis, elaboration, clock definition, reset initialization, and verification execution. |

The RTL contains the following package and modules:

| RTL component | Function |
| --- | --- |
| `can_xl_semantic_pkg` | Shared frame, configuration, state-update, security-evidence, and incident types. |
| `can_xl_state_store` | Stateful domain ownership, timing validation, and persistent state updates. |
| `can_xl_multi_pdu_parser` | Streaming inner-PDU header parsing, authorization, boundary tracking, and evidence accumulation. |
| `can_xl_semantic_ids` | Top-level semantic interpretation, domain binding, authorization, payload processing, finalization, and incident reporting. |

The formal checker comments correspond to the paper's Formal Assertion Catalog, Formal Assumption Catalog, and Formal Cover Property Catalog.

## 3. Reproducing the formal verification setup

### Requirements

- A licensed Synopsys VC Formal installation with SystemVerilog/SVA support. The reported evaluation used VC Static Y-2026.03-SP2 in Formal Property Verification (FPV) mode on Linux.
- A compatible execution environment with sufficient computational and memory resources. The supplied script requests 16 remote-shell workers; availability depends on the installation and grid configuration.
- The three source files together in the working directory.

Clone the repository and enter its root directory:

```bash
git clone https://github.com/AAF20/CAN-XL-Semantic-IDS.git
cd CAN-XL-Semantic-IDS
```

Launch VC Formal with the supplied Tcl script (for installations supporting the conventional `-f` invocation):

```bash
vcf -f canxl-IDS.tcl
```

The script elaborates `can_xl_semantic_ids` with its bound SVA checkers, enables vacuity and witness analysis, defines the formal clock, initializes the design through active-low reset, saves the initialized state, and executes `check_fv`.

The script retains the original proof-resource settings:

```tcl
set_fml_var fml_max_time 200H
set_fml_var fml_max_mem 24GB
set_fml_var fml_auto_scale_task_count 16
set_grid_usage -type rsh=16
```

The evaluated configuration uses eight domain bindings, 16 outer-service rules, 16 inner-PDU rules, and 256 state entries. Four active SVA assumptions constrain stalled metadata and payload transfers and a checker-only symbolic state-store index. Initial reset is established separately through Tcl. The verification environment does not assume authorized traffic, unique policy matches, successful CANsec checks, or eventual payload completion.

Changing the tool version, grid configuration, resource limits, design parameters, assumptions, or executable source may affect proof effort or results.

## 4. Reported formal results

All 42 assertions were proven and all 22 cover properties were reached under the specified environmental assumptions.

| Verification component | Assertions proven | Cover properties reached |
| --- | ---: | ---: |
| Top-level semantic IDS | 26 / 26 | 16 / 16 |
| State store | 8 / 8 | 2 / 2 |
| Multi-PDU parser | 8 / 8 | 4 / 4 |
| **Total** | **42 / 42** | **22 / 22** |

Additional metrics from the supplied VC Formal summary:

| Measure | Result |
| --- | ---: |
| Reported vacuity checks | 41 / 41 non-vacuous |
| Reported witness goals | 46 / 46 covered |
| Active SVA assumptions | 4 |

The proven properties cover RTL-level safety requirements for pipeline control, authorization decisions, stream validation, persistent state protection, multi-PDU parsing, evidence accumulation, and incident reporting. They do not establish unrestricted system-level correctness or detection of all possible attacks.

## 5. FPGA implementation

The proposed semantic IDS was implemented on the AMD Kria KV260 FPGA platform using AMD Vivado 2026.1. The paper reports the following post-implementation results for the IDS core and timing evaluation:

| Measure | Reported result |
| --- | ---: |
| Look-up tables (LUTs) | 1,786 |
| Flip-flops (FFs) | 305 |
| Target clock frequency | 100 MHz |
| Worst negative slack (WNS) | +0.275 ns |

On-chip functional validation used Virtual Input/Output (VIO) and an Integrated Logic Analyzer (ILA) to evaluate legitimate native and multi-PDU frames and four security violation scenarios. The FPGA evaluation is described in the paper; the FPGA test infrastructure and experimental waveform figures are not included in this repository.

## 6. Manuscript and citation

**Associated paper:**

Amir Alipour-Fanid, Monireh Dabaghchian, and Mandar Munishwar, “A Formally Verified Semantic Intrusion Detection System for Automotive CAN XL Networks.”

**Publication status:** Accepted for publication by IEEE. Final bibliographic details, including the publication venue and DOI, will be added when available.

The paper presents the system model, threat model, proposed semantic IDS architecture, formal verification methodology and results, FPGA implementation, and experimental validation.

If you use this implementation or build upon the proposed architecture in your research, please cite the associated paper.

## 7. License and research use

The source code is made available under the [MIT License](LICENSE) to support academic research, transparency, reproducibility, and further development. The associated IEEE paper and its figures are subject to their applicable publication and copyright terms.

## 8. Acknowledgments

This work was supported in part by the U.S. National Science Foundation (NSF) Research Initiation Award under Grant No. 2500079 and NSF TRAILS under Award No. 2229885.

The authors thank Synopsys and Ravindra Aneja for providing VC Formal tool support for the formal verification of the proposed semantic IDS.

**AI Assistance Statement:** During the preparation of this work, the authors used ChatGPT (OpenAI) for language polishing and Codex (OpenAI) to assist with developing, debugging, and refining the SystemVerilog RTL and formal verification assertions. All figures were prepared by the authors. All AI-assisted work was reviewed and validated by the authors, who take full responsibility for the content and results of the paper.
