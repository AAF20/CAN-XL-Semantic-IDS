## A Formally Verified Semantic Intrusion Detection System for Automotive CAN XL Networks
## Synopsys VC Formal FPV flow (paper Section V-C; VC Static Y-2026.03-SP2).
## Run from the directory containing canxl-IDS-rtl.sv and canxl-IDS-formal-sva.sv.
## This script preserves the original proof configuration.
## ============================================================================
## CAN-XL v2.1 VC Formal script
## ============================================================================

## Application setup
## Select Formal Property Verification (FPV), not simulation or synthesis.
set_app_var fml_mode_on true
set_fml_appmode FPV

## Enable vacuity and witness analysis in addition to assertion proofs and covers.
set_fml_var fml_vacuity_on true
set_fml_var fml_witness_on true

## Runtime/resource settings
## Proof limits: 200 hours, 24 GB and an auto-scale task count of 16.
set_fml_var fml_max_time 200H
set_fml_var fml_max_mem 24GB
set_fml_var fml_auto_scale_task_count 16

## Use 16 VC Formal workers (rsh grid allocation).
## Configure the original remote-shell grid allocation.
set_grid_usage -type rsh=16


## Echo the effective settings and grid configuration for reproducibility.
puts "Max time         = [get_fml_var fml_max_time]"
puts "Memory           = [get_fml_var fml_max_mem]"
puts "Auto-scale tasks = [get_fml_var fml_auto_scale_task_count]"

report_grid_usage

## --------------------------------------------------------------------------
## RTL source organization (package and three synthesizable modules):
##   can_xl_semantic_pkg      - shared configuration, frame and evidence types
##   can_xl_state_store       - stateful ownership and timing protection
##   can_xl_multi_pdu_parser  - streaming inner-PDU parsing and authorization
##   can_xl_semantic_ids      - three-level semantic IDS and incident reporting
## --------------------------------------------------------------------------

## Analyze DUT RTL first
## The package must be analyzed before the bound checkers that import its types.
analyze -format sverilog -vcs {
    canxl-IDS-rtl.sv
}

## Analyze formal assertions
## Load 42 assertions, four active assumptions and 22 cover properties.
analyze -format sverilog -vcs {
    canxl-IDS-formal-sva.sv
}

## Elaborate the top-level module
## Elaborate the IDS and its three bound white-box formal checkers.
elaborate can_xl_semantic_ids -sva

## Clock configuration
## Preserve the original formal clock period; FPGA timing is evaluated separately.
create_clock clk -period 4000

## Initialize the RTL using asserted reset
## Initial active-low reset is supplied by this flow rather than an active m_reset SVA.
sim_force rst_n -apply 1'b0

## Save initialized state
## Run to a stable reset state and save it as the formal starting state.
sim_run -stable
sim_save_reset

## Run formal verification
## Execute the configured proof and cover checks under the active assumptions.
check_fv
