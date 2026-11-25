// A Formally Verified Semantic Intrusion Detection System for Automotive CAN XL Networks
// White-box formal verification using SystemVerilog Assertions (paper Section V).
// Bound checkers: top-level semantic IDS (26 assertions, 16 covers), state store
// (8 assertions, 2 covers), and multi-PDU parser (8 assertions, 4 covers).
// Four active SVA assumptions constrain interface stability and a checker-only
// symbolic index. Initial reset is established by the VC Formal Tcl script.
// No assumptions require authorized traffic, unique matches, or eventual completion.

//

`default_nettype none
// Top-level checker: pipeline control, authorization, evidence and incident provenance.
module can_xl_research_top_fv import can_xl_semantic_pkg::*;
#(parameter int NUM_BINDINGS=8, NUM_RULES=16)(
  input logic clk, rst_n, meta_valid, meta_ready, meta_accept,
  input frame_meta_t meta_in,
  input logic [7:0] active_config_generation,
  input logic payload_valid, payload_ready, payload_last, frame_abort, beat_accept,
  input logic [63:0] payload_data,
  input logic [7:0] payload_keep,
  input pipeline_state_e state_q,
  input frame_context_t ctx_q,
  input sdt_descriptor_t desc_w,
  input domain_binding_t binding_q, binding_w,
  input domain_binding_t bindings[NUM_BINDINGS],
  input semantic_rule_t rule_w,
  input semantic_rule_t rules[NUM_RULES],
  input logic sdt_ok_q, domain_ok_q, decoder_ok_q, policy_ok_w, abort_q,
  input logic state_check, state_commit, parser_boundary,
  input logic [PDU_INDEX_W:0] pdu_count,
  input pending_update_t pending_q, pending_w,
  input evidence_t evidence_q, stage_ev, state_ev, stream_ev, parser_ev, final_ev,
  input logic [LENGTH_W:0] actual_q,
  input pdu_detail_t pdu_detail,
  input logic incident_valid,
  input semantic_incident_t incident_data
);
  // Sample on the rising edge; normal properties are disabled during active-low reset.
  default clocking cb @(posedge clk); endclocking
  default disable iff (!rst_n);
  // Checker-only history tracks accepted metadata, generation, abort, commit and evidence.
  logic f_past, f_active, f_abort, f_committed;
  frame_meta_t f_meta;
  logic [7:0] f_generation;
  evidence_t f_seen;
  // The catalog reset condition is supplied by Tcl initialization; this SVA is inactive.
  //initial m_reset: assume (!rst_n);
  // Hold valid metadata stable while the IDS is not ready.
  m_meta_stable: assume property (meta_valid && !meta_ready |=> meta_valid && $stable(meta_in));
  // Abort cancels the current payload transaction, including a stalled beat.
  // Hold a stalled payload beat stable unless abort cancels the frame.
  m_payload_stable: assume property (payload_valid && !payload_ready && !frame_abort |=>
    frame_abort || (payload_valid && $stable({payload_data,payload_keep,payload_last})));
  // Track the originating frame independently from acceptance through reporting.
  always_ff @(posedge clk or negedge rst_n) begin
    if (!rst_n) begin
      f_past<=0; f_active<=0; f_abort<=0; f_committed<=0;
      f_meta<='0; f_generation<=0; f_seen<=0;
    end else begin
      f_past<=1;
      if (meta_accept) begin
        f_active<=1; f_abort<=frame_abort; f_committed<=0;
        f_meta<=meta_in; f_generation<=active_config_generation;
        f_seen<=0;
        if (frame_abort) f_seen[EV_ABORT]<=1;
      end else if (f_active) begin
        if (state_q inside {ST_SDT,ST_DOMAIN,ST_POLICY,ST_PAYLOAD,ST_FINALIZE}) begin
          f_seen<=f_seen|stage_ev|state_ev|stream_ev|
            ((ctx_q.semantic_class==SEM_MULTI_PDU)?parser_ev:evidence_t'(0));
          if (frame_abort) begin f_abort<=1; f_seen[EV_ABORT]<=1; end
          if (active_config_generation!=f_generation) f_seen[EV_CONFIG_GENERATION]<=1;
        end
        if (state_commit) f_committed<=1;
        if (state_q==ST_REPORT) f_active<=0;
      end
    end
  end
  // Reference finite-state transition relation, including permitted idle/payload stalls.
  function automatic logic f_transition(pipeline_state_e p, n);
    case (p)
      ST_IDLE: return n inside {ST_IDLE,ST_SDT};
      ST_SDT: return n==ST_DOMAIN;
      ST_DOMAIN: return n==ST_POLICY;
      ST_POLICY: return n inside {ST_PAYLOAD,ST_FINALIZE};
      ST_PAYLOAD: return n inside {ST_PAYLOAD,ST_FINALIZE};
      ST_FINALIZE: return n==ST_REPORT;
      ST_REPORT: return n==ST_IDLE;
      default: return 0;
    endcase
  endfunction
  // Independently derive the required evidence for a uniquely selected outer-service rule.
  function automatic evidence_t f_constraints(frame_meta_t m, semantic_rule_t r);
    evidence_t e;
    logic need_check;
    e=0;
    need_check=r.security.require_cansec || r.security.require_auth ||
      r.security.require_freshness || r.security.require_integrity ||
      r.security.require_confidentiality || r.security.channel_mask!=0;
    e[EV_PID]=((m.pid^r.pid_value)&r.pid_mask)!=0;
    e[EV_LENGTH]=m.payload_length==0 || m.payload_length>2048 ||
      m.payload_length<r.min_length || m.payload_length>r.max_length;
    e[EV_SEC_MISSING]=r.security.require_sec && !m.sec;
    e[EV_CANSEC_NOT_CHECKED]=need_check && !m.cansec.checked;
    e[EV_CANSEC_AUTH]=r.security.require_auth && m.cansec.checked && !m.cansec.auth_ok;
    e[EV_CANSEC_FRESHNESS]=r.security.require_freshness && m.cansec.checked && !m.cansec.freshness_ok;
    e[EV_CANSEC_INTEGRITY]=r.security.require_integrity && m.cansec.checked && !m.cansec.integrity_ok;
    e[EV_CANSEC_CONFIDENTIALITY]=r.security.require_confidentiality && m.cansec.checked && !m.cansec.confidentiality_on;
    e[EV_CANSEC_CHANNEL]=m.cansec.checked && ((m.cansec.channel_id^r.security.channel_value)&r.security.channel_mask)!=0;
    e[EV_CONFIG_GENERATION]=r.generation!=f_generation;
    return e;
  endfunction
  integer f_domain_hits, f_rule_hits;
  domain_binding_t f_binding;
  semantic_rule_t f_rule;
  logic f_authorized;
  evidence_t f_required;
  logic [LENGTH_W+1:0] f_sum;
  logic [LENGTH_W:0] f_length;
  // Reference lookup cardinality and byte count; do not reuse DUT lookup/count helpers.
  always_comb begin
    f_binding='0; f_rule='0; f_rule.rule_id=8'hff;
    f_domain_hits=0; f_rule_hits=0;
    // Domain binding: reconstruct the first matching entry and total number of matches.
    for (int i=0;i<NUM_BINDINGS;i++) begin
      if (sdt_ok_q && bindings[i].valid && bindings[i].semantic_class==ctx_q.semantic_class &&
          (((ctx_q.meta.vcid^bindings[i].vcid_value)&bindings[i].vcid_mask)==0)) begin
        f_domain_hits=f_domain_hits+1;
        if (f_domain_hits==1) f_binding=bindings[i];
      end
    end
    // Outer-service lookup restricted to the captured domain binding's assigned range.
    for (int i=0;i<NUM_RULES;i++) begin
      if (sdt_ok_q && domain_ok_q && decoder_ok_q &&
          i>=int'(binding_q.rule_base) && i<int'(binding_q.rule_base)+int'(binding_q.rule_count) &&
          rules[i].enable && rules[i].semantic_class==ctx_q.semantic_class && rules[i].domain_id==ctx_q.domain_id &&
          (((ctx_q.service_id^rules[i].service_value)&rules[i].service_mask)==0)) begin
        f_rule_hits=f_rule_hits+1;
        if (f_rule_hits==1) f_rule=rules[i];
      end
    end
    f_required=f_constraints(ctx_q.meta,f_rule);
    f_authorized=sdt_ok_q && domain_ok_q && decoder_ok_q && f_rule_hits==1 &&
      f_required==0 && evidence_q==0 && !abort_q && !frame_abort && active_config_generation==f_generation;
    // Reference saturating count uses $countones rather than the RTL byte_count function.
    f_sum={1'b0,actual_q}+(LENGTH_W+2)'($countones(payload_keep));
    f_length=f_sum[LENGTH_W+1]?{(LENGTH_W+1){1'b1}}:f_sum[LENGTH_W:0];
  end
  // Reset and one-frame-at-a-time control, including exact FSM timing.
  // Reset returns the controller to idle and clears incident, count and pending update.
  a_reset: assert property (@(posedge clk) disable iff (1'b0) !rst_n |=>
    state_q==ST_IDLE && !incident_valid && actual_q==0 && pending_q==0);
  // Every controller transition follows the permitted reference relation.
  a_fsm: assert property (f_past |-> f_transition($past(state_q),state_q));
  // Metadata and payload ready/accept signals follow their exact handshake definitions.
  a_handshakes: assert property (meta_ready==(state_q==ST_IDLE) &&
    meta_accept==(meta_valid && meta_ready) &&
    payload_ready==(state_q==ST_PAYLOAD && !abort_q && !frame_abort) &&
    beat_accept==(payload_valid && payload_ready));
  // Active frame metadata and generation match acceptance; no second frame is accepted.
  a_origin: assert property (f_active |-> ctx_q.meta==f_meta && ctx_q.generation==f_generation && !meta_accept);
  // Frame context remains stable across payload processing and finalization.
  a_context_stable: assert property (f_past && $past(state_q inside {ST_PAYLOAD,ST_FINALIZE}) |-> $stable(ctx_q));
  // Independent lookup cardinality; no assertions inside table loops.
  // Registered SDT validity reflects enablement, supported class and generation agreement.
  a_sdt: assert property (state_q==ST_SDT |=> f_past &&
    sdt_ok_q==$past(desc_w.enable && desc_w.semantic_class inside {SEM_NATIVE,SEM_MULTI_PDU} && desc_w.generation==ctx_q.generation));
  // The combinational domain binding equals the reference first match.
  a_domain: assert property (state_q==ST_DOMAIN |-> binding_w==f_binding);
  // Registered domain validity requires exactly one generation-consistent match.
  a_domain_capture: assert property (state_q==ST_DOMAIN |=> f_past &&
    domain_ok_q==$past(f_domain_hits==1 && f_binding.generation==ctx_q.generation));
  // Selected outer rule and authorization match the reference; required evidence is present.
  a_policy: assert property (state_q==ST_POLICY |-> rule_w==f_rule && policy_ok_w==f_authorized &&
    (!(f_rule_hits==1) || (stage_ev & f_required)==f_required));
  // Stateful checking occurs only for an authorized policy evaluation, never with commit.
  a_check: assert property (state_check |-> state_q==ST_POLICY && f_authorized && !state_commit);
  // Policy authorization and pending update are captured on the next cycle.
  a_allocation: assert property (state_q==ST_POLICY |=> f_past &&
    ctx_q.authorized==$past(f_authorized) && pending_q==$past(pending_w));
  // Abort history begins at acceptance, not one setup cycle later.
  // Latched abort prevents payload acceptance and persistent state commit.
  a_abort: assert property (f_abort && state_q inside {ST_SDT,ST_DOMAIN,ST_POLICY,ST_PAYLOAD,ST_FINALIZE}
    |-> abort_q && !beat_accept && !state_commit);
  // Pending update remains stable across payload-processing cycles.
  a_pending: assert property (f_past && $past(state_q==ST_PAYLOAD) |-> $stable(pending_q));
  // Counts saturate, malformed keeps remain unconstrained and generate evidence.
  // Each accepted beat updates the actual-byte count to the reference saturating sum.
  a_bytes: assert property (beat_accept |=> f_past && actual_q==$past(f_length));
  // Actual-byte count is stable without preceding metadata or payload acceptance.
  a_no_bytes: assert property (f_past && !$past(beat_accept || meta_accept) |-> $stable(actual_q));
  // Invalid keep, payload overrun or final length mismatch raises the required evidence.
  a_stream: assert property (beat_accept |->
    ((!payload_last && payload_keep!=8'hff) || (payload_last && !final_keep_ok(payload_keep)) ? stream_ev[EV_KEEP] : 1'b1) &&
    ((f_sum>{2'b0,ctx_q.meta.payload_length} || (payload_last && f_sum!={2'b0,ctx_q.meta.payload_length})) ? stream_ev[EV_STREAM_LENGTH] : 1'b1));
  // Abort or accepted final beat advances payload processing to finalization.
  a_terminal: assert property (state_q==ST_PAYLOAD && (frame_abort || abort_q || (beat_accept && payload_last)) |=> state_q==ST_FINALIZE);
  // Finalization must originate from an allowed abort or accepted final beat.
  a_finalize_reason: assert property (state_q==ST_FINALIZE |-> f_past &&
    $past((state_q==ST_POLICY && (abort_q || frame_abort)) ||
      (state_q==ST_PAYLOAD && (abort_q || frame_abort || (beat_accept && payload_last)))));
  // Evidence completeness checks the output against independently accumulated pulses.
  // Every independently observed violation is retained in the reported incident.
  a_evidence: assert property (state_q==ST_REPORT && f_seen!=0 |-> incident_valid && (incident_data.evidence & f_seen)==f_seen);
  // Zero final evidence implies authorization and a nonempty, complete multi-PDU payload.
  a_clean: assert property (state_q==ST_FINALIZE && final_ev==0 |-> ctx_q.authorized &&
    (ctx_q.semantic_class!=SEM_MULTI_PDU || (parser_boundary && pdu_count!=0)));
  // Commit and incident decisions must use the same finalization edge.
  // Commit is unique, clean, authorized and tied to the originating frame and generation.
  a_commit: assert property (state_commit |-> !f_committed && f_active && state_q==ST_FINALIZE &&
    ctx_q.authorized && final_ev==0 && pending_q.valid &&
    pending_q.domain_id==ctx_q.domain_id && pending_q.timestamp==ctx_q.meta.timestamp &&
    pending_q.generation==ctx_q.generation && active_config_generation==ctx_q.generation);
  // A clean authorized frame with a valid pending update must commit at finalization.
  a_commit_complete: assert property (state_q==ST_FINALIZE && ctx_q.authorized && pending_q.valid && final_ev==0 |-> state_commit);
  // Incident valid is asserted exactly when preceding final evidence was nonzero.
  a_disposition: assert property (state_q==ST_FINALIZE |=> f_past && incident_valid==($past(final_ev)!=0));
  // Incident pulse occurs only in reporting with the originating frame active.
  a_pulse: assert property (incident_valid |-> state_q==ST_REPORT && f_active);
  // Incident valid lasts one cycle; incident data remains stable afterward.
  a_pulse_end: assert property (incident_valid |=> !incident_valid && $stable(incident_data));
  // Explicit tuple proves complete compact-record provenance, including final-beat evidence.
  // Incident fields, lengths, evidence and first-PDU detail match finalization context.
  a_incident: assert property (state_q==ST_FINALIZE && final_ev!=0 |=> f_past &&
    {incident_data.frame_tag,incident_data.sdt,incident_data.vcid,incident_data.domain_id,
     incident_data.semantic_class,incident_data.service_id,incident_data.pid,incident_data.rule_id,
     incident_data.generation,incident_data.declared_length,incident_data.actual_length,incident_data.evidence}==
    $past({ctx_q.meta.frame_tag,ctx_q.meta.sdt,ctx_q.meta.vcid,ctx_q.domain_id,
     ctx_q.semantic_class,ctx_q.service_id,ctx_q.meta.pid,ctx_q.rule_id,
     ctx_q.generation,ctx_q.meta.payload_length,actual_q,final_ev}) &&
    incident_data.pdu==$past((ctx_q.semantic_class==SEM_MULTI_PDU)?pdu_detail:pdu_detail_t'(0)));
  // Architectural covers; every report cover implies an accepted originating frame.
  // Reach clean native-frame finalization.
  c_clean_native: cover property (state_q==ST_FINALIZE && ctx_q.semantic_class==SEM_NATIVE && final_ev==0);
  // Reach clean multi-PDU finalization with more than one parsed PDU.
  c_clean_multi: cover property (state_q==ST_FINALIZE && ctx_q.semantic_class==SEM_MULTI_PDU && pdu_count>1 && final_ev==0);
  // Reach an incident for an unknown or disabled SDT.
  c_unknown: cover property (incident_valid && incident_data.evidence[EV_UNKNOWN_SDT]);
  // Reach an unbound VCID or ambiguous domain-binding incident.
  c_domain: cover property (incident_valid && (incident_data.evidence[EV_UNBOUND_VCID] || incident_data.evidence[EV_AMBIGUOUS_DOMAIN]));
  // Reach an incident with no matching outer-service authorization rule.
  c_service_denied: cover property (incident_valid && incident_data.evidence[EV_SERVICE_DENIED]);
  // Reach an incident with multiple matching outer-service rules.
  c_policy_ambiguous: cover property (incident_valid && incident_data.evidence[EV_AMBIGUOUS_POLICY]);
  // Reach an incident reporting a PID policy violation.
  c_priority: cover property (incident_valid && incident_data.evidence[EV_PID]);
  // Reach failed CANsec authentication or a missing required CANsec check.
  c_cansec: cover property (incident_valid && (incident_data.evidence[EV_CANSEC_AUTH] || incident_data.evidence[EV_CANSEC_NOT_CHECKED]));
  // Reach an incident reporting a configuration-generation violation.
  c_generation: cover property (incident_valid && incident_data.evidence[EV_CONFIG_GENERATION]);
  // Reach an aborted-frame incident.
  c_abort: cover property (incident_valid && incident_data.evidence[EV_ABORT]);
  // Reach an invalid keep or payload-length incident.
  c_stream: cover property (incident_valid && (incident_data.evidence[EV_KEEP] || incident_data.evidence[EV_STREAM_LENGTH]));
  // Reach an unauthorized inner-PDU incident.
  c_inner: cover property (incident_valid && incident_data.evidence[EV_INNER_DENIED]);
  // Reach an ambiguous inner-PDU authorization incident.
  c_inner_ambiguous: cover property (incident_valid && incident_data.evidence[EV_INNER_AMBIGUOUS]);
  // Reach an incomplete multi-PDU payload incident.
  c_incomplete: cover property (incident_valid && incident_data.evidence[EV_INCOMPLETE_PDU]);
  // Reach a minimum-interval timing violation incident.
  c_timing: cover property (incident_valid && incident_data.evidence[EV_TIMING]);
  // Reach a successful persistent state commit.
  c_commit: cover property (state_commit);
endmodule

// State-store checker: pending updates, domain ownership, timing and persistent writes.
module can_xl_research_state_fv import can_xl_semantic_pkg::*;
#(parameter int STATE_DEPTH=256, INDEX_W=(STATE_DEPTH<=1)?1:$clog2(STATE_DEPTH))(
  input logic clk, rst_n, check_valid, commit_valid, write_ok, range_ok, owner_ok,
  input frame_context_t frame_ctx,
  input domain_binding_t binding,
  input semantic_rule_t rule,
  input pending_update_t pending, commit_update,
  input evidence_t evidence,
  input logic [31:0] interval_w,
  input logic [INDEX_W-1:0] check_index, commit_index,
  input logic [STATE_DEPTH-1:0] seen,
  input logic [7:0] owner[STATE_DEPTH],
  input logic [31:0] last_ts[STATE_DEPTH],
  input logic [INDEX_W-1:0] f_track
);
  default clocking cb @(posedge clk); endclocking
  default disable iff (!rst_n);
  logic f_past;
  always_ff @(posedge clk or negedge rst_n)
    if (!rst_n) f_past<=0; else f_past<=1;
  // Free checker-only index: do not tie it to an address or correlate it with traffic.
  // Restrict only the symbolic checker index to an implemented state entry.
  m_index: assume property (@(posedge clk) disable iff (1'b0) int'(f_track)<STATE_DEPTH);
  // Keep the symbolic index constant for arbitrary-entry proofs.
  m_constant: assume property (f_past |-> $stable(f_track));
  // Pending validity is equivalent to a stateful check passing range and ownership.
  a_pending_valid: assert property (pending.valid==(check_valid && rule.stateful_enable && range_ok && owner_ok));
  // Pending address, domain, timestamp and generation match the current frame and rule.
  a_pending: assert property (pending.valid |-> check_valid && rule.stateful_enable && range_ok && owner_ok &&
    {1'b0,pending.address}==({1'b0,binding.state_base}+(STATE_ADDR_W+1)'(rule.state_profile)) &&
    pending.domain_id==frame_ctx.domain_id && pending.timestamp==frame_ctx.meta.timestamp && pending.generation==frame_ctx.generation);
  // Range or ownership failure suppresses pending validity and raises ownership evidence.
  a_reject: assert property (check_valid && rule.stateful_enable && (!range_ok || !owner_ok) |->
    !pending.valid && evidence[EV_STATE_OWNERSHIP]);
  // Check modulo-2^32 interval and exact minimum-interval violation evidence.
  a_timing: assert property (pending.valid |-> interval_w==frame_ctx.meta.timestamp-last_ts[check_index] &&
    evidence[EV_TIMING]==(seen[check_index] && interval_w<rule.min_interval));
  // Every commit is valid, writable, in range and preserves domain ownership.
  a_commit: assert property (commit_valid |-> write_ok && commit_update.valid && int'(commit_update.address)<STATE_DEPTH &&
    (!seen[commit_index] || owner[commit_index]==commit_update.domain_id));
  // The symbolic entry is unchanged unless the preceding cycle wrote that entry.
  a_preserve: assert property (f_past && !$past(write_ok && commit_index==f_track) |->
    $stable({seen[f_track],owner[f_track],last_ts[f_track]}));
  // Writing the symbolic entry sets seen and stores committed domain and timestamp.
  a_write: assert property (write_ok && commit_index==f_track |=> f_past && seen[f_track] &&
    owner[f_track]==$past(commit_update.domain_id) && last_ts[f_track]==$past(commit_update.timestamp));
  // Reset clears the symbolic entry's seen bit, owner and timestamp.
  a_reset: assert property (@(posedge clk) disable iff (1'b0) !rst_n |=>
    !seen[f_track] && owner[f_track]==0 && last_ts[f_track]==0);
  // Reach a stateful check blocked by ownership mismatch with evidence asserted.
  c_owner_block: cover property (check_valid && rule.stateful_enable && !owner_ok && evidence[EV_STATE_OWNERSHIP]);
  // Reach a write to the arbitrary symbolic tracked entry.
  c_tracked_write: cover property (write_ok && commit_index==f_track);
endmodule

// Multi-PDU checker: independent byte-level transition model and parser invariants.
module can_xl_research_mpdu_fv import can_xl_semantic_pkg::*;
#(parameter int NUM_INNER_RULES=16)(
  input logic clk, rst_n, frame_start, enable, beat_accept, boundary,
  input logic [63:0] payload_data, header_q,
  input logic [7:0] payload_keep,
  input logic [1:0] phase_q,
  input logic [2:0] header_bytes_q,
  input logic [11:0] remaining_q,
  input logic [LENGTH_W:0] offset_q, start_q,
  input logic [PDU_INDEX_W:0] pdu_count,
  input evidence_t evidence,
  input pdu_detail_t detail,
  input frame_context_t frame_ctx,
  input inner_pdu_rule_t inner_rules[NUM_INNER_RULES]
);
  default clocking cb @(posedge clk); endclocking
  default disable iff (!rst_n);
  logic f_past;
  always_ff @(posedge clk or negedge rst_n)
    if (!rst_n) f_past<=0; else f_past<=1;
  // Reference transition model: independently resolves each completed header.
  // It explicitly represents fail-stop ERROR, not a truncated-length phase guess.
  typedef struct packed {
    logic [1:0] phase;
    logic [63:0] header;
    logic [2:0] bytes;
    logic [11:0] remaining;
    logic [LENGTH_W:0] offset, start;
    logic [PDU_INDEX_W:0] count;
    evidence_t ev;
    pdu_detail_t first;
  } model_t;
  model_t f_now, f_next;
  integer f_hits;
  inner_pdu_rule_t f_rule;
  evidence_t f_header_ev;
  evidence_code_e f_code;
  logic [15:0] f_length;
  logic [PDU_INDEX_W-1:0] f_index;
  logic f_crossed_header, f_body_then_header;
  logic f_body_ended;
  // Reconstruct the next parser state from the current state and accepted byte lanes.
  always_comb begin
    f_now='{phase:phase_q,header:header_q,bytes:header_bytes_q,remaining:remaining_q,
      offset:offset_q,start:start_q,count:pdu_count,ev:evidence,first:detail};
    f_next=f_now; f_hits=0; f_rule='0; f_header_ev='0;
    f_code=EV_MALFORMED_PDU; f_length=0; f_index=0;
    f_crossed_header=0; f_body_then_header=0; f_body_ended=0;
    // Frame start takes precedence over parsing and clears the reference state.
    if (frame_start) f_next='0;
    else if (enable && beat_accept) begin
      for (int lane=0;lane<8;lane++) begin
        if (payload_keep[lane]) begin
          if (f_next.phase==1) begin
            if (f_next.remaining==1) begin f_next.remaining=0; f_next.phase=0; f_body_ended=1; end
            else f_next.remaining=f_next.remaining-1'b1;
          end else if (f_next.phase==0) begin
            if (f_next.bytes==0) begin f_next.start=f_next.offset; if (f_body_ended) f_body_then_header=1; end
            f_next.header[int'(f_next.bytes)*8 +: 8]=payload_data[lane*8 +: 8];
            if (f_next.bytes!=7) f_next.bytes=f_next.bytes+1'b1;
            else begin
              // Resolve the complete research-defined header and check index saturation.
              f_crossed_header=(header_bytes_q!=0);
              f_length=f_next.header[47:32]; f_header_ev=0; f_hits=0; f_rule='0;
              f_index=f_next.count[PDU_INDEX_W]?{PDU_INDEX_W{1'b1}}:f_next.count[PDU_INDEX_W-1:0];
              if (f_next.count[PDU_INDEX_W]) begin
                f_header_ev[EV_PDU_OVERFLOW]=1; f_code=EV_PDU_OVERFLOW; f_next.phase=2;
              end else begin
                f_next.count=f_next.count+1'b1;
                if (f_next.header[63:48]!=0 || f_length==0 || f_length>2048) begin
                  f_header_ev[EV_MALFORMED_PDU]=1; f_code=EV_MALFORMED_PDU; f_next.phase=2;
                end else begin
                  f_next.phase=1; f_next.remaining=f_length[11:0];
                  // Independently authorize the inner PDU in its outer frame context.
                  for (int r=0;r<NUM_INNER_RULES;r++) begin
                    if (inner_rules[r].enable && inner_rules[r].outer_domain==frame_ctx.domain_id &&
                      (((frame_ctx.service_id^inner_rules[r].outer_service_value)&inner_rules[r].outer_service_mask)==0) &&
                      inner_rules[r].pdu_type==f_next.header[7:0] && inner_rules[r].inner_domain==f_next.header[15:8] &&
                      (((f_next.header[31:16]^inner_rules[r].inner_service_value)&inner_rules[r].inner_service_mask)==0)) begin
                      f_hits=f_hits+1; if (f_hits==1) f_rule=inner_rules[r];
                    end
                  end
                  if (f_hits==0) begin f_header_ev[EV_INNER_DENIED]=1; f_code=EV_INNER_DENIED; end
                  else if (f_hits>1) begin f_header_ev[EV_INNER_AMBIGUOUS]=1; f_code=EV_INNER_AMBIGUOUS; end
                  else begin
                    f_header_ev[EV_CONFIG_GENERATION]=f_rule.generation!=frame_ctx.generation;
                    f_header_ev[EV_INNER_DENIED]=f_length<{4'b0,f_rule.min_length} || f_length>{4'b0,f_rule.max_length};
                    f_code=f_header_ev[EV_CONFIG_GENERATION]?EV_CONFIG_GENERATION:EV_INNER_DENIED;
                  end
                end
              end
              // Preserve the first violation while retaining all subsequent evidence bits.
              if (f_header_ev!=0 && !f_next.first.valid)
                f_next.first='{valid:1'b1,code:f_code,index:f_index,domain_id:f_next.header[15:8],
                  service_id:f_next.header[31:16],offset:f_next.start};
              f_next.ev=f_next.ev|f_header_ev; f_next.header=0; f_next.bytes=0;
            end
          end
          if (!(&f_next.offset)) f_next.offset=f_next.offset+1'b1;
        end
      end
    end
  end
  // One reference assertion replaces per-byte/per-rule assertion replication.
  // Full parser state equals the preceding reference next state.
  a_transition: assert property (f_past |-> f_now==$past(f_next));
  // Boundary is true exactly at an empty header phase.
  a_boundary: assert property (boundary==(phase_q==0 && header_bytes_q==0));
  // An active body has 1 to 2048 remaining bytes.
  a_body_range: assert property (phase_q==1 |-> remaining_q inside {[1:2048]});
  // Saturating PDU count never exceeds 256 for the configured 8-bit index.
  a_count: assert property (pdu_count<=(PDU_INDEX_W+1)'(256));
  // Previously set parser evidence persists until a new frame starts.
  a_sticky: assert property (f_past && !$past(frame_start) |-> (evidence & $past(evidence))==$past(evidence));
  // First-violation detail remains stable once valid until a new frame starts.
  a_provenance: assert property (f_past && !$past(frame_start) && $past(detail.valid) |-> $stable(detail));
  // A valid detail code is in range and has its corresponding evidence bit set.
  a_detail_bit: assert property (detail.valid |-> int'(detail.code)<EVIDENCE_W && evidence[detail.code]);
  // Frame start clears the complete parser state represented by the reference model.
  a_start: assert property (frame_start |=> f_now==0);
  // Reach completion of a header split across payload beats.
  c_split_header: cover property (f_crossed_header);
  // Reach a body ending and the next header beginning in one beat.
  c_same_beat: cover property (f_body_then_header);
  // Reach both inner denial and ambiguous inner-policy evidence in one frame.
  c_two_kinds: cover property (evidence[EV_INNER_DENIED] && evidence[EV_INNER_AMBIGUOUS]);
  // Reach PDU-index saturation with overflow evidence.
  c_overflow: cover property (evidence[EV_PDU_OVERFLOW]);
endmodule

// Bind the checkers to internal RTL signals without modifying the synthesizable design.
// All bind statements are at the end. Inputs only: no checker drives DUT state.
bind can_xl_semantic_ids can_xl_research_top_fv #(.NUM_BINDINGS(NUM_BINDINGS),.NUM_RULES(NUM_RULES)) fv_top(
  .clk(clk),.rst_n(rst_n),.meta_valid(meta_valid),.meta_ready(meta_ready),.meta_accept(meta_accept),
  .meta_in('{frame_tag:frame_tag,sdt:sdt,vcid:vcid,af:af,pid:pid,sec:sec,payload_length:payload_length,timestamp:timestamp,cansec:cansec}),
  .active_config_generation(active_config_generation),.payload_valid(payload_valid),.payload_ready(payload_ready),
  .payload_last(payload_last),.frame_abort(frame_abort),.beat_accept(beat_accept),.payload_data(payload_data),.payload_keep(payload_keep),
  .state_q(state_q),.ctx_q(ctx_q),.desc_w(desc_w),.binding_q(binding_q),.binding_w(binding_w),.bindings(bindings),
  .rule_w(rule_w),.rules(rules),.sdt_ok_q(sdt_ok_q),.domain_ok_q(domain_ok_q),.decoder_ok_q(decoder_ok_q),
  .policy_ok_w(policy_ok_w),.abort_q(abort_q),.state_check(state_check),.state_commit(state_commit),
  .parser_boundary(parser_boundary),.pdu_count(pdu_count),.pending_q(pending_q),.pending_w(pending_w),
  .evidence_q(evidence_q),.stage_ev(stage_ev),.state_ev(state_ev),.stream_ev(stream_ev),.parser_ev(parser_ev),
  .final_ev(final_ev),.actual_q(actual_q),.pdu_detail(pdu_detail),.incident_valid(incident_valid),.incident_data(incident_data));
bind can_xl_state_store can_xl_research_state_fv #(.STATE_DEPTH(STATE_DEPTH),.INDEX_W(INDEX_W)) fv_state(
  .clk(clk),.rst_n(rst_n),.check_valid(check_valid),.commit_valid(commit_valid),.write_ok(write_ok),.range_ok(range_ok),.owner_ok(owner_ok),
  .frame_ctx(frame_ctx),.binding(binding),.rule(rule),.pending(pending),.commit_update(commit_update),.evidence(evidence),.interval_w(interval_w),
  .check_index(check_index),.commit_index(commit_index),.seen(seen),.owner(owner),.last_ts(last_ts),.f_track());
bind can_xl_multi_pdu_parser can_xl_research_mpdu_fv #(.NUM_INNER_RULES(NUM_INNER_RULES)) fv_mpdu(
  .clk(clk),.rst_n(rst_n),.frame_start(frame_start),.enable(enable),.beat_accept(beat_accept),.boundary(boundary),
  .payload_data(payload_data),.header_q(header_q),.payload_keep(payload_keep),.phase_q(phase_q),.header_bytes_q(header_bytes_q),
  .remaining_q(remaining_q),.offset_q(offset_q),.start_q(start_q),.pdu_count(pdu_count),.evidence(evidence),.detail(detail),
  .frame_ctx(frame_ctx),.inner_rules(inner_rules));
`default_nettype wire
