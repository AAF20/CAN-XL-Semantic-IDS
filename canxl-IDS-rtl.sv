// A Formally Verified Semantic Intrusion Detection System for Automotive CAN XL Networks
// Synthesizable SystemVerilog RTL (paper Sections III and IV).
// Three security levels: SDT-based semantic interpretation, VCID-based domain
// binding, and domain-specific authorization of outer services and inner PDUs.
// The IDS consumes receiver-provided metadata and payload; it does not implement
// CAN XL signaling or perform CANsec cryptographic verification itself.
// Persistent state is committed only after violation-free frame finalization.
//

`default_nettype none
// Shared frame, configuration, state, and incident-reporting types.
package can_xl_semantic_pkg;
  // Length fields support up to 2048 payload bytes; wider counters saturate.
  parameter int LENGTH_W=12, PDU_INDEX_W=8, STATE_ADDR_W=16;
  parameter int EVIDENCE_W=27;
  localparam logic [11:0] MAX_PAYLOAD=12'd2048;
  typedef enum logic [1:0] {SEM_NATIVE, SEM_MULTI_PDU, SEM_UNSUPPORTED} semantic_class_e;
  // Seven-state, one-frame-at-a-time semantic IDS controller.
  typedef enum logic [2:0] {
    ST_IDLE, ST_SDT, ST_DOMAIN, ST_POLICY, ST_PAYLOAD, ST_FINALIZE, ST_REPORT
  } pipeline_state_e;
  // Each evidence code indexes an independent bit in the frame-level bitmap.
  typedef enum logic [4:0] {
    EV_UNKNOWN_SDT, EV_UNSUPPORTED_CONTEXT, EV_UNBOUND_VCID,
    EV_AMBIGUOUS_DOMAIN, EV_SERVICE_DENIED, EV_AMBIGUOUS_POLICY,
    EV_CONFIG_GENERATION, EV_AF_DECODER, EV_PID, EV_LENGTH,
    EV_SEC_MISSING, EV_CANSEC_NOT_CHECKED, EV_CANSEC_AUTH,
    EV_CANSEC_FRESHNESS, EV_CANSEC_INTEGRITY, EV_CANSEC_CONFIDENTIALITY,
    EV_CANSEC_CHANNEL, EV_STATE_OWNERSHIP, EV_TIMING, EV_STREAM_LENGTH,
    EV_KEEP, EV_ABORT, EV_MALFORMED_PDU, EV_INNER_DENIED,
    EV_INNER_AMBIGUOUS, EV_INCOMPLETE_PDU, EV_PDU_OVERFLOW
  } evidence_code_e;
  typedef logic [EVIDENCE_W-1:0] evidence_t;
  // Trusted receiver-provided CANsec status and service-specific requirements.
  typedef struct packed {
    logic checked, auth_ok, freshness_ok, integrity_ok, confidentiality_on;
    logic [7:0] channel_id;
  } cansec_status_t;
  typedef struct packed {
    logic require_sec, require_cansec, require_auth, require_freshness;
    logic require_integrity, require_confidentiality;
    logic [7:0] channel_value, channel_mask;
  } security_policy_t;
  // SDT descriptor table: enablement, semantic class, AF decoding, generation.
  typedef struct packed {
    logic enable;
    semantic_class_e semantic_class;
    logic [3:0] af_decoder_id;
    logic [7:0] generation;
  } sdt_descriptor_t;
  // Domain-binding table: masked VCID and class select a domain and its ranges.
  typedef struct packed {
    logic valid;
    semantic_class_e semantic_class;
    logic [7:0] vcid_value, vcid_mask, domain_id;
    logic [11:0] rule_base;
    logic [7:0] rule_count;
    logic [STATE_ADDR_W-1:0] state_base;
    logic [7:0] state_count, generation;
  } domain_binding_t;
  // Outer-service rule: masked service/PID, length, security and stateful policy.
  typedef struct packed {
    logic enable;
    semantic_class_e semantic_class;
    logic [7:0] domain_id;
    logic [15:0] service_value, service_mask;
    logic [10:0] pid_value, pid_mask;
    logic [11:0] min_length, max_length;
    security_policy_t security;
    logic stateful_enable;
    logic [7:0] state_profile;
    logic [31:0] min_interval;
    logic [7:0] rule_id, generation;
  } semantic_rule_t;
  // Inner-PDU rule: authorize a PDU within its outer domain and service context.
  typedef struct packed {
    logic enable;
    logic [7:0] outer_domain;
    logic [15:0] outer_service_value, outer_service_mask;
    logic [7:0] pdu_type, inner_domain;
    logic [15:0] inner_service_value, inner_service_mask;
    logic [11:0] min_length, max_length;
    logic [7:0] generation;
  } inner_pdu_rule_t;
  // Accepted frame metadata, including receiver-supplied timestamp and frame tag.
  typedef struct packed {
    logic [15:0] frame_tag;
    logic [7:0] sdt, vcid;
    logic [31:0] af;
    logic [10:0] pid;
    logic sec;
    logic [11:0] payload_length;
    logic [31:0] timestamp;
    cansec_status_t cansec;
  } frame_meta_t;
  // Frame context progressively resolved during the three security levels.
  typedef struct packed {
    frame_meta_t meta;
    semantic_class_e semantic_class;
    logic [7:0] domain_id;
    logic [15:0] service_id;
    logic [7:0] rule_id, generation;
    logic authorized;
  } frame_context_t;
  // Candidate state update; preparing it does not modify persistent state.
  typedef struct packed {
    logic valid;
    logic [STATE_ADDR_W-1:0] address;
    logic [7:0] domain_id, generation;
    logic [31:0] timestamp;
  } pending_update_t;
  // First detected inner-PDU violation: zero-based index and header byte offset.
  typedef struct packed {
    logic valid;
    evidence_code_e code;
    logic [PDU_INDEX_W-1:0] index;
    logic [7:0] domain_id;
    logic [15:0] service_id;
    logic [LENGTH_W:0] offset;
  } pdu_detail_t;
  // Compact incident: bitmap has no lossy priority encoder. The PDU detail
  // independently describes the FIRST inner violation, not a global primary.
  typedef struct packed {
    logic [15:0] frame_tag;
    logic [7:0] sdt, vcid, domain_id;
    semantic_class_e semantic_class;
    logic [15:0] service_id;
    logic [10:0] pid;
    logic [7:0] rule_id, generation;
    logic [11:0] declared_length;
    logic [LENGTH_W:0] actual_length;
    evidence_t evidence;
    pdu_detail_t pdu;
  } semantic_incident_t;
  // Mask bit 1 requires equality; mask bit 0 ignores the corresponding ID bit.
  function automatic logic service_match(logic [15:0] id, value, mask);
    return ((id^value)&mask)==0;
  endfunction
  // Count accepted byte lanes; a final keep must be nonzero and contiguous from lane 0.
  function automatic logic [3:0] byte_count(logic [7:0] keep);
    logic [3:0] n;
    n=0;
    for (int i=0;i<8;i++) n=n+{3'b000,keep[i]};
    return n;
  endfunction
  function automatic logic final_keep_ok(logic [7:0] keep);
    return keep!=0 && (({1'b0,keep}&({1'b0,keep}+9'd1))==0);
  endfunction
endpackage

// -----------------------------------------------------------------------------
// Stateful ownership and timing protection (Section IV-C).
// Check the domain-assigned state-storage range and ownership before preparing
// a pending update. Only the finalization-stage commit can write persistent state.
module can_xl_state_store import can_xl_semantic_pkg::*;
#(parameter int STATE_DEPTH=256)(
  input logic clk, rst_n, check_valid,
  input frame_context_t frame_ctx,
  input domain_binding_t binding,
  input semantic_rule_t rule,
  output pending_update_t pending,
  output evidence_t evidence,
  input logic commit_valid,
  input pending_update_t commit_update
);
  localparam int INDEX_W=(STATE_DEPTH<=1)?1:$clog2(STATE_DEPTH);
  logic [INDEX_W-1:0] check_index, commit_index;
  // Each persistent entry records validity, owning domain and last committed time.
  logic [STATE_DEPTH-1:0] seen;
  logic [7:0] owner[STATE_DEPTH];
  logic [31:0] last_ts[STATE_DEPTH];
  logic [STATE_ADDR_W:0] address_w;
  logic range_ok, owner_ok, write_ok;
  logic [31:0] interval_w;
  // Derive the state address with an extra bit to detect address overflow.
  always_comb begin
    address_w={1'b0,binding.state_base}+{{(STATE_ADDR_W-7){1'b0}},rule.state_profile};
    check_index=INDEX_W'(address_w);
    commit_index=INDEX_W'(commit_update.address);
    range_ok=!address_w[STATE_ADDR_W] && rule.state_profile<binding.state_count && int'(address_w)<STATE_DEPTH;
    owner_ok=0; interval_w=0; pending='0; evidence='0;
    if (range_ok) begin
      owner_ok=!seen[check_index] ||
        owner[check_index]==frame_ctx.domain_id;
      // Unsigned 32-bit subtraction implements modulo-2^32 elapsed time.
      interval_w=frame_ctx.meta.timestamp-last_ts[check_index];
    end
    // A timing violation raises evidence; it need not invalidate the candidate update.
    if (check_valid && rule.stateful_enable) begin
      if (!range_ok || !owner_ok) evidence[EV_STATE_OWNERSHIP]=1;
      else begin
        pending.valid=1;
        pending.address=address_w[STATE_ADDR_W-1:0];
        pending.domain_id=frame_ctx.domain_id;
        pending.generation=frame_ctx.generation;
        pending.timestamp=frame_ctx.meta.timestamp;
        if (seen[check_index] && interval_w<rule.min_interval)
          evidence[EV_TIMING]=1;
      end
    end
    // Recheck address, generation and ownership at commit, not just at policy time.
    write_ok=0;
    if (commit_valid && commit_update.valid && int'(commit_update.address)<STATE_DEPTH &&
        commit_update.generation==frame_ctx.generation)
      write_ok=!seen[commit_index] || owner[commit_index]==commit_update.domain_id;
  end
  // Reset releases ownership; otherwise only the selected writable entry changes.
  always_ff @(posedge clk or negedge rst_n) begin
    if (!rst_n) begin
      seen<='0;
      for (int i=0;i<STATE_DEPTH;i++) begin owner[i]<='0; last_ts[i]<='0; end
    end else if (write_ok) begin
      seen[commit_index]<=1;
      owner[commit_index]<=commit_update.domain_id;
      last_ts[commit_index]<=commit_update.timestamp;
    end
  end
endmodule

// -----------------------------------------------------------------------------
// Streaming multi-PDU parser and inner-PDU authorization (Section IV-E).
// Research-defined 8-byte header, in stream order (low byte lane first):
//   byte 0: PDU type; byte 1: inner domain; bytes 2-3: inner service ID;
//   bytes 4-5: body length; bytes 6-7: reserved (must be zero).
// Multibyte fields are assembled least-significant byte first. Bodies are opaque;
// their lengths delimit the next header, even within the same payload beat.
module can_xl_multi_pdu_parser import can_xl_semantic_pkg::*;
#(parameter int NUM_INNER_RULES=16)(
  input logic clk, rst_n, frame_start, enable, beat_accept,
  input logic [63:0] payload_data,
  input logic [7:0] payload_keep,
  input frame_context_t frame_ctx,
  input inner_pdu_rule_t inner_rules[NUM_INNER_RULES],
  output logic boundary,
  output logic [PDU_INDEX_W:0] pdu_count,
  output evidence_t evidence,
  output pdu_detail_t detail
);
  typedef enum logic [1:0] {MP_HEADER, MP_BODY, MP_ERROR} phase_e;
  phase_e phase_q, phase_n;
  logic [63:0] header_q, header_n;
  logic [2:0] header_bytes_q, header_bytes_n;
  logic [11:0] remaining_q, remaining_n;
  logic [LENGTH_W:0] offset_q, offset_n, start_q, start_n;
  logic [PDU_INDEX_W:0] count_n;
  evidence_t evidence_n;
  pdu_detail_t detail_n;
  inner_pdu_rule_t selected;
  integer hits;
  logic [15:0] body_length;
  logic bad_header;
  evidence_t header_evidence;
  evidence_code_e first_code;
  // One byte cursor handles all lanes. Malformed structure and count overflow
  // enter a fail-stop parser state; the top still drains/checks the outer stream.
  // Every complete header is resolved atomically, so one saturating count suffices.
  always_comb begin
    phase_n=phase_q; header_n=header_q; header_bytes_n=header_bytes_q;
    remaining_n=remaining_q; offset_n=offset_q; start_n=start_q;
    count_n=pdu_count; evidence_n=evidence; detail_n=detail;
    selected='0; hits=0; body_length=0; bad_header=0;
    header_evidence='0; first_code=EV_MALFORMED_PDU;
    // Process only accepted bytes, carrying intermediate state across the eight lanes.
    if (enable && beat_accept) begin
      for (int lane=0;lane<8;lane++) begin
        if (payload_keep[lane]) begin
          case (phase_n)
            MP_HEADER: begin
              if (header_bytes_n==0) start_n=offset_n;
              header_n[int'(header_bytes_n)*8 +: 8]=payload_data[lane*8 +: 8];
              // Resolve a complete header atomically and reject invalid body lengths.
              if (header_bytes_n==7) begin
                body_length=header_n[47:32];
                bad_header=header_n[63:48]!=0 || body_length==0 || body_length>{4'b0,MAX_PAYLOAD};
                header_evidence='0; hits=0; selected='0;
                // Match inner rules against both the outer frame context and inner header.
                for (int r=0;r<NUM_INNER_RULES;r++) begin
                  if (inner_rules[r].enable && inner_rules[r].outer_domain==frame_ctx.domain_id &&
                      service_match(frame_ctx.service_id,inner_rules[r].outer_service_value,inner_rules[r].outer_service_mask) &&
                      inner_rules[r].pdu_type==header_n[7:0] && inner_rules[r].inner_domain==header_n[15:8] &&
                      service_match(header_n[31:16],inner_rules[r].inner_service_value,inner_rules[r].inner_service_mask)) begin
                    hits=hits+1;
                    if (hits==1) selected=inner_rules[r];
                  end
                end
                // Structural errors take priority for this header's first detail.
                // Independently accumulated evidence never depends on old detail.
                // Saturate the PDU count at 256 for the configured 8-bit index.
                if (pdu_count[PDU_INDEX_W]) begin
                  header_evidence[EV_PDU_OVERFLOW]=1; first_code=EV_PDU_OVERFLOW;
                  phase_n=MP_ERROR;
                end else begin
                  count_n=count_n+1'b1;
                  if (bad_header) begin
                    header_evidence[EV_MALFORMED_PDU]=1; first_code=EV_MALFORMED_PDU;
                    phase_n=MP_ERROR;
                  // Authorization failures preserve parsing; structural failures stop it.
                  end else begin
                    remaining_n=body_length[11:0]; phase_n=MP_BODY;
                    if (hits==0) begin header_evidence[EV_INNER_DENIED]=1; first_code=EV_INNER_DENIED; end
                    else if (hits>1) begin header_evidence[EV_INNER_AMBIGUOUS]=1; first_code=EV_INNER_AMBIGUOUS; end
                      // A unique match must also satisfy generation and body-length bounds.
                    else begin
                      if (selected.generation!=frame_ctx.generation) header_evidence[EV_CONFIG_GENERATION]=1;
                      if (body_length<{4'b0,selected.min_length} || body_length>{4'b0,selected.max_length})
                        header_evidence[EV_INNER_DENIED]=1;
                      first_code=header_evidence[EV_CONFIG_GENERATION]?EV_CONFIG_GENERATION:EV_INNER_DENIED;
                    end
                  end
                end
                // Preserve first-violation provenance while accumulating every evidence bit.
                if (header_evidence!=0 && !detail_n.valid) begin
                  detail_n.valid=1; detail_n.code=first_code;
                  // Zero based. Overflow detail points to the maximum representable
                  // index; its EV_PDU_OVERFLOW code distinguishes the exhausted count.
                  detail_n.index=pdu_count[PDU_INDEX_W]?{PDU_INDEX_W{1'b1}}:pdu_count[PDU_INDEX_W-1:0];
                  detail_n.domain_id=header_n[15:8]; detail_n.service_id=header_n[31:16];
                  detail_n.offset=start_n;
                end
                evidence_n=evidence_n|header_evidence;
                header_n='0; header_bytes_n=0;
              end else header_bytes_n=header_bytes_n+1'b1;
            end
            // Count down the opaque body; its last byte returns to header parsing.
            MP_BODY: begin
              if (remaining_n==1) begin remaining_n=0; phase_n=MP_HEADER; end
              else remaining_n=remaining_n-1'b1;
            end
            default: phase_n=MP_ERROR;
          endcase
          // Saturation, not wraparound, keeps malformed long streams deterministic.
          if (!(&offset_n)) offset_n=offset_n+1'b1;
        end
      end
    end
  end
  // A valid boundary means no partially assembled header or unfinished body.
  assign boundary=phase_q==MP_HEADER && header_bytes_q==0;
  // Clear all parser context at reset or at acceptance of a new outer frame.
  always_ff @(posedge clk or negedge rst_n) begin
    if (!rst_n) begin
      phase_q<=MP_HEADER; header_q<=0; header_bytes_q<=0; remaining_q<=0;
      offset_q<=0; start_q<=0; pdu_count<=0; evidence<=0; detail<='0;
    end else if (frame_start) begin
      phase_q<=MP_HEADER; header_q<=0; header_bytes_q<=0; remaining_q<=0;
      offset_q<=0; start_q<=0; pdu_count<=0; evidence<=0; detail<='0;
    end else begin
      phase_q<=phase_n; header_q<=header_n; header_bytes_q<=header_bytes_n;
      remaining_q<=remaining_n; offset_q<=offset_n; start_q<=start_n;
      pdu_count<=count_n; evidence<=evidence_n; detail<=detail_n;
    end
  end
endmodule

// -----------------------------------------------------------------------------
// Top-level semantic IDS (Sections IV-A through IV-F).
// Metadata precedes the 64-bit payload stream. The four policy tables are
// supplied by a trusted configuration source; generation tags detect changes
// observed during frame processing. Incident output is a one-cycle valid pulse.
module can_xl_semantic_ids import can_xl_semantic_pkg::*;
#(parameter int NUM_BINDINGS=8, NUM_RULES=16, NUM_INNER_RULES=16, STATE_DEPTH=256)(
  input logic clk, rst_n,
  input logic [7:0] active_config_generation,
  // Metadata valid/ready interface and received CAN XL frame fields.
  input logic meta_valid,
  output logic meta_ready,
  input logic [15:0] frame_tag,
  input logic [7:0] sdt, vcid,
  input logic [31:0] af,
  input logic [10:0] pid,
  input logic sec,
  input logic [11:0] payload_length,
  input logic [31:0] timestamp,
  input cansec_status_t cansec,
  // Payload valid/ready interface: keep selects bytes and last terminates a frame.
  input logic payload_valid,
  output logic payload_ready,
  input logic [63:0] payload_data,
  input logic [7:0] payload_keep,
  input logic payload_last, frame_abort,
  // Four hierarchical configuration and authorization structures (Section III-D).
  input sdt_descriptor_t sdt_table[256],
  input domain_binding_t bindings[NUM_BINDINGS],
  input semantic_rule_t rules[NUM_RULES],
  input inner_pdu_rule_t inner_rules[NUM_INNER_RULES],
  output logic incident_valid,
  output semantic_incident_t incident_data
);
  // Registered frame context, stage decisions, pending update and security evidence.
  pipeline_state_e state_q;
  frame_context_t ctx_q;
  sdt_descriptor_t desc_w;
  logic [3:0] decoder_q;
  domain_binding_t binding_q, binding_w;
  semantic_rule_t rule_w;
  pending_update_t pending_q, pending_w;
  evidence_t evidence_q, stage_ev, state_ev, parser_ev, stream_ev, final_ev;
  logic sdt_ok_q, domain_ok_q, decoder_ok_q, abort_q;
  logic sdt_ok_w, domain_ok_w, policy_ok_w, needs_checked;
  logic meta_accept, beat_accept, state_check, state_commit, parser_boundary;
  logic [PDU_INDEX_W:0] pdu_count;
  pdu_detail_t pdu_detail;
  logic [LENGTH_W:0] actual_q, actual_next;
  logic [LENGTH_W+1:0] byte_sum;
  integer domain_hits, rule_hits;
  semantic_incident_t incident_w;
  // Abort takes precedence over payload acceptance, including a stalled transfer.
  assign meta_ready=rst_n && state_q==ST_IDLE;
  assign meta_accept=meta_valid && meta_ready;
  assign payload_ready=rst_n && state_q==ST_PAYLOAD && !abort_q && !frame_abort;
  assign beat_accept=payload_valid && payload_ready;

  // Stage-local lookups: no global directory and no authorization by PID identity.
  always_comb begin
    desc_w=sdt_table[ctx_q.meta.sdt]; binding_w='0; rule_w='0;
    rule_w.rule_id=8'hff; domain_hits=0; rule_hits=0; stage_ev='0;
    // Level 1: SDT-based semantic interpretation and descriptor generation check.
    sdt_ok_w=desc_w.enable && (desc_w.semantic_class inside {SEM_NATIVE,SEM_MULTI_PDU}) &&
      desc_w.generation==ctx_q.generation;
    // Level 2: count all class/VCID matches; a first match alone is not authorization.
    if (state_q==ST_DOMAIN && sdt_ok_q) begin
      for (int i=0;i<NUM_BINDINGS;i++) begin
        if (bindings[i].valid && bindings[i].semantic_class==ctx_q.semantic_class &&
            (((ctx_q.meta.vcid^bindings[i].vcid_value)&bindings[i].vcid_mask)==0)) begin
          domain_hits=domain_hits+1;
          if (domain_hits==1) binding_w=bindings[i];
        end
      end
    end
    domain_ok_w=domain_hits==1 && binding_w.generation==ctx_q.generation;
    // Level 3: search only the selected domain's outer-service rule range.
    if (state_q==ST_POLICY && sdt_ok_q && domain_ok_q && decoder_ok_q) begin
      for (int i=0;i<NUM_RULES;i++) begin
        if (i>=int'(binding_q.rule_base) && i<(int'(binding_q.rule_base)+int'(binding_q.rule_count)) &&
            rules[i].enable && rules[i].semantic_class==ctx_q.semantic_class && rules[i].domain_id==ctx_q.domain_id &&
            service_match(ctx_q.service_id,rules[i].service_value,rules[i].service_mask)) begin
          rule_hits=rule_hits+1;
          if (rule_hits==1) rule_w=rules[i];
        end
      end
    end
    needs_checked=rule_w.security.require_cansec || rule_w.security.require_auth ||
      rule_w.security.require_freshness || rule_w.security.require_integrity ||
      rule_w.security.require_confidentiality || rule_w.security.channel_mask!=0;
    // Translate stage-local failures into independent evidence bits.
    case (state_q)
      ST_SDT: begin
        if (!desc_w.enable) stage_ev[EV_UNKNOWN_SDT]=1;
        else if (!(desc_w.semantic_class inside {SEM_NATIVE,SEM_MULTI_PDU})) stage_ev[EV_UNSUPPORTED_CONTEXT]=1;
        else if (desc_w.generation!=ctx_q.generation) stage_ev[EV_CONFIG_GENERATION]=1;
      end
      ST_DOMAIN: if (sdt_ok_q) begin
        if (domain_hits==0) stage_ev[EV_UNBOUND_VCID]=1;
        else if (domain_hits>1) stage_ev[EV_AMBIGUOUS_DOMAIN]=1;
        else if (binding_w.generation!=ctx_q.generation) stage_ev[EV_CONFIG_GENERATION]=1;
        if (decoder_q>2) stage_ev[EV_AF_DECODER]=1;
      end
      // Only a unique outer-service match is eligible for policy constraint checks.
      ST_POLICY: begin
        if (ctx_q.meta.payload_length==0 || ctx_q.meta.payload_length>MAX_PAYLOAD) stage_ev[EV_LENGTH]=1;
        if (sdt_ok_q && domain_ok_q && decoder_ok_q) begin
          if (rule_hits==0) stage_ev[EV_SERVICE_DENIED]=1;
          else if (rule_hits>1) stage_ev[EV_AMBIGUOUS_POLICY]=1;
          else begin
            if (rule_w.generation!=ctx_q.generation) stage_ev[EV_CONFIG_GENERATION]=1;
            if (((ctx_q.meta.pid^rule_w.pid_value)&rule_w.pid_mask)!=0) stage_ev[EV_PID]=1;
            if (ctx_q.meta.payload_length<rule_w.min_length || ctx_q.meta.payload_length>rule_w.max_length)
              stage_ev[EV_LENGTH]=1;
            if (rule_w.security.require_sec && !ctx_q.meta.sec) stage_ev[EV_SEC_MISSING]=1;
            // Any required CANsec subcheck implies checked, even without require_cansec.
            if (needs_checked && !ctx_q.meta.cansec.checked) stage_ev[EV_CANSEC_NOT_CHECKED]=1;
            if (ctx_q.meta.cansec.checked) begin
              if (rule_w.security.require_auth && !ctx_q.meta.cansec.auth_ok) stage_ev[EV_CANSEC_AUTH]=1;
              if (rule_w.security.require_freshness && !ctx_q.meta.cansec.freshness_ok) stage_ev[EV_CANSEC_FRESHNESS]=1;
              if (rule_w.security.require_integrity && !ctx_q.meta.cansec.integrity_ok) stage_ev[EV_CANSEC_INTEGRITY]=1;
              if (rule_w.security.require_confidentiality && !ctx_q.meta.cansec.confidentiality_on) stage_ev[EV_CANSEC_CONFIDENTIALITY]=1;
              if (((ctx_q.meta.cansec.channel_id^rule_w.security.channel_value)&rule_w.security.channel_mask)!=0)
                stage_ev[EV_CANSEC_CHANNEL]=1;
            end
          end
        end
      end
      default: stage_ev='0;
    endcase
    // Outer authorization requires no earlier evidence, generation change or abort.
    policy_ok_w=sdt_ok_q && domain_ok_q && decoder_ok_q && rule_hits==1 && stage_ev==0 && evidence_q==0 &&
      active_config_generation==ctx_q.generation && !abort_q && !frame_abort;
  end
  // Stateful validation is separate from outer-service authorization; commit is deferred.
  assign state_check=rst_n && state_q==ST_POLICY && policy_ok_w;
  can_xl_state_store #(.STATE_DEPTH(STATE_DEPTH)) u_state(
    .clk(clk),.rst_n(rst_n),.check_valid(state_check),.frame_ctx(ctx_q),
    .binding(binding_q),.rule(rule_w),.pending(pending_w),.evidence(state_ev),
    .commit_valid(state_commit),.commit_update(pending_q));
  // The inner-PDU parser runs only for multi-PDU traffic during payload processing.
  can_xl_multi_pdu_parser #(.NUM_INNER_RULES(NUM_INNER_RULES)) u_mpdu(
    .clk(clk),.rst_n(rst_n),.frame_start(meta_accept),
    .enable(state_q==ST_PAYLOAD && ctx_q.semantic_class==SEM_MULTI_PDU),
    .beat_accept(beat_accept),.payload_data(payload_data),.payload_keep(payload_keep),
    .frame_ctx(ctx_q),.inner_rules(inner_rules),.boundary(parser_boundary),
    .pdu_count(pdu_count),.evidence(parser_ev),.detail(pdu_detail));

  // Payload-stream validation, final evidence and contextual incident construction.
  always_comb begin
    // Saturating actual-byte count prevents wraparound on malformed long streams.
    byte_sum={1'b0,actual_q}+{{(LENGTH_W-2){1'b0}},byte_count(payload_keep)};
    actual_next=byte_sum[LENGTH_W+1]?{(LENGTH_W+1){1'b1}}:byte_sum[LENGTH_W:0];
    stream_ev='0;
    if (beat_accept) begin
      // Nonfinal beats must be full; final beats must use contiguous low byte lanes.
      if ((!payload_last && payload_keep!=8'hff) || (payload_last && !final_keep_ok(payload_keep))) stream_ev[EV_KEEP]=1;
      if (byte_sum>{2'b00,ctx_q.meta.payload_length} ||
          (payload_last && byte_sum!={2'b00,ctx_q.meta.payload_length})) stream_ev[EV_STREAM_LENGTH]=1;
    end
    // Combine all accumulated evidence and require complete multi-PDU boundaries.
    final_ev=evidence_q;
    if (ctx_q.semantic_class==SEM_MULTI_PDU) begin
      final_ev=final_ev|parser_ev;
      if (!parser_boundary || pdu_count==0) final_ev[EV_INCOMPLETE_PDU]=1;
    end
    if (abort_q || frame_abort) final_ev[EV_ABORT]=1;
    if (active_config_generation!=ctx_q.generation) final_ev[EV_CONFIG_GENERATION]=1;
    // Report the available originating frame context and full evidence bitmap.
    incident_w='0;
    incident_w.frame_tag=ctx_q.meta.frame_tag; incident_w.sdt=ctx_q.meta.sdt;
    incident_w.vcid=ctx_q.meta.vcid; incident_w.domain_id=ctx_q.domain_id;
    incident_w.semantic_class=ctx_q.semantic_class; incident_w.service_id=ctx_q.service_id;
    incident_w.pid=ctx_q.meta.pid; incident_w.rule_id=ctx_q.rule_id;
    incident_w.generation=ctx_q.generation; incident_w.declared_length=ctx_q.meta.payload_length;
    incident_w.actual_length=actual_q; incident_w.evidence=final_ev;
    if (ctx_q.semantic_class==SEM_MULTI_PDU) incident_w.pdu=pdu_detail;
  end
  // Clean-frame-only commitment: one finalization edge, no detected violation.
  assign state_commit=rst_n && state_q==ST_FINALIZE && ctx_q.authorized && pending_q.valid && final_ev==0;
  always_ff @(posedge clk or negedge rst_n) begin
    if (!rst_n) begin
      state_q<=ST_IDLE; ctx_q<='0; decoder_q<=0; binding_q<='0;
      pending_q<='0; evidence_q<='0; actual_q<=0;
      sdt_ok_q<=0; domain_ok_q<=0; decoder_ok_q<=0; abort_q<=0;
      incident_valid<=0; incident_data<='0;
    end else begin
      incident_valid<=0;
      // Evidence and abort history are sticky across all active processing stages.
      if (state_q inside {ST_SDT,ST_DOMAIN,ST_POLICY,ST_PAYLOAD}) begin
        evidence_q<=evidence_q|stage_ev|state_ev|stream_ev;
        if (frame_abort) begin abort_q<=1; evidence_q[EV_ABORT]<=1; end
        if (active_config_generation!=ctx_q.generation) evidence_q[EV_CONFIG_GENERATION]<=1;
      end
      case (state_q)
        // Capture metadata and generation once; initialize per-frame context.
        ST_IDLE: if (meta_accept) begin
          ctx_q<='0;
          ctx_q.meta<='{frame_tag:frame_tag,sdt:sdt,vcid:vcid,af:af,pid:pid,sec:sec,
            payload_length:payload_length,timestamp:timestamp,cansec:cansec};
          ctx_q.semantic_class<=SEM_UNSUPPORTED;
          ctx_q.domain_id<=8'hff; ctx_q.service_id<=16'hffff; ctx_q.rule_id<=8'hff;
          ctx_q.generation<=active_config_generation;
          sdt_ok_q<=0; domain_ok_q<=0; decoder_ok_q<=0;
          binding_q<='0; pending_q<='0; evidence_q<='0; actual_q<=0;
          abort_q<=frame_abort;
          if (frame_abort) evidence_q[EV_ABORT]<=1;
          state_q<=ST_SDT;
        end
        // Capture the SDT descriptor result before domain identification.
        ST_SDT: begin
          decoder_q<=desc_w.af_decoder_id; ctx_q.semantic_class<=desc_w.semantic_class;
          sdt_ok_q<=sdt_ok_w; state_q<=ST_DOMAIN;
        end
        // Bind the VCID and extract the outer service ID using the SDT-selected AF decoder.
        ST_DOMAIN: begin
          binding_q<=binding_w; domain_ok_q<=domain_ok_w;
          if (domain_ok_w) ctx_q.domain_id<=binding_w.domain_id;
          decoder_ok_q<=sdt_ok_q && decoder_q<=2;
          if (sdt_ok_q) begin
            // Decoder IDs select AF low half, high half, or high/low byte pair.
            case (decoder_q)
              0: ctx_q.service_id<=ctx_q.meta.af[15:0];
              1: ctx_q.service_id<=ctx_q.meta.af[31:16];
              2: ctx_q.service_id<={ctx_q.meta.af[31:24],ctx_q.meta.af[7:0]};
              default: ctx_q.service_id<=16'hffff;
            endcase
          end
          state_q<=ST_POLICY;
        end
        // Register outer authorization and the candidate state update, if any.
        ST_POLICY: begin
          ctx_q.rule_id<=rule_w.rule_id;
          ctx_q.authorized<=policy_ok_w; pending_q<=pending_w;
          state_q<=(abort_q || frame_abort)?ST_FINALIZE:ST_PAYLOAD;
        end
        // Drain accepted payload until the last transfer or an abort.
        ST_PAYLOAD: begin
          if (beat_accept) actual_q<=actual_next;
          if (abort_q || frame_abort || (beat_accept && payload_last)) state_q<=ST_FINALIZE;
        end
        ST_FINALIZE: begin
          // Parser registers and terminal-beat stream evidence are now updated.
          // Commit and incident disposition use this SAME final evidence value.
          if (final_ev!=0) begin incident_data<=incident_w; incident_valid<=1; end
          pending_q<='0; state_q<=ST_REPORT;
        end
        // Return to idle after the one-cycle reporting state.
        ST_REPORT: begin state_q<=ST_IDLE; ctx_q<='0; end
        default: state_q<=ST_IDLE;
      endcase
    end
  end
endmodule
`default_nettype wire
