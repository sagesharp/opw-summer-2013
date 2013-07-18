import tracecmd
from struct import unpack


def add_ctx_entry(l, field, data):
    dma, va, i = l[-1][1:]
    ctx_entry = "%-10s\t0x%08x\t@%08x\t@%08x\n" % (field, data[i], dma, va)
    if field != "deq" and field.find("rsvd64") < 0:
        dma += 4
        va += 4
    else:
        dma += 8
        va += 8
    i += 1
    l.append([ctx_entry, dma, va, i])


def xhci_ctx_handler(trace_seq, event):
    """
    Parse the data in the xhci_container_ctx structure and print the field
    values and addresses of Device Context and Input Context data structures.
    """

    slot_id = int(event['slot_id'])
    ctx_dma = long(event['ctx_dma'])
    ctx_va = long(event['ctx_va'])
    ctx_last_ep = int(event['ctx_last_ep'])

    ctx_is_64bytes = int(event['ctx_64'])
    ctx_type_is_device = int(event['ctx_type']) == 0x1
    ctx_type_is_input = int(event['ctx_type']) == 0x2

    if ctx_type_is_device:
        direction = "Output";
        if ctx_is_64bytes:
            ctx_data_fmt = "<8I4Q" + "2IQ4I4Q"*31
        else:
            ctx_data_fmt = "<8I" + "2IQ4I"*31
    elif ctx_type_is_input:
        direction = "Input"
        if ctx_is_64bytes:
            ctx_data_fmt = "<8I4Q8I4Q" + "2IQ4I4Q"*31
        else:
            ctx_data_fmt = "<8I8I" + "2IQ4I"*31
    else:
        trace_seq.puts("\nUnknown context type: %d\n" % int(event['ctx_type']))
        return

    ctx_bytes = unpack(ctx_data_fmt, event['ctx_data'].data)
    label = "%-10s\t%-10s\t%-9s\t%s\n" % ("Field", "Value", "DMA", "Virtual")
    rsvd = [("rsvd" + str(i)) for i in range(6)]
    cntl_fields = ["drop_flags", "add_flags"] + rsvd
    slot_fields = ["dev_info", "dev_info2", "tt_info", "dev_state"] + rsvd[:4]
    ep_fields = ["ep_info", "ep_info2", "deq", "tx_info"] + rsvd[:3]

    l = [["", ctx_dma, ctx_va, 0]];
    if ctx_type_is_input:
        l[-1][0] += "\nInput Control Context:\n\n" + label
        [add_ctx_entry(l, cntl_fields[j], ctx_bytes) for j in range(8)]
        if ctx_is_64bytes:
            [add_ctx_entry(l, "rsvd64[%d]" % j, ctx_bytes) for j in range(4)]

    l[-1][0] += "\nSlot ID %d %s Context:\n\n%s" % (slot_id, direction, label)
    [add_ctx_entry(l, slot_fields[j], ctx_bytes) for j in range(8)]
    if ctx_is_64bytes:
            [add_ctx_entry(l, "rsvd64[%d]" % j, ctx_bytes) for j in range(4)]

    for ep in range(ctx_last_ep):
        l[-1][0] += "\nEndpoint %d %s Context:\n\n%s" % (ep, direction, label)
        [add_ctx_entry(l, ep_fields[j], ctx_bytes) for j in range(7)]
        if ctx_is_64bytes:
            [add_ctx_entry(l, "rsvd64[%d]" % j, ctx_bytes) for j in range(4)]

    [trace_seq.puts(t[0]) for t in l]


def get_compl_code_str(code):
    """
    Return a stringified version of the command completion code.
    """

    compl_codes = { 0  : "Invalid",
                    1  : "Success",
                    2  : "Data Buffer Error ",
                    3  : "Babble Detected Error",
                    4  : "USB Transaction Error",
                    5  : "TRB Error",
                    6  : "Stall Error",
                    7  : "Resource Error",
                    8  : "Bandwidth Error",
                    9  : "No Slots Available Error",
                    10 : "Invalid Stream Type Error",
                    11 : "Slot Not Enabled Error",
                    12 : "Endpoint Not Enabled Error",
                    13 : "Short Packet",
                    14 : "Ring Underrun",
                    15 : "Ring Overrun",
                    16 : "VF Event Ring Full Error",
                    17 : "Parameter Error",
                    18 : "Bandwidth Overrun Error",
                    19 : "Context State Error",
                    20 : "No Ping Response Error",
                    21 : "Event Ring Full Error",
                    22 : "Incompatible Device Error",
                    23 : "Missed Service Error",
                    24 : "Command Ring Stopped",
                    25 : "Command Aborted",
                    26 : "Stopped",
                    27 : "Stopped - Length Invalid",
                    29 : "Max Exit Latency Too Large Error",
                    31 : "Isoch Buffer Overrun",
                    32 : "Event Lost Error",
                    33 : "Undefined Error",
                    34 : "Invalid Stream ID Error",
                    35 : "Secondary Bandwidth Error",
                    36 : "Split Transaction Error" }

    if code in compl_codes:
        return compl_codes[code]
    else:
        return "Vendor specific"


def get_cmd_data(cmd):
    """
    Parse Command TRB depending on the type of the command
    and return a list with first element a string denoting
    the command type and second element a string with the
    remaining fields.
    """

    cmd_type = cmd[4] >> 2
    cmd_types = { 9  : ["Enable Slot Command", ""],
                  10 : ["Disable Slot Command", "[SlotID=%d]" % (cmd[6])],
                  11 : ["Address Device Command",
                        "[InputCtxPtr=%x][BSR=%d][SlotID=%d]" %
                        (cmd[0], cmd[4] & 0x2, cmd[6])],
                  12 : ["Configure Endpoint Command",
                        "[InputCtxPtr=%x][DC=%d][SlotID=%d]" %
                        (cmd[0], cmd[4] & 0x2, cmd[6])],
                  13 : ["Evaluate Context Command",
                        "[InputCtxPtr=%x][SlotID=%d]" % (cmd[0], cmd[6])],
                  14 : ["Reset Endpoint Command",
                        "[TSP=%d][EndpointID=%d][SlotID=%d]" %
                        (cmd[4] & 0x2, cmd[5], cmd[6])],
                  15 : ["Stop Endpoint Command",
                        "[EndpointID=%d][SP=%d][SlotID=%d]" %
                        (cmd[5] & 0x7f, cmd[5] >> 7, cmd[6])],
                  16 : ["Set TR Dequeue Pointer Command",
                        "[SCT=%d][TRDeqPtr=%x][StreamID=%d][EpID=%d][SlotID=%d]"
                        % ((cmd[0] & 0xf) >> 1, cmd[0] & ~0xf,
                           cmd[2], cmd[5], cmd[6])],
                  17 : ["Reset Device Command", "[SlotID=%d]" % (cmd[6])],
                  18 : ["Force Event Command",
                        "[EventTRBPtr=%x][VFIntrID=%d][VFID=%d]" %
                        (cmd[0], cmd[2] >> 8, cmd[5])],
                  19 : ["Negotiate Bandwidth Command",
                        "[SlotID=%d]" % (cmd[6])],
                  20 : ["Set Latency Tolerance Value Command",
                        "[BELT=%d]" % (cmd[6] << 8 | cmd[5])],
                  21 : ["Get Port Bandwidth Command",
                        "[PortBwCtxPtr=%x][DevSpeed=%d][HubSlotID=%d]" %
                        (cmd[0], cmd[5], cmd[6])],
                  22 : ["Force Header Command",
                        "[PacketType=%d][RootHubPort=%d]" %
                        (cmd[0] & 0x1f, cmd[6])],
                  23 : ["No Op Command", ""] }

    if cmd_type in cmd_types:
        return cmd_types[cmd_type]
    else:
        return ("Invalid Command Type", "Unknown")


def xhci_cmd_handler(trace_seq, event):
    """
    Print Command Completion Event fields and the associated Command TRB fields.
    """

    cmd_trb_dma = long(event['dma'])
    cmd_trb_va = long(event['va'])
    status = unpack("@4B", event['status'].data)
    flags = unpack("@4B", event['flags'].data)
    cmd_trb = unpack("<Q2H4B", event['cmd_trb'].data)

    compl_status = get_compl_code_str(status[3]);
    event_type = flags[1] >> 2
    vf_id = flags[2];
    slot_id = flags[3];
    cmd_data = get_cmd_data(cmd_trb)

    trace_seq.puts("\n")
    trace_seq.puts("%-10s\t%s\n" % ("Type:", cmd_data[0]))
    trace_seq.puts("%-10s\t%s\n" % ("Status:", compl_status))
    trace_seq.puts("%-10s\t@%x\n" % ("DMA addr:", cmd_trb_dma))
    trace_seq.puts("%-10s\t@%x\n" % ("Virtual addr:", cmd_trb_va))
    trace_seq.puts("%-10s\t%i\n" % ("VF ID:", vf_id))
    trace_seq.puts("%-10s\t%i\n" % ("Slot ID:", slot_id))
    trace_seq.puts("%-10s\t%s\n" % ("Cmd Fields:", cmd_data[1]))


def register(pevent):
    pevent.register_event_handler('xhci-hcd', 'xhci_ctx', xhci_ctx_handler)
    pevent.register_event_handler('xhci-hcd', 'xhci_cmd', xhci_cmd_handler)

