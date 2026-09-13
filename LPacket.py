import sys
import os
import argparse
import threading
import curses
from datetime import datetime

try:
    from scapy.all import sniff, wrpcap, rdpcap, get_if_list
    from scapy.layers.l2 import Ether
    from scapy.layers.inet import IP, TCP, UDP, ICMP
    from scapy.layers.inet6 import IPv6
    from scapy.layers.dns import DNS
except ImportError:
    print("Scapy is not installed. Install it with: pip install scapy")
    sys.exit(1)

PROTO_NAMES = {1: "ICMP", 6: "TCP", 17: "UDP"}
PROTO_COLOR = {"TCP": 2, "UDP": 3, "ICMP": 4, "DNS": 5, "HTTP": 6, "OTHER": 7}


class Session:
    def __init__(self, interface=None):
        self.interface = interface
        self.packets = []
        self.raw_packets = []
        self.lock = threading.Lock()
        self.running = False
        self.stop_event = threading.Event()
        self.filter = None
        self.filter_desc = "none"
        self.follow = True
        self.selected_abs = None
        self.top = 0
        self.input_buffer = ""
        self.message = "Type 'help' for a list of commands."
        self.overlay_lines = None
        self.overlay_offset = 0
        self.quit = False


def check_root():
    if os.name == "posix" and os.geteuid() != 0:
        print("Root/sudo privileges are required to capture live traffic")
        return False
    return True


def list_interfaces():
    try:
        return get_if_list()
    except Exception:
        return []


def choose_interface():
    interfaces = list_interfaces()
    if not interfaces:
        print("No network interfaces found.")
        return None
    print("Available Interfaces\n")
    for i, name in enumerate(interfaces, 1):
        print("[%d] %s" % (i, name))
    print()
    while True:
        choice = input("Select interface: ").strip()
        if not choice.isdigit():
            print("Invalid selection.")
            continue
        idx = int(choice)
        if idx < 1 or idx > len(interfaces):
            print("Invalid selection.")
            continue
        return interfaces[idx - 1]


def get_proto_name(ip_layer):
    return PROTO_NAMES.get(ip_layer.proto, str(ip_layer.proto))


def parse_packet(pkt, number):
    info = {
        "number": number,
        "time": datetime.fromtimestamp(float(pkt.time)).strftime("%H:%M:%S"),
        "src": "",
        "dst": "",
        "protocol": "OTHER",
        "length": len(bytes(pkt)),
        "src_port": None,
        "dst_port": None,
        "ttl": None,
        "flags": None,
        "icmp_type": None,
        "icmp_code": None,
        "eth_src": None,
        "eth_dst": None,
        "eth_type": None,
        "raw": bytes(pkt),
    }

    if Ether in pkt:
        eth = pkt[Ether]
        info["eth_src"] = eth.src
        info["eth_dst"] = eth.dst
        info["eth_type"] = hex(eth.type)

    if IP in pkt:
        ip = pkt[IP]
        info["src"] = ip.src
        info["dst"] = ip.dst
        info["ttl"] = ip.ttl
        info["protocol"] = get_proto_name(ip)
    elif IPv6 in pkt:
        ip6 = pkt[IPv6]
        info["src"] = ip6.src
        info["dst"] = ip6.dst
        info["ttl"] = ip6.hlim
        info["protocol"] = PROTO_NAMES.get(ip6.nh, str(ip6.nh))

    if TCP in pkt:
        tcp = pkt[TCP]
        info["src_port"] = tcp.sport
        info["dst_port"] = tcp.dport
        info["flags"] = str(tcp.flags)
        if tcp.sport in (80, 8080) or tcp.dport in (80, 8080):
            info["protocol"] = "HTTP"
    elif UDP in pkt:
        udp = pkt[UDP]
        info["src_port"] = udp.sport
        info["dst_port"] = udp.dport
        if udp.sport == 53 or udp.dport == 53 or DNS in pkt:
            info["protocol"] = "DNS"
    elif ICMP in pkt:
        icmp = pkt[ICMP]
        info["icmp_type"] = icmp.type
        info["icmp_code"] = icmp.code

    return info


def matches_filter(info, filt):
    if filt is None:
        return True
    ftype, fvalue = filt
    if ftype == "proto":
        return info["protocol"].lower() == fvalue.lower()
    if ftype == "ip":
        return info["src"] == fvalue or info["dst"] == fvalue
    if ftype == "src":
        return info["src"] == fvalue
    if ftype == "dst":
        return info["dst"] == fvalue
    if ftype == "port":
        return str(info["src_port"]) == fvalue or str(info["dst_port"]) == fvalue
    return True


def hexdump_lines(data, length=16):
    lines = []
    for i in range(0, len(data), length):
        chunk = data[i:i + length]
        hex_part = " ".join("%02x" % b for b in chunk)
        ascii_part = "".join(chr(b) if 32 <= b < 127 else "." for b in chunk)
        lines.append("%08x  %-*s  %s" % (i, length * 3, hex_part, ascii_part))
    return lines


def packet_detail_lines(session, number):
    with session.lock:
        matching = [p for p in session.packets if p["number"] == number]
    if not matching:
        return None
    info = matching[0]
    lines = []
    lines.append("PACKET #%d" % info["number"])
    lines.append("")
    lines.append("Ethernet")
    lines.append("  Source MAC: %s" % (info["eth_src"] or "-"))
    lines.append("  Destination MAC: %s" % (info["eth_dst"] or "-"))
    lines.append("  Type: %s" % (info["eth_type"] or "-"))
    lines.append("")
    lines.append("IP")
    lines.append("  Source: %s" % (info["src"] or "-"))
    lines.append("  Destination: %s" % (info["dst"] or "-"))
    lines.append("  TTL: %s" % (info["ttl"] if info["ttl"] is not None else "-"))
    lines.append("  Protocol: %s" % info["protocol"])
    lines.append("")
    if info["protocol"] in ("TCP", "HTTP"):
        lines.append("TCP")
        lines.append("  Source Port: %s" % info["src_port"])
        lines.append("  Destination Port: %s" % info["dst_port"])
        lines.append("  Flags: %s" % info["flags"])
        lines.append("")
    elif info["protocol"] in ("UDP", "DNS"):
        lines.append("UDP")
        lines.append("  Source Port: %s" % info["src_port"])
        lines.append("  Destination Port: %s" % info["dst_port"])
        lines.append("")
    elif info["protocol"] == "ICMP":
        lines.append("ICMP")
        lines.append("  Type: %s" % info["icmp_type"])
        lines.append("  Code: %s" % info["icmp_code"])
        lines.append("")
    lines.append("Payload")
    lines.append("  Length: %d" % len(info["raw"]))
    lines.append("  Hex:")
    lines.extend(hexdump_lines(info["raw"]))
    return lines


def stats_lines(session):
    with session.lock:
        packets = list(session.packets)
    total = len(packets)
    proto_counts = {"TCP": 0, "UDP": 0, "ICMP": 0, "DNS": 0, "Other": 0}
    src_counts = {}
    dst_counts = {}
    port_counts = {}
    for info in packets:
        proto = info["protocol"]
        if proto in proto_counts:
            proto_counts[proto] += 1
        else:
            proto_counts["Other"] += 1
        if info["src"]:
            src_counts[info["src"]] = src_counts.get(info["src"], 0) + 1
        if info["dst"]:
            dst_counts[info["dst"]] = dst_counts.get(info["dst"], 0) + 1
        if info["src_port"]:
            port_counts[info["src_port"]] = port_counts.get(info["src_port"], 0) + 1
        if info["dst_port"]:
            port_counts[info["dst_port"]] = port_counts.get(info["dst_port"], 0) + 1

    def top_n(counter, n=5):
        return sorted(counter.items(), key=lambda x: x[1], reverse=True)[:n]

    lines = []
    lines.append("PACKET STATISTICS")
    lines.append("")
    lines.append("Total packets: %d" % total)
    lines.append("")
    lines.append("TCP   : %d" % proto_counts["TCP"])
    lines.append("UDP   : %d" % proto_counts["UDP"])
    lines.append("ICMP  : %d" % proto_counts["ICMP"])
    lines.append("DNS   : %d" % proto_counts["DNS"])
    lines.append("Other : %d" % proto_counts["Other"])
    if src_counts:
        lines.append("")
        lines.append("Top source IPs")
        for ip, count in top_n(src_counts):
            lines.append("  %-16s %d" % (ip, count))
    if dst_counts:
        lines.append("")
        lines.append("Top destination IPs")
        for ip, count in top_n(dst_counts):
            lines.append("  %-16s %d" % (ip, count))
    if port_counts:
        lines.append("")
        lines.append("Top ports")
        for port, count in top_n(port_counts):
            lines.append("  %-6s %d" % (port, count))
    return lines


def help_lines():
    return [
        "COMMANDS",
        "",
        "help                    show this help message",
        "start                   start capturing packets",
        "stop                    stop capturing packets",
        "clear                   clear captured packets",
        "filter tcp|udp|icmp|dns show only matching protocol",
        "filter ip <addr>        show packets involving an IP",
        "filter port <port>      show packets involving a port",
        "filter src <addr>       show packets from a source IP",
        "filter dst <addr>       show packets to a destination IP",
        "filter clear            remove active filter",
        "show <number>           show details for a packet number",
        "stats                   show packet statistics",
        "interfaces              list available interfaces",
        "save <filename>         save captured packets to a pcap file",
        "load <filename>         load packets from a pcap file",
        "quit                    exit the program",
        "",
        "UP/DOWN                 browse the packet list",
        "ENTER on a row          show details for the highlighted packet",
    ]


def parse_filter_command(args):
    if not args:
        return None, "usage: filter <tcp|udp|icmp|dns|ip|port|src|dst|clear>"
    if args[0] == "clear":
        return ("clear", None), None
    if args[0] in ("tcp", "udp", "icmp", "dns"):
        return ("proto", args[0].upper()), None
    if args[0] in ("ip", "port", "src", "dst") and len(args) >= 2:
        return (args[0], args[1]), None
    return None, "invalid filter"


def capture_thread_func(session):
    def on_packet(pkt):
        if session.stop_event.is_set():
            return
        with session.lock:
            number = len(session.packets) + 1
            info = parse_packet(pkt, number)
            session.packets.append(info)
            session.raw_packets.append(pkt)

    def should_stop(pkt):
        return session.stop_event.is_set()

    try:
        sniff(iface=session.interface, prn=on_packet, stop_filter=should_stop, store=False)
    except PermissionError:
        session.message = "Error: permission denied, run with root/sudo privileges."
    except OSError as exc:
        session.message = "Error: failed to capture on '%s': %s" % (session.interface, exc)
    session.running = False


def start_capture(session):
    if session.running:
        session.message = "Capture already running."
        return
    if not session.interface:
        session.message = "Error: no interface selected."
        return
    session.stop_event.clear()
    session.running = True
    thread = threading.Thread(target=capture_thread_func, args=(session,), daemon=True)
    thread.start()
    session.message = "Capturing on %s." % session.interface


def stop_capture(session):
    if not session.running:
        return
    session.stop_event.set()
    session.running = False


def save_pcap(session, filename):
    with session.lock:
        packets = list(session.raw_packets)
    if not packets:
        return "Error: no packets to save."
    try:
        wrpcap(filename, packets)
        return "Saved %d packets to %s" % (len(packets), filename)
    except OSError as exc:
        return "Error: failed to save file: %s" % exc


def load_pcap(session, filename):
    if not os.path.isfile(filename):
        return "Error: pcap file not found: %s" % filename
    try:
        packets = rdpcap(filename)
    except Exception as exc:
        return "Error: failed to read pcap file: %s" % exc
    with session.lock:
        session.packets.clear()
        session.raw_packets.clear()
        for pkt in packets:
            number = len(session.packets) + 1
            info = parse_packet(pkt, number)
            session.packets.append(info)
            session.raw_packets.append(pkt)
    session.selected_abs = None
    session.follow = True
    return "Loaded %d packets from %s" % (len(session.packets), filename)


def process_command(session, line):
    line = line.strip()
    if not line:
        return
    parts = line.split()
    cmd = parts[0].lower()
    args = parts[1:]

    if cmd == "help":
        session.overlay_lines = help_lines()
        session.overlay_offset = 0
    elif cmd == "start":
        start_capture(session)
    elif cmd == "stop":
        stop_capture(session)
        session.message = "Capture stopped."
    elif cmd == "clear":
        with session.lock:
            session.packets.clear()
            session.raw_packets.clear()
        session.selected_abs = None
        session.message = "Packet buffer cleared."
    elif cmd == "filter":
        result, error = parse_filter_command(args)
        if error:
            session.message = "Error: %s" % error
        elif result[0] == "clear":
            session.filter = None
            session.filter_desc = "none"
            session.message = "Filter cleared."
        else:
            session.filter = result
            session.filter_desc = "%s %s" % result
            session.message = "Filter set: %s" % session.filter_desc
        session.selected_abs = None
        session.follow = True
    elif cmd == "show":
        if not args or not args[0].isdigit():
            session.message = "Error: usage show <packet_number>"
        else:
            lines = packet_detail_lines(session, int(args[0]))
            if lines is None:
                session.message = "Error: invalid packet number."
            else:
                session.overlay_lines = lines
                session.overlay_offset = 0
    elif cmd == "stats":
        session.overlay_lines = stats_lines(session)
        session.overlay_offset = 0
    elif cmd == "interfaces":
        session.overlay_lines = ["AVAILABLE INTERFACES", ""] + list_interfaces()
        session.overlay_offset = 0
    elif cmd == "save":
        if not args:
            session.message = "Error: usage save <filename>"
        else:
            session.message = save_pcap(session, args[0])
    elif cmd == "load":
        if not args:
            session.message = "Error: usage load <filename>"
        else:
            session.message = load_pcap(session, args[0])
    elif cmd in ("quit", "exit"):
        stop_capture(session)
        session.quit = True
    else:
        session.message = "Unknown command: %s" % cmd


def init_colors():
    curses.start_color()
    curses.use_default_colors()
    curses.init_pair(1, curses.COLOR_CYAN, -1)
    curses.init_pair(2, curses.COLOR_GREEN, -1)
    curses.init_pair(3, curses.COLOR_YELLOW, -1)
    curses.init_pair(4, curses.COLOR_RED, -1)
    curses.init_pair(5, curses.COLOR_MAGENTA, -1)
    curses.init_pair(6, curses.COLOR_BLUE, -1)
    curses.init_pair(7, curses.COLOR_WHITE, -1)
    curses.init_pair(8, curses.COLOR_BLACK, curses.COLOR_WHITE)
    curses.init_pair(9, curses.COLOR_RED, -1)
    curses.init_pair(10, curses.COLOR_BLACK, curses.COLOR_CYAN)


def safe_addstr(win, y, x, text, attr=0):
    height, width = win.getmaxyx()
    if y < 0 or y >= height or x >= width:
        return
    max_len = width - x - 1
    if max_len <= 0:
        return
    try:
        win.addstr(y, x, text[:max_len], attr)
    except curses.error:
        pass


def draw(stdscr, session):
    height, width = stdscr.getmaxyx()
    stdscr.erase()

    header_bar = " MINI WIRESHARK "
    safe_addstr(stdscr, 0, 0, header_bar.ljust(width), curses.color_pair(10) | curses.A_BOLD)

    status = "CAPTURING" if session.running else "STOPPED"
    info_line = "Interface: %s   Status: %s   Filter: %s   Packets: %d" % (
        session.interface or "-", status, session.filter_desc, len(session.packets)
    )
    safe_addstr(stdscr, 1, 0, info_line.ljust(width), curses.color_pair(1))

    col_header = "%-9s %-16s %-16s %-8s %-7s" % ("TIME", "SOURCE", "DESTINATION", "PROTOCOL", "LENGTH")
    safe_addstr(stdscr, 2, 0, col_header.ljust(width), curses.A_BOLD)

    footer_height = 3
    list_start = 3
    list_height = max(0, height - list_start - footer_height)

    with session.lock:
        filtered = [p for p in session.packets if matches_filter(p, session.filter)]

    if session.overlay_lines is not None:
        draw_overlay(stdscr, session, list_start, list_height, width)
    else:
        draw_list(stdscr, session, filtered, list_start, list_height, width)

    hint = "commands: help start stop filter show stats save load quit"
    safe_addstr(stdscr, height - 3, 0, hint.ljust(width), curses.A_DIM)

    message = session.message or ""
    attr = curses.color_pair(9) if message.startswith("Error") else curses.A_NORMAL
    safe_addstr(stdscr, height - 2, 0, message.ljust(width), attr)

    prompt = "> " + session.input_buffer
    safe_addstr(stdscr, height - 1, 0, prompt.ljust(width))
    curses.curs_set(1)
    try:
        stdscr.move(height - 1, min(width - 1, len(prompt)))
    except curses.error:
        pass


def draw_list(stdscr, session, filtered, list_start, list_height, width):
    total = len(filtered)
    if total == 0:
        session.selected_abs = None
        session.top = 0
        stdscr.refresh()
        return

    if session.follow or session.selected_abs is None:
        session.selected_abs = total - 1

    session.selected_abs = max(0, min(session.selected_abs, total - 1))

    top = session.top
    if session.selected_abs < top:
        top = session.selected_abs
    if session.selected_abs > top + list_height - 1:
        top = session.selected_abs - list_height + 1
    top = max(0, min(top, max(0, total - list_height)))
    session.top = top

    visible = filtered[top:top + list_height]
    for row, info in enumerate(visible):
        abs_index = top + row
        line = "%-9s %-16s %-16s %-8s %-7s" % (
            info["time"], info["src"] or "-", info["dst"] or "-", info["protocol"], str(info["length"])
        )
        if abs_index == session.selected_abs:
            attr = curses.color_pair(8) | curses.A_BOLD
        else:
            attr = curses.color_pair(PROTO_COLOR.get(info["protocol"], 7))
        safe_addstr(stdscr, list_start + row, 0, line.ljust(width), attr)


def draw_overlay(stdscr, session, list_start, list_height, width):
    lines = session.overlay_lines
    visible = lines[session.overlay_offset:session.overlay_offset + list_height - 2]
    border = "+" + "-" * (width - 2) + "+"
    safe_addstr(stdscr, list_start, 0, border)
    for row, text in enumerate(visible):
        safe_addstr(stdscr, list_start + 1 + row, 0, "| " + text)
    bottom_row = list_start + list_height - 1
    if bottom_row > list_start:
        safe_addstr(stdscr, bottom_row, 0, border)
    hint = " press any key to close, UP/DOWN to scroll "
    safe_addstr(stdscr, bottom_row, 2, hint, curses.A_DIM)


def handle_overlay_key(session, ch, list_height):
    if ch == curses.KEY_UP:
        session.overlay_offset = max(0, session.overlay_offset - 1)
        return
    if ch == curses.KEY_DOWN:
        max_offset = max(0, len(session.overlay_lines) - (list_height - 2))
        session.overlay_offset = min(max_offset, session.overlay_offset + 1)
        return
    session.overlay_lines = None
    session.overlay_offset = 0


def handle_key(session, ch, filtered, list_height):
    if session.overlay_lines is not None:
        handle_overlay_key(session, ch, list_height)
        return

    if ch in (curses.KEY_UP,):
        if filtered:
            if session.selected_abs is None:
                session.selected_abs = len(filtered) - 1
            else:
                session.selected_abs = max(0, session.selected_abs - 1)
            session.follow = False
    elif ch in (curses.KEY_DOWN,):
        if filtered:
            if session.selected_abs is None:
                session.selected_abs = len(filtered) - 1
            else:
                session.selected_abs = min(len(filtered) - 1, session.selected_abs + 1)
            session.follow = session.selected_abs == len(filtered) - 1
    elif ch in (curses.KEY_BACKSPACE, 127, 8):
        session.input_buffer = session.input_buffer[:-1]
    elif ch in (10, 13, curses.KEY_ENTER):
        if session.input_buffer:
            process_command(session, session.input_buffer)
            session.input_buffer = ""
        elif filtered and session.selected_abs is not None:
            number = filtered[session.selected_abs]["number"]
            lines = packet_detail_lines(session, number)
            if lines is not None:
                session.overlay_lines = lines
                session.overlay_offset = 0
    elif 32 <= ch <= 126:
        session.input_buffer += chr(ch)


def curses_main(stdscr, session):
    init_colors()
    stdscr.nodelay(True)
    stdscr.timeout(150)
    stdscr.keypad(True)

    if session.interface and not session.packets:
        start_capture(session)

    while not session.quit:
        height, width = stdscr.getmaxyx()
        footer_height = 3
        list_height = max(0, height - 3 - footer_height)
        with session.lock:
            filtered = [p for p in session.packets if matches_filter(p, session.filter)]
        draw(stdscr, session)
        stdscr.refresh()
        ch = stdscr.getch()
        if ch == -1:
            continue
        if ch == curses.KEY_RESIZE:
            continue
        handle_key(session, ch, filtered, list_height)

    stop_capture(session)


def main():
    parser = argparse.ArgumentParser(
        prog="lpacket.py",
        description="Terminal based network packet analyzer inspired by Wireshark.",
    )
    parser.add_argument("-i", dest="interface", help="network interface to capture on")
    parser.add_argument("-r", dest="pcap_file", help="pcap file to load and analyze")
    args = parser.parse_args()

    session = Session()

    if args.pcap_file:
        message = load_pcap(session, args.pcap_file)
        if message.startswith("Error"):
            print(message)
            return
        session.message = message
        curses.wrapper(curses_main, session)
        return

    interface = args.interface
    if not interface:
        interface = choose_interface()
        if not interface:
            return
    else:
        if interface not in list_interfaces():
            print("Interface not found: %s" % interface)
            return

    if not check_root():
        return

    session.interface = interface
    curses.wrapper(curses_main, session)


if __name__ == "__main__":
    main()
