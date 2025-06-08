from rich.console import Console 
from rich.text import Text 
from pathlib import Path
from rich.syntax import Syntax
import re 

console = Console()

def highlight_nmap(file_content = str):
    lines = file_content.splitlines()
    
    last_report_start = 0 
    for i, line in enumerate(lines):
        if line.startswith("Nmap scan report for"):
            last_report_start = i

    trimmed_lines = lines[last_report_start:]
    
    for line in trimmed_lines: 
        
        if re.search(r"(Stats:|UDP Scan Timing|ETC:|About \d+% done)", line):
            continue
        
        text = Text()

        if line.startswith("# Nmap") or line.startswith("# Nmap done") or "scan report" in line:
            text.append(line, style="cyan")
        elif line.startswith("PORT"):
            text.append(line, style="bold")
        
        elif re.match(r"^\d+/(tcp|udp)", line):
            match = re.match(r"^(\d+/\w+)\s+(\S+)\s+(.*)", line)
            if match: 
                port_proto, state, service = match.groups()

                proto = port_proto.split("/")[1]
                port_color = "blue" if proto == "tcp" else "cyan"
                state_color = {
                    "open": "green",
                    "closed": "red",
                    "filtered": "yellow"
                }.get(state, "white")

                state_padding = 15 if proto == "udp" else 7

                #split service into name and version
                service_parts = service.split(None, 1)
                service_name = service_parts[0]
                version_info = service_parts[1] if len(service_parts) > 1 else ""
                
                text.append(f"{port_proto:<12}", style=port_color)
                text.append(f"{state:<{state_padding}}", style=state_color)

                # Clean separation: service name padded, version follows on same line
                text.append(f"{service_name:<20}", style="magenta")  # <- adjust 20 if needed

                if version_info: 
                    text.append(version_info, style="bright_black")

                console.print(text)
            else:
                text.append(line)
        elif line.startswith("Not shown") or line.startswith("Host is up"):
            text.append(line, style="dim")
        else:
            text.append(line)

        console.print(text)

def highlight_web_enum(file_content: str):
    for line in file_content.splitlines():
        text = Text
        # Gobuster/Ferox format: /path (Status: 200) [Size: XYZ]
        match = re.match(r"(/[\w\-_/\.]+)\s+\(Status:\s+(\d+)\)", line)
        if match: 
            path, status = match.groups()
            status_code = int(status)
            color = "green" if 200 <= status_code < 300 else "yellow" if 300 <= status_code < 400 else "red"
            text.append(f"{path:<30}", style="cyan")
            text.append(f"(Status: {status})", status=color)

        else: 
            text.append(line)

        console.print(text)


def view_file(env, subargs): 
    box = env["BOXNAME"]
    outdir = Path(env["OUTDIR"])

    if not subargs: 
        console.print("[yellow]Usage:[/yellow] view <tcp|service|udp|gobuster|ferox|notes|filename>")
        return 
    
    shortname = subargs[0].lower()
    view_map = {
        "tcp": outdir / f"{box}.tcp_scan.txt",
        "service": outdir / f"{box}.service_scan.txt",
        "udp": outdir / f"{box}.udp.txt",
        "gobuster": outdir / "web_gobuster.txt",
        "ferox": outdir / "web_ferrox.txt",
        "notes": outdir / f"{box}_notes.txt",
    }

    target_file = view_map.get(shortname, outdir / shortname)

    if target_file.exists():
        console.rule(f"[bold green]Viewing {target_file.name}")
        content = target_file.read_text()

        if shortname in {"tcp", "udp", "service"}:
            highlight_nmap(content)
        elif shortname in {"gobuster", "ferox"}:
            highlight_web_enum(content)
        else: 
            syntax = Syntax(content, "text", theme="monokai", line_numbers= True)
            console.print(syntax)
    else: 
        console.print(f"[red][!] File not found:[/red] {target_file}")