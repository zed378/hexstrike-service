"""HexStrike routes — tools2 (blueprint)."""

from hexstrike_lib.server.deps import *  # noqa: F401,F403

bp = Blueprint("tools2", __name__)


@bp.route("/api/tools/smbmap", methods=["POST"])
def smbmap():
    """Execute SMBMap for SMB share enumeration with enhanced logging"""
    try:
        params = request.json
        target = params.get("target", "")
        username = params.get("username", "")
        password = params.get("password", "")
        domain = params.get("domain", "")
        additional_args = params.get("additional_args", "")

        if not target:
            logger.warning("🎯 SMBMap called without target parameter")
            return jsonify({
                "error": "Target parameter is required"
            }), 400

        command = f"smbmap -H {target}"

        if username:
            command += f" -u {username}"

        if password:
            command += f" -p {password}"

        if domain:
            command += f" -d {domain}"

        if additional_args:
            command += f" {additional_args}"

        logger.info(f"🔍 Starting SMBMap: {target}")
        result = execute_command(command)
        logger.info(f"📊 SMBMap completed for {target}")
        return jsonify(result)
    except Exception as e:
        logger.error(f"💥 Error in smbmap endpoint: {str(e)}")
        return jsonify({
            "error": f"Server error: {str(e)}"
        }), 500

# ============================================================================
# ENHANCED NETWORK PENETRATION TESTING TOOLS (v6.0)
# ============================================================================

@bp.route("/api/tools/rustscan", methods=["POST"])
def rustscan():
    """Execute Rustscan for ultra-fast port scanning with enhanced logging"""
    try:
        params = request.json
        target = params.get("target", "")
        ports = params.get("ports", "")
        ulimit = params.get("ulimit", 5000)
        batch_size = params.get("batch_size", 4500)
        timeout = params.get("timeout", 1500)
        scripts = params.get("scripts", "")
        additional_args = params.get("additional_args", "")

        if not target:
            logger.warning("🎯 Rustscan called without target parameter")
            return jsonify({"error": "Target parameter is required"}), 400

        command = f"rustscan -a {target} --ulimit {ulimit} -b {batch_size} -t {timeout}"

        if ports:
            command += f" -p {ports}"

        if scripts:
            command += f" -- -sC -sV"

        if additional_args:
            command += f" {additional_args}"

        logger.info(f"⚡ Starting Rustscan: {target}")
        result = execute_command(command)
        logger.info(f"📊 Rustscan completed for {target}")
        return jsonify(result)
    except Exception as e:
        logger.error(f"💥 Error in rustscan endpoint: {str(e)}")
        return jsonify({"error": f"Server error: {str(e)}"}), 500

@bp.route("/api/tools/masscan", methods=["POST"])
def masscan():
    """Execute Masscan for high-speed Internet-scale port scanning with intelligent rate limiting"""
    try:
        params = request.json
        target = params.get("target", "")
        ports = params.get("ports", "1-65535")
        rate = params.get("rate", 1000)
        interface = params.get("interface", "")
        router_mac = params.get("router_mac", "")
        source_ip = params.get("source_ip", "")
        banners = params.get("banners", False)
        additional_args = params.get("additional_args", "")

        if not target:
            logger.warning("🎯 Masscan called without target parameter")
            return jsonify({"error": "Target parameter is required"}), 400

        command = f"masscan {target} -p{ports} --rate={rate}"

        if interface:
            command += f" -e {interface}"

        if router_mac:
            command += f" --router-mac {router_mac}"

        if source_ip:
            command += f" --source-ip {source_ip}"

        if banners:
            command += " --banners"

        if additional_args:
            command += f" {additional_args}"

        logger.info(f"🚀 Starting Masscan: {target} at rate {rate}")
        result = execute_command(command)
        logger.info(f"📊 Masscan completed for {target}")
        return jsonify(result)
    except Exception as e:
        logger.error(f"💥 Error in masscan endpoint: {str(e)}")
        return jsonify({"error": f"Server error: {str(e)}"}), 500

@bp.route("/api/tools/nmap-advanced", methods=["POST"])
def nmap_advanced():
    """Execute advanced Nmap scans with custom NSE scripts and optimized timing"""
    try:
        params = request.json
        target = params.get("target", "")
        scan_type = params.get("scan_type", "-sS")
        ports = params.get("ports", "")
        timing = params.get("timing", "T4")
        nse_scripts = params.get("nse_scripts", "")
        os_detection = params.get("os_detection", False)
        version_detection = params.get("version_detection", False)
        aggressive = params.get("aggressive", False)
        stealth = params.get("stealth", False)
        additional_args = params.get("additional_args", "")

        if not target:
            logger.warning("🎯 Advanced Nmap called without target parameter")
            return jsonify({"error": "Target parameter is required"}), 400

        command = f"nmap {scan_type} {target}"

        if ports:
            command += f" -p {ports}"

        if stealth:
            command += " -T2 -f --mtu 24"
        else:
            command += f" -{timing}"

        if os_detection:
            command += " -O"

        if version_detection:
            command += " -sV"

        if aggressive:
            command += " -A"

        if nse_scripts:
            command += f" --script={nse_scripts}"
        elif not aggressive:  # Default useful scripts if not aggressive
            command += " --script=default,discovery,safe"

        if additional_args:
            command += f" {additional_args}"

        logger.info(f"🔍 Starting Advanced Nmap: {target}")
        result = execute_command(command)
        logger.info(f"📊 Advanced Nmap completed for {target}")
        return jsonify(result)
    except Exception as e:
        logger.error(f"💥 Error in advanced nmap endpoint: {str(e)}")
        return jsonify({"error": f"Server error: {str(e)}"}), 500

@bp.route("/api/tools/autorecon", methods=["POST"])
def autorecon():
    """Execute AutoRecon for comprehensive automated reconnaissance"""
    try:
        params = request.json
        target = params.get("target", "")
        output_dir = params.get("output_dir", "/tmp/autorecon")
        port_scans = params.get("port_scans", "top-100-ports")
        service_scans = params.get("service_scans", "default")
        heartbeat = params.get("heartbeat", 60)
        timeout = params.get("timeout", 300)
        additional_args = params.get("additional_args", "")

        if not target:
            logger.warning("🎯 AutoRecon called without target parameter")
            return jsonify({"error": "Target parameter is required"}), 400

        command = f"autorecon {target} -o {output_dir} --heartbeat {heartbeat} --timeout {timeout}"

        if port_scans != "default":
            command += f" --port-scans {port_scans}"

        if service_scans != "default":
            command += f" --service-scans {service_scans}"

        if additional_args:
            command += f" {additional_args}"

        logger.info(f"🔄 Starting AutoRecon: {target}")
        result = execute_command(command)
        logger.info(f"📊 AutoRecon completed for {target}")
        return jsonify(result)
    except Exception as e:
        logger.error(f"💥 Error in autorecon endpoint: {str(e)}")
        return jsonify({"error": f"Server error: {str(e)}"}), 500

@bp.route("/api/tools/enum4linux-ng", methods=["POST"])
def enum4linux_ng():
    """Execute Enum4linux-ng for advanced SMB enumeration with enhanced logging"""
    try:
        params = request.json
        target = params.get("target", "")
        username = params.get("username", "")
        password = params.get("password", "")
        domain = params.get("domain", "")
        shares = params.get("shares", True)
        users = params.get("users", True)
        groups = params.get("groups", True)
        policy = params.get("policy", True)
        additional_args = params.get("additional_args", "")

        if not target:
            logger.warning("🎯 Enum4linux-ng called without target parameter")
            return jsonify({"error": "Target parameter is required"}), 400

        command = f"enum4linux-ng {target}"

        if username:
            command += f" -u {username}"

        if password:
            command += f" -p {password}"

        if domain:
            command += f" -d {domain}"

        # Add specific enumeration options
        enum_options = []
        if shares:
            enum_options.append("S")
        if users:
            enum_options.append("U")
        if groups:
            enum_options.append("G")
        if policy:
            enum_options.append("P")

        if enum_options:
            command += f" -A {','.join(enum_options)}"

        if additional_args:
            command += f" {additional_args}"

        logger.info(f"🔍 Starting Enum4linux-ng: {target}")
        result = execute_command(command)
        logger.info(f"📊 Enum4linux-ng completed for {target}")
        return jsonify(result)
    except Exception as e:
        logger.error(f"💥 Error in enum4linux-ng endpoint: {str(e)}")
        return jsonify({"error": f"Server error: {str(e)}"}), 500

@bp.route("/api/tools/rpcclient", methods=["POST"])
def rpcclient():
    """Execute rpcclient for RPC enumeration with enhanced logging"""
    try:
        params = request.json
        target = params.get("target", "")
        username = params.get("username", "")
        password = params.get("password", "")
        domain = params.get("domain", "")
        commands = params.get("commands", "enumdomusers;enumdomgroups;querydominfo")
        additional_args = params.get("additional_args", "")

        if not target:
            logger.warning("🎯 rpcclient called without target parameter")
            return jsonify({"error": "Target parameter is required"}), 400

        # Build authentication string
        auth_string = ""
        if username and password:
            auth_string = f"-U {username}%{password}"
        elif username:
            auth_string = f"-U {username}"
        else:
            auth_string = "-U ''"  # Anonymous

        if domain:
            auth_string += f" -W {domain}"

        # Create command sequence
        command_sequence = commands.replace(";", "\n")

        command = f"echo -e '{command_sequence}' | rpcclient {auth_string} {target}"

        if additional_args:
            command += f" {additional_args}"

        logger.info(f"🔍 Starting rpcclient: {target}")
        result = execute_command(command)
        logger.info(f"📊 rpcclient completed for {target}")
        return jsonify(result)
    except Exception as e:
        logger.error(f"💥 Error in rpcclient endpoint: {str(e)}")
        return jsonify({"error": f"Server error: {str(e)}"}), 500

@bp.route("/api/tools/nbtscan", methods=["POST"])
def nbtscan():
    """Execute nbtscan for NetBIOS name scanning with enhanced logging"""
    try:
        params = request.json
        target = params.get("target", "")
        verbose = params.get("verbose", False)
        timeout = params.get("timeout", 2)
        additional_args = params.get("additional_args", "")

        if not target:
            logger.warning("🎯 nbtscan called without target parameter")
            return jsonify({"error": "Target parameter is required"}), 400

        command = f"nbtscan -t {timeout}"

        if verbose:
            command += " -v"

        command += f" {target}"

        if additional_args:
            command += f" {additional_args}"

        logger.info(f"🔍 Starting nbtscan: {target}")
        result = execute_command(command)
        logger.info(f"📊 nbtscan completed for {target}")
        return jsonify(result)
    except Exception as e:
        logger.error(f"💥 Error in nbtscan endpoint: {str(e)}")
        return jsonify({"error": f"Server error: {str(e)}"}), 500

@bp.route("/api/tools/arp-scan", methods=["POST"])
def arp_scan():
    """Execute arp-scan for network discovery with enhanced logging"""
    try:
        params = request.json
        target = params.get("target", "")
        interface = params.get("interface", "")
        local_network = params.get("local_network", False)
        timeout = params.get("timeout", 500)
        retry = params.get("retry", 3)
        additional_args = params.get("additional_args", "")

        if not target and not local_network:
            logger.warning("🎯 arp-scan called without target parameter")
            return jsonify({"error": "Target parameter or local_network flag is required"}), 400

        command = f"arp-scan -t {timeout} -r {retry}"

        if interface:
            command += f" -I {interface}"

        if local_network:
            command += " -l"
        else:
            command += f" {target}"

        if additional_args:
            command += f" {additional_args}"

        logger.info(f"🔍 Starting arp-scan: {target if target else 'local network'}")
        result = execute_command(command)
        logger.info(f"📊 arp-scan completed")
        return jsonify(result)
    except Exception as e:
        logger.error(f"💥 Error in arp-scan endpoint: {str(e)}")
        return jsonify({"error": f"Server error: {str(e)}"}), 500

@bp.route("/api/tools/responder", methods=["POST"])
def responder():
    """Execute Responder for credential harvesting with enhanced logging"""
    try:
        params = request.json
        interface = params.get("interface", "eth0")
        analyze = params.get("analyze", False)
        wpad = params.get("wpad", True)
        force_wpad_auth = params.get("force_wpad_auth", False)
        fingerprint = params.get("fingerprint", False)
        duration = params.get("duration", 300)  # 5 minutes default
        additional_args = params.get("additional_args", "")

        if not interface:
            logger.warning("🎯 Responder called without interface parameter")
            return jsonify({"error": "Interface parameter is required"}), 400

        command = f"timeout {duration} responder -I {interface}"

        if analyze:
            command += " -A"

        if wpad:
            command += " -w"

        if force_wpad_auth:
            command += " -F"

        if fingerprint:
            command += " -f"

        if additional_args:
            command += f" {additional_args}"

        logger.info(f"🔍 Starting Responder on interface: {interface}")
        result = execute_command(command)
        logger.info(f"📊 Responder completed")
        return jsonify(result)
    except Exception as e:
        logger.error(f"💥 Error in responder endpoint: {str(e)}")
        return jsonify({"error": f"Server error: {str(e)}"}), 500

@bp.route("/api/tools/volatility", methods=["POST"])
def volatility():
    """Execute Volatility for memory forensics with enhanced logging"""
    try:
        params = request.json
        memory_file = params.get("memory_file", "")
        plugin = params.get("plugin", "")
        profile = params.get("profile", "")
        additional_args = params.get("additional_args", "")

        if not memory_file:
            logger.warning("🧠 Volatility called without memory_file parameter")
            return jsonify({
                "error": "Memory file parameter is required"
            }), 400

        if not plugin:
            logger.warning("🧠 Volatility called without plugin parameter")
            return jsonify({
                "error": "Plugin parameter is required"
            }), 400

        command = f"volatility -f {memory_file}"

        if profile:
            command += f" --profile={profile}"

        command += f" {plugin}"

        if additional_args:
            command += f" {additional_args}"

        logger.info(f"🧠 Starting Volatility analysis: {plugin}")
        result = execute_command(command)
        logger.info(f"📊 Volatility analysis completed")
        return jsonify(result)
    except Exception as e:
        logger.error(f"💥 Error in volatility endpoint: {str(e)}")
        return jsonify({
            "error": f"Server error: {str(e)}"
        }), 500

@bp.route("/api/tools/msfvenom", methods=["POST"])
def msfvenom():
    """Execute MSFVenom to generate payloads with enhanced logging"""
    try:
        params = request.json
        payload = params.get("payload", "")
        format_type = params.get("format", "")
        output_file = params.get("output_file", "")
        encoder = params.get("encoder", "")
        iterations = params.get("iterations", "")
        additional_args = params.get("additional_args", "")

        if not payload:
            logger.warning("🚀 MSFVenom called without payload parameter")
            return jsonify({
                "error": "Payload parameter is required"
            }), 400

        command = f"msfvenom -p {payload}"

        if format_type:
            command += f" -f {format_type}"

        if output_file:
            command += f" -o {output_file}"

        if encoder:
            command += f" -e {encoder}"

        if iterations:
            command += f" -i {iterations}"

        if additional_args:
            command += f" {additional_args}"

        logger.info(f"🚀 Starting MSFVenom payload generation: {payload}")
        result = execute_command(command)
        logger.info(f"📊 MSFVenom payload generated")
        return jsonify(result)
    except Exception as e:
        logger.error(f"💥 Error in msfvenom endpoint: {str(e)}")
        return jsonify({
            "error": f"Server error: {str(e)}"
        }), 500

# ============================================================================
# BINARY ANALYSIS & REVERSE ENGINEERING TOOLS
# ============================================================================

@bp.route("/api/tools/gdb", methods=["POST"])
def gdb():
    """Execute GDB for binary analysis and debugging with enhanced logging"""
    try:
        params = request.json
        binary = params.get("binary", "")
        commands = params.get("commands", "")
        script_file = params.get("script_file", "")
        additional_args = params.get("additional_args", "")

        if not binary:
            logger.warning("🔧 GDB called without binary parameter")
            return jsonify({
                "error": "Binary parameter is required"
            }), 400

        command = f"gdb {binary}"

        if script_file:
            command += f" -x {script_file}"

        if commands:
            temp_script = "/tmp/gdb_commands.txt"
            with open(temp_script, "w") as f:
                f.write(commands)
            command += f" -x {temp_script}"

        if additional_args:
            command += f" {additional_args}"

        command += " -batch"

        logger.info(f"🔧 Starting GDB analysis: {binary}")
        result = execute_command(command)

        if commands and os.path.exists("/tmp/gdb_commands.txt"):
            try:
                os.remove("/tmp/gdb_commands.txt")
            except:
                pass

        logger.info(f"📊 GDB analysis completed for {binary}")
        return jsonify(result)
    except Exception as e:
        logger.error(f"💥 Error in gdb endpoint: {str(e)}")
        return jsonify({
            "error": f"Server error: {str(e)}"
        }), 500

@bp.route("/api/tools/radare2", methods=["POST"])
def radare2():
    """Execute Radare2 for binary analysis and reverse engineering with enhanced logging"""
    try:
        params = request.json
        binary = params.get("binary", "")
        commands = params.get("commands", "")
        additional_args = params.get("additional_args", "")

        if not binary:
            logger.warning("🔧 Radare2 called without binary parameter")
            return jsonify({
                "error": "Binary parameter is required"
            }), 400

        if commands:
            temp_script = "/tmp/r2_commands.txt"
            with open(temp_script, "w") as f:
                f.write(commands)
            command = f"r2 -i {temp_script} -q {binary}"
        else:
            command = f"r2 -q {binary}"

        if additional_args:
            command += f" {additional_args}"

        logger.info(f"🔧 Starting Radare2 analysis: {binary}")
        result = execute_command(command)

        if commands and os.path.exists("/tmp/r2_commands.txt"):
            try:
                os.remove("/tmp/r2_commands.txt")
            except:
                pass

        logger.info(f"📊 Radare2 analysis completed for {binary}")
        return jsonify(result)
    except Exception as e:
        logger.error(f"💥 Error in radare2 endpoint: {str(e)}")
        return jsonify({
            "error": f"Server error: {str(e)}"
        }), 500

@bp.route("/api/tools/binwalk", methods=["POST"])
def binwalk():
    """Execute Binwalk for firmware and file analysis with enhanced logging"""
    try:
        params = request.json
        file_path = params.get("file_path", "")
        extract = params.get("extract", False)
        additional_args = params.get("additional_args", "")

        if not file_path:
            logger.warning("🔧 Binwalk called without file_path parameter")
            return jsonify({
                "error": "File path parameter is required"
            }), 400

        command = f"binwalk"

        if extract:
            command += " -e"

        if additional_args:
            command += f" {additional_args}"

        command += f" {file_path}"

        logger.info(f"🔧 Starting Binwalk analysis: {file_path}")
        result = execute_command(command)
        logger.info(f"📊 Binwalk analysis completed for {file_path}")
        return jsonify(result)
    except Exception as e:
        logger.error(f"💥 Error in binwalk endpoint: {str(e)}")
        return jsonify({
            "error": f"Server error: {str(e)}"
        }), 500

@bp.route("/api/tools/ropgadget", methods=["POST"])
def ropgadget():
    """Search for ROP gadgets in a binary using ROPgadget with enhanced logging"""
    try:
        params = request.json
        binary = params.get("binary", "")
        gadget_type = params.get("gadget_type", "")
        additional_args = params.get("additional_args", "")

        if not binary:
            logger.warning("🔧 ROPgadget called without binary parameter")
            return jsonify({
                "error": "Binary parameter is required"
            }), 400

        command = f"ROPgadget --binary {binary}"

        if gadget_type:
            command += f" --only '{gadget_type}'"

        if additional_args:
            command += f" {additional_args}"

        logger.info(f"🔧 Starting ROPgadget search: {binary}")
        result = execute_command(command)
        logger.info(f"📊 ROPgadget search completed for {binary}")
        return jsonify(result)
    except Exception as e:
        logger.error(f"💥 Error in ropgadget endpoint: {str(e)}")
        return jsonify({
            "error": f"Server error: {str(e)}"
        }), 500

@bp.route("/api/tools/checksec", methods=["POST"])
def checksec():
    """Check security features of a binary with enhanced logging"""
    try:
        params = request.json
        binary = params.get("binary", "")

        if not binary:
            logger.warning("🔧 Checksec called without binary parameter")
            return jsonify({
                "error": "Binary parameter is required"
            }), 400

        command = f"checksec --file={binary}"

        logger.info(f"🔧 Starting Checksec analysis: {binary}")
        result = execute_command(command)
        logger.info(f"📊 Checksec analysis completed for {binary}")
        return jsonify(result)
    except Exception as e:
        logger.error(f"💥 Error in checksec endpoint: {str(e)}")
        return jsonify({
            "error": f"Server error: {str(e)}"
        }), 500

@bp.route("/api/tools/xxd", methods=["POST"])
def xxd():
    """Create a hex dump of a file using xxd with enhanced logging"""
    try:
        params = request.json
        file_path = params.get("file_path", "")
        offset = params.get("offset", "0")
        length = params.get("length", "")
        additional_args = params.get("additional_args", "")

        if not file_path:
            logger.warning("🔧 XXD called without file_path parameter")
            return jsonify({
                "error": "File path parameter is required"
            }), 400

        command = f"xxd -s {offset}"

        if length:
            command += f" -l {length}"

        if additional_args:
            command += f" {additional_args}"

        command += f" {file_path}"

        logger.info(f"🔧 Starting XXD hex dump: {file_path}")
        result = execute_command(command)
        logger.info(f"📊 XXD hex dump completed for {file_path}")
        return jsonify(result)
    except Exception as e:
        logger.error(f"💥 Error in xxd endpoint: {str(e)}")
        return jsonify({
            "error": f"Server error: {str(e)}"
        }), 500

@bp.route("/api/tools/strings", methods=["POST"])
def strings():
    """Extract strings from a binary file with enhanced logging"""
    try:
        params = request.json
        file_path = params.get("file_path", "")
        min_len = params.get("min_len", 4)
        additional_args = params.get("additional_args", "")

        if not file_path:
            logger.warning("🔧 Strings called without file_path parameter")
            return jsonify({
                "error": "File path parameter is required"
            }), 400

        command = f"strings -n {min_len}"

        if additional_args:
            command += f" {additional_args}"

        command += f" {file_path}"

        logger.info(f"🔧 Starting Strings extraction: {file_path}")
        result = execute_command(command)
        logger.info(f"📊 Strings extraction completed for {file_path}")
        return jsonify(result)
    except Exception as e:
        logger.error(f"💥 Error in strings endpoint: {str(e)}")
        return jsonify({
            "error": f"Server error: {str(e)}"
        }), 500

@bp.route("/api/tools/objdump", methods=["POST"])
def objdump():
    """Analyze a binary using objdump with enhanced logging"""
    try:
        params = request.json
        binary = params.get("binary", "")
        disassemble = params.get("disassemble", True)
        additional_args = params.get("additional_args", "")

        if not binary:
            logger.warning("🔧 Objdump called without binary parameter")
            return jsonify({
                "error": "Binary parameter is required"
            }), 400

        command = f"objdump"

        if disassemble:
            command += " -d"
        else:
            command += " -x"

        if additional_args:
            command += f" {additional_args}"

        command += f" {binary}"

        logger.info(f"🔧 Starting Objdump analysis: {binary}")
        result = execute_command(command)
        logger.info(f"📊 Objdump analysis completed for {binary}")
        return jsonify(result)
    except Exception as e:
        logger.error(f"💥 Error in objdump endpoint: {str(e)}")
        return jsonify({
            "error": f"Server error: {str(e)}"
        }), 500

# ============================================================================
# ENHANCED BINARY ANALYSIS AND EXPLOITATION FRAMEWORK (v6.0)
# ============================================================================

@bp.route("/api/tools/ghidra", methods=["POST"])
def ghidra():
    """Execute Ghidra for advanced binary analysis and reverse engineering"""
    try:
        params = request.json
        binary = params.get("binary", "")
        project_name = params.get("project_name", "hexstrike_analysis")
        script_file = params.get("script_file", "")
        analysis_timeout = params.get("analysis_timeout", 300)
        output_format = params.get("output_format", "xml")
        additional_args = params.get("additional_args", "")

        if not binary:
            logger.warning("🔧 Ghidra called without binary parameter")
            return jsonify({"error": "Binary parameter is required"}), 400

        # Create Ghidra project directory
        project_dir = f"/tmp/ghidra_projects/{project_name}"
        os.makedirs(project_dir, exist_ok=True)

        # Base Ghidra command for headless analysis
        command = f"analyzeHeadless {project_dir} {project_name} -import {binary} -deleteProject"

        if script_file:
            command += f" -postScript {script_file}"

        if output_format == "xml":
            command += f" -postScript ExportXml.java {project_dir}/analysis.xml"

        if additional_args:
            command += f" {additional_args}"

        logger.info(f"🔧 Starting Ghidra analysis: {binary}")
        result = execute_command(command, timeout=analysis_timeout)
        logger.info(f"📊 Ghidra analysis completed for {binary}")
        return jsonify(result)
    except Exception as e:
        logger.error(f"💥 Error in ghidra endpoint: {str(e)}")
        return jsonify({"error": f"Server error: {str(e)}"}), 500

@bp.route("/api/tools/pwntools", methods=["POST"])
def pwntools():
    """Execute Pwntools for exploit development and automation"""
    try:
        params = request.json
        script_content = params.get("script_content", "")
        target_binary = params.get("target_binary", "")
        target_host = params.get("target_host", "")
        target_port = params.get("target_port", 0)
        exploit_type = params.get("exploit_type", "local")  # local, remote, format_string, rop
        additional_args = params.get("additional_args", "")

        if not script_content and not target_binary:
            logger.warning("🔧 Pwntools called without script content or target binary")
            return jsonify({"error": "Script content or target binary is required"}), 400

        # Create temporary Python script
        script_file = "/tmp/pwntools_exploit.py"

        if script_content:
            # Use provided script content
            with open(script_file, "w") as f:
                f.write(script_content)
        else:
            # Generate basic exploit template
            template = f"""#!/usr/bin/env python3
from pwn import *

# Configuration
context.arch = 'amd64'
context.os = 'linux'
context.log_level = 'info'

# Target configuration
binary = '{target_binary}' if '{target_binary}' else None
host = '{target_host}' if '{target_host}' else None
port = {target_port} if {target_port} else None

# Exploit logic
if binary:
    p = process(binary)
    log.info(f"Started local process: {{binary}}")
elif host and port:
    p = remote(host, port)
    log.info(f"Connected to {{host}}:{{port}}")
else:
    log.error("No target specified")
    exit(1)

# Basic interaction
p.interactive()
"""
            with open(script_file, "w") as f:
                f.write(template)

        command = f"python3 {script_file}"

        if additional_args:
            command += f" {additional_args}"

        logger.info(f"🔧 Starting Pwntools exploit: {exploit_type}")
        result = execute_command(command)

        # Cleanup
        try:
            os.remove(script_file)
        except:
            pass

        logger.info(f"📊 Pwntools exploit completed")
        return jsonify(result)
    except Exception as e:
        logger.error(f"💥 Error in pwntools endpoint: {str(e)}")
        return jsonify({"error": f"Server error: {str(e)}"}), 500

@bp.route("/api/tools/one-gadget", methods=["POST"])
def one_gadget():
    """Execute one_gadget to find one-shot RCE gadgets in libc"""
    try:
        params = request.json
        libc_path = params.get("libc_path", "")
        level = params.get("level", 1)  # 0, 1, 2 for different constraint levels
        additional_args = params.get("additional_args", "")

        if not libc_path:
            logger.warning("🔧 one_gadget called without libc_path parameter")
            return jsonify({"error": "libc_path parameter is required"}), 400

        command = f"one_gadget {libc_path} --level {level}"

        if additional_args:
            command += f" {additional_args}"

        logger.info(f"🔧 Starting one_gadget analysis: {libc_path}")
        result = execute_command(command)
        logger.info(f"📊 one_gadget analysis completed")
        return jsonify(result)
    except Exception as e:
        logger.error(f"💥 Error in one_gadget endpoint: {str(e)}")
        return jsonify({"error": f"Server error: {str(e)}"}), 500

@bp.route("/api/tools/libc-database", methods=["POST"])
def libc_database():
    """Execute libc-database for libc identification and offset lookup"""
    try:
        params = request.json
        action = params.get("action", "find")  # find, dump, download
        symbols = params.get("symbols", "")  # format: "symbol1:offset1 symbol2:offset2"
        libc_id = params.get("libc_id", "")
        additional_args = params.get("additional_args", "")

        if action == "find" and not symbols:
            logger.warning("🔧 libc-database find called without symbols")
            return jsonify({"error": "Symbols parameter is required for find action"}), 400

        if action in ["dump", "download"] and not libc_id:
            logger.warning("🔧 libc-database called without libc_id for dump/download")
            return jsonify({"error": "libc_id parameter is required for dump/download actions"}), 400

        # Navigate to libc-database directory (assuming it's installed)
        base_command = "cd /opt/libc-database 2>/dev/null || cd ~/libc-database 2>/dev/null || echo 'libc-database not found'"

        if action == "find":
            command = f"{base_command} && ./find {symbols}"
        elif action == "dump":
            command = f"{base_command} && ./dump {libc_id}"
        elif action == "download":
            command = f"{base_command} && ./download {libc_id}"
        else:
            return jsonify({"error": f"Invalid action: {action}"}), 400

        if additional_args:
            command += f" {additional_args}"

        logger.info(f"🔧 Starting libc-database {action}: {symbols or libc_id}")
        result = execute_command(command)
        logger.info(f"📊 libc-database {action} completed")
        return jsonify(result)
    except Exception as e:
        logger.error(f"💥 Error in libc-database endpoint: {str(e)}")
        return jsonify({"error": f"Server error: {str(e)}"}), 500

@bp.route("/api/tools/gdb-peda", methods=["POST"])
def gdb_peda():
    """Execute GDB with PEDA for enhanced debugging and exploitation"""
    try:
        params = request.json
        binary = params.get("binary", "")
        commands = params.get("commands", "")
        attach_pid = params.get("attach_pid", 0)
        core_file = params.get("core_file", "")
        additional_args = params.get("additional_args", "")

        if not binary and not attach_pid and not core_file:
            logger.warning("🔧 GDB-PEDA called without binary, PID, or core file")
            return jsonify({"error": "Binary, PID, or core file parameter is required"}), 400

        # Base GDB command with PEDA
        command = "gdb -q"

        if binary:
            command += f" {binary}"

        if core_file:
            command += f" {core_file}"

        if attach_pid:
            command += f" -p {attach_pid}"

        # Create command script
        if commands:
            temp_script = "/tmp/gdb_peda_commands.txt"
            peda_commands = f"""
source ~/peda/peda.py
{commands}
quit
"""
            with open(temp_script, "w") as f:
                f.write(peda_commands)
            command += f" -x {temp_script}"
        else:
            # Default PEDA initialization
            command += " -ex 'source ~/peda/peda.py' -ex 'quit'"

        if additional_args:
            command += f" {additional_args}"

        target_info = binary or f'PID {attach_pid}' or core_file
        logger.info(f"🔧 Starting GDB-PEDA analysis: {target_info}")
        result = execute_command(command)

        # Cleanup
        if commands and os.path.exists("/tmp/gdb_peda_commands.txt"):
            try:
                os.remove("/tmp/gdb_peda_commands.txt")
            except:
                pass

        logger.info(f"📊 GDB-PEDA analysis completed")
        return jsonify(result)
    except Exception as e:
        logger.error(f"💥 Error in gdb-peda endpoint: {str(e)}")
        return jsonify({"error": f"Server error: {str(e)}"}), 500

@bp.route("/api/tools/angr", methods=["POST"])
def angr():
    """Execute angr for symbolic execution and binary analysis"""
    try:
        params = request.json
        binary = params.get("binary", "")
        script_content = params.get("script_content", "")
        find_address = params.get("find_address", "")
        avoid_addresses = params.get("avoid_addresses", "")
        analysis_type = params.get("analysis_type", "symbolic")  # symbolic, cfg, static
        additional_args = params.get("additional_args", "")

        if not binary:
            logger.warning("🔧 angr called without binary parameter")
            return jsonify({"error": "Binary parameter is required"}), 400

        # Create angr script
        script_file = "/tmp/angr_analysis.py"

        if script_content:
            with open(script_file, "w") as f:
                f.write(script_content)
        else:
            # Generate basic angr template
            template = f"""#!/usr/bin/env python3
import angr
import sys

# Load binary
project = angr.Project('{binary}', auto_load_libs=False)
print(f"Loaded binary: {binary}")
print(f"Architecture: {{project.arch}}")
print(f"Entry point: {{hex(project.entry)}}")

"""
            if analysis_type == "symbolic":
                template += f"""
# Symbolic execution
state = project.factory.entry_state()
simgr = project.factory.simulation_manager(state)

# Find and avoid addresses
find_addr = {find_address if find_address else 'None'}
avoid_addrs = {avoid_addresses.split(',') if avoid_addresses else '[]'}

if find_addr:
    simgr.explore(find=find_addr, avoid=avoid_addrs)
    if simgr.found:
        print("Found solution!")
        solution_state = simgr.found[0]
        print(f"Input: {{solution_state.posix.dumps(0)}}")
    else:
        print("No solution found")
else:
    print("No find address specified, running basic analysis")
"""
            elif analysis_type == "cfg":
                template += """
# Control Flow Graph analysis
cfg = project.analyses.CFGFast()
print(f"CFG nodes: {len(cfg.graph.nodes())}")
print(f"CFG edges: {len(cfg.graph.edges())}")

# Function analysis
for func_addr, func in cfg.functions.items():
    print(f"Function: {func.name} at {hex(func_addr)}")
"""

            with open(script_file, "w") as f:
                f.write(template)

        command = f"python3 {script_file}"

        if additional_args:
            command += f" {additional_args}"

        logger.info(f"🔧 Starting angr analysis: {binary}")
        result = execute_command(command, timeout=600)  # Longer timeout for symbolic execution

        # Cleanup
        try:
            os.remove(script_file)
        except:
            pass

        logger.info(f"📊 angr analysis completed")
        return jsonify(result)
    except Exception as e:
        logger.error(f"💥 Error in angr endpoint: {str(e)}")
        return jsonify({"error": f"Server error: {str(e)}"}), 500

@bp.route("/api/tools/ropper", methods=["POST"])
def ropper():
    """Execute ropper for advanced ROP/JOP gadget searching"""
    try:
        params = request.json
        binary = params.get("binary", "")
        gadget_type = params.get("gadget_type", "rop")  # rop, jop, sys, all
        quality = params.get("quality", 1)  # 1-5, higher = better quality
        arch = params.get("arch", "")  # x86, x86_64, arm, etc.
        search_string = params.get("search_string", "")
        additional_args = params.get("additional_args", "")

        if not binary:
            logger.warning("🔧 ropper called without binary parameter")
            return jsonify({"error": "Binary parameter is required"}), 400

        command = f"ropper --file {binary}"

        if gadget_type == "rop":
            command += " --rop"
        elif gadget_type == "jop":
            command += " --jop"
        elif gadget_type == "sys":
            command += " --sys"
        elif gadget_type == "all":
            command += " --all"

        if quality > 1:
            command += f" --quality {quality}"

        if arch:
            command += f" --arch {arch}"

        if search_string:
            command += f" --search '{search_string}'"

        if additional_args:
            command += f" {additional_args}"

        logger.info(f"🔧 Starting ropper analysis: {binary}")
        result = execute_command(command)
        logger.info(f"📊 ropper analysis completed")
        return jsonify(result)
    except Exception as e:
        logger.error(f"💥 Error in ropper endpoint: {str(e)}")
        return jsonify({"error": f"Server error: {str(e)}"}), 500

@bp.route("/api/tools/pwninit", methods=["POST"])
def pwninit():
    """Execute pwninit for CTF binary exploitation setup"""
    try:
        params = request.json
        binary = params.get("binary", "")
        libc = params.get("libc", "")
        ld = params.get("ld", "")
        template_type = params.get("template_type", "python")  # python, c
        additional_args = params.get("additional_args", "")

        if not binary:
            logger.warning("🔧 pwninit called without binary parameter")
            return jsonify({"error": "Binary parameter is required"}), 400

        command = f"pwninit --bin {binary}"

        if libc:
            command += f" --libc {libc}"

        if ld:
            command += f" --ld {ld}"

        if template_type:
            command += f" --template {template_type}"

        if additional_args:
            command += f" {additional_args}"

        logger.info(f"🔧 Starting pwninit setup: {binary}")
        result = execute_command(command)
        logger.info(f"📊 pwninit setup completed")
        return jsonify(result)
    except Exception as e:
        logger.error(f"💥 Error in pwninit endpoint: {str(e)}")
        return jsonify({"error": f"Server error: {str(e)}"}), 500

# ============================================================================
# ADDITIONAL WEB SECURITY TOOLS
# ============================================================================

@bp.route("/api/tools/feroxbuster", methods=["POST"])
def feroxbuster():
    """Execute Feroxbuster for recursive content discovery with enhanced logging"""
    try:
        params = request.json
        url = params.get("url", "")
        wordlist = params.get("wordlist", "/usr/share/wordlists/dirb/common.txt")
        threads = params.get("threads", 10)
        additional_args = params.get("additional_args", "")

        if not url:
            logger.warning("🌐 Feroxbuster called without URL parameter")
            return jsonify({
                "error": "URL parameter is required"
            }), 400

        command = f"feroxbuster -u {url} -w {wordlist} -t {threads}"

        if additional_args:
            command += f" {additional_args}"

        logger.info(f"🔍 Starting Feroxbuster scan: {url}")
        result = execute_command(command)
        logger.info(f"📊 Feroxbuster scan completed for {url}")
        return jsonify(result)
    except Exception as e:
        logger.error(f"💥 Error in feroxbuster endpoint: {str(e)}")
        return jsonify({
            "error": f"Server error: {str(e)}"
        }), 500

@bp.route("/api/tools/dotdotpwn", methods=["POST"])
def dotdotpwn():
    """Execute DotDotPwn for directory traversal testing with enhanced logging"""
    try:
        params = request.json
        target = params.get("target", "")
        module = params.get("module", "http")
        additional_args = params.get("additional_args", "")

        if not target:
            logger.warning("🎯 DotDotPwn called without target parameter")
            return jsonify({
                "error": "Target parameter is required"
            }), 400

        command = f"dotdotpwn -m {module} -h {target}"

        if additional_args:
            command += f" {additional_args}"

        command += " -b"

        logger.info(f"🔍 Starting DotDotPwn scan: {target}")
        result = execute_command(command)
        logger.info(f"📊 DotDotPwn scan completed for {target}")
        return jsonify(result)
    except Exception as e:
        logger.error(f"💥 Error in dotdotpwn endpoint: {str(e)}")
        return jsonify({
            "error": f"Server error: {str(e)}"
        }), 500

@bp.route("/api/tools/xsser", methods=["POST"])
def xsser():
    """Execute XSSer for XSS vulnerability testing with enhanced logging"""
    try:
        params = request.json
        url = params.get("url", "")
        params_str = params.get("params", "")
        additional_args = params.get("additional_args", "")

        if not url:
            logger.warning("🌐 XSSer called without URL parameter")
            return jsonify({
                "error": "URL parameter is required"
            }), 400

        command = f"xsser --url '{url}'"

        if params_str:
            command += f" --param='{params_str}'"

        if additional_args:
            command += f" {additional_args}"

        logger.info(f"🔍 Starting XSSer scan: {url}")
        result = execute_command(command)
        logger.info(f"📊 XSSer scan completed for {url}")
        return jsonify(result)
    except Exception as e:
        logger.error(f"💥 Error in xsser endpoint: {str(e)}")
        return jsonify({
            "error": f"Server error: {str(e)}"
        }), 500

@bp.route("/api/tools/wfuzz", methods=["POST"])
def wfuzz():
    """Execute Wfuzz for web application fuzzing with enhanced logging"""
    try:
        params = request.json
        url = params.get("url", "")
        wordlist = params.get("wordlist", "/usr/share/wordlists/dirb/common.txt")
        additional_args = params.get("additional_args", "")

        if not url:
            logger.warning("🌐 Wfuzz called without URL parameter")
            return jsonify({
                "error": "URL parameter is required"
            }), 400

        command = f"wfuzz -w {wordlist} '{url}'"

        if additional_args:
            command += f" {additional_args}"

        logger.info(f"🔍 Starting Wfuzz scan: {url}")
        result = execute_command(command)
        logger.info(f"📊 Wfuzz scan completed for {url}")
        return jsonify(result)
    except Exception as e:
        logger.error(f"💥 Error in wfuzz endpoint: {str(e)}")
        return jsonify({
            "error": f"Server error: {str(e)}"
        }), 500

# ============================================================================
# ENHANCED WEB APPLICATION SECURITY TOOLS (v6.0)
# ============================================================================

@bp.route("/api/tools/dirsearch", methods=["POST"])
def dirsearch():
    """Execute Dirsearch for advanced directory and file discovery with enhanced logging"""
    try:
        params = request.json
        url = params.get("url", "")
        extensions = params.get("extensions", "php,html,js,txt,xml,json")
        wordlist = params.get("wordlist", "/usr/share/wordlists/dirsearch/common.txt")
        threads = params.get("threads", 30)
        recursive = params.get("recursive", False)
        additional_args = params.get("additional_args", "")

        if not url:
            logger.warning("🌐 Dirsearch called without URL parameter")
            return jsonify({"error": "URL parameter is required"}), 400

        command = f"dirsearch -u {url} -e {extensions} -w {wordlist} -t {threads}"

        if recursive:
            command += " -r"

        if additional_args:
            command += f" {additional_args}"

        logger.info(f"📁 Starting Dirsearch scan: {url}")
        result = execute_command(command)
        logger.info(f"📊 Dirsearch scan completed for {url}")
        return jsonify(result)
    except Exception as e:
        logger.error(f"💥 Error in dirsearch endpoint: {str(e)}")
        return jsonify({"error": f"Server error: {str(e)}"}), 500

@bp.route("/api/tools/katana", methods=["POST"])
def katana():
    """Execute Katana for next-generation crawling and spidering with enhanced logging"""
    try:
        params = request.json
        url = params.get("url", "")
        depth = params.get("depth", 3)
        js_crawl = params.get("js_crawl", True)
        form_extraction = params.get("form_extraction", True)
        output_format = params.get("output_format", "json")
        additional_args = params.get("additional_args", "")

        if not url:
            logger.warning("🌐 Katana called without URL parameter")
            return jsonify({"error": "URL parameter is required"}), 400

        command = f"katana -u {url} -d {depth}"

        if js_crawl:
            command += " -jc"

        if form_extraction:
            command += " -fx"

        if output_format == "json":
            command += " -jsonl"

        if additional_args:
            command += f" {additional_args}"

        logger.info(f"⚔️  Starting Katana crawl: {url}")
        result = execute_command(command)
        logger.info(f"📊 Katana crawl completed for {url}")
        return jsonify(result)
    except Exception as e:
        logger.error(f"💥 Error in katana endpoint: {str(e)}")
        return jsonify({"error": f"Server error: {str(e)}"}), 500

@bp.route("/api/tools/gau", methods=["POST"])
def gau():
    """Execute Gau (Get All URLs) for URL discovery from multiple sources with enhanced logging"""
    try:
        params = request.json
        domain = params.get("domain", "")
        providers = params.get("providers", "wayback,commoncrawl,otx,urlscan")
        include_subs = params.get("include_subs", True)
        blacklist = params.get("blacklist", "png,jpg,gif,jpeg,swf,woff,svg,pdf,css,ico")
        additional_args = params.get("additional_args", "")

        if not domain:
            logger.warning("🌐 Gau called without domain parameter")
            return jsonify({"error": "Domain parameter is required"}), 400

        command = f"gau {domain}"

        if providers != "wayback,commoncrawl,otx,urlscan":
            command += f" --providers {providers}"

        if include_subs:
            command += " --subs"

        if blacklist:
            command += f" --blacklist {blacklist}"

        if additional_args:
            command += f" {additional_args}"

        logger.info(f"📡 Starting Gau URL discovery: {domain}")
        result = execute_command(command)
        logger.info(f"📊 Gau URL discovery completed for {domain}")
        return jsonify(result)
    except Exception as e:
        logger.error(f"💥 Error in gau endpoint: {str(e)}")
        return jsonify({"error": f"Server error: {str(e)}"}), 500

@bp.route("/api/tools/waybackurls", methods=["POST"])
def waybackurls():
    """Execute Waybackurls for historical URL discovery with enhanced logging"""
    try:
        params = request.json
        domain = params.get("domain", "")
        get_versions = params.get("get_versions", False)
        no_subs = params.get("no_subs", False)
        additional_args = params.get("additional_args", "")

        if not domain:
            logger.warning("🌐 Waybackurls called without domain parameter")
            return jsonify({"error": "Domain parameter is required"}), 400

        command = f"waybackurls {domain}"

        if get_versions:
            command += " --get-versions"

        if no_subs:
            command += " --no-subs"

        if additional_args:
            command += f" {additional_args}"

        logger.info(f"🕰️  Starting Waybackurls discovery: {domain}")
        result = execute_command(command)
        logger.info(f"📊 Waybackurls discovery completed for {domain}")
        return jsonify(result)
    except Exception as e:
        logger.error(f"💥 Error in waybackurls endpoint: {str(e)}")
        return jsonify({"error": f"Server error: {str(e)}"}), 500

@bp.route("/api/tools/arjun", methods=["POST"])
def arjun():
    """Execute Arjun for HTTP parameter discovery with enhanced logging"""
    try:
        params = request.json
        url = params.get("url", "")
        method = params.get("method", "GET")
        wordlist = params.get("wordlist", "")
        delay = params.get("delay", 0)
        threads = params.get("threads", 25)
        stable = params.get("stable", False)
        additional_args = params.get("additional_args", "")

        if not url:
            logger.warning("🌐 Arjun called without URL parameter")
            return jsonify({"error": "URL parameter is required"}), 400

        command = f"arjun -u {url} -m {method} -t {threads}"

        if wordlist:
            command += f" -w {wordlist}"

        if delay > 0:
            command += f" -d {delay}"

        if stable:
            command += " --stable"

        if additional_args:
            command += f" {additional_args}"

        logger.info(f"🎯 Starting Arjun parameter discovery: {url}")
        result = execute_command(command)
        logger.info(f"📊 Arjun parameter discovery completed for {url}")
        return jsonify(result)
    except Exception as e:
        logger.error(f"💥 Error in arjun endpoint: {str(e)}")
        return jsonify({"error": f"Server error: {str(e)}"}), 500

@bp.route("/api/tools/paramspider", methods=["POST"])
def paramspider():
    """Execute ParamSpider for parameter mining from web archives with enhanced logging"""
    try:
        params = request.json
        domain = params.get("domain", "")
        level = params.get("level", 2)
        exclude = params.get("exclude", "png,jpg,gif,jpeg,swf,woff,svg,pdf,css,ico")
        output = params.get("output", "")
        additional_args = params.get("additional_args", "")

        if not domain:
            logger.warning("🌐 ParamSpider called without domain parameter")
            return jsonify({"error": "Domain parameter is required"}), 400

        command = f"paramspider -d {domain} -l {level}"

        if exclude:
            command += f" --exclude {exclude}"

        if output:
            command += f" -o {output}"

        if additional_args:
            command += f" {additional_args}"

        logger.info(f"🕷️  Starting ParamSpider mining: {domain}")
        result = execute_command(command)
        logger.info(f"📊 ParamSpider mining completed for {domain}")
        return jsonify(result)
    except Exception as e:
        logger.error(f"💥 Error in paramspider endpoint: {str(e)}")
        return jsonify({"error": f"Server error: {str(e)}"}), 500

@bp.route("/api/tools/x8", methods=["POST"])
def x8():
    """Execute x8 for hidden parameter discovery with enhanced logging"""
    try:
        params = request.json
        url = params.get("url", "")
        wordlist = params.get("wordlist", "/usr/share/wordlists/x8/params.txt")
        method = params.get("method", "GET")
        body = params.get("body", "")
        headers = params.get("headers", "")
        additional_args = params.get("additional_args", "")

        if not url:
            logger.warning("🌐 x8 called without URL parameter")
            return jsonify({"error": "URL parameter is required"}), 400

        command = f"x8 -u {url} -w {wordlist} -X {method}"

        if body:
            command += f" -b '{body}'"

        if headers:
            command += f" -H '{headers}'"

        if additional_args:
            command += f" {additional_args}"

        logger.info(f"🔍 Starting x8 parameter discovery: {url}")
        result = execute_command(command)
        logger.info(f"📊 x8 parameter discovery completed for {url}")
        return jsonify(result)
    except Exception as e:
        logger.error(f"💥 Error in x8 endpoint: {str(e)}")
        return jsonify({"error": f"Server error: {str(e)}"}), 500

@bp.route("/api/tools/jaeles", methods=["POST"])
def jaeles():
    """Execute Jaeles for advanced vulnerability scanning with custom signatures"""
    try:
        params = request.json
        url = params.get("url", "")
        signatures = params.get("signatures", "")
        config = params.get("config", "")
        threads = params.get("threads", 20)
        timeout = params.get("timeout", 20)
        additional_args = params.get("additional_args", "")

        if not url:
            logger.warning("🌐 Jaeles called without URL parameter")
            return jsonify({"error": "URL parameter is required"}), 400

        command = f"jaeles scan -u {url} -c {threads} --timeout {timeout}"

        if signatures:
            command += f" -s {signatures}"

        if config:
            command += f" --config {config}"

        if additional_args:
            command += f" {additional_args}"

        logger.info(f"🔬 Starting Jaeles vulnerability scan: {url}")
        result = execute_command(command)
        logger.info(f"📊 Jaeles vulnerability scan completed for {url}")
        return jsonify(result)
    except Exception as e:
        logger.error(f"💥 Error in jaeles endpoint: {str(e)}")
        return jsonify({"error": f"Server error: {str(e)}"}), 500

@bp.route("/api/tools/dalfox", methods=["POST"])
def dalfox():
    """Execute Dalfox for advanced XSS vulnerability scanning with enhanced logging"""
    try:
        params = request.json
        url = params.get("url", "")
        pipe_mode = params.get("pipe_mode", False)
        blind = params.get("blind", False)
        mining_dom = params.get("mining_dom", True)
        mining_dict = params.get("mining_dict", True)
        custom_payload = params.get("custom_payload", "")
        additional_args = params.get("additional_args", "")

        if not url and not pipe_mode:
            logger.warning("🌐 Dalfox called without URL parameter")
            return jsonify({"error": "URL parameter is required"}), 400

        if pipe_mode:
            command = "dalfox pipe"
        else:
            command = f"dalfox url {url}"

        if blind:
            command += " --blind"

        if mining_dom:
            command += " --mining-dom"

        if mining_dict:
            command += " --mining-dict"

        if custom_payload:
            command += f" --custom-payload '{custom_payload}'"

        if additional_args:
            command += f" {additional_args}"

        logger.info(f"🎯 Starting Dalfox XSS scan: {url if url else 'pipe mode'}")
        result = execute_command(command)
        logger.info(f"📊 Dalfox XSS scan completed")
        return jsonify(result)
    except Exception as e:
        logger.error(f"💥 Error in dalfox endpoint: {str(e)}")
        return jsonify({"error": f"Server error: {str(e)}"}), 500

