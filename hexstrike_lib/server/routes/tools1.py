"""HexStrike routes — tools1 (blueprint)."""

from hexstrike_lib.server.deps import *  # noqa: F401,F403

bp = Blueprint("tools1", __name__)


@bp.route("/api/intelligence/technology-detection", methods=["POST"])
def detect_technologies():
    """Detect technologies and create technology-specific testing recommendations"""
    try:
        data = request.get_json()
        if not data or 'target' not in data:
            return jsonify({"error": "Target is required"}), 400

        target = data['target']

        logger.info(f"🔍 Detecting technologies for {target}")

        # Analyze target
        profile = decision_engine.analyze_target(target)

        # Get technology-specific recommendations
        tech_recommendations = {}
        for tech in profile.technologies:
            if tech == TechnologyStack.WORDPRESS:
                tech_recommendations["WordPress"] = {
                    "tools": ["wpscan", "nuclei"],
                    "focus_areas": ["plugin vulnerabilities", "theme issues", "user enumeration"],
                    "priority": "high"
                }
            elif tech == TechnologyStack.PHP:
                tech_recommendations["PHP"] = {
                    "tools": ["nikto", "sqlmap", "ffuf"],
                    "focus_areas": ["code injection", "file inclusion", "SQL injection"],
                    "priority": "high"
                }
            elif tech == TechnologyStack.NODEJS:
                tech_recommendations["Node.js"] = {
                    "tools": ["nuclei", "ffuf"],
                    "focus_areas": ["prototype pollution", "dependency vulnerabilities"],
                    "priority": "medium"
                }

        logger.info(f"✅ Technology detection completed for {target}")

        return jsonify({
            "success": True,
            "target": target,
            "detected_technologies": [tech.value for tech in profile.technologies],
            "cms_type": profile.cms_type,
            "technology_recommendations": tech_recommendations,
            "target_profile": profile.to_dict(),
            "timestamp": datetime.now().isoformat()
        })

    except Exception as e:
        logger.error(f"💥 Error in technology detection: {str(e)}")
        return jsonify({"error": f"Server error: {str(e)}"}), 500

# ============================================================================
# BUG BOUNTY HUNTING WORKFLOW API ENDPOINTS
# ============================================================================

@bp.route("/api/bugbounty/reconnaissance-workflow", methods=["POST"])
def create_reconnaissance_workflow():
    """Create comprehensive reconnaissance workflow for bug bounty hunting"""
    try:
        data = request.get_json()
        if not data or 'domain' not in data:
            return jsonify({"error": "Domain is required"}), 400

        domain = data['domain']
        scope = data.get('scope', [])
        out_of_scope = data.get('out_of_scope', [])
        program_type = data.get('program_type', 'web')

        logger.info(f"🎯 Creating reconnaissance workflow for {domain}")

        # Create bug bounty target
        target = BugBountyTarget(
            domain=domain,
            scope=scope,
            out_of_scope=out_of_scope,
            program_type=program_type
        )

        # Generate reconnaissance workflow
        workflow = bugbounty_manager.create_reconnaissance_workflow(target)

        logger.info(f"✅ Reconnaissance workflow created for {domain}")

        return jsonify({
            "success": True,
            "workflow": workflow,
            "timestamp": datetime.now().isoformat()
        })

    except Exception as e:
        logger.error(f"💥 Error creating reconnaissance workflow: {str(e)}")
        return jsonify({"error": f"Server error: {str(e)}"}), 500

@bp.route("/api/bugbounty/vulnerability-hunting-workflow", methods=["POST"])
def create_vulnerability_hunting_workflow():
    """Create vulnerability hunting workflow prioritized by impact"""
    try:
        data = request.get_json()
        if not data or 'domain' not in data:
            return jsonify({"error": "Domain is required"}), 400

        domain = data['domain']
        priority_vulns = data.get('priority_vulns', ["rce", "sqli", "xss", "idor", "ssrf"])
        bounty_range = data.get('bounty_range', 'unknown')

        logger.info(f"🎯 Creating vulnerability hunting workflow for {domain}")

        # Create bug bounty target
        target = BugBountyTarget(
            domain=domain,
            priority_vulns=priority_vulns,
            bounty_range=bounty_range
        )

        # Generate vulnerability hunting workflow
        workflow = bugbounty_manager.create_vulnerability_hunting_workflow(target)

        logger.info(f"✅ Vulnerability hunting workflow created for {domain}")

        return jsonify({
            "success": True,
            "workflow": workflow,
            "timestamp": datetime.now().isoformat()
        })

    except Exception as e:
        logger.error(f"💥 Error creating vulnerability hunting workflow: {str(e)}")
        return jsonify({"error": f"Server error: {str(e)}"}), 500

@bp.route("/api/bugbounty/business-logic-workflow", methods=["POST"])
def create_business_logic_workflow():
    """Create business logic testing workflow"""
    try:
        data = request.get_json()
        if not data or 'domain' not in data:
            return jsonify({"error": "Domain is required"}), 400

        domain = data['domain']
        program_type = data.get('program_type', 'web')

        logger.info(f"🎯 Creating business logic testing workflow for {domain}")

        # Create bug bounty target
        target = BugBountyTarget(domain=domain, program_type=program_type)

        # Generate business logic testing workflow
        workflow = bugbounty_manager.create_business_logic_testing_workflow(target)

        logger.info(f"✅ Business logic testing workflow created for {domain}")

        return jsonify({
            "success": True,
            "workflow": workflow,
            "timestamp": datetime.now().isoformat()
        })

    except Exception as e:
        logger.error(f"💥 Error creating business logic workflow: {str(e)}")
        return jsonify({"error": f"Server error: {str(e)}"}), 500

@bp.route("/api/bugbounty/osint-workflow", methods=["POST"])
def create_osint_workflow():
    """Create OSINT gathering workflow"""
    try:
        data = request.get_json()
        if not data or 'domain' not in data:
            return jsonify({"error": "Domain is required"}), 400

        domain = data['domain']

        logger.info(f"🎯 Creating OSINT workflow for {domain}")

        # Create bug bounty target
        target = BugBountyTarget(domain=domain)

        # Generate OSINT workflow
        workflow = bugbounty_manager.create_osint_workflow(target)

        logger.info(f"✅ OSINT workflow created for {domain}")

        return jsonify({
            "success": True,
            "workflow": workflow,
            "timestamp": datetime.now().isoformat()
        })

    except Exception as e:
        logger.error(f"💥 Error creating OSINT workflow: {str(e)}")
        return jsonify({"error": f"Server error: {str(e)}"}), 500

@bp.route("/api/bugbounty/file-upload-testing", methods=["POST"])
def create_file_upload_testing():
    """Create file upload vulnerability testing workflow"""
    try:
        data = request.get_json()
        if not data or 'target_url' not in data:
            return jsonify({"error": "Target URL is required"}), 400

        target_url = data['target_url']

        logger.info(f"🎯 Creating file upload testing workflow for {target_url}")

        # Generate file upload testing workflow
        workflow = fileupload_framework.create_upload_testing_workflow(target_url)

        # Generate test files
        test_files = fileupload_framework.generate_test_files()
        workflow["test_files"] = test_files

        logger.info(f"✅ File upload testing workflow created for {target_url}")

        return jsonify({
            "success": True,
            "workflow": workflow,
            "timestamp": datetime.now().isoformat()
        })

    except Exception as e:
        logger.error(f"💥 Error creating file upload testing workflow: {str(e)}")
        return jsonify({"error": f"Server error: {str(e)}"}), 500

@bp.route("/api/bugbounty/comprehensive-assessment", methods=["POST"])
def create_comprehensive_bugbounty_assessment():
    """Create comprehensive bug bounty assessment combining all workflows"""
    try:
        data = request.get_json()
        if not data or 'domain' not in data:
            return jsonify({"error": "Domain is required"}), 400

        domain = data['domain']
        scope = data.get('scope', [])
        priority_vulns = data.get('priority_vulns', ["rce", "sqli", "xss", "idor", "ssrf"])
        include_osint = data.get('include_osint', True)
        include_business_logic = data.get('include_business_logic', True)

        logger.info(f"🎯 Creating comprehensive bug bounty assessment for {domain}")

        # Create bug bounty target
        target = BugBountyTarget(
            domain=domain,
            scope=scope,
            priority_vulns=priority_vulns
        )

        # Generate all workflows
        assessment = {
            "target": domain,
            "reconnaissance": bugbounty_manager.create_reconnaissance_workflow(target),
            "vulnerability_hunting": bugbounty_manager.create_vulnerability_hunting_workflow(target)
        }

        if include_osint:
            assessment["osint"] = bugbounty_manager.create_osint_workflow(target)

        if include_business_logic:
            assessment["business_logic"] = bugbounty_manager.create_business_logic_testing_workflow(target)

        # Calculate total estimates
        total_time = sum(workflow.get("estimated_time", 0) for workflow in assessment.values() if isinstance(workflow, dict))
        total_tools = sum(workflow.get("tools_count", 0) for workflow in assessment.values() if isinstance(workflow, dict))

        assessment["summary"] = {
            "total_estimated_time": total_time,
            "total_tools": total_tools,
            "workflow_count": len([k for k in assessment.keys() if k != "target"]),
            "priority_score": assessment["vulnerability_hunting"].get("priority_score", 0)
        }

        logger.info(f"✅ Comprehensive bug bounty assessment created for {domain}")

        return jsonify({
            "success": True,
            "assessment": assessment,
            "timestamp": datetime.now().isoformat()
        })

    except Exception as e:
        logger.error(f"💥 Error creating comprehensive assessment: {str(e)}")
        return jsonify({"error": f"Server error: {str(e)}"}), 500

# ============================================================================
# SECURITY TOOLS API ENDPOINTS
# ============================================================================

@bp.route("/api/tools/nmap", methods=["POST"])
def nmap():
    """Execute nmap scan with enhanced logging, caching, and intelligent error handling"""
    try:
        params = request.json
        target = params.get("target", "")
        scan_type = params.get("scan_type", "-sCV")
        ports = params.get("ports", "")
        additional_args = params.get("additional_args", "-T4 -Pn")
        use_recovery = params.get("use_recovery", True)

        if not target:
            logger.warning("🎯 Nmap called without target parameter")
            return jsonify({
                "error": "Target parameter is required"
            }), 400

        command = f"nmap {scan_type}"

        if ports:
            command += f" -p {ports}"

        if additional_args:
            command += f" {additional_args}"

        command += f" {target}"

        logger.info(f"🔍 Starting Nmap scan: {target}")

        # Use intelligent error handling if enabled
        if use_recovery:
            tool_params = {
                "target": target,
                "scan_type": scan_type,
                "ports": ports,
                "additional_args": additional_args
            }
            result = execute_command_with_recovery("nmap", command, tool_params)
        else:
            result = execute_command(command)

        logger.info(f"📊 Nmap scan completed for {target}")
        return jsonify(result)

    except Exception as e:
        logger.error(f"💥 Error in nmap endpoint: {str(e)}")
        return jsonify({
            "error": f"Server error: {str(e)}"
        }), 500

@bp.route("/api/tools/gobuster", methods=["POST"])
def gobuster():
    """Execute gobuster with enhanced logging and intelligent error handling"""
    try:
        params = request.json
        url = params.get("url", "")
        mode = params.get("mode", "dir")
        wordlist = params.get("wordlist", "/usr/share/wordlists/dirb/common.txt")
        additional_args = params.get("additional_args", "")
        use_recovery = params.get("use_recovery", True)

        if not url:
            logger.warning("🌐 Gobuster called without URL parameter")
            return jsonify({
                "error": "URL parameter is required"
            }), 400

        # Validate mode
        if mode not in ["dir", "dns", "fuzz", "vhost"]:
            logger.warning(f"❌ Invalid gobuster mode: {mode}")
            return jsonify({
                "error": f"Invalid mode: {mode}. Must be one of: dir, dns, fuzz, vhost"
            }), 400

        command = f"gobuster {mode} -u {url} -w {wordlist}"

        if additional_args:
            command += f" {additional_args}"

        logger.info(f"📁 Starting Gobuster {mode} scan: {url}")

        # Use intelligent error handling if enabled
        if use_recovery:
            tool_params = {
                "target": url,
                "mode": mode,
                "wordlist": wordlist,
                "additional_args": additional_args
            }
            result = execute_command_with_recovery("gobuster", command, tool_params)
        else:
            result = execute_command(command)

        logger.info(f"📊 Gobuster scan completed for {url}")
        return jsonify(result)

    except Exception as e:
        logger.error(f"💥 Error in gobuster endpoint: {str(e)}")
        return jsonify({
            "error": f"Server error: {str(e)}"
        }), 500

@bp.route("/api/tools/nuclei", methods=["POST"])
def nuclei():
    """Execute Nuclei vulnerability scanner with enhanced logging and intelligent error handling"""
    try:
        params = request.json
        target = params.get("target", "")
        severity = params.get("severity", "")
        tags = params.get("tags", "")
        template = params.get("template", "")
        additional_args = params.get("additional_args", "")
        use_recovery = params.get("use_recovery", True)

        if not target:
            logger.warning("🎯 Nuclei called without target parameter")
            return jsonify({
                "error": "Target parameter is required"
            }), 400

        command = f"nuclei -u {target}"

        if severity:
            command += f" -severity {severity}"

        if tags:
            command += f" -tags {tags}"

        if template:
            command += f" -t {template}"

        if additional_args:
            command += f" {additional_args}"

        logger.info(f"🔬 Starting Nuclei vulnerability scan: {target}")

        # Use intelligent error handling if enabled
        if use_recovery:
            tool_params = {
                "target": target,
                "severity": severity,
                "tags": tags,
                "template": template,
                "additional_args": additional_args
            }
            result = execute_command_with_recovery("nuclei", command, tool_params)
        else:
            result = execute_command(command)

        logger.info(f"📊 Nuclei scan completed for {target}")
        return jsonify(result)

    except Exception as e:
        logger.error(f"💥 Error in nuclei endpoint: {str(e)}")
        return jsonify({
            "error": f"Server error: {str(e)}"
        }), 500

# ============================================================================
# CLOUD SECURITY TOOLS
# ============================================================================

@bp.route("/api/tools/prowler", methods=["POST"])
def prowler():
    """Execute Prowler for AWS security assessment"""
    try:
        params = request.json
        provider = params.get("provider", "aws")
        profile = params.get("profile", "default")
        region = params.get("region", "")
        checks = params.get("checks", "")
        output_dir = params.get("output_dir", "/tmp/prowler_output")
        output_format = params.get("output_format", "json")
        additional_args = params.get("additional_args", "")

        # Ensure output directory exists
        Path(output_dir).mkdir(parents=True, exist_ok=True)

        command = f"prowler {provider}"

        if profile:
            command += f" --profile {profile}"

        if region:
            command += f" --region {region}"

        if checks:
            command += f" --checks {checks}"

        command += f" --output-directory {output_dir}"
        command += f" --output-format {output_format}"

        if additional_args:
            command += f" {additional_args}"

        logger.info(f"☁️  Starting Prowler {provider} security assessment")
        result = execute_command(command)
        result["output_directory"] = output_dir
        logger.info(f"📊 Prowler assessment completed")
        return jsonify(result)
    except Exception as e:
        logger.error(f"💥 Error in prowler endpoint: {str(e)}")
        return jsonify({
            "error": f"Server error: {str(e)}"
        }), 500

@bp.route("/api/tools/trivy", methods=["POST"])
def trivy():
    """Execute Trivy for container/filesystem vulnerability scanning"""
    try:
        params = request.json
        scan_type = params.get("scan_type", "image")  # image, fs, repo
        target = params.get("target", "")
        output_format = params.get("output_format", "json")
        severity = params.get("severity", "")
        output_file = params.get("output_file", "")
        additional_args = params.get("additional_args", "")

        if not target:
            logger.warning("🎯 Trivy called without target parameter")
            return jsonify({
                "error": "Target parameter is required"
            }), 400

        command = f"trivy {scan_type} {target}"

        if output_format:
            command += f" --format {output_format}"

        if severity:
            command += f" --severity {severity}"

        if output_file:
            command += f" --output {output_file}"

        if additional_args:
            command += f" {additional_args}"

        logger.info(f"🔍 Starting Trivy {scan_type} scan: {target}")
        result = execute_command(command)
        if output_file:
            result["output_file"] = output_file
        logger.info(f"📊 Trivy scan completed for {target}")
        return jsonify(result)
    except Exception as e:
        logger.error(f"💥 Error in trivy endpoint: {str(e)}")
        return jsonify({
            "error": f"Server error: {str(e)}"
        }), 500

# ============================================================================
# ENHANCED CLOUD AND CONTAINER SECURITY TOOLS (v6.0)
# ============================================================================

@bp.route("/api/tools/scout-suite", methods=["POST"])
def scout_suite():
    """Execute Scout Suite for multi-cloud security assessment"""
    try:
        params = request.json
        provider = params.get("provider", "aws")  # aws, azure, gcp, aliyun, oci
        profile = params.get("profile", "default")
        report_dir = params.get("report_dir", "/tmp/scout-suite")
        services = params.get("services", "")
        exceptions = params.get("exceptions", "")
        additional_args = params.get("additional_args", "")

        # Ensure report directory exists
        Path(report_dir).mkdir(parents=True, exist_ok=True)

        command = f"scout {provider}"

        if profile and provider == "aws":
            command += f" --profile {profile}"

        if services:
            command += f" --services {services}"

        if exceptions:
            command += f" --exceptions {exceptions}"

        command += f" --report-dir {report_dir}"

        if additional_args:
            command += f" {additional_args}"

        logger.info(f"☁️  Starting Scout Suite {provider} assessment")
        result = execute_command(command)
        result["report_directory"] = report_dir
        logger.info(f"📊 Scout Suite assessment completed")
        return jsonify(result)
    except Exception as e:
        logger.error(f"💥 Error in scout-suite endpoint: {str(e)}")
        return jsonify({"error": f"Server error: {str(e)}"}), 500

@bp.route("/api/tools/cloudmapper", methods=["POST"])
def cloudmapper():
    """Execute CloudMapper for AWS network visualization and security analysis"""
    try:
        params = request.json
        action = params.get("action", "collect")  # collect, prepare, webserver, find_admins, etc.
        account = params.get("account", "")
        config = params.get("config", "config.json")
        additional_args = params.get("additional_args", "")

        if not account and action != "webserver":
            logger.warning("☁️  CloudMapper called without account parameter")
            return jsonify({"error": "Account parameter is required for most actions"}), 400

        command = f"cloudmapper {action}"

        if account:
            command += f" --account {account}"

        if config:
            command += f" --config {config}"

        if additional_args:
            command += f" {additional_args}"

        logger.info(f"☁️  Starting CloudMapper {action}")
        result = execute_command(command)
        logger.info(f"📊 CloudMapper {action} completed")
        return jsonify(result)
    except Exception as e:
        logger.error(f"💥 Error in cloudmapper endpoint: {str(e)}")
        return jsonify({"error": f"Server error: {str(e)}"}), 500

@bp.route("/api/tools/pacu", methods=["POST"])
def pacu():
    """Execute Pacu for AWS exploitation framework"""
    try:
        params = request.json
        session_name = params.get("session_name", "hexstrike_session")
        modules = params.get("modules", "")
        data_services = params.get("data_services", "")
        regions = params.get("regions", "")
        additional_args = params.get("additional_args", "")

        # Create Pacu command sequence
        commands = []
        commands.append(f"set_session {session_name}")

        if data_services:
            commands.append(f"data {data_services}")

        if regions:
            commands.append(f"set_regions {regions}")

        if modules:
            for module in modules.split(","):
                commands.append(f"run {module.strip()}")

        commands.append("exit")

        # Create command file
        command_file = "/tmp/pacu_commands.txt"
        with open(command_file, "w") as f:
            f.write("\n".join(commands))

        command = f"pacu < {command_file}"

        if additional_args:
            command += f" {additional_args}"

        logger.info(f"☁️  Starting Pacu AWS exploitation")
        result = execute_command(command)

        # Cleanup
        try:
            os.remove(command_file)
        except:
            pass

        logger.info(f"📊 Pacu exploitation completed")
        return jsonify(result)
    except Exception as e:
        logger.error(f"💥 Error in pacu endpoint: {str(e)}")
        return jsonify({"error": f"Server error: {str(e)}"}), 500

@bp.route("/api/tools/kube-hunter", methods=["POST"])
def kube_hunter():
    """Execute kube-hunter for Kubernetes penetration testing"""
    try:
        params = request.json
        target = params.get("target", "")
        remote = params.get("remote", "")
        cidr = params.get("cidr", "")
        interface = params.get("interface", "")
        active = params.get("active", False)
        report = params.get("report", "json")
        additional_args = params.get("additional_args", "")

        command = "kube-hunter"

        if target:
            command += f" --remote {target}"
        elif remote:
            command += f" --remote {remote}"
        elif cidr:
            command += f" --cidr {cidr}"
        elif interface:
            command += f" --interface {interface}"
        else:
            # Default to pod scanning
            command += " --pod"

        if active:
            command += " --active"

        if report:
            command += f" --report {report}"

        if additional_args:
            command += f" {additional_args}"

        logger.info(f"☁️  Starting kube-hunter Kubernetes scan")
        result = execute_command(command)
        logger.info(f"📊 kube-hunter scan completed")
        return jsonify(result)
    except Exception as e:
        logger.error(f"💥 Error in kube-hunter endpoint: {str(e)}")
        return jsonify({"error": f"Server error: {str(e)}"}), 500

@bp.route("/api/tools/kube-bench", methods=["POST"])
def kube_bench():
    """Execute kube-bench for CIS Kubernetes benchmark checks"""
    try:
        params = request.json
        targets = params.get("targets", "")  # master, node, etcd, policies
        version = params.get("version", "")
        config_dir = params.get("config_dir", "")
        output_format = params.get("output_format", "json")
        additional_args = params.get("additional_args", "")

        command = "kube-bench"

        if targets:
            command += f" --targets {targets}"

        if version:
            command += f" --version {version}"

        if config_dir:
            command += f" --config-dir {config_dir}"

        if output_format:
            command += f" --outputfile /tmp/kube-bench-results.{output_format} --json"

        if additional_args:
            command += f" {additional_args}"

        logger.info(f"☁️  Starting kube-bench CIS benchmark")
        result = execute_command(command)
        logger.info(f"📊 kube-bench benchmark completed")
        return jsonify(result)
    except Exception as e:
        logger.error(f"💥 Error in kube-bench endpoint: {str(e)}")
        return jsonify({"error": f"Server error: {str(e)}"}), 500

@bp.route("/api/tools/docker-bench-security", methods=["POST"])
def docker_bench_security():
    """Execute Docker Bench for Security for Docker security assessment"""
    try:
        params = request.json
        checks = params.get("checks", "")  # Specific checks to run
        exclude = params.get("exclude", "")  # Checks to exclude
        output_file = params.get("output_file", "/tmp/docker-bench-results.json")
        additional_args = params.get("additional_args", "")

        command = "docker-bench-security"

        if checks:
            command += f" -c {checks}"

        if exclude:
            command += f" -e {exclude}"

        if output_file:
            command += f" -l {output_file}"

        if additional_args:
            command += f" {additional_args}"

        logger.info(f"🐳 Starting Docker Bench Security assessment")
        result = execute_command(command)
        result["output_file"] = output_file
        logger.info(f"📊 Docker Bench Security completed")
        return jsonify(result)
    except Exception as e:
        logger.error(f"💥 Error in docker-bench-security endpoint: {str(e)}")
        return jsonify({"error": f"Server error: {str(e)}"}), 500

@bp.route("/api/tools/clair", methods=["POST"])
def clair():
    """Execute Clair for container vulnerability analysis"""
    try:
        params = request.json
        image = params.get("image", "")
        config = params.get("config", "/etc/clair/config.yaml")
        output_format = params.get("output_format", "json")
        additional_args = params.get("additional_args", "")

        if not image:
            logger.warning("🐳 Clair called without image parameter")
            return jsonify({"error": "Image parameter is required"}), 400

        # Use clairctl for scanning
        command = f"clairctl analyze {image}"

        if config:
            command += f" --config {config}"

        if output_format:
            command += f" --format {output_format}"

        if additional_args:
            command += f" {additional_args}"

        logger.info(f"🐳 Starting Clair vulnerability scan: {image}")
        result = execute_command(command)
        logger.info(f"📊 Clair scan completed for {image}")
        return jsonify(result)
    except Exception as e:
        logger.error(f"💥 Error in clair endpoint: {str(e)}")
        return jsonify({"error": f"Server error: {str(e)}"}), 500

@bp.route("/api/tools/falco", methods=["POST"])
def falco():
    """Execute Falco for runtime security monitoring"""
    try:
        params = request.json
        config_file = params.get("config_file", "/etc/falco/falco.yaml")
        rules_file = params.get("rules_file", "")
        output_format = params.get("output_format", "json")
        duration = params.get("duration", 60)  # seconds
        additional_args = params.get("additional_args", "")

        command = f"timeout {duration} falco"

        if config_file:
            command += f" --config {config_file}"

        if rules_file:
            command += f" --rules {rules_file}"

        if output_format == "json":
            command += " --json"

        if additional_args:
            command += f" {additional_args}"

        logger.info(f"🛡️  Starting Falco runtime monitoring for {duration}s")
        result = execute_command(command)
        logger.info(f"📊 Falco monitoring completed")
        return jsonify(result)
    except Exception as e:
        logger.error(f"💥 Error in falco endpoint: {str(e)}")
        return jsonify({"error": f"Server error: {str(e)}"}), 500

@bp.route("/api/tools/checkov", methods=["POST"])
def checkov():
    """Execute Checkov for infrastructure as code security scanning"""
    try:
        params = request.json
        directory = params.get("directory", ".")
        framework = params.get("framework", "")  # terraform, cloudformation, kubernetes, etc.
        check = params.get("check", "")
        skip_check = params.get("skip_check", "")
        output_format = params.get("output_format", "json")
        additional_args = params.get("additional_args", "")

        command = f"checkov -d {directory}"

        if framework:
            command += f" --framework {framework}"

        if check:
            command += f" --check {check}"

        if skip_check:
            command += f" --skip-check {skip_check}"

        if output_format:
            command += f" --output {output_format}"

        if additional_args:
            command += f" {additional_args}"

        logger.info(f"🔍 Starting Checkov IaC scan: {directory}")
        result = execute_command(command)
        logger.info(f"📊 Checkov scan completed")
        return jsonify(result)
    except Exception as e:
        logger.error(f"💥 Error in checkov endpoint: {str(e)}")
        return jsonify({"error": f"Server error: {str(e)}"}), 500

@bp.route("/api/tools/terrascan", methods=["POST"])
def terrascan():
    """Execute Terrascan for infrastructure as code security scanning"""
    try:
        params = request.json
        scan_type = params.get("scan_type", "all")  # all, terraform, k8s, etc.
        iac_dir = params.get("iac_dir", ".")
        policy_type = params.get("policy_type", "")
        output_format = params.get("output_format", "json")
        severity = params.get("severity", "")
        additional_args = params.get("additional_args", "")

        command = f"terrascan scan -t {scan_type} -d {iac_dir}"

        if policy_type:
            command += f" -p {policy_type}"

        if output_format:
            command += f" -o {output_format}"

        if severity:
            command += f" --severity {severity}"

        if additional_args:
            command += f" {additional_args}"

        logger.info(f"🔍 Starting Terrascan IaC scan: {iac_dir}")
        result = execute_command(command)
        logger.info(f"📊 Terrascan scan completed")
        return jsonify(result)
    except Exception as e:
        logger.error(f"💥 Error in terrascan endpoint: {str(e)}")
        return jsonify({"error": f"Server error: {str(e)}"}), 500

@bp.route("/api/tools/dirb", methods=["POST"])
def dirb():
    """Execute dirb with enhanced logging"""
    try:
        params = request.json
        url = params.get("url", "")
        wordlist = params.get("wordlist", "/usr/share/wordlists/dirb/common.txt")
        additional_args = params.get("additional_args", "")

        if not url:
            logger.warning("🌐 Dirb called without URL parameter")
            return jsonify({
                "error": "URL parameter is required"
            }), 400

        command = f"dirb {url} {wordlist}"

        if additional_args:
            command += f" {additional_args}"

        logger.info(f"📁 Starting Dirb scan: {url}")
        result = execute_command(command)
        logger.info(f"📊 Dirb scan completed for {url}")
        return jsonify(result)
    except Exception as e:
        logger.error(f"💥 Error in dirb endpoint: {str(e)}")
        return jsonify({
            "error": f"Server error: {str(e)}"
        }), 500

@bp.route("/api/tools/nikto", methods=["POST"])
def nikto():
    """Execute nikto with enhanced logging"""
    try:
        params = request.json
        target = params.get("target", "")
        additional_args = params.get("additional_args", "")

        if not target:
            logger.warning("🎯 Nikto called without target parameter")
            return jsonify({
                "error": "Target parameter is required"
            }), 400

        command = f"nikto -h {target}"

        if additional_args:
            command += f" {additional_args}"

        logger.info(f"🔬 Starting Nikto scan: {target}")
        result = execute_command(command)
        logger.info(f"📊 Nikto scan completed for {target}")
        return jsonify(result)
    except Exception as e:
        logger.error(f"💥 Error in nikto endpoint: {str(e)}")
        return jsonify({
            "error": f"Server error: {str(e)}"
        }), 500

@bp.route("/api/tools/sqlmap", methods=["POST"])
def sqlmap():
    """Execute sqlmap with enhanced logging"""
    try:
        params = request.json
        url = params.get("url", "")
        data = params.get("data", "")
        additional_args = params.get("additional_args", "")

        if not url:
            logger.warning("🎯 SQLMap called without URL parameter")
            return jsonify({
                "error": "URL parameter is required"
            }), 400

        command = f"sqlmap -u {url} --batch"

        if data:
            command += f" --data=\"{data}\""

        if additional_args:
            command += f" {additional_args}"

        logger.info(f"💉 Starting SQLMap scan: {url}")
        result = execute_command(command)
        logger.info(f"📊 SQLMap scan completed for {url}")
        return jsonify(result)
    except Exception as e:
        logger.error(f"💥 Error in sqlmap endpoint: {str(e)}")
        return jsonify({
            "error": f"Server error: {str(e)}"
        }), 500

@bp.route("/api/tools/metasploit", methods=["POST"])
def metasploit():
    """Execute metasploit module with enhanced logging"""
    try:
        params = request.json
        module = params.get("module", "")
        options = params.get("options", {})

        if not module:
            logger.warning("🚀 Metasploit called without module parameter")
            return jsonify({
                "error": "Module parameter is required"
            }), 400

        # Create an MSF resource script
        resource_content = f"use {module}\n"
        for key, value in options.items():
            resource_content += f"set {key} {value}\n"
        resource_content += "exploit\n"

        # Save resource script to a temporary file
        resource_file = "/tmp/mcp_msf_resource.rc"
        with open(resource_file, "w") as f:
            f.write(resource_content)

        command = f"msfconsole -q -r {resource_file}"

        logger.info(f"🚀 Starting Metasploit module: {module}")
        result = execute_command(command)

        # Clean up the temporary file
        try:
            os.remove(resource_file)
        except Exception as e:
            logger.warning(f"Error removing temporary resource file: {str(e)}")

        logger.info(f"📊 Metasploit module completed: {module}")
        return jsonify(result)
    except Exception as e:
        logger.error(f"💥 Error in metasploit endpoint: {str(e)}")
        return jsonify({
            "error": f"Server error: {str(e)}"
        }), 500

@bp.route("/api/tools/hydra", methods=["POST"])
def hydra():
    """Execute hydra with enhanced logging"""
    try:
        params = request.json
        target = params.get("target", "")
        service = params.get("service", "")
        username = params.get("username", "")
        username_file = params.get("username_file", "")
        password = params.get("password", "")
        password_file = params.get("password_file", "")
        additional_args = params.get("additional_args", "")

        if not target or not service:
            logger.warning("🎯 Hydra called without target or service parameter")
            return jsonify({
                "error": "Target and service parameters are required"
            }), 400

        if not (username or username_file) or not (password or password_file):
            logger.warning("🔑 Hydra called without username/password parameters")
            return jsonify({
                "error": "Username/username_file and password/password_file are required"
            }), 400

        command = f"hydra -t 4"

        if username:
            command += f" -l {username}"
        elif username_file:
            command += f" -L {username_file}"

        if password:
            command += f" -p {password}"
        elif password_file:
            command += f" -P {password_file}"

        if additional_args:
            command += f" {additional_args}"

        command += f" {target} {service}"

        logger.info(f"🔑 Starting Hydra attack: {target}:{service}")
        result = execute_command(command)
        logger.info(f"📊 Hydra attack completed for {target}")
        return jsonify(result)
    except Exception as e:
        logger.error(f"💥 Error in hydra endpoint: {str(e)}")
        return jsonify({
            "error": f"Server error: {str(e)}"
        }), 500

@bp.route("/api/tools/john", methods=["POST"])
def john():
    """Execute john with enhanced logging"""
    try:
        params = request.json
        hash_file = params.get("hash_file", "")
        wordlist = params.get("wordlist", "/usr/share/wordlists/rockyou.txt")
        format_type = params.get("format", "")
        additional_args = params.get("additional_args", "")

        if not hash_file:
            logger.warning("🔐 John called without hash_file parameter")
            return jsonify({
                "error": "Hash file parameter is required"
            }), 400

        command = f"john"

        if format_type:
            command += f" --format={format_type}"

        if wordlist:
            command += f" --wordlist={wordlist}"

        if additional_args:
            command += f" {additional_args}"

        command += f" {hash_file}"

        logger.info(f"🔐 Starting John the Ripper: {hash_file}")
        result = execute_command(command)
        logger.info(f"📊 John the Ripper completed")
        return jsonify(result)
    except Exception as e:
        logger.error(f"💥 Error in john endpoint: {str(e)}")
        return jsonify({
            "error": f"Server error: {str(e)}"
        }), 500

@bp.route("/api/tools/wpscan", methods=["POST"])
def wpscan():
    """Execute wpscan with enhanced logging"""
    try:
        params = request.json
        url = params.get("url", "")
        additional_args = params.get("additional_args", "")

        if not url:
            logger.warning("🌐 WPScan called without URL parameter")
            return jsonify({
                "error": "URL parameter is required"
            }), 400

        command = f"wpscan --url {url}"

        if additional_args:
            command += f" {additional_args}"

        logger.info(f"🔍 Starting WPScan: {url}")
        result = execute_command(command)
        logger.info(f"📊 WPScan completed for {url}")
        return jsonify(result)
    except Exception as e:
        logger.error(f"💥 Error in wpscan endpoint: {str(e)}")
        return jsonify({
            "error": f"Server error: {str(e)}"
        }), 500

@bp.route("/api/tools/enum4linux", methods=["POST"])
def enum4linux():
    """Execute enum4linux with enhanced logging"""
    try:
        params = request.json
        target = params.get("target", "")
        additional_args = params.get("additional_args", "-a")

        if not target:
            logger.warning("🎯 Enum4linux called without target parameter")
            return jsonify({
                "error": "Target parameter is required"
            }), 400

        command = f"enum4linux {additional_args} {target}"

        logger.info(f"🔍 Starting Enum4linux: {target}")
        result = execute_command(command)
        logger.info(f"📊 Enum4linux completed for {target}")
        return jsonify(result)
    except Exception as e:
        logger.error(f"💥 Error in enum4linux endpoint: {str(e)}")
        return jsonify({
            "error": f"Server error: {str(e)}"
        }), 500

@bp.route("/api/tools/ffuf", methods=["POST"])
def ffuf():
    """Execute FFuf web fuzzer with enhanced logging"""
    try:
        params = request.json
        url = params.get("url", "")
        wordlist = params.get("wordlist", "/usr/share/wordlists/dirb/common.txt")
        mode = params.get("mode", "directory")
        match_codes = params.get("match_codes", "200,204,301,302,307,401,403")
        additional_args = params.get("additional_args", "")

        if not url:
            logger.warning("🌐 FFuf called without URL parameter")
            return jsonify({
                "error": "URL parameter is required"
            }), 400

        command = f"ffuf"

        if mode == "directory":
            command += f" -u {url}/FUZZ -w {wordlist}"
        elif mode == "vhost":
            command += f" -u {url} -H 'Host: FUZZ' -w {wordlist}"
        elif mode == "parameter":
            command += f" -u {url}?FUZZ=value -w {wordlist}"
        else:
            command += f" -u {url} -w {wordlist}"

        command += f" -mc {match_codes}"

        if additional_args:
            command += f" {additional_args}"

        logger.info(f"🔍 Starting FFuf {mode} fuzzing: {url}")
        result = execute_command(command)
        logger.info(f"📊 FFuf fuzzing completed for {url}")
        return jsonify(result)
    except Exception as e:
        logger.error(f"💥 Error in ffuf endpoint: {str(e)}")
        return jsonify({
            "error": f"Server error: {str(e)}"
        }), 500

@bp.route("/api/tools/netexec", methods=["POST"])
def netexec():
    """Execute NetExec (formerly CrackMapExec) with enhanced logging"""
    try:
        params = request.json
        target = params.get("target", "")
        protocol = params.get("protocol", "smb")
        username = params.get("username", "")
        password = params.get("password", "")
        hash_value = params.get("hash", "")
        module = params.get("module", "")
        additional_args = params.get("additional_args", "")

        if not target:
            logger.warning("🎯 NetExec called without target parameter")
            return jsonify({
                "error": "Target parameter is required"
            }), 400

        command = f"nxc {protocol} {target}"

        if username:
            command += f" -u {username}"

        if password:
            command += f" -p {password}"

        if hash_value:
            command += f" -H {hash_value}"

        if module:
            command += f" -M {module}"

        if additional_args:
            command += f" {additional_args}"

        logger.info(f"🔍 Starting NetExec {protocol} scan: {target}")
        result = execute_command(command)
        logger.info(f"📊 NetExec scan completed for {target}")
        return jsonify(result)
    except Exception as e:
        logger.error(f"💥 Error in netexec endpoint: {str(e)}")
        return jsonify({
            "error": f"Server error: {str(e)}"
        }), 500

@bp.route("/api/tools/amass", methods=["POST"])
def amass():
    """Execute Amass for subdomain enumeration with enhanced logging"""
    try:
        params = request.json
        domain = params.get("domain", "")
        mode = params.get("mode", "enum")
        additional_args = params.get("additional_args", "")

        if not domain:
            logger.warning("🌐 Amass called without domain parameter")
            return jsonify({
                "error": "Domain parameter is required"
            }), 400

        command = f"amass {mode}"

        if mode == "enum":
            command += f" -d {domain}"
        else:
            command += f" -d {domain}"

        if additional_args:
            command += f" {additional_args}"

        logger.info(f"🔍 Starting Amass {mode}: {domain}")
        result = execute_command(command)
        logger.info(f"📊 Amass completed for {domain}")
        return jsonify(result)
    except Exception as e:
        logger.error(f"💥 Error in amass endpoint: {str(e)}")
        return jsonify({
            "error": f"Server error: {str(e)}"
        }), 500

@bp.route("/api/tools/hashcat", methods=["POST"])
def hashcat():
    """Execute Hashcat for password cracking with enhanced logging"""
    try:
        params = request.json
        hash_file = params.get("hash_file", "")
        hash_type = params.get("hash_type", "")
        attack_mode = params.get("attack_mode", "0")
        wordlist = params.get("wordlist", "/usr/share/wordlists/rockyou.txt")
        mask = params.get("mask", "")
        additional_args = params.get("additional_args", "")

        if not hash_file:
            logger.warning("🔐 Hashcat called without hash_file parameter")
            return jsonify({
                "error": "Hash file parameter is required"
            }), 400

        if not hash_type:
            logger.warning("🔐 Hashcat called without hash_type parameter")
            return jsonify({
                "error": "Hash type parameter is required"
            }), 400

        command = f"hashcat -m {hash_type} -a {attack_mode} {hash_file}"

        if attack_mode == "0" and wordlist:
            command += f" {wordlist}"
        elif attack_mode == "3" and mask:
            command += f" {mask}"

        if additional_args:
            command += f" {additional_args}"

        logger.info(f"🔐 Starting Hashcat attack: mode {attack_mode}")
        result = execute_command(command)
        logger.info(f"📊 Hashcat attack completed")
        return jsonify(result)
    except Exception as e:
        logger.error(f"💥 Error in hashcat endpoint: {str(e)}")
        return jsonify({
            "error": f"Server error: {str(e)}"
        }), 500

@bp.route("/api/tools/subfinder", methods=["POST"])
def subfinder():
    """Execute Subfinder for passive subdomain enumeration with enhanced logging"""
    try:
        params = request.json
        domain = params.get("domain", "")
        silent = params.get("silent", True)
        all_sources = params.get("all_sources", False)
        additional_args = params.get("additional_args", "")

        if not domain:
            logger.warning("🌐 Subfinder called without domain parameter")
            return jsonify({
                "error": "Domain parameter is required"
            }), 400

        command = f"subfinder -d {domain}"

        if silent:
            command += " -silent"

        if all_sources:
            command += " -all"

        if additional_args:
            command += f" {additional_args}"

        logger.info(f"🔍 Starting Subfinder: {domain}")
        result = execute_command(command)
        logger.info(f"📊 Subfinder completed for {domain}")
        return jsonify(result)
    except Exception as e:
        logger.error(f"💥 Error in subfinder endpoint: {str(e)}")
        return jsonify({
            "error": f"Server error: {str(e)}"
        }), 500

