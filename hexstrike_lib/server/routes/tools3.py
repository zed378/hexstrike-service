"""HexStrike routes — tools3 (blueprint)."""

from hexstrike_lib.server.deps import *  # noqa: F401,F403

bp = Blueprint("tools3", __name__)


@bp.route("/api/tools/httpx", methods=["POST"])
def httpx():
    """Execute httpx for fast HTTP probing and technology detection"""
    try:
        params = request.json
        target = params.get("target", "")
        probe = params.get("probe", True)
        tech_detect = params.get("tech_detect", False)
        status_code = params.get("status_code", False)
        content_length = params.get("content_length", False)
        title = params.get("title", False)
        web_server = params.get("web_server", False)
        threads = params.get("threads", 50)
        additional_args = params.get("additional_args", "")

        if not target:
            logger.warning("🌐 httpx called without target parameter")
            return jsonify({"error": "Target parameter is required"}), 400

        command = f"httpx -l {target} -t {threads}"

        if probe:
            command += " -probe"

        if tech_detect:
            command += " -tech-detect"

        if status_code:
            command += " -sc"

        if content_length:
            command += " -cl"

        if title:
            command += " -title"

        if web_server:
            command += " -server"

        if additional_args:
            command += f" {additional_args}"

        logger.info(f"🌍 Starting httpx probe: {target}")
        result = execute_command(command)
        logger.info(f"📊 httpx probe completed for {target}")
        return jsonify(result)
    except Exception as e:
        logger.error(f"💥 Error in httpx endpoint: {str(e)}")
        return jsonify({"error": f"Server error: {str(e)}"}), 500

@bp.route("/api/tools/anew", methods=["POST"])
def anew():
    """Execute anew for appending new lines to files (useful for data processing)"""
    try:
        params = request.json
        input_data = params.get("input_data", "")
        output_file = params.get("output_file", "")
        additional_args = params.get("additional_args", "")

        if not input_data:
            logger.warning("📝 Anew called without input data")
            return jsonify({"error": "Input data is required"}), 400

        if output_file:
            command = f"echo '{input_data}' | anew {output_file}"
        else:
            command = f"echo '{input_data}' | anew"

        if additional_args:
            command += f" {additional_args}"

        logger.info("📝 Starting anew data processing")
        result = execute_command(command)
        logger.info("📊 anew data processing completed")
        return jsonify(result)
    except Exception as e:
        logger.error(f"💥 Error in anew endpoint: {str(e)}")
        return jsonify({"error": f"Server error: {str(e)}"}), 500

@bp.route("/api/tools/qsreplace", methods=["POST"])
def qsreplace():
    """Execute qsreplace for query string parameter replacement"""
    try:
        params = request.json
        urls = params.get("urls", "")
        replacement = params.get("replacement", "FUZZ")
        additional_args = params.get("additional_args", "")

        if not urls:
            logger.warning("🌐 qsreplace called without URLs")
            return jsonify({"error": "URLs parameter is required"}), 400

        command = f"echo '{urls}' | qsreplace '{replacement}'"

        if additional_args:
            command += f" {additional_args}"

        logger.info("🔄 Starting qsreplace parameter replacement")
        result = execute_command(command)
        logger.info("📊 qsreplace parameter replacement completed")
        return jsonify(result)
    except Exception as e:
        logger.error(f"💥 Error in qsreplace endpoint: {str(e)}")
        return jsonify({"error": f"Server error: {str(e)}"}), 500

@bp.route("/api/tools/uro", methods=["POST"])
def uro():
    """Execute uro for filtering out similar URLs"""
    try:
        params = request.json
        urls = params.get("urls", "")
        whitelist = params.get("whitelist", "")
        blacklist = params.get("blacklist", "")
        additional_args = params.get("additional_args", "")

        if not urls:
            logger.warning("🌐 uro called without URLs")
            return jsonify({"error": "URLs parameter is required"}), 400

        command = f"echo '{urls}' | uro"

        if whitelist:
            command += f" --whitelist {whitelist}"

        if blacklist:
            command += f" --blacklist {blacklist}"

        if additional_args:
            command += f" {additional_args}"

        logger.info("🔍 Starting uro URL filtering")
        result = execute_command(command)
        logger.info("📊 uro URL filtering completed")
        return jsonify(result)
    except Exception as e:
        logger.error(f"💥 Error in uro endpoint: {str(e)}")
        return jsonify({"error": f"Server error: {str(e)}"}), 500

# ============================================================================
# ADVANCED WEB SECURITY TOOLS CONTINUED
# ============================================================================

# ============================================================================
# ENHANCED HTTP TESTING FRAMEWORK (BURP SUITE ALTERNATIVE)
# ============================================================================


@bp.route("/api/tools/http-framework", methods=["POST"])
def http_framework_endpoint():
    """Enhanced HTTP testing framework (Burp Suite alternative)"""
    try:
        params = request.json
        action = params.get("action", "request")  # request, spider, proxy_history, set_rules, set_scope, repeater, intruder
        url = params.get("url", "")
        method = params.get("method", "GET")
        data = params.get("data", {})
        headers = params.get("headers", {})
        cookies = params.get("cookies", {})

        logger.info(f"{ModernVisualEngine.create_section_header('HTTP FRAMEWORK', '🔥', 'FIRE_RED')}")

        if action == "request":
            if not url:
                return jsonify({"error": "URL parameter is required for request action"}), 400

            request_command = f"{method} {url}"
            logger.info(f"{ModernVisualEngine.format_command_execution(request_command, 'STARTING')}")
            result = http_framework.intercept_request(url, method, data, headers, cookies)

            if result.get("success"):
                logger.info(f"{ModernVisualEngine.format_tool_status('HTTP-Framework', 'SUCCESS', url)}")
            else:
                logger.error(f"{ModernVisualEngine.format_tool_status('HTTP-Framework', 'FAILED', url)}")

            return jsonify(result)

        elif action == "spider":
            if not url:
                return jsonify({"error": "URL parameter is required for spider action"}), 400

            max_depth = params.get("max_depth", 3)
            max_pages = params.get("max_pages", 100)

            spider_command = f"Spider {url}"
            logger.info(f"{ModernVisualEngine.format_command_execution(spider_command, 'STARTING')}")
            result = http_framework.spider_website(url, max_depth, max_pages)

            if result.get("success"):
                total_pages = result.get("total_pages", 0)
                pages_info = f"{total_pages} pages"
                logger.info(f"{ModernVisualEngine.format_tool_status('HTTP-Spider', 'SUCCESS', pages_info)}")
            else:
                logger.error(f"{ModernVisualEngine.format_tool_status('HTTP-Spider', 'FAILED', url)}")

            return jsonify(result)

        elif action == "proxy_history":
            return jsonify({
                "success": True,
                "history": http_framework.proxy_history[-100:],  # Last 100 requests
                "total_requests": len(http_framework.proxy_history),
                "vulnerabilities": http_framework.vulnerabilities,
            })

        elif action == "set_rules":
            rules = params.get("rules", [])
            http_framework.set_match_replace_rules(rules)
            return jsonify({"success": True, "rules_set": len(rules)})

        elif action == "set_scope":
            scope_host = params.get("host")
            include_sub = params.get("include_subdomains", True)
            if not scope_host:
                return jsonify({"error": "host parameter required"}), 400
            http_framework.set_scope(scope_host, include_sub)
            return jsonify({"success": True, "scope": http_framework.scope})

        elif action == "repeater":
            request_spec = params.get("request") or {}
            result = http_framework.send_custom_request(request_spec)
            return jsonify(result)

        elif action == "intruder":
            if not url:
                return jsonify({"error": "URL parameter required"}), 400
            method = params.get("method", "GET")
            location = params.get("location", "query")
            fuzz_params = params.get("params", [])
            payloads = params.get("payloads", [])
            base_data = params.get("base_data", {})
            max_requests = params.get("max_requests", 100)
            result = http_framework.intruder_sniper(
                url, method, location, fuzz_params, payloads, base_data, max_requests
            )
            return jsonify(result)

        else:
            return jsonify({"error": f"Unknown action: {action}"}), 400

    except Exception as e:
        logger.error(f"{ModernVisualEngine.format_error_card('ERROR', 'HTTP-Framework', str(e))}")
        return jsonify({"error": f"Server error: {str(e)}"}), 500

@bp.route("/api/tools/browser-agent", methods=["POST"])
def browser_agent_endpoint():
    """AI-powered browser agent for web application inspection"""
    try:
        params = request.json or {}
        action = params.get("action", "navigate")  # navigate, screenshot, close
        url = params.get("url", "")
        headless = params.get("headless", True)
        wait_time = params.get("wait_time", 5)
        proxy_port = params.get("proxy_port")
        active_tests = params.get("active_tests", False)

        logger.info(
            f"{ModernVisualEngine.create_section_header('BROWSER AGENT', '🌐', 'CRIMSON')}"
        )

        if action == "navigate":
            if not url:
                return (
                    jsonify({"error": "URL parameter is required for navigate action"}),
                    400,
                )

            # Setup browser if not already done
            if not browser_agent.driver:
                setup_success = browser_agent.setup_browser(headless, proxy_port)
                if not setup_success:
                    return jsonify({"error": "Failed to setup browser"}), 500

            result = browser_agent.navigate_and_inspect(url, wait_time)
            if result.get("success") and active_tests:
                active_results = browser_agent.run_active_tests(
                    result.get("page_info", {})
                )
                result["active_tests"] = active_results
                if active_results["active_findings"]:
                    logger.warning(
                        ModernVisualEngine.format_error_card(
                            "WARNING",
                            "BrowserAgent",
                            f"Active findings: {len(active_results['active_findings'])}",
                        )
                    )
            return jsonify(result)

        elif action == "screenshot":
            if not browser_agent.driver:
                return (
                    jsonify(
                        {"error": "Browser not initialized. Use navigate action first."}
                    ),
                    400,
                )

            screenshot_path = f"/tmp/hexstrike_screenshot_{int(time.time())}.png"
            browser_agent.driver.save_screenshot(screenshot_path)

            return jsonify(
                {
                    "success": True,
                    "screenshot": screenshot_path,
                    "current_url": browser_agent.driver.current_url,
                    "timestamp": datetime.now().isoformat(),
                }
            )

        elif action == "close":
            browser_agent.close_browser()
            return jsonify({"success": True, "message": "Browser closed successfully"})

        elif action == "status":
            return jsonify(
                {
                    "success": True,
                    "browser_active": browser_agent.driver is not None,
                    "screenshots_taken": len(browser_agent.screenshots),
                    "pages_visited": len(browser_agent.page_sources),
                }
            )

        else:
            return jsonify({"error": f"Unknown action: {action}"}), 400

    except Exception as e:
        logger.error(
            f"{ModernVisualEngine.format_error_card('ERROR', 'BrowserAgent', str(e))}"
        )
        return jsonify({"error": f"Server error: {str(e)}"}), 500

@bp.route("/api/tools/burpsuite-alternative", methods=["POST"])
def burpsuite_alternative():
    """Comprehensive Burp Suite alternative combining HTTP framework and browser agent"""
    try:
        params = request.json
        target = params.get("target", "")
        scan_type = params.get("scan_type", "comprehensive")  # comprehensive, spider, passive, active
        headless = params.get("headless", True)
        max_depth = params.get("max_depth", 3)
        max_pages = params.get("max_pages", 50)

        if not target:
            return jsonify({"error": "Target parameter is required"}), 400

        logger.info(f"{ModernVisualEngine.create_section_header('BURP SUITE ALTERNATIVE', '🔥', 'BLOOD_RED')}")
        scan_message = f'Starting {scan_type} scan of {target}'
        logger.info(f"{ModernVisualEngine.format_highlighted_text(scan_message, 'RED')}")

        results = {
            'target': target,
            'scan_type': scan_type,
            'timestamp': datetime.now().isoformat(),
            'success': True
        }

        # Phase 1: Browser-based reconnaissance
        if scan_type in ['comprehensive', 'spider']:
            logger.info(f"{ModernVisualEngine.format_tool_status('BrowserAgent', 'RUNNING', 'Reconnaissance Phase')}")

            if not browser_agent.driver:
                browser_agent.setup_browser(headless)

            browser_result = browser_agent.navigate_and_inspect(target)
            results['browser_analysis'] = browser_result

        # Phase 2: HTTP spidering
        if scan_type in ['comprehensive', 'spider']:
            logger.info(f"{ModernVisualEngine.format_tool_status('HTTP-Spider', 'RUNNING', 'Discovery Phase')}")

            spider_result = http_framework.spider_website(target, max_depth, max_pages)
            results['spider_analysis'] = spider_result

        # Phase 3: Vulnerability analysis
        if scan_type in ['comprehensive', 'active']:
            logger.info(f"{ModernVisualEngine.format_tool_status('VulnScanner', 'RUNNING', 'Analysis Phase')}")

            # Test discovered endpoints
            discovered_urls = results.get('spider_analysis', {}).get('discovered_urls', [target])
            vuln_results = []

            for url in discovered_urls[:20]:  # Limit to 20 URLs
                test_result = http_framework.intercept_request(url)
                if test_result.get('success'):
                    vuln_results.append(test_result)

            results['vulnerability_analysis'] = {
                'tested_urls': len(vuln_results),
                'total_vulnerabilities': len(http_framework.vulnerabilities),
                'recent_vulnerabilities': http_framework._get_recent_vulns(20)
            }

        # Generate summary
        total_vulns = len(http_framework.vulnerabilities)
        vuln_summary = {}
        for vuln in http_framework.vulnerabilities:
            severity = vuln.get('severity', 'unknown')
            vuln_summary[severity] = vuln_summary.get(severity, 0) + 1

        results['summary'] = {
            'total_vulnerabilities': total_vulns,
            'vulnerability_breakdown': vuln_summary,
            'pages_analyzed': len(results.get('spider_analysis', {}).get('discovered_urls', [])),
            'security_score': max(0, 100 - (total_vulns * 5))
        }

        # Display summary with enhanced colors
        logger.info(f"{ModernVisualEngine.create_section_header('SCAN COMPLETE', '✅', 'SUCCESS')}")
        vuln_message = f'Found {total_vulns} vulnerabilities'
        color_choice = 'YELLOW' if total_vulns > 0 else 'GREEN'
        logger.info(f"{ModernVisualEngine.format_highlighted_text(vuln_message, color_choice)}")

        for severity, count in vuln_summary.items():
            logger.info(f"  {ModernVisualEngine.format_vulnerability_severity(severity, count)}")

        return jsonify(results)

    except Exception as e:
        logger.error(f"{ModernVisualEngine.format_error_card('CRITICAL', 'BurpAlternative', str(e))}")
        return jsonify({"error": f"Server error: {str(e)}"}), 500
        logger.error(f"💥 Error in burpsuite endpoint: {str(e)}")
        return jsonify({
            "error": f"Server error: {str(e)}"
        }), 500

@bp.route("/api/tools/zap", methods=["POST"])
def zap():
    """Execute OWASP ZAP with enhanced logging"""
    try:
        params = request.json
        target = params.get("target", "")
        scan_type = params.get("scan_type", "baseline")
        api_key = params.get("api_key", "")
        daemon = params.get("daemon", False)
        port = params.get("port", "8090")
        host = params.get("host", "0.0.0.0")
        format_type = params.get("format", "xml")
        output_file = params.get("output_file", "")
        additional_args = params.get("additional_args", "")

        if not target and scan_type != "daemon":
            logger.warning("🎯 ZAP called without target parameter")
            return jsonify({
                "error": "Target parameter is required for scans"
            }), 400

        if daemon:
            command = f"zaproxy -daemon -host {host} -port {port}"
            if api_key:
                command += f" -config api.key={api_key}"
        else:
            command = f"zaproxy -cmd -quickurl {target}"

            if format_type:
                command += f" -quickout {format_type}"

            if output_file:
                command += f" -quickprogress -dir \"{output_file}\""

            if api_key:
                command += f" -config api.key={api_key}"

        if additional_args:
            command += f" {additional_args}"

        logger.info(f"🔍 Starting ZAP scan: {target}")
        result = execute_command(command)
        logger.info(f"📊 ZAP scan completed for {target}")
        return jsonify(result)
    except Exception as e:
        logger.error(f"💥 Error in zap endpoint: {str(e)}")
        return jsonify({
            "error": f"Server error: {str(e)}"
        }), 500

@bp.route("/api/tools/wafw00f", methods=["POST"])
def wafw00f():
    """Execute wafw00f to identify and fingerprint WAF products with enhanced logging"""
    try:
        params = request.json
        target = params.get("target", "")
        additional_args = params.get("additional_args", "")

        if not target:
            logger.warning("🛡️ Wafw00f called without target parameter")
            return jsonify({
                "error": "Target parameter is required"
            }), 400

        command = f"wafw00f {target}"

        if additional_args:
            command += f" {additional_args}"

        logger.info(f"🛡️ Starting Wafw00f WAF detection: {target}")
        result = execute_command(command)
        logger.info(f"📊 Wafw00f completed for {target}")
        return jsonify(result)
    except Exception as e:
        logger.error(f"💥 Error in wafw00f endpoint: {str(e)}")
        return jsonify({
            "error": f"Server error: {str(e)}"
        }), 500

@bp.route("/api/tools/fierce", methods=["POST"])
def fierce():
    """Execute fierce for DNS reconnaissance with enhanced logging"""
    try:
        params = request.json
        domain = params.get("domain", "")
        dns_server = params.get("dns_server", "")
        additional_args = params.get("additional_args", "")

        if not domain:
            logger.warning("🌐 Fierce called without domain parameter")
            return jsonify({
                "error": "Domain parameter is required"
            }), 400

        command = f"fierce --domain {domain}"

        if dns_server:
            command += f" --dns-servers {dns_server}"

        if additional_args:
            command += f" {additional_args}"

        logger.info(f"🔍 Starting Fierce DNS recon: {domain}")
        result = execute_command(command)
        logger.info(f"📊 Fierce completed for {domain}")
        return jsonify(result)
    except Exception as e:
        logger.error(f"💥 Error in fierce endpoint: {str(e)}")
        return jsonify({
            "error": f"Server error: {str(e)}"
        }), 500

@bp.route("/api/tools/dnsenum", methods=["POST"])
def dnsenum():
    """Execute dnsenum for DNS enumeration with enhanced logging"""
    try:
        params = request.json
        domain = params.get("domain", "")
        dns_server = params.get("dns_server", "")
        wordlist = params.get("wordlist", "")
        additional_args = params.get("additional_args", "")

        if not domain:
            logger.warning("🌐 DNSenum called without domain parameter")
            return jsonify({
                "error": "Domain parameter is required"
            }), 400

        command = f"dnsenum {domain}"

        if dns_server:
            command += f" --dnsserver {dns_server}"

        if wordlist:
            command += f" --file {wordlist}"

        if additional_args:
            command += f" {additional_args}"

        logger.info(f"🔍 Starting DNSenum: {domain}")
        result = execute_command(command)
        logger.info(f"📊 DNSenum completed for {domain}")
        return jsonify(result)
    except Exception as e:
        logger.error(f"💥 Error in dnsenum endpoint: {str(e)}")
        return jsonify({
            "error": f"Server error: {str(e)}"
        }), 500

# Python Environment Management Endpoints
@bp.route("/api/python/install", methods=["POST"])
def install_python_package():
    """Install a Python package in a virtual environment"""
    try:
        params = request.json
        package = params.get("package", "")
        env_name = params.get("env_name", "default")

        if not package:
            return jsonify({"error": "Package name is required"}), 400

        logger.info(f"📦 Installing Python package: {package} in env {env_name}")
        success = env_manager.install_package(env_name, package)

        if success:
            return jsonify({
                "success": True,
                "message": f"Package {package} installed successfully",
                "env_name": env_name
            })
        else:
            return jsonify({
                "success": False,
                "error": f"Failed to install package {package}"
            }), 500

    except Exception as e:
        logger.error(f"💥 Error installing Python package: {str(e)}")
        return jsonify({"error": f"Server error: {str(e)}"}), 500

@bp.route("/api/python/execute", methods=["POST"])
def execute_python_script():
    """Execute a Python script in a virtual environment"""
    try:
        params = request.json
        script = params.get("script", "")
        env_name = params.get("env_name", "default")
        filename = params.get("filename", f"script_{int(time.time())}.py")

        if not script:
            return jsonify({"error": "Script content is required"}), 400

        # Create script file
        script_result = file_manager.create_file(filename, script)
        if not script_result["success"]:
            return jsonify(script_result), 500

        # Get Python path for environment
        python_path = env_manager.get_python_path(env_name)
        script_path = script_result["path"]

        # Execute script
        command = f"{python_path} {script_path}"
        logger.info(f"🐍 Executing Python script in env {env_name}: {filename}")
        result = execute_command(command, use_cache=False)

        # Clean up script file
        file_manager.delete_file(filename)

        result["env_name"] = env_name
        result["script_filename"] = filename
        logger.info(f"📊 Python script execution completed")
        return jsonify(result)

    except Exception as e:
        logger.error(f"💥 Error executing Python script: {str(e)}")
        return jsonify({"error": f"Server error: {str(e)}"}), 500

# ============================================================================
# AI-POWERED PAYLOAD GENERATION (v5.0 ENHANCEMENT) UNDER DEVELOPMENT
# ============================================================================


@bp.route("/api/ai/generate_payload", methods=["POST"])
def ai_generate_payload():
    """Generate AI-powered contextual payloads for security testing"""
    try:
        params = request.json
        target_info = {
            "attack_type": params.get("attack_type", "xss"),
            "complexity": params.get("complexity", "basic"),
            "technology": params.get("technology", ""),
            "url": params.get("url", "")
        }

        logger.info(f"🤖 Generating AI payloads for {target_info['attack_type']} attack")
        result = ai_payload_generator.generate_contextual_payload(target_info)

        logger.info(f"✅ Generated {result['payload_count']} contextual payloads")

        return jsonify({
            "success": True,
            "ai_payload_generation": result,
            "timestamp": datetime.now().isoformat()
        })

    except Exception as e:
        logger.error(f"💥 Error in AI payload generation: {str(e)}")
        return jsonify({
            "success": False,
            "error": f"Server error: {str(e)}"
        }), 500

@bp.route("/api/ai/test_payload", methods=["POST"])
def ai_test_payload():
    """Test generated payload against target with AI analysis"""
    try:
        params = request.json
        payload = params.get("payload", "")
        target_url = params.get("target_url", "")
        method = params.get("method", "GET")

        if not payload or not target_url:
            return jsonify({
                "success": False,
                "error": "Payload and target_url are required"
            }), 400

        logger.info(f"🧪 Testing AI-generated payload against {target_url}")

        # Create test command based on method and payload
        if method.upper() == "GET":
            encoded_payload = payload.replace(" ", "%20").replace("'", "%27")
            test_command = f"curl -s '{target_url}?test={encoded_payload}'"
        else:
            test_command = f"curl -s -X POST -d 'test={payload}' '{target_url}'"

        # Execute test
        result = execute_command(test_command, use_cache=False)

        # AI analysis of results
        analysis = {
            "payload_tested": payload,
            "target_url": target_url,
            "method": method,
            "response_size": len(result.get("stdout", "")),
            "success": result.get("success", False),
            "potential_vulnerability": payload.lower() in result.get("stdout", "").lower(),
            "recommendations": [
                "Analyze response for payload reflection",
                "Check for error messages indicating vulnerability",
                "Monitor application behavior changes"
            ]
        }

        logger.info(f"🔍 Payload test completed | Potential vuln: {analysis['potential_vulnerability']}")

        return jsonify({
            "success": True,
            "test_result": result,
            "ai_analysis": analysis,
            "timestamp": datetime.now().isoformat()
        })

    except Exception as e:
        logger.error(f"💥 Error in AI payload testing: {str(e)}")
        return jsonify({
            "success": False,
            "error": f"Server error: {str(e)}"
        }), 500

# ============================================================================
# ADVANCED API TESTING TOOLS (v5.0 ENHANCEMENT)
# ============================================================================

@bp.route("/api/tools/api_fuzzer", methods=["POST"])
def api_fuzzer():
    """Advanced API endpoint fuzzing with intelligent parameter discovery"""
    try:
        params = request.json
        base_url = params.get("base_url", "")
        endpoints = params.get("endpoints", [])
        methods = params.get("methods", ["GET", "POST", "PUT", "DELETE"])
        wordlist = params.get("wordlist", "/usr/share/wordlists/api/api-endpoints.txt")

        if not base_url:
            logger.warning("🌐 API Fuzzer called without base_url parameter")
            return jsonify({
                "error": "Base URL parameter is required"
            }), 400

        # Create comprehensive API fuzzing command
        if endpoints:
            # Test specific endpoints
            results = []
            for endpoint in endpoints:
                for method in methods:
                    test_url = f"{base_url.rstrip('/')}/{endpoint.lstrip('/')}"
                    command = f"curl -s -X {method} -w '%{{http_code}}|%{{size_download}}' '{test_url}'"
                    result = execute_command(command, use_cache=False)
                    results.append({
                        "endpoint": endpoint,
                        "method": method,
                        "result": result
                    })

            logger.info(f"🔍 API endpoint testing completed for {len(endpoints)} endpoints")
            return jsonify({
                "success": True,
                "fuzzing_type": "endpoint_testing",
                "results": results
            })
        else:
            # Discover endpoints using wordlist
            command = f"ffuf -u {base_url}/FUZZ -w {wordlist} -mc 200,201,202,204,301,302,307,401,403,405 -t 50"

            logger.info(f"🔍 Starting API endpoint discovery: {base_url}")
            result = execute_command(command)
            logger.info(f"📊 API endpoint discovery completed")

            return jsonify({
                "success": True,
                "fuzzing_type": "endpoint_discovery",
                "result": result
            })

    except Exception as e:
        logger.error(f"💥 Error in API fuzzer: {str(e)}")
        return jsonify({
            "error": f"Server error: {str(e)}"
        }), 500

@bp.route("/api/tools/graphql_scanner", methods=["POST"])
def graphql_scanner():
    """Advanced GraphQL security scanning and introspection"""
    try:
        params = request.json
        endpoint = params.get("endpoint", "")
        introspection = params.get("introspection", True)
        query_depth = params.get("query_depth", 10)
        mutations = params.get("test_mutations", True)

        if not endpoint:
            logger.warning("🌐 GraphQL Scanner called without endpoint parameter")
            return jsonify({
                "error": "GraphQL endpoint parameter is required"
            }), 400

        logger.info(f"🔍 Starting GraphQL security scan: {endpoint}")

        results = {
            "endpoint": endpoint,
            "tests_performed": [],
            "vulnerabilities": [],
            "recommendations": []
        }

        # Test 1: Introspection query
        if introspection:
            introspection_query = '''
            {
                __schema {
                    types {
                        name
                        fields {
                            name
                            type {
                                name
                            }
                        }
                    }
                }
            }
            '''

            clean_query = introspection_query.replace('\n', ' ').replace('  ', ' ').strip()
            command = f"curl -s -X POST -H 'Content-Type: application/json' -d '{{\"query\":\"{clean_query}\"}}' '{endpoint}'"
            result = execute_command(command, use_cache=False)

            results["tests_performed"].append("introspection_query")

            if "data" in result.get("stdout", ""):
                results["vulnerabilities"].append({
                    "type": "introspection_enabled",
                    "severity": "MEDIUM",
                    "description": "GraphQL introspection is enabled"
                })

        # Test 2: Query depth analysis
        deep_query = "{ " * query_depth + "field" + " }" * query_depth
        command = f"curl -s -X POST -H 'Content-Type: application/json' -d '{{\"query\":\"{deep_query}\"}}' {endpoint}"
        depth_result = execute_command(command, use_cache=False)

        results["tests_performed"].append("query_depth_analysis")

        if "error" not in depth_result.get("stdout", "").lower():
            results["vulnerabilities"].append({
                "type": "no_query_depth_limit",
                "severity": "HIGH",
                "description": f"No query depth limiting detected (tested depth: {query_depth})"
            })

        # Test 3: Batch query testing
        batch_query = '[' + ','.join(['{\"query\":\"{field}\"}' for _ in range(10)]) + ']'
        command = f"curl -s -X POST -H 'Content-Type: application/json' -d '{batch_query}' {endpoint}"
        batch_result = execute_command(command, use_cache=False)

        results["tests_performed"].append("batch_query_testing")

        if "data" in batch_result.get("stdout", "") and batch_result.get("success"):
            results["vulnerabilities"].append({
                "type": "batch_queries_allowed",
                "severity": "MEDIUM",
                "description": "Batch queries are allowed without rate limiting"
            })

        # Generate recommendations
        if results["vulnerabilities"]:
            results["recommendations"] = [
                "Disable introspection in production",
                "Implement query depth limiting",
                "Add rate limiting for batch queries",
                "Implement query complexity analysis",
                "Add authentication for sensitive operations"
            ]

        logger.info(f"📊 GraphQL scan completed | Vulnerabilities found: {len(results['vulnerabilities'])}")

        return jsonify({
            "success": True,
            "graphql_scan_results": results
        })

    except Exception as e:
        logger.error(f"💥 Error in GraphQL scanner: {str(e)}")
        return jsonify({
            "error": f"Server error: {str(e)}"
        }), 500

@bp.route("/api/tools/jwt_analyzer", methods=["POST"])
def jwt_analyzer():
    """Advanced JWT token analysis and vulnerability testing"""
    try:
        params = request.json
        jwt_token = params.get("jwt_token", "")
        target_url = params.get("target_url", "")

        if not jwt_token:
            logger.warning("🔐 JWT Analyzer called without jwt_token parameter")
            return jsonify({
                "error": "JWT token parameter is required"
            }), 400

        logger.info(f"🔍 Starting JWT security analysis")

        results = {
            "token": jwt_token[:50] + "..." if len(jwt_token) > 50 else jwt_token,
            "vulnerabilities": [],
            "token_info": {},
            "attack_vectors": []
        }

        # Decode JWT header and payload (basic analysis)
        try:
            parts = jwt_token.split('.')
            if len(parts) >= 2:
                # Decode header
                import base64
                import json

                # Add padding if needed
                header_b64 = parts[0] + '=' * (4 - len(parts[0]) % 4)
                payload_b64 = parts[1] + '=' * (4 - len(parts[1]) % 4)

                try:
                    header = json.loads(base64.b64decode(header_b64))
                    payload = json.loads(base64.b64decode(payload_b64))

                    results["token_info"] = {
                        "header": header,
                        "payload": payload,
                        "algorithm": header.get("alg", "unknown")
                    }

                    # Check for vulnerabilities
                    algorithm = header.get("alg", "").lower()

                    if algorithm == "none":
                        results["vulnerabilities"].append({
                            "type": "none_algorithm",
                            "severity": "CRITICAL",
                            "description": "JWT uses 'none' algorithm - no signature verification"
                        })

                    if algorithm in ["hs256", "hs384", "hs512"]:
                        results["attack_vectors"].append("hmac_key_confusion")
                        results["vulnerabilities"].append({
                            "type": "hmac_algorithm",
                            "severity": "MEDIUM",
                            "description": "HMAC algorithm detected - vulnerable to key confusion attacks"
                        })

                    # Check token expiration
                    exp = payload.get("exp")
                    if not exp:
                        results["vulnerabilities"].append({
                            "type": "no_expiration",
                            "severity": "HIGH",
                            "description": "JWT token has no expiration time"
                        })

                except Exception as decode_error:
                    results["vulnerabilities"].append({
                        "type": "malformed_token",
                        "severity": "HIGH",
                        "description": f"Token decoding failed: {str(decode_error)}"
                    })

        except Exception as e:
            results["vulnerabilities"].append({
                "type": "invalid_format",
                "severity": "HIGH",
                "description": "Invalid JWT token format"
            })

        # Test token manipulation if target URL provided
        if target_url:
            # Test none algorithm attack
            none_token_parts = jwt_token.split('.')
            if len(none_token_parts) >= 2:
                # Create none algorithm token
                none_header = base64.b64encode('{"alg":"none","typ":"JWT"}'.encode()).decode().rstrip('=')
                none_token = f"{none_header}.{none_token_parts[1]}."

                command = f"curl -s -H 'Authorization: Bearer {none_token}' '{target_url}'"
                none_result = execute_command(command, use_cache=False)

                if "200" in none_result.get("stdout", "") or "success" in none_result.get("stdout", "").lower():
                    results["vulnerabilities"].append({
                        "type": "none_algorithm_accepted",
                        "severity": "CRITICAL",
                        "description": "Server accepts tokens with 'none' algorithm"
                    })

        logger.info(f"📊 JWT analysis completed | Vulnerabilities found: {len(results['vulnerabilities'])}")

        return jsonify({
            "success": True,
            "jwt_analysis_results": results
        })

    except Exception as e:
        logger.error(f"💥 Error in JWT analyzer: {str(e)}")
        return jsonify({
            "error": f"Server error: {str(e)}"
        }), 500

@bp.route("/api/tools/api_schema_analyzer", methods=["POST"])
def api_schema_analyzer():
    """Analyze API schemas and identify potential security issues"""
    try:
        params = request.json
        schema_url = params.get("schema_url", "")
        schema_type = params.get("schema_type", "openapi")  # openapi, swagger, graphql

        if not schema_url:
            logger.warning("📋 API Schema Analyzer called without schema_url parameter")
            return jsonify({
                "error": "Schema URL parameter is required"
            }), 400

        logger.info(f"🔍 Starting API schema analysis: {schema_url}")

        # Fetch schema
        command = f"curl -s '{schema_url}'"
        result = execute_command(command, use_cache=True)

        if not result.get("success"):
            return jsonify({
                "error": "Failed to fetch API schema"
            }), 400

        schema_content = result.get("stdout", "")

        analysis_results = {
            "schema_url": schema_url,
            "schema_type": schema_type,
            "endpoints_found": [],
            "security_issues": [],
            "recommendations": []
        }

        # Parse schema based on type
        try:
            import json
            schema_data = json.loads(schema_content)

            if schema_type.lower() in ["openapi", "swagger"]:
                # OpenAPI/Swagger analysis
                paths = schema_data.get("paths", {})

                for path, methods in paths.items():
                    for method, details in methods.items():
                        if isinstance(details, dict):
                            endpoint_info = {
                                "path": path,
                                "method": method.upper(),
                                "summary": details.get("summary", ""),
                                "parameters": details.get("parameters", []),
                                "security": details.get("security", [])
                            }
                            analysis_results["endpoints_found"].append(endpoint_info)

                            # Check for security issues
                            if not endpoint_info["security"]:
                                analysis_results["security_issues"].append({
                                    "endpoint": f"{method.upper()} {path}",
                                    "issue": "no_authentication",
                                    "severity": "MEDIUM",
                                    "description": "Endpoint has no authentication requirements"
                                })

                            # Check for sensitive data in parameters
                            for param in endpoint_info["parameters"]:
                                param_name = param.get("name", "").lower()
                                if any(sensitive in param_name for sensitive in ["password", "token", "key", "secret"]):
                                    analysis_results["security_issues"].append({
                                        "endpoint": f"{method.upper()} {path}",
                                        "issue": "sensitive_parameter",
                                        "severity": "HIGH",
                                        "description": f"Sensitive parameter detected: {param_name}"
                                    })

            # Generate recommendations
            if analysis_results["security_issues"]:
                analysis_results["recommendations"] = [
                    "Implement authentication for all endpoints",
                    "Use HTTPS for all API communications",
                    "Validate and sanitize all input parameters",
                    "Implement rate limiting",
                    "Add proper error handling",
                    "Use secure headers (CORS, CSP, etc.)"
                ]

        except json.JSONDecodeError:
            analysis_results["security_issues"].append({
                "endpoint": "schema",
                "issue": "invalid_json",
                "severity": "HIGH",
                "description": "Schema is not valid JSON"
            })

        logger.info(f"📊 Schema analysis completed | Issues found: {len(analysis_results['security_issues'])}")

        return jsonify({
            "success": True,
            "schema_analysis_results": analysis_results
        })

    except Exception as e:
        logger.error(f"💥 Error in API schema analyzer: {str(e)}")
        return jsonify({
            "error": f"Server error: {str(e)}"
        }), 500

# ============================================================================
# ADVANCED CTF TOOLS (v5.0 ENHANCEMENT)
# ============================================================================

@bp.route("/api/tools/volatility3", methods=["POST"])
def volatility3():
    """Execute Volatility3 for advanced memory forensics with enhanced logging"""
    try:
        params = request.json
        memory_file = params.get("memory_file", "")
        plugin = params.get("plugin", "")
        output_file = params.get("output_file", "")
        additional_args = params.get("additional_args", "")

        if not memory_file:
            logger.warning("🧠 Volatility3 called without memory_file parameter")
            return jsonify({
                "error": "Memory file parameter is required"
            }), 400

        if not plugin:
            logger.warning("🧠 Volatility3 called without plugin parameter")
            return jsonify({
                "error": "Plugin parameter is required"
            }), 400

        command = f"vol.py -f {memory_file} {plugin}"

        if output_file:
            command += f" -o {output_file}"

        if additional_args:
            command += f" {additional_args}"

        logger.info(f"🧠 Starting Volatility3 analysis: {plugin}")
        result = execute_command(command)
        logger.info(f"📊 Volatility3 analysis completed")
        return jsonify(result)
    except Exception as e:
        logger.error(f"💥 Error in volatility3 endpoint: {str(e)}")
        return jsonify({
            "error": f"Server error: {str(e)}"
        }), 500

