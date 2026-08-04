"""HexStrike routes — misc (blueprint)."""

from hexstrike_lib.server.deps import *  # noqa: F401,F403

bp = Blueprint("misc", __name__)


@bp.route("/api/tools/foremost", methods=["POST"])
def foremost():
    """Execute Foremost for file carving with enhanced logging"""
    try:
        params = request.json
        input_file = params.get("input_file", "")
        output_dir = params.get("output_dir", "/tmp/foremost_output")
        file_types = params.get("file_types", "")
        additional_args = params.get("additional_args", "")

        if not input_file:
            logger.warning("📁 Foremost called without input_file parameter")
            return jsonify({
                "error": "Input file parameter is required"
            }), 400

        # Ensure output directory exists
        Path(output_dir).mkdir(parents=True, exist_ok=True)

        command = f"foremost -o {output_dir}"

        if file_types:
            command += f" -t {file_types}"

        if additional_args:
            command += f" {additional_args}"

        command += f" {input_file}"

        logger.info(f"📁 Starting Foremost file carving: {input_file}")
        result = execute_command(command)
        result["output_directory"] = output_dir
        logger.info(f"📊 Foremost carving completed")
        return jsonify(result)
    except Exception as e:
        logger.error(f"💥 Error in foremost endpoint: {str(e)}")
        return jsonify({
            "error": f"Server error: {str(e)}"
        }), 500

@bp.route("/api/tools/steghide", methods=["POST"])
def steghide():
    """Execute Steghide for steganography analysis with enhanced logging"""
    try:
        params = request.json
        action = params.get("action", "extract")  # extract, embed, info
        cover_file = params.get("cover_file", "")
        embed_file = params.get("embed_file", "")
        passphrase = params.get("passphrase", "")
        output_file = params.get("output_file", "")
        additional_args = params.get("additional_args", "")

        if not cover_file:
            logger.warning("🖼️ Steghide called without cover_file parameter")
            return jsonify({
                "error": "Cover file parameter is required"
            }), 400

        if action == "extract":
            command = f"steghide extract -sf {cover_file}"
            if output_file:
                command += f" -xf {output_file}"
        elif action == "embed":
            if not embed_file:
                return jsonify({"error": "Embed file required for embed action"}), 400
            command = f"steghide embed -cf {cover_file} -ef {embed_file}"
        elif action == "info":
            command = f"steghide info {cover_file}"
        else:
            return jsonify({"error": "Invalid action. Use: extract, embed, info"}), 400

        if passphrase:
            command += f" -p {passphrase}"
        else:
            command += " -p ''"  # Empty passphrase

        if additional_args:
            command += f" {additional_args}"

        logger.info(f"🖼️ Starting Steghide {action}: {cover_file}")
        result = execute_command(command)
        logger.info(f"📊 Steghide {action} completed")
        return jsonify(result)
    except Exception as e:
        logger.error(f"💥 Error in steghide endpoint: {str(e)}")
        return jsonify({
            "error": f"Server error: {str(e)}"
        }), 500

@bp.route("/api/tools/exiftool", methods=["POST"])
def exiftool():
    """Execute ExifTool for metadata extraction with enhanced logging"""
    try:
        params = request.json
        file_path = params.get("file_path", "")
        output_format = params.get("output_format", "")  # json, xml, csv
        tags = params.get("tags", "")
        additional_args = params.get("additional_args", "")

        if not file_path:
            logger.warning("📷 ExifTool called without file_path parameter")
            return jsonify({
                "error": "File path parameter is required"
            }), 400

        command = f"exiftool"

        if output_format:
            command += f" -{output_format}"

        if tags:
            command += f" -{tags}"

        if additional_args:
            command += f" {additional_args}"

        command += f" {file_path}"

        logger.info(f"📷 Starting ExifTool analysis: {file_path}")
        result = execute_command(command)
        logger.info(f"📊 ExifTool analysis completed")
        return jsonify(result)
    except Exception as e:
        logger.error(f"💥 Error in exiftool endpoint: {str(e)}")
        return jsonify({
            "error": f"Server error: {str(e)}"
        }), 500

@bp.route("/api/tools/hashpump", methods=["POST"])
def hashpump():
    """Execute HashPump for hash length extension attacks with enhanced logging"""
    try:
        params = request.json
        signature = params.get("signature", "")
        data = params.get("data", "")
        key_length = params.get("key_length", "")
        append_data = params.get("append_data", "")
        additional_args = params.get("additional_args", "")

        if not all([signature, data, key_length, append_data]):
            logger.warning("🔐 HashPump called without required parameters")
            return jsonify({
                "error": "Signature, data, key_length, and append_data parameters are required"
            }), 400

        command = f"hashpump -s {signature} -d '{data}' -k {key_length} -a '{append_data}'"

        if additional_args:
            command += f" {additional_args}"

        logger.info(f"🔐 Starting HashPump attack")
        result = execute_command(command)
        logger.info(f"📊 HashPump attack completed")
        return jsonify(result)
    except Exception as e:
        logger.error(f"💥 Error in hashpump endpoint: {str(e)}")
        return jsonify({
            "error": f"Server error: {str(e)}"
        }), 500

# ============================================================================
# BUG BOUNTY RECONNAISSANCE TOOLS (v5.0 ENHANCEMENT)
# ============================================================================

@bp.route("/api/tools/hakrawler", methods=["POST"])
def hakrawler():
    """
    Execute Hakrawler for web endpoint discovery with enhanced logging

    Note: This implementation uses the standard Kali Linux hakrawler (hakluke/hakrawler)
    command line arguments, NOT the Elsfa7-110 fork. The standard version uses:
    - echo URL | hakrawler (stdin input)
    - -d for depth (not -depth)
    - -s for showing sources (not -forms)
    - -u for unique URLs
    - -subs for subdomain inclusion
    """
    try:
        params = request.json
        url = params.get("url", "")
        depth = params.get("depth", 2)
        forms = params.get("forms", True)
        robots = params.get("robots", True)
        sitemap = params.get("sitemap", True)
        wayback = params.get("wayback", False)
        additional_args = params.get("additional_args", "")

        if not url:
            logger.warning("🕷️ Hakrawler called without URL parameter")
            return jsonify({
                "error": "URL parameter is required"
            }), 400

        # Build command for standard Kali Linux hakrawler (hakluke version)
        command = f"echo '{url}' | hakrawler -d {depth}"

        if forms:
            command += " -s"  # Show sources (includes forms)
        if robots or sitemap or wayback:
            command += " -subs"  # Include subdomains for better coverage

        # Add unique URLs flag for cleaner output
        command += " -u"

        if additional_args:
            command += f" {additional_args}"

        logger.info(f"🕷️ Starting Hakrawler crawling: {url}")
        result = execute_command(command)
        logger.info(f"📊 Hakrawler crawling completed")
        return jsonify(result)
    except Exception as e:
        logger.error(f"💥 Error in hakrawler endpoint: {str(e)}")
        return jsonify({
            "error": f"Server error: {str(e)}"
        }), 500

# ============================================================================
# ADVANCED VULNERABILITY INTELLIGENCE API ENDPOINTS (v6.0 ENHANCEMENT)
# ============================================================================

@bp.route("/api/vuln-intel/cve-monitor", methods=["POST"])
def cve_monitor():
    """Monitor CVE databases for new vulnerabilities with AI analysis"""
    try:
        params = request.json
        hours = params.get("hours", 24)
        severity_filter = params.get("severity_filter", "HIGH,CRITICAL")
        keywords = params.get("keywords", "")

        logger.info(f"🔍 Monitoring CVE feeds for last {hours} hours with severity filter: {severity_filter}")

        # Fetch latest CVEs
        cve_results = cve_intelligence.fetch_latest_cves(hours, severity_filter)

        # Filter by keywords if provided
        if keywords and cve_results.get("success"):
            keyword_list = [k.strip().lower() for k in keywords.split(",")]
            filtered_cves = []

            for cve in cve_results.get("cves", []):
                description = cve.get("description", "").lower()
                if any(keyword in description for keyword in keyword_list):
                    filtered_cves.append(cve)

            cve_results["cves"] = filtered_cves
            cve_results["filtered_by_keywords"] = keywords
            cve_results["total_after_filter"] = len(filtered_cves)

        # Analyze exploitability for top CVEs
        exploitability_analysis = []
        for cve in cve_results.get("cves", [])[:5]:  # Analyze top 5 CVEs
            cve_id = cve.get("cve_id", "")
            if cve_id:
                analysis = cve_intelligence.analyze_cve_exploitability(cve_id)
                if analysis.get("success"):
                    exploitability_analysis.append(analysis)

        result = {
            "success": True,
            "cve_monitoring": cve_results,
            "exploitability_analysis": exploitability_analysis,
            "timestamp": datetime.now().isoformat()
        }

        logger.info(f"📊 CVE monitoring completed | Found: {len(cve_results.get('cves', []))} CVEs")
        return jsonify(result)

    except Exception as e:
        logger.error(f"💥 Error in CVE monitoring: {str(e)}")
        return jsonify({
            "success": False,
            "error": f"Server error: {str(e)}"
        }), 500

@bp.route("/api/vuln-intel/exploit-generate", methods=["POST"])
def exploit_generate():
    """Generate exploits from vulnerability data using AI"""
    try:
        params = request.json
        cve_id = params.get("cve_id", "")
        target_os = params.get("target_os", "")
        target_arch = params.get("target_arch", "x64")
        exploit_type = params.get("exploit_type", "poc")
        evasion_level = params.get("evasion_level", "none")

        # Additional target context
        target_info = {
            "target_os": target_os,
            "target_arch": target_arch,
            "exploit_type": exploit_type,
            "evasion_level": evasion_level,
            "target_ip": params.get("target_ip", "192.168.1.100"),
            "target_port": params.get("target_port", 80),
            "description": params.get("target_description", f"Target for {cve_id}")
        }

        if not cve_id:
            logger.warning("🤖 Exploit generation called without CVE ID")
            return jsonify({
                "success": False,
                "error": "CVE ID parameter is required"
            }), 400

        logger.info(f"🤖 Generating exploit for {cve_id} | Target: {target_os} {target_arch}")

        # First analyze the CVE for context
        cve_analysis = cve_intelligence.analyze_cve_exploitability(cve_id)

        if not cve_analysis.get("success"):
            return jsonify({
                "success": False,
                "error": f"Failed to analyze CVE {cve_id}: {cve_analysis.get('error', 'Unknown error')}"
            }), 400

        # Prepare CVE data for exploit generation
        cve_data = {
            "cve_id": cve_id,
            "description": f"Vulnerability analysis for {cve_id}",
            "exploitability_level": cve_analysis.get("exploitability_level", "UNKNOWN"),
            "exploitability_score": cve_analysis.get("exploitability_score", 0)
        }

        # Generate exploit
        exploit_result = exploit_generator.generate_exploit_from_cve(cve_data, target_info)

        # Search for existing exploits for reference
        existing_exploits = cve_intelligence.search_existing_exploits(cve_id)

        result = {
            "success": True,
            "cve_analysis": cve_analysis,
            "exploit_generation": exploit_result,
            "existing_exploits": existing_exploits,
            "target_info": target_info,
            "timestamp": datetime.now().isoformat()
        }

        logger.info(f"🎯 Exploit generation completed for {cve_id}")
        return jsonify(result)

    except Exception as e:
        logger.error(f"💥 Error in exploit generation: {str(e)}")
        return jsonify({
            "success": False,
            "error": f"Server error: {str(e)}"
        }), 500

@bp.route("/api/vuln-intel/attack-chains", methods=["POST"])
def discover_attack_chains():
    """Discover multi-stage attack possibilities"""
    try:
        params = request.json
        target_software = params.get("target_software", "")
        attack_depth = params.get("attack_depth", 3)
        include_zero_days = params.get("include_zero_days", False)

        if not target_software:
            logger.warning("🔗 Attack chain discovery called without target software")
            return jsonify({
                "success": False,
                "error": "Target software parameter is required"
            }), 400

        logger.info(f"🔗 Discovering attack chains for {target_software} | Depth: {attack_depth}")

        # Discover attack chains
        chain_results = vulnerability_correlator.find_attack_chains(target_software, attack_depth)

        # Enhance with exploit generation for viable chains
        if chain_results.get("success") and chain_results.get("attack_chains"):
            enhanced_chains = []

            for chain in chain_results["attack_chains"][:2]:  # Enhance top 2 chains
                enhanced_chain = chain.copy()
                enhanced_stages = []

                for stage in chain["stages"]:
                    enhanced_stage = stage.copy()

                    # Try to generate exploit for this stage
                    vuln = stage.get("vulnerability", {})
                    cve_id = vuln.get("cve_id", "")

                    if cve_id:
                        try:
                            cve_data = {"cve_id": cve_id, "description": vuln.get("description", "")}
                            target_info = {"target_os": "linux", "target_arch": "x64", "evasion_level": "basic"}

                            exploit_result = exploit_generator.generate_exploit_from_cve(cve_data, target_info)
                            enhanced_stage["exploit_available"] = exploit_result.get("success", False)

                            if exploit_result.get("success"):
                                enhanced_stage["exploit_code"] = exploit_result.get("exploit_code", "")[:500] + "..."
                        except:
                            enhanced_stage["exploit_available"] = False

                    enhanced_stages.append(enhanced_stage)

                enhanced_chain["stages"] = enhanced_stages
                enhanced_chains.append(enhanced_chain)

            chain_results["enhanced_chains"] = enhanced_chains

        result = {
            "success": True,
            "attack_chain_discovery": chain_results,
            "parameters": {
                "target_software": target_software,
                "attack_depth": attack_depth,
                "include_zero_days": include_zero_days
            },
            "timestamp": datetime.now().isoformat()
        }

        logger.info(f"🎯 Attack chain discovery completed | Found: {len(chain_results.get('attack_chains', []))} chains")
        return jsonify(result)

    except Exception as e:
        logger.error(f"💥 Error in attack chain discovery: {str(e)}")
        return jsonify({
            "success": False,
            "error": f"Server error: {str(e)}"
        }), 500

@bp.route("/api/vuln-intel/threat-feeds", methods=["POST"])
def threat_intelligence_feeds():
    """Aggregate and correlate threat intelligence from multiple sources"""
    try:
        params = request.json
        indicators = params.get("indicators", [])
        timeframe = params.get("timeframe", "30d")
        sources = params.get("sources", "all")

        if isinstance(indicators, str):
            indicators = [i.strip() for i in indicators.split(",")]

        if not indicators:
            logger.warning("🧠 Threat intelligence called without indicators")
            return jsonify({
                "success": False,
                "error": "Indicators parameter is required"
            }), 400

        logger.info(f"🧠 Correlating threat intelligence for {len(indicators)} indicators")

        correlation_results = {
            "indicators_analyzed": indicators,
            "timeframe": timeframe,
            "sources": sources,
            "correlations": [],
            "threat_score": 0,
            "recommendations": []
        }

        # Analyze each indicator
        cve_indicators = [i for i in indicators if i.startswith("CVE-")]
        ip_indicators = [i for i in indicators if i.replace(".", "").isdigit()]
        hash_indicators = [i for i in indicators if len(i) in [32, 40, 64] and all(c in "0123456789abcdef" for c in i.lower())]

        # Process CVE indicators
        for cve_id in cve_indicators:
            try:
                cve_analysis = cve_intelligence.analyze_cve_exploitability(cve_id)
                if cve_analysis.get("success"):
                    correlation_results["correlations"].append({
                        "indicator": cve_id,
                        "type": "cve",
                        "analysis": cve_analysis,
                        "threat_level": cve_analysis.get("exploitability_level", "UNKNOWN")
                    })

                    # Add to threat score
                    exploit_score = cve_analysis.get("exploitability_score", 0)
                    correlation_results["threat_score"] += min(exploit_score, 100)

                # Search for existing exploits
                exploits = cve_intelligence.search_existing_exploits(cve_id)
                if exploits.get("success") and exploits.get("total_exploits", 0) > 0:
                    correlation_results["correlations"].append({
                        "indicator": cve_id,
                        "type": "exploit_availability",
                        "exploits_found": exploits.get("total_exploits", 0),
                        "threat_level": "HIGH"
                    })
                    correlation_results["threat_score"] += 25

            except Exception as e:
                logger.warning(f"Error analyzing CVE {cve_id}: {str(e)}")

        # Process IP indicators (basic reputation check simulation)
        for ip in ip_indicators:
            # Simulate threat intelligence lookup
            correlation_results["correlations"].append({
                "indicator": ip,
                "type": "ip_reputation",
                "analysis": {
                    "reputation": "unknown",
                    "geolocation": "unknown",
                    "associated_threats": []
                },
                "threat_level": "MEDIUM"  # Default for unknown IPs
            })

        # Process hash indicators
        for hash_val in hash_indicators:
            correlation_results["correlations"].append({
                "indicator": hash_val,
                "type": "file_hash",
                "analysis": {
                    "hash_type": f"hash{len(hash_val)}",
                    "malware_family": "unknown",
                    "detection_rate": "unknown"
                },
                "threat_level": "MEDIUM"
            })

        # Calculate overall threat score and generate recommendations
        total_indicators = len(indicators)
        if total_indicators > 0:
            correlation_results["threat_score"] = min(correlation_results["threat_score"] / total_indicators, 100)

            if correlation_results["threat_score"] >= 75:
                correlation_results["recommendations"] = [
                    "Immediate threat response required",
                    "Block identified indicators",
                    "Enhance monitoring for related IOCs",
                    "Implement emergency patches for identified CVEs"
                ]
            elif correlation_results["threat_score"] >= 50:
                correlation_results["recommendations"] = [
                    "Elevated threat level detected",
                    "Increase monitoring for identified indicators",
                    "Plan patching for identified vulnerabilities",
                    "Review security controls"
                ]
            else:
                correlation_results["recommendations"] = [
                    "Low to medium threat level",
                    "Continue standard monitoring",
                    "Plan routine patching",
                    "Consider additional threat intelligence sources"
                ]

        result = {
            "success": True,
            "threat_intelligence": correlation_results,
            "timestamp": datetime.now().isoformat()
        }

        logger.info(f"🎯 Threat intelligence correlation completed | Threat Score: {correlation_results['threat_score']:.1f}")
        return jsonify(result)

    except Exception as e:
        logger.error(f"💥 Error in threat intelligence: {str(e)}")
        return jsonify({
            "success": False,
            "error": f"Server error: {str(e)}"
        }), 500

@bp.route("/api/vuln-intel/zero-day-research", methods=["POST"])
def zero_day_research():
    """Automated zero-day vulnerability research using AI analysis"""
    try:
        params = request.json
        target_software = params.get("target_software", "")
        analysis_depth = params.get("analysis_depth", "standard")
        source_code_url = params.get("source_code_url", "")

        if not target_software:
            logger.warning("🔬 Zero-day research called without target software")
            return jsonify({
                "success": False,
                "error": "Target software parameter is required"
            }), 400

        logger.info(f"🔬 Starting zero-day research for {target_software} | Depth: {analysis_depth}")

        research_results = {
            "target_software": target_software,
            "analysis_depth": analysis_depth,
            "research_areas": [],
            "potential_vulnerabilities": [],
            "risk_assessment": {},
            "recommendations": []
        }

        # Define research areas based on software type
        common_research_areas = [
            "Input validation vulnerabilities",
            "Memory corruption issues",
            "Authentication bypasses",
            "Authorization flaws",
            "Cryptographic weaknesses",
            "Race conditions",
            "Logic flaws"
        ]

        # Software-specific research areas
        web_research_areas = [
            "Cross-site scripting (XSS)",
            "SQL injection",
            "Server-side request forgery (SSRF)",
            "Insecure deserialization",
            "Template injection"
        ]

        system_research_areas = [
            "Buffer overflows",
            "Privilege escalation",
            "Kernel vulnerabilities",
            "Service exploitation",
            "Configuration weaknesses"
        ]

        # Determine research areas based on target
        target_lower = target_software.lower()
        if any(web_tech in target_lower for web_tech in ["apache", "nginx", "tomcat", "php", "node", "django"]):
            research_results["research_areas"] = common_research_areas + web_research_areas
        elif any(sys_tech in target_lower for sys_tech in ["windows", "linux", "kernel", "driver"]):
            research_results["research_areas"] = common_research_areas + system_research_areas
        else:
            research_results["research_areas"] = common_research_areas

        # Simulate vulnerability discovery based on analysis depth
        vuln_count = {"quick": 2, "standard": 4, "comprehensive": 6}.get(analysis_depth, 4)

        for i in range(vuln_count):
            potential_vuln = {
                "id": f"RESEARCH-{target_software.upper()}-{i+1:03d}",
                "category": research_results["research_areas"][i % len(research_results["research_areas"])],
                "severity": ["LOW", "MEDIUM", "HIGH", "CRITICAL"][i % 4],
                "confidence": ["LOW", "MEDIUM", "HIGH"][i % 3],
                "description": f"Potential {research_results['research_areas'][i % len(research_results['research_areas'])].lower()} in {target_software}",
                "attack_vector": "To be determined through further analysis",
                "impact": "To be assessed",
                "proof_of_concept": "Research phase - PoC development needed"
            }
            research_results["potential_vulnerabilities"].append(potential_vuln)

        # Risk assessment
        high_risk_count = sum(1 for v in research_results["potential_vulnerabilities"] if v["severity"] in ["HIGH", "CRITICAL"])
        total_vulns = len(research_results["potential_vulnerabilities"])

        research_results["risk_assessment"] = {
            "total_areas_analyzed": len(research_results["research_areas"]),
            "potential_vulnerabilities_found": total_vulns,
            "high_risk_findings": high_risk_count,
            "risk_score": min((high_risk_count * 25 + (total_vulns - high_risk_count) * 10), 100),
            "research_confidence": analysis_depth
        }

        # Generate recommendations
        if high_risk_count > 0:
            research_results["recommendations"] = [
                "Prioritize security testing in identified high-risk areas",
                "Conduct focused penetration testing",
                "Implement additional security controls",
                "Consider bug bounty program for target software",
                "Perform code review in identified areas"
            ]
        else:
            research_results["recommendations"] = [
                "Continue standard security testing",
                "Monitor for new vulnerability research",
                "Implement defense-in-depth strategies",
                "Regular security assessments recommended"
            ]

        # Source code analysis simulation
        if source_code_url:
            research_results["source_code_analysis"] = {
                "repository_url": source_code_url,
                "analysis_status": "simulated",
                "findings": [
                    "Static analysis patterns identified",
                    "Potential code quality issues detected",
                    "Security-relevant functions located"
                ],
                "recommendation": "Manual code review recommended for identified areas"
            }

        result = {
            "success": True,
            "zero_day_research": research_results,
            "disclaimer": "This is simulated research for demonstration. Real zero-day research requires extensive manual analysis.",
            "timestamp": datetime.now().isoformat()
        }

        logger.info(f"🎯 Zero-day research completed | Risk Score: {research_results['risk_assessment']['risk_score']}")
        return jsonify(result)

    except Exception as e:
        logger.error(f"💥 Error in zero-day research: {str(e)}")
        return jsonify({
            "success": False,
            "error": f"Server error: {str(e)}"
        }), 500

@bp.route("/api/ai/advanced-payload-generation", methods=["POST"])
def advanced_payload_generation():
    """Generate advanced payloads with AI-powered evasion techniques"""
    try:
        params = request.json
        attack_type = params.get("attack_type", "rce")
        target_context = params.get("target_context", "")
        evasion_level = params.get("evasion_level", "standard")
        custom_constraints = params.get("custom_constraints", "")

        if not attack_type:
            logger.warning("🎯 Advanced payload generation called without attack type")
            return jsonify({
                "success": False,
                "error": "Attack type parameter is required"
            }), 400

        logger.info(f"🎯 Generating advanced {attack_type} payload with {evasion_level} evasion")

        # Enhanced payload generation with contextual AI
        target_info = {
            "attack_type": attack_type,
            "complexity": "advanced",
            "technology": target_context,
            "evasion_level": evasion_level,
            "constraints": custom_constraints
        }

        # Generate base payloads using existing AI system
        base_result = ai_payload_generator.generate_contextual_payload(target_info)

        # Enhance with advanced techniques
        advanced_payloads = []

        for payload_info in base_result.get("payloads", [])[:10]:  # Limit to 10 advanced payloads
            enhanced_payload = {
                "payload": payload_info["payload"],
                "original_context": payload_info["context"],
                "risk_level": payload_info["risk_level"],
                "evasion_techniques": [],
                "deployment_methods": []
            }

            # Apply evasion techniques based on level
            if evasion_level in ["advanced", "nation-state"]:
                # Advanced encoding techniques
                encoded_variants = [
                    {
                        "technique": "Double URL Encoding",
                        "payload": payload_info["payload"].replace("%", "%25").replace(" ", "%2520")
                    },
                    {
                        "technique": "Unicode Normalization",
                        "payload": payload_info["payload"].replace("script", "scr\u0131pt")
                    },
                    {
                        "technique": "Case Variation",
                        "payload": "".join(c.upper() if i % 2 else c.lower() for i, c in enumerate(payload_info["payload"]))
                    }
                ]
                enhanced_payload["evasion_techniques"].extend(encoded_variants)

            if evasion_level == "nation-state":
                # Nation-state level techniques
                advanced_techniques = [
                    {
                        "technique": "Polyglot Payload",
                        "payload": f"/*{payload_info['payload']}*/ OR {payload_info['payload']}"
                    },
                    {
                        "technique": "Time-delayed Execution",
                        "payload": f"setTimeout(function(){{{payload_info['payload']}}}, 1000)"
                    },
                    {
                        "technique": "Environmental Keying",
                        "payload": f"if(navigator.userAgent.includes('specific')){{ {payload_info['payload']} }}"
                    }
                ]
                enhanced_payload["evasion_techniques"].extend(advanced_techniques)

            # Deployment methods
            enhanced_payload["deployment_methods"] = [
                "Direct injection",
                "Parameter pollution",
                "Header injection",
                "Cookie manipulation",
                "Fragment-based delivery"
            ]

            advanced_payloads.append(enhanced_payload)

        # Generate deployment instructions
        deployment_guide = {
            "pre_deployment": [
                "Reconnaissance of target environment",
                "Identification of input validation mechanisms",
                "Analysis of security controls (WAF, IDS, etc.)",
                "Selection of appropriate evasion techniques"
            ],
            "deployment": [
                "Start with least detectable payloads",
                "Monitor for defensive responses",
                "Escalate evasion techniques as needed",
                "Document successful techniques for future use"
            ],
            "post_deployment": [
                "Monitor for payload execution",
                "Clean up traces if necessary",
                "Document findings",
                "Report vulnerabilities responsibly"
            ]
        }

        result = {
            "success": True,
            "advanced_payload_generation": {
                "attack_type": attack_type,
                "evasion_level": evasion_level,
                "target_context": target_context,
                "payload_count": len(advanced_payloads),
                "advanced_payloads": advanced_payloads,
                "deployment_guide": deployment_guide,
                "custom_constraints_applied": custom_constraints if custom_constraints else "none"
            },
            "disclaimer": "These payloads are for authorized security testing only. Ensure proper authorization before use.",
            "timestamp": datetime.now().isoformat()
        }

        logger.info(f"🎯 Advanced payload generation completed | Generated: {len(advanced_payloads)} payloads")
        return jsonify(result)

    except Exception as e:
        logger.error(f"💥 Error in advanced payload generation: {str(e)}")
        return jsonify({
            "success": False,
            "error": f"Server error: {str(e)}"
        }), 500

# ============================================================================
# CTF COMPETITION EXCELLENCE FRAMEWORK API ENDPOINTS (v8.0 ENHANCEMENT)
# ============================================================================

@bp.route("/api/ctf/create-challenge-workflow", methods=["POST"])
def create_ctf_challenge_workflow():
    """Create specialized workflow for CTF challenge"""
    try:
        params = request.json
        challenge_name = params.get("name", "")
        category = params.get("category", "misc")
        difficulty = params.get("difficulty", "unknown")
        points = params.get("points", 100)
        description = params.get("description", "")
        target = params.get("target", "")

        if not challenge_name:
            return jsonify({"error": "Challenge name is required"}), 400

        # Create CTF challenge object
        challenge = CTFChallenge(
            name=challenge_name,
            category=category,
            difficulty=difficulty,
            points=points,
            description=description,
            target=target
        )

        # Generate workflow
        workflow = ctf_manager.create_ctf_challenge_workflow(challenge)

        logger.info(f"🎯 CTF workflow created for {challenge_name} | Category: {category} | Difficulty: {difficulty}")
        return jsonify({
            "success": True,
            "workflow": workflow,
            "challenge": challenge.to_dict(),
            "timestamp": datetime.now().isoformat()
        })

    except Exception as e:
        logger.error(f"💥 Error creating CTF workflow: {str(e)}")
        return jsonify({"error": f"Server error: {str(e)}"}), 500

@bp.route("/api/ctf/auto-solve-challenge", methods=["POST"])
def auto_solve_ctf_challenge():
    """Attempt to automatically solve a CTF challenge"""
    try:
        params = request.json
        challenge_name = params.get("name", "")
        category = params.get("category", "misc")
        difficulty = params.get("difficulty", "unknown")
        points = params.get("points", 100)
        description = params.get("description", "")
        target = params.get("target", "")

        if not challenge_name:
            return jsonify({"error": "Challenge name is required"}), 400

        # Create CTF challenge object
        challenge = CTFChallenge(
            name=challenge_name,
            category=category,
            difficulty=difficulty,
            points=points,
            description=description,
            target=target
        )

        # Attempt automated solving
        result = ctf_automator.auto_solve_challenge(challenge)

        logger.info(f"🤖 CTF auto-solve attempted for {challenge_name} | Status: {result['status']}")
        return jsonify({
            "success": True,
            "solve_result": result,
            "challenge": challenge.to_dict(),
            "timestamp": datetime.now().isoformat()
        })

    except Exception as e:
        logger.error(f"💥 Error in CTF auto-solve: {str(e)}")
        return jsonify({"error": f"Server error: {str(e)}"}), 500

@bp.route("/api/ctf/team-strategy", methods=["POST"])
def create_ctf_team_strategy():
    """Create optimal team strategy for CTF competition"""
    try:
        params = request.json
        challenges_data = params.get("challenges", [])
        team_skills = params.get("team_skills", {})

        if not challenges_data:
            return jsonify({"error": "Challenges data is required"}), 400

        # Convert challenge data to CTFChallenge objects
        challenges = []
        for challenge_data in challenges_data:
            challenge = CTFChallenge(
                name=challenge_data.get("name", ""),
                category=challenge_data.get("category", "misc"),
                difficulty=challenge_data.get("difficulty", "unknown"),
                points=challenge_data.get("points", 100),
                description=challenge_data.get("description", ""),
                target=challenge_data.get("target", "")
            )
            challenges.append(challenge)

        # Generate team strategy
        strategy = ctf_coordinator.optimize_team_strategy(challenges, team_skills)

        logger.info(f"👥 CTF team strategy created | Challenges: {len(challenges)} | Team members: {len(team_skills)}")
        return jsonify({
            "success": True,
            "strategy": strategy,
            "challenges_count": len(challenges),
            "team_size": len(team_skills),
            "timestamp": datetime.now().isoformat()
        })

    except Exception as e:
        logger.error(f"💥 Error creating CTF team strategy: {str(e)}")
        return jsonify({"error": f"Server error: {str(e)}"}), 500

@bp.route("/api/ctf/suggest-tools", methods=["POST"])
def suggest_ctf_tools():
    """Suggest optimal tools for CTF challenge based on description and category"""
    try:
        params = request.json
        description = params.get("description", "")
        category = params.get("category", "misc")

        if not description:
            return jsonify({"error": "Challenge description is required"}), 400

        # Get tool suggestions
        suggested_tools = ctf_tools.suggest_tools_for_challenge(description, category)
        category_tools = ctf_tools.get_category_tools(f"{category}_recon")

        # Get tool commands
        tool_commands = {}
        for tool in suggested_tools:
            try:
                tool_commands[tool] = ctf_tools.get_tool_command(tool, "TARGET")
            except:
                tool_commands[tool] = f"{tool} TARGET"

        logger.info(f"🔧 CTF tools suggested | Category: {category} | Tools: {len(suggested_tools)}")
        return jsonify({
            "success": True,
            "suggested_tools": suggested_tools,
            "category_tools": category_tools,
            "tool_commands": tool_commands,
            "category": category,
            "timestamp": datetime.now().isoformat()
        })

    except Exception as e:
        logger.error(f"💥 Error suggesting CTF tools: {str(e)}")
        return jsonify({"error": f"Server error: {str(e)}"}), 500

@bp.route("/api/ctf/cryptography-solver", methods=["POST"])
def ctf_cryptography_solver():
    """Advanced cryptography challenge solver with multiple attack methods"""
    try:
        params = request.json
        cipher_text = params.get("cipher_text", "")
        cipher_type = params.get("cipher_type", "unknown")
        key_hint = params.get("key_hint", "")
        known_plaintext = params.get("known_plaintext", "")
        additional_info = params.get("additional_info", "")

        if not cipher_text:
            return jsonify({"error": "Cipher text is required"}), 400

        results = {
            "cipher_text": cipher_text,
            "cipher_type": cipher_type,
            "analysis_results": [],
            "potential_solutions": [],
            "recommended_tools": [],
            "next_steps": []
        }

        # Cipher type identification
        if cipher_type == "unknown":
            # Basic cipher identification heuristics
            if re.match(r'^[0-9a-fA-F]+$', cipher_text.replace(' ', '')):
                results["analysis_results"].append("Possible hexadecimal encoding")
                results["recommended_tools"].extend(["hex", "xxd"])

            if re.match(r'^[A-Za-z0-9+/]+=*$', cipher_text.replace(' ', '')):
                results["analysis_results"].append("Possible Base64 encoding")
                results["recommended_tools"].append("base64")

            if len(set(cipher_text.upper().replace(' ', ''))) <= 26:
                results["analysis_results"].append("Possible substitution cipher")
                results["recommended_tools"].extend(["frequency-analysis", "substitution-solver"])

        # Hash identification
        hash_patterns = {
            32: "MD5",
            40: "SHA1",
            64: "SHA256",
            128: "SHA512"
        }

        clean_text = cipher_text.replace(' ', '').replace('\n', '')
        if len(clean_text) in hash_patterns and re.match(r'^[0-9a-fA-F]+$', clean_text):
            hash_type = hash_patterns[len(clean_text)]
            results["analysis_results"].append(f"Possible {hash_type} hash")
            results["recommended_tools"].extend(["hashcat", "john", "hash-identifier"])

        # Frequency analysis for substitution ciphers
        if cipher_type in ["substitution", "caesar", "vigenere"] or "substitution" in results["analysis_results"]:
            char_freq = {}
            for char in cipher_text.upper():
                if char.isalpha():
                    char_freq[char] = char_freq.get(char, 0) + 1

            if char_freq:
                most_common = max(char_freq, key=char_freq.get)
                results["analysis_results"].append(f"Most frequent character: {most_common} ({char_freq[most_common]} occurrences)")
                results["next_steps"].append("Try substituting most frequent character with 'E'")

        # ROT/Caesar cipher detection
        if cipher_type == "caesar" or len(set(cipher_text.upper().replace(' ', ''))) <= 26:
            results["recommended_tools"].append("rot13")
            results["next_steps"].append("Try all ROT values (1-25)")

        # RSA-specific analysis
        if cipher_type == "rsa" or "rsa" in additional_info.lower():
            results["recommended_tools"].extend(["rsatool", "factordb", "yafu"])
            results["next_steps"].extend([
                "Check if modulus can be factored",
                "Look for small public exponent attacks",
                "Check for common modulus attacks"
            ])

        # Vigenère cipher analysis
        if cipher_type == "vigenere" or "vigenere" in additional_info.lower():
            results["recommended_tools"].append("vigenere-solver")
            results["next_steps"].extend([
                "Perform Kasiski examination for key length",
                "Use index of coincidence analysis",
                "Try common key words"
            ])

        logger.info(f"🔐 CTF crypto analysis completed | Type: {cipher_type} | Tools: {len(results['recommended_tools'])}")
        return jsonify({
            "success": True,
            "analysis": results,
            "timestamp": datetime.now().isoformat()
        })

    except Exception as e:
        logger.error(f"💥 Error in CTF crypto solver: {str(e)}")
        return jsonify({"error": f"Server error: {str(e)}"}), 500

@bp.route("/api/ctf/forensics-analyzer", methods=["POST"])
def ctf_forensics_analyzer():
    """Advanced forensics challenge analyzer with multiple investigation techniques"""
    try:
        params = request.json
        file_path = params.get("file_path", "")
        analysis_type = params.get("analysis_type", "comprehensive")
        extract_hidden = params.get("extract_hidden", True)
        check_steganography = params.get("check_steganography", True)

        if not file_path:
            return jsonify({"error": "File path is required"}), 400

        results = {
            "file_path": file_path,
            "analysis_type": analysis_type,
            "file_info": {},
            "metadata": {},
            "hidden_data": [],
            "steganography_results": [],
            "recommended_tools": [],
            "next_steps": []
        }

        # Basic file analysis
        try:
            # File command
            file_result = subprocess.run(['file', file_path], capture_output=True, text=True, timeout=30)
            if file_result.returncode == 0:
                results["file_info"]["type"] = file_result.stdout.strip()

                # Determine file category and suggest tools
                file_type = file_result.stdout.lower()
                if "image" in file_type:
                    results["recommended_tools"].extend(["exiftool", "steghide", "stegsolve", "zsteg"])
                    results["next_steps"].extend([
                        "Extract EXIF metadata",
                        "Check for steganographic content",
                        "Analyze color channels separately"
                    ])
                elif "audio" in file_type:
                    results["recommended_tools"].extend(["audacity", "sonic-visualizer", "spectrum-analyzer"])
                    results["next_steps"].extend([
                        "Analyze audio spectrum",
                        "Check for hidden data in audio channels",
                        "Look for DTMF tones or morse code"
                    ])
                elif "pdf" in file_type:
                    results["recommended_tools"].extend(["pdfinfo", "pdftotext", "binwalk"])
                    results["next_steps"].extend([
                        "Extract text and metadata",
                        "Check for embedded files",
                        "Analyze PDF structure"
                    ])
                elif "zip" in file_type or "archive" in file_type:
                    results["recommended_tools"].extend(["unzip", "7zip", "binwalk"])
                    results["next_steps"].extend([
                        "Extract archive contents",
                        "Check for password protection",
                        "Look for hidden files"
                    ])
        except Exception as e:
            results["file_info"]["error"] = str(e)

        # Metadata extraction
        try:
            exif_result = subprocess.run(['exiftool', file_path], capture_output=True, text=True, timeout=30)
            if exif_result.returncode == 0:
                results["metadata"]["exif"] = exif_result.stdout
        except Exception as e:
            results["metadata"]["exif_error"] = str(e)

        # Binwalk analysis for hidden files
        if extract_hidden:
            try:
                binwalk_result = subprocess.run(['binwalk', '-e', file_path], capture_output=True, text=True, timeout=60)
                if binwalk_result.returncode == 0:
                    results["hidden_data"].append({
                        "tool": "binwalk",
                        "output": binwalk_result.stdout
                    })
            except Exception as e:
                results["hidden_data"].append({
                    "tool": "binwalk",
                    "error": str(e)
                })

        # Steganography checks
        if check_steganography:
            # Check for common steganography tools
            steg_tools = ["steghide", "zsteg", "outguess"]
            for tool in steg_tools:
                try:
                    if tool == "steghide":
                        steg_result = subprocess.run([tool, 'info', file_path], capture_output=True, text=True, timeout=30)
                    elif tool == "zsteg":
                        steg_result = subprocess.run([tool, '-a', file_path], capture_output=True, text=True, timeout=30)
                    elif tool == "outguess":
                        steg_result = subprocess.run([tool, '-r', file_path, '/tmp/outguess_output'], capture_output=True, text=True, timeout=30)

                    if steg_result.returncode == 0 and steg_result.stdout.strip():
                        results["steganography_results"].append({
                            "tool": tool,
                            "output": steg_result.stdout
                        })
                except Exception as e:
                    results["steganography_results"].append({
                        "tool": tool,
                        "error": str(e)
                    })

        # Strings analysis
        try:
            strings_result = subprocess.run(['strings', file_path], capture_output=True, text=True, timeout=30)
            if strings_result.returncode == 0:
                # Look for interesting strings (flags, URLs, etc.)
                interesting_strings = []
                for line in strings_result.stdout.split('\n'):
                    if any(keyword in line.lower() for keyword in ['flag', 'password', 'key', 'secret', 'http', 'ftp']):
                        interesting_strings.append(line.strip())

                if interesting_strings:
                    results["hidden_data"].append({
                        "tool": "strings",
                        "interesting_strings": interesting_strings[:20]  # Limit to first 20
                    })
        except Exception as e:
            results["hidden_data"].append({
                "tool": "strings",
                "error": str(e)
            })

        logger.info(f"🔍 CTF forensics analysis completed | File: {file_path} | Tools used: {len(results['recommended_tools'])}")
        return jsonify({
            "success": True,
            "analysis": results,
            "timestamp": datetime.now().isoformat()
        })

    except Exception as e:
        logger.error(f"💥 Error in CTF forensics analyzer: {str(e)}")
        return jsonify({"error": f"Server error: {str(e)}"}), 500

@bp.route("/api/ctf/binary-analyzer", methods=["POST"])
def ctf_binary_analyzer():
    """Advanced binary analysis for reverse engineering and pwn challenges"""
    try:
        params = request.json
        binary_path = params.get("binary_path", "")
        analysis_depth = params.get("analysis_depth", "comprehensive")  # basic, comprehensive, deep
        check_protections = params.get("check_protections", True)
        find_gadgets = params.get("find_gadgets", True)

        if not binary_path:
            return jsonify({"error": "Binary path is required"}), 400

        results = {
            "binary_path": binary_path,
            "analysis_depth": analysis_depth,
            "file_info": {},
            "security_protections": {},
            "interesting_functions": [],
            "strings_analysis": {},
            "gadgets": [],
            "recommended_tools": [],
            "exploitation_hints": []
        }

        # Basic file information
        try:
            file_result = subprocess.run(['file', binary_path], capture_output=True, text=True, timeout=30)
            if file_result.returncode == 0:
                results["file_info"]["type"] = file_result.stdout.strip()

                # Determine architecture and suggest tools
                file_output = file_result.stdout.lower()
                if "x86-64" in file_output or "x86_64" in file_output:
                    results["file_info"]["architecture"] = "x86_64"
                elif "i386" in file_output or "80386" in file_output:
                    results["file_info"]["architecture"] = "i386"
                elif "arm" in file_output:
                    results["file_info"]["architecture"] = "ARM"

                results["recommended_tools"].extend(["gdb-peda", "radare2", "ghidra"])
        except Exception as e:
            results["file_info"]["error"] = str(e)

        # Security protections check
        if check_protections:
            try:
                checksec_result = subprocess.run(['checksec', '--file', binary_path], capture_output=True, text=True, timeout=30)
                if checksec_result.returncode == 0:
                    results["security_protections"]["checksec"] = checksec_result.stdout

                    # Parse protections and provide exploitation hints
                    output = checksec_result.stdout.lower()
                    if "no canary found" in output:
                        results["exploitation_hints"].append("Stack canary disabled - buffer overflow exploitation possible")
                    if "nx disabled" in output:
                        results["exploitation_hints"].append("NX disabled - shellcode execution on stack possible")
                    if "no pie" in output:
                        results["exploitation_hints"].append("PIE disabled - fixed addresses, ROP/ret2libc easier")
                    if "no relro" in output:
                        results["exploitation_hints"].append("RELRO disabled - GOT overwrite attacks possible")
            except Exception as e:
                results["security_protections"]["error"] = str(e)

        # Strings analysis
        try:
            strings_result = subprocess.run(['strings', binary_path], capture_output=True, text=True, timeout=30)
            if strings_result.returncode == 0:
                strings_output = strings_result.stdout.split('\n')

                # Categorize interesting strings
                interesting_categories = {
                    "functions": [],
                    "format_strings": [],
                    "file_paths": [],
                    "potential_flags": [],
                    "system_calls": []
                }

                for string in strings_output:
                    string = string.strip()
                    if not string:
                        continue

                    # Look for function names
                    if any(func in string for func in ['printf', 'scanf', 'gets', 'strcpy', 'system', 'execve']):
                        interesting_categories["functions"].append(string)

                    # Look for format strings
                    if '%' in string and any(fmt in string for fmt in ['%s', '%d', '%x', '%n']):
                        interesting_categories["format_strings"].append(string)

                    # Look for file paths
                    if string.startswith('/') or '\\' in string:
                        interesting_categories["file_paths"].append(string)

                    # Look for potential flags
                    if any(keyword in string.lower() for keyword in ['flag', 'ctf', 'key', 'password']):
                        interesting_categories["potential_flags"].append(string)

                    # Look for system calls
                    if string in ['sh', 'bash', '/bin/sh', '/bin/bash', 'cmd.exe']:
                        interesting_categories["system_calls"].append(string)

                results["strings_analysis"] = interesting_categories

                # Add exploitation hints based on strings
                if interesting_categories["functions"]:
                    dangerous_funcs = ['gets', 'strcpy', 'sprintf', 'scanf']
                    found_dangerous = [f for f in dangerous_funcs if any(f in s for s in interesting_categories["functions"])]
                    if found_dangerous:
                        results["exploitation_hints"].append(f"Dangerous functions found: {', '.join(found_dangerous)} - potential buffer overflow")

                if interesting_categories["format_strings"]:
                    if any('%n' in s for s in interesting_categories["format_strings"]):
                        results["exploitation_hints"].append("Format string with %n found - potential format string vulnerability")

        except Exception as e:
            results["strings_analysis"]["error"] = str(e)

        # ROP gadgets search
        if find_gadgets and analysis_depth in ["comprehensive", "deep"]:
            try:
                ropgadget_result = subprocess.run(['ROPgadget', '--binary', binary_path, '--only', 'pop|ret'], capture_output=True, text=True, timeout=60)
                if ropgadget_result.returncode == 0:
                    gadget_lines = ropgadget_result.stdout.split('\n')
                    useful_gadgets = []

                    for line in gadget_lines:
                        if 'pop' in line and 'ret' in line:
                            useful_gadgets.append(line.strip())

                    results["gadgets"] = useful_gadgets[:20]  # Limit to first 20 gadgets

                    if useful_gadgets:
                        results["exploitation_hints"].append(f"Found {len(useful_gadgets)} ROP gadgets - ROP chain exploitation possible")
                        results["recommended_tools"].append("ropper")

            except Exception as e:
                results["gadgets"] = [f"Error finding gadgets: {str(e)}"]

        # Function analysis with objdump
        if analysis_depth in ["comprehensive", "deep"]:
            try:
                objdump_result = subprocess.run(['objdump', '-t', binary_path], capture_output=True, text=True, timeout=30)
                if objdump_result.returncode == 0:
                    functions = []
                    for line in objdump_result.stdout.split('\n'):
                        if 'F .text' in line:  # Function in text section
                            parts = line.split()
                            if len(parts) >= 6:
                                func_name = parts[-1]
                                functions.append(func_name)

                    results["interesting_functions"] = functions[:50]  # Limit to first 50 functions
            except Exception as e:
                results["interesting_functions"] = [f"Error analyzing functions: {str(e)}"]

        # Add tool recommendations based on findings
        if results["exploitation_hints"]:
            results["recommended_tools"].extend(["pwntools", "gdb-peda", "one-gadget"])

        if "format string" in str(results["exploitation_hints"]).lower():
            results["recommended_tools"].append("format-string-exploiter")

        logger.info(f"🔬 CTF binary analysis completed | Binary: {binary_path} | Hints: {len(results['exploitation_hints'])}")
        return jsonify({
            "success": True,
            "analysis": results,
            "timestamp": datetime.now().isoformat()
        })

    except Exception as e:
        logger.error(f"💥 Error in CTF binary analyzer: {str(e)}")
        return jsonify({"error": f"Server error: {str(e)}"}), 500

# ============================================================================
# ADVANCED PROCESS MANAGEMENT API ENDPOINTS (v10.0 ENHANCEMENT)
# ============================================================================

@bp.route("/api/process/execute-async", methods=["POST"])
def execute_command_async():
    """Execute command asynchronously using enhanced process management"""
    try:
        params = request.json
        command = params.get("command", "")
        context = params.get("context", {})

        if not command:
            return jsonify({"error": "Command parameter is required"}), 400

        # Execute command asynchronously
        task_id = enhanced_process_manager.execute_command_async(command, context)

        logger.info(f"🚀 Async command execution started | Task ID: {task_id}")
        return jsonify({
            "success": True,
            "task_id": task_id,
            "command": command,
            "status": "submitted",
            "timestamp": datetime.now().isoformat()
        })

    except Exception as e:
        logger.error(f"💥 Error in async command execution: {str(e)}")
        return jsonify({"error": f"Server error: {str(e)}"}), 500

@bp.route("/api/process/get-task-result/<task_id>", methods=["GET"])
def get_async_task_result(task_id):
    """Get result of asynchronous task"""
    try:
        result = enhanced_process_manager.get_task_result(task_id)

        if result["status"] == "not_found":
            return jsonify({"error": "Task not found"}), 404

        logger.info(f"📋 Task result retrieved | Task ID: {task_id} | Status: {result['status']}")
        return jsonify({
            "success": True,
            "task_id": task_id,
            "result": result,
            "timestamp": datetime.now().isoformat()
        })

    except Exception as e:
        logger.error(f"💥 Error getting task result: {str(e)}")
        return jsonify({"error": f"Server error: {str(e)}"}), 500

@bp.route("/api/process/pool-stats", methods=["GET"])
def get_process_pool_stats():
    """Get process pool statistics and performance metrics"""
    try:
        stats = enhanced_process_manager.get_comprehensive_stats()

        logger.info(f"📊 Process pool stats retrieved | Active workers: {stats['process_pool']['active_workers']}")
        return jsonify({
            "success": True,
            "stats": stats,
            "timestamp": datetime.now().isoformat()
        })

    except Exception as e:
        logger.error(f"💥 Error getting pool stats: {str(e)}")
        return jsonify({"error": f"Server error: {str(e)}"}), 500

@bp.route("/api/process/cache-stats", methods=["GET"])
def get_cache_stats():
    """Get advanced cache statistics"""
    try:
        cache_stats = enhanced_process_manager.cache.get_stats()

        logger.info(f"💾 Cache stats retrieved | Hit rate: {cache_stats['hit_rate']:.1f}%")
        return jsonify({
            "success": True,
            "cache_stats": cache_stats,
            "timestamp": datetime.now().isoformat()
        })

    except Exception as e:
        logger.error(f"💥 Error getting cache stats: {str(e)}")
        return jsonify({"error": f"Server error: {str(e)}"}), 500

@bp.route("/api/process/clear-cache", methods=["POST"])
def clear_process_cache():
    """Clear the advanced cache"""
    try:
        enhanced_process_manager.cache.clear()

        logger.info("🧹 Process cache cleared")
        return jsonify({
            "success": True,
            "message": "Cache cleared successfully",
            "timestamp": datetime.now().isoformat()
        })

    except Exception as e:
        logger.error(f"💥 Error clearing cache: {str(e)}")
        return jsonify({"error": f"Server error: {str(e)}"}), 500

@bp.route("/api/process/resource-usage", methods=["GET"])
def get_resource_usage():
    """Get current system resource usage and trends"""
    try:
        current_usage = enhanced_process_manager.resource_monitor.get_current_usage()
        usage_trends = enhanced_process_manager.resource_monitor.get_usage_trends()

        logger.info(f"📈 Resource usage retrieved | CPU: {current_usage['cpu_percent']:.1f}% | Memory: {current_usage['memory_percent']:.1f}%")
        return jsonify({
            "success": True,
            "current_usage": current_usage,
            "usage_trends": usage_trends,
            "timestamp": datetime.now().isoformat()
        })

    except Exception as e:
        logger.error(f"💥 Error getting resource usage: {str(e)}")
        return jsonify({"error": f"Server error: {str(e)}"}), 500

@bp.route("/api/process/performance-dashboard", methods=["GET"])
def get_performance_dashboard():
    """Get performance dashboard data"""
    try:
        dashboard_data = enhanced_process_manager.performance_dashboard.get_summary()
        pool_stats = enhanced_process_manager.process_pool.get_pool_stats()
        resource_usage = enhanced_process_manager.resource_monitor.get_current_usage()

        # Create comprehensive dashboard
        dashboard = {
            "performance_summary": dashboard_data,
            "process_pool": pool_stats,
            "resource_usage": resource_usage,
            "cache_stats": enhanced_process_manager.cache.get_stats(),
            "auto_scaling_status": enhanced_process_manager.auto_scaling_enabled,
            "system_health": {
                "cpu_status": "healthy" if resource_usage["cpu_percent"] < 80 else "warning" if resource_usage["cpu_percent"] < 95 else "critical",
                "memory_status": "healthy" if resource_usage["memory_percent"] < 85 else "warning" if resource_usage["memory_percent"] < 95 else "critical",
                "disk_status": "healthy" if resource_usage["disk_percent"] < 90 else "warning" if resource_usage["disk_percent"] < 98 else "critical"
            }
        }

        logger.info(f"📊 Performance dashboard retrieved | Success rate: {dashboard_data.get('success_rate', 0):.1f}%")
        return jsonify({
            "success": True,
            "dashboard": dashboard,
            "timestamp": datetime.now().isoformat()
        })

    except Exception as e:
        logger.error(f"💥 Error getting performance dashboard: {str(e)}")
        return jsonify({"error": f"Server error: {str(e)}"}), 500

@bp.route("/api/process/terminate-gracefully/<int:pid>", methods=["POST"])
def terminate_process_gracefully(pid):
    """Terminate process with graceful degradation"""
    try:
        params = request.json or {}
        timeout = params.get("timeout", 30)

        success = enhanced_process_manager.terminate_process_gracefully(pid, timeout)

        if success:
            logger.info(f"✅ Process {pid} terminated gracefully")
            return jsonify({
                "success": True,
                "message": f"Process {pid} terminated successfully",
                "pid": pid,
                "timestamp": datetime.now().isoformat()
            })
        else:
            return jsonify({
                "success": False,
                "error": f"Failed to terminate process {pid}",
                "pid": pid,
                "timestamp": datetime.now().isoformat()
            }), 400

    except Exception as e:
        logger.error(f"💥 Error terminating process {pid}: {str(e)}")
        return jsonify({"error": f"Server error: {str(e)}"}), 500

@bp.route("/api/process/auto-scaling", methods=["POST"])
def configure_auto_scaling():
    """Configure auto-scaling settings"""
    try:
        params = request.json
        enabled = params.get("enabled", True)
        thresholds = params.get("thresholds", {})

        # Update auto-scaling configuration
        enhanced_process_manager.auto_scaling_enabled = enabled

        if thresholds:
            enhanced_process_manager.resource_thresholds.update(thresholds)

        logger.info(f"⚙️ Auto-scaling configured | Enabled: {enabled}")
        return jsonify({
            "success": True,
            "auto_scaling_enabled": enabled,
            "resource_thresholds": enhanced_process_manager.resource_thresholds,
            "timestamp": datetime.now().isoformat()
        })

    except Exception as e:
        logger.error(f"💥 Error configuring auto-scaling: {str(e)}")
        return jsonify({"error": f"Server error: {str(e)}"}), 500

@bp.route("/api/process/scale-pool", methods=["POST"])
def manual_scale_pool():
    """Manually scale the process pool"""
    try:
        params = request.json
        action = params.get("action", "")  # "up" or "down"
        count = params.get("count", 1)

        if action not in ["up", "down"]:
            return jsonify({"error": "Action must be 'up' or 'down'"}), 400

        current_stats = enhanced_process_manager.process_pool.get_pool_stats()
        current_workers = current_stats["active_workers"]

        if action == "up":
            max_workers = enhanced_process_manager.process_pool.max_workers
            if current_workers + count <= max_workers:
                enhanced_process_manager.process_pool._scale_up(count)
                new_workers = current_workers + count
                message = f"Scaled up by {count} workers"
            else:
                return jsonify({"error": f"Cannot scale up: would exceed max workers ({max_workers})"}), 400
        else:  # down
            min_workers = enhanced_process_manager.process_pool.min_workers
            if current_workers - count >= min_workers:
                enhanced_process_manager.process_pool._scale_down(count)
                new_workers = current_workers - count
                message = f"Scaled down by {count} workers"
            else:
                return jsonify({"error": f"Cannot scale down: would go below min workers ({min_workers})"}), 400

        logger.info(f"📏 Manual scaling | {message} | Workers: {current_workers} → {new_workers}")
        return jsonify({
            "success": True,
            "message": message,
            "previous_workers": current_workers,
            "current_workers": new_workers,
            "timestamp": datetime.now().isoformat()
        })

    except Exception as e:
        logger.error(f"💥 Error scaling pool: {str(e)}")
        return jsonify({"error": f"Server error: {str(e)}"}), 500

@bp.route("/api/process/health-check", methods=["GET"])
def process_health_check():
    """Comprehensive health check of the process management system"""
    try:
        # Get all system stats
        comprehensive_stats = enhanced_process_manager.get_comprehensive_stats()

        # Determine overall health
        resource_usage = comprehensive_stats["resource_usage"]
        pool_stats = comprehensive_stats["process_pool"]
        cache_stats = comprehensive_stats["cache"]

        health_score = 100
        issues = []

        # CPU health
        if resource_usage["cpu_percent"] > 95:
            health_score -= 30
            issues.append("Critical CPU usage")
        elif resource_usage["cpu_percent"] > 80:
            health_score -= 15
            issues.append("High CPU usage")

        # Memory health
        if resource_usage["memory_percent"] > 95:
            health_score -= 25
            issues.append("Critical memory usage")
        elif resource_usage["memory_percent"] > 85:
            health_score -= 10
            issues.append("High memory usage")

        # Disk health
        if resource_usage["disk_percent"] > 98:
            health_score -= 20
            issues.append("Critical disk usage")
        elif resource_usage["disk_percent"] > 90:
            health_score -= 5
            issues.append("High disk usage")

        # Process pool health
        if pool_stats["queue_size"] > 50:
            health_score -= 15
            issues.append("High task queue backlog")

        # Cache health
        if cache_stats["hit_rate"] < 30:
            health_score -= 10
            issues.append("Low cache hit rate")

        health_score = max(0, health_score)

        # Determine status
        if health_score >= 90:
            status = "excellent"
        elif health_score >= 75:
            status = "good"
        elif health_score >= 50:
            status = "fair"
        elif health_score >= 25:
            status = "poor"
        else:
            status = "critical"

        health_report = {
            "overall_status": status,
            "health_score": health_score,
            "issues": issues,
            "system_stats": comprehensive_stats,
            "recommendations": []
        }

        # Add recommendations based on issues
        if "High CPU usage" in issues:
            health_report["recommendations"].append("Consider reducing concurrent processes or upgrading CPU")
        if "High memory usage" in issues:
            health_report["recommendations"].append("Clear caches or increase available memory")
        if "High task queue backlog" in issues:
            health_report["recommendations"].append("Scale up process pool or optimize task processing")
        if "Low cache hit rate" in issues:
            health_report["recommendations"].append("Review cache TTL settings or increase cache size")

        logger.info(f"🏥 Health check completed | Status: {status} | Score: {health_score}/100")
        return jsonify({
            "success": True,
            "health_report": health_report,
            "timestamp": datetime.now().isoformat()
        })

    except Exception as e:
        logger.error(f"💥 Error in health check: {str(e)}")
        return jsonify({"error": f"Server error: {str(e)}"}), 500

# ============================================================================
# BANNER AND STARTUP CONFIGURATION
# ============================================================================

# ============================================================================
# INTELLIGENT ERROR HANDLING API ENDPOINTS
# ============================================================================

@bp.route("/api/error-handling/statistics", methods=["GET"])
def get_error_statistics():
    """Get error handling statistics"""
    try:
        stats = error_handler.get_error_statistics()
        return jsonify({
            "success": True,
            "statistics": stats,
            "timestamp": datetime.now().isoformat()
        })
    except Exception as e:
        logger.error(f"Error getting error statistics: {str(e)}")
        return jsonify({"error": f"Server error: {str(e)}"}), 500

@bp.route("/api/error-handling/test-recovery", methods=["POST"])
def test_error_recovery():
    """Test error recovery system with simulated failures"""
    try:
        data = request.get_json()
        tool_name = data.get("tool_name", "nmap")
        error_type = data.get("error_type", "timeout")
        target = data.get("target", "example.com")

        # Simulate an error for testing
        if error_type == "timeout":
            exception = TimeoutError("Simulated timeout error")
        elif error_type == "permission_denied":
            exception = PermissionError("Simulated permission error")
        elif error_type == "network_unreachable":
            exception = ConnectionError("Simulated network error")
        else:
            exception = Exception(f"Simulated {error_type} error")

        context = {
            "target": target,
            "parameters": data.get("parameters", {}),
            "attempt_count": 1
        }

        # Get recovery strategy
        recovery_strategy = error_handler.handle_tool_failure(tool_name, exception, context)

        return jsonify({
            "success": True,
            "recovery_strategy": {
                "action": recovery_strategy.action.value,
                "parameters": recovery_strategy.parameters,
                "max_attempts": recovery_strategy.max_attempts,
                "success_probability": recovery_strategy.success_probability,
                "estimated_time": recovery_strategy.estimated_time
            },
            "error_classification": error_handler.classify_error(str(exception), exception).value,
            "alternative_tools": error_handler.tool_alternatives.get(tool_name, []),
            "timestamp": datetime.now().isoformat()
        })

    except Exception as e:
        logger.error(f"Error testing recovery system: {str(e)}")
        return jsonify({"error": f"Server error: {str(e)}"}), 500

@bp.route("/api/error-handling/fallback-chains", methods=["GET"])
def get_fallback_chains():
    """Get available fallback tool chains"""
    try:
        operation = request.args.get("operation", "")
        failed_tools = request.args.getlist("failed_tools")

        if operation:
            fallback_chain = degradation_manager.create_fallback_chain(operation, failed_tools)
            return jsonify({
                "success": True,
                "operation": operation,
                "fallback_chain": fallback_chain,
                "is_critical": degradation_manager.is_critical_operation(operation),
                "timestamp": datetime.now().isoformat()
            })
        else:
            return jsonify({
                "success": True,
                "available_operations": list(degradation_manager.fallback_chains.keys()),
                "critical_operations": list(degradation_manager.critical_operations),
                "timestamp": datetime.now().isoformat()
            })

    except Exception as e:
        logger.error(f"Error getting fallback chains: {str(e)}")
        return jsonify({"error": f"Server error: {str(e)}"}), 500

@bp.route("/api/error-handling/execute-with-recovery", methods=["POST"])
def execute_with_recovery_endpoint():
    """Execute a command with intelligent error handling and recovery"""
    try:
        data = request.get_json()
        tool_name = data.get("tool_name", "")
        command = data.get("command", "")
        parameters = data.get("parameters", {})
        max_attempts = data.get("max_attempts", 3)
        use_cache = data.get("use_cache", True)

        if not tool_name or not command:
            return jsonify({"error": "tool_name and command are required"}), 400

        # Execute command with recovery
        result = execute_command_with_recovery(
            tool_name=tool_name,
            command=command,
            parameters=parameters,
            use_cache=use_cache,
            max_attempts=max_attempts
        )

        return jsonify({
            "success": result.get("success", False),
            "result": result,
            "timestamp": datetime.now().isoformat()
        })

    except Exception as e:
        logger.error(f"Error executing command with recovery: {str(e)}")
        return jsonify({"error": f"Server error: {str(e)}"}), 500

@bp.route("/api/error-handling/classify-error", methods=["POST"])
def classify_error_endpoint():
    """Classify an error message"""
    try:
        data = request.get_json()
        error_message = data.get("error_message", "")

        if not error_message:
            return jsonify({"error": "error_message is required"}), 400

        error_type = error_handler.classify_error(error_message)
        recovery_strategies = error_handler.recovery_strategies.get(error_type, [])

        return jsonify({
            "success": True,
            "error_type": error_type.value,
            "recovery_strategies": [
                {
                    "action": strategy.action.value,
                    "parameters": strategy.parameters,
                    "success_probability": strategy.success_probability,
                    "estimated_time": strategy.estimated_time
                }
                for strategy in recovery_strategies
            ],
            "timestamp": datetime.now().isoformat()
        })

    except Exception as e:
        logger.error(f"Error classifying error: {str(e)}")
        return jsonify({"error": f"Server error: {str(e)}"}), 500

@bp.route("/api/error-handling/parameter-adjustments", methods=["POST"])
def get_parameter_adjustments():
    """Get parameter adjustments for a tool and error type"""
    try:
        data = request.get_json()
        tool_name = data.get("tool_name", "")
        error_type_str = data.get("error_type", "")
        original_params = data.get("original_params", {})

        if not tool_name or not error_type_str:
            return jsonify({"error": "tool_name and error_type are required"}), 400

        # Convert string to ErrorType enum
        try:
            error_type = ErrorType(error_type_str)
        except ValueError:
            return jsonify({"error": f"Invalid error_type: {error_type_str}"}), 400

        adjusted_params = error_handler.auto_adjust_parameters(tool_name, error_type, original_params)

        return jsonify({
            "success": True,
            "tool_name": tool_name,
            "error_type": error_type.value,
            "original_params": original_params,
            "adjusted_params": adjusted_params,
            "timestamp": datetime.now().isoformat()
        })

    except Exception as e:
        logger.error(f"Error getting parameter adjustments: {str(e)}")
        return jsonify({"error": f"Server error: {str(e)}"}), 500

@bp.route("/api/error-handling/alternative-tools", methods=["GET"])
def get_alternative_tools():
    """Get alternative tools for a given tool"""
    try:
        tool_name = request.args.get("tool_name", "")

        if not tool_name:
            return jsonify({"error": "tool_name parameter is required"}), 400

        alternatives = error_handler.tool_alternatives.get(tool_name, [])

        return jsonify({
            "success": True,
            "tool_name": tool_name,
            "alternatives": alternatives,
            "has_alternatives": len(alternatives) > 0,
            "timestamp": datetime.now().isoformat()
        })

    except Exception as e:
        logger.error(f"Error getting alternative tools: {str(e)}")
        return jsonify({"error": f"Server error: {str(e)}"}), 500

# Create the banner after all classes are defined
