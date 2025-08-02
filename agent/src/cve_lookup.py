"""
CVE Lookup Module
Queries vulnerability databases for CVE information
"""

import logging
import requests
import time
from typing import Dict, List, Any, Optional
from urllib.parse import quote
import json


class CVELookup:
    """Looks up CVEs from various vulnerability databases"""
    
    def __init__(self, config: Dict[str, Any]):
        self.config = config
        self.logger = logging.getLogger('hbvm_agent.cve_lookup')
        self.cve_sources = config.get('cve_sources', {})
        
        # Configure session with retries
        self.session = requests.Session()
        self.session.headers.update({
            'User-Agent': 'HBVM-Agent/1.0.0'
        })
        
        # Rate limiting
        self.request_delay = 1.0  # seconds between requests
        self.last_request_time = 0
        
        self.logger.info("CVE lookup module initialized")
    
    def lookup_vulnerabilities(self, scan_data: Dict[str, Any]) -> List[Dict[str, Any]]:
        """Look up vulnerabilities for discovered software"""
        self.logger.info("Starting CVE lookup")
        
        all_cves = []
        
        # Extract software from scan data
        software_list = self._extract_software_list(scan_data)
        
        if not software_list:
            self.logger.info("No software found for CVE lookup")
            return all_cves
        
        self.logger.info(f"Looking up CVEs for {len(software_list)} software items")
        
        # Query each enabled CVE source
        if self.cve_sources.get('nvd', {}).get('enabled', False):
            nvd_cves = self._query_nvd(software_list)
            all_cves.extend(nvd_cves)
        
        if self.cve_sources.get('vulners', {}).get('enabled', False):
            vulners_cves = self._query_vulners(software_list)
            all_cves.extend(vulners_cves)
        
        # Remove duplicates and sort by severity
        unique_cves = self._deduplicate_cves(all_cves)
        sorted_cves = sorted(unique_cves, key=lambda x: x.get('cvss_score', 0), reverse=True)
        
        self.logger.info(f"Found {len(sorted_cves)} unique CVEs")
        return sorted_cves
    
    def _extract_software_list(self, scan_data: Dict[str, Any]) -> List[Dict[str, str]]:
        """Extract software information from scan data"""
        software_list = []
        
        # From installed packages
        packages = scan_data.get('packages', [])
        for package in packages:
            if isinstance(package, dict) and package.get('name'):
                software_list.append({
                    'name': package['name'],
                    'version': package.get('version', ''),
                    'type': 'package',
                    'package_manager': package.get('package_manager', '')
                })
        
        # From running services
        services = scan_data.get('services', [])
        for service in services:
            if isinstance(service, dict) and service.get('name'):
                # Skip system processes
                name = service['name'].lower()
                if not any(skip in name for skip in ['kernel', 'systemd', 'kthread', 'migration']):
                    software_list.append({
                        'name': service['name'],
                        'version': service.get('version', ''),
                        'type': 'service',
                        'service_type': service.get('service_type', '')
                    })
        
        # From port/service detection
        ports = scan_data.get('ports', [])
        for port_info in ports:
            if isinstance(port_info, dict) and port_info.get('service'):
                service_name = port_info['service']
                if service_name not in ['unknown', 'tcpwrapped']:
                    software_list.append({
                        'name': service_name,
                        'version': port_info.get('version', ''),
                        'type': 'network_service',
                        'port': port_info.get('port', ''),
                        'protocol': port_info.get('protocol', '')
                    })
        
        return software_list
    
    def _query_nvd(self, software_list: List[Dict[str, str]]) -> List[Dict[str, Any]]:
        """Query National Vulnerability Database"""
        self.logger.info("Querying NVD for vulnerabilities")
        
        nvd_cves = []
        nvd_config = self.cve_sources.get('nvd', {})
        api_key = nvd_config.get('api_key', '')
        
        # NVD API endpoint
        base_url = "https://services.nvd.nist.gov/rest/json/cves/2.0"
        
        headers = {}
        if api_key:
            headers['apiKey'] = api_key
        
        for software in software_list:
            try:
                self._rate_limit()
                
                # Search for CVEs related to this software
                params = {
                    'keywordSearch': software['name'],
                    'resultsPerPage': 20  # Limit results
                }
                
                # Add version-specific search if available
                if software.get('version'):
                    params['keywordSearch'] = f"{software['name']} {software['version']}"
                
                response = self.session.get(
                    base_url,
                    params=params,
                    headers=headers,
                    timeout=30
                )
                
                if response.status_code == 200:
                    data = response.json()
                    
                    for cve_item in data.get('vulnerabilities', []):
                        cve_data = self._parse_nvd_cve(cve_item, software)
                        if cve_data:
                            nvd_cves.append(cve_data)
                
                elif response.status_code == 429:
                    # Rate limited
                    self.logger.warning("NVD rate limit hit, waiting...")
                    time.sleep(5)
                    continue
                else:
                    self.logger.warning(f"NVD API error {response.status_code}: {response.text}")
                    
            except Exception as e:
                self.logger.error(f"Error querying NVD for {software['name']}: {e}")
                continue
        
        return nvd_cves
    
    def _parse_nvd_cve(self, cve_item: Dict[str, Any], software: Dict[str, str]) -> Optional[Dict[str, Any]]:
        """Parse CVE data from NVD response"""
        try:
            cve = cve_item.get('cve', {})
            cve_id = cve.get('id', '')
            
            if not cve_id:
                return None
            
            # Get description
            descriptions = cve.get('descriptions', [])
            description = ""
            for desc in descriptions:
                if desc.get('lang') == 'en':
                    description = desc.get('value', '')
                    break
            
            # Get CVSS scores
            metrics = cve_item.get('metrics', {})
            cvss_score = 0.0
            cvss_vector = ""
            cvss_version = ""
            
            # Try CVSS v3.1 first, then v3.0, then v2.0
            for cvss_key in ['cvssMetricV31', 'cvssMetricV30', 'cvssMetricV2']:
                if cvss_key in metrics and metrics[cvss_key]:
                    cvss_data = metrics[cvss_key][0].get('cvssData', {})
                    cvss_score = cvss_data.get('baseScore', 0.0)
                    cvss_vector = cvss_data.get('vectorString', '')
                    cvss_version = cvss_key.replace('cvssMetric', '').replace('V', 'v')
                    break
            
            # Get severity
            severity = self._get_severity_from_score(cvss_score)
            
            # Get published and modified dates
            published = cve.get('published', '')
            last_modified = cve.get('lastModified', '')
            
            return {
                'cve_id': cve_id,
                'description': description,
                'cvss_score': cvss_score,
                'cvss_vector': cvss_vector,
                'cvss_version': cvss_version,
                'severity': severity,
                'published_date': published,
                'last_modified': last_modified,
                'affected_software': software['name'],
                'software_version': software.get('version', ''),
                'software_type': software.get('type', ''),
                'source': 'nvd'
            }
            
        except Exception as e:
            self.logger.error(f"Error parsing NVD CVE data: {e}")
            return None
    
    def _query_vulners(self, software_list: List[Dict[str, str]]) -> List[Dict[str, Any]]:
        """Query Vulners API"""
        self.logger.info("Querying Vulners for vulnerabilities")
        
        vulners_cves = []
        vulners_config = self.cve_sources.get('vulners', {})
        api_key = vulners_config.get('api_key', '')
        
        if not api_key:
            self.logger.warning("Vulners API key not configured")
            return vulners_cves
        
        base_url = "https://vulners.com/api/v3/search/lucene/"
        
        for software in software_list:
            try:
                self._rate_limit()
                
                # Construct search query
                query = f"title:{software['name']}"
                if software.get('version'):
                    query += f" AND affectedSoftware.name:{software['name']} AND affectedSoftware.version:{software['version']}"
                
                params = {
                    'apikey': api_key,
                    'query': query,
                    'skip': 0,
                    'size': 20  # Limit results
                }
                
                response = self.session.get(
                    base_url,
                    params=params,
                    timeout=30
                )
                
                if response.status_code == 200:
                    data = response.json()
                    
                    if data.get('result') == 'OK':
                        for vuln in data.get('data', {}).get('search', []):
                            cve_data = self._parse_vulners_cve(vuln, software)
                            if cve_data:
                                vulners_cves.append(cve_data)
                    else:
                        self.logger.warning(f"Vulners API error: {data.get('data', {}).get('error', 'Unknown error')}")
                        
                elif response.status_code == 429:
                    self.logger.warning("Vulners rate limit hit, waiting...")
                    time.sleep(5)
                    continue
                else:
                    self.logger.warning(f"Vulners API error {response.status_code}: {response.text}")
                    
            except Exception as e:
                self.logger.error(f"Error querying Vulners for {software['name']}: {e}")
                continue
        
        return vulners_cves
    
    def _parse_vulners_cve(self, vuln_item: Dict[str, Any], software: Dict[str, str]) -> Optional[Dict[str, Any]]:
        """Parse CVE data from Vulners response"""
        try:
            doc = vuln_item.get('_source', {})
            
            cve_id = doc.get('id', '')
            if not cve_id or not cve_id.startswith('CVE-'):
                return None
            
            description = doc.get('description', '')
            cvss_score = float(doc.get('cvss', {}).get('score', 0))
            cvss_vector = doc.get('cvss', {}).get('vector', '')
            
            severity = self._get_severity_from_score(cvss_score)
            
            published = doc.get('published', '')
            modified = doc.get('modified', '')
            
            return {
                'cve_id': cve_id,
                'description': description,
                'cvss_score': cvss_score,
                'cvss_vector': cvss_vector,
                'cvss_version': 'v2',  # Vulners primarily uses CVSS v2
                'severity': severity,
                'published_date': published,
                'last_modified': modified,
                'affected_software': software['name'],
                'software_version': software.get('version', ''),
                'software_type': software.get('type', ''),
                'source': 'vulners'
            }
            
        except Exception as e:
            self.logger.error(f"Error parsing Vulners CVE data: {e}")
            return None
    
    def _get_severity_from_score(self, cvss_score: float) -> str:
        """Convert CVSS score to severity level"""
        if cvss_score >= 9.0:
            return 'Critical'
        elif cvss_score >= 7.0:
            return 'High'
        elif cvss_score >= 4.0:
            return 'Medium'
        elif cvss_score > 0.0:
            return 'Low'
        else:
            return 'None'
    
    def _deduplicate_cves(self, cves: List[Dict[str, Any]]) -> List[Dict[str, Any]]:
        """Remove duplicate CVEs based on CVE ID"""
        seen_cves = {}
        
        for cve in cves:
            cve_id = cve.get('cve_id', '')
            if cve_id:
                if cve_id not in seen_cves:
                    seen_cves[cve_id] = cve
                else:
                    # Keep the one with higher CVSS score or more recent data
                    existing = seen_cves[cve_id]
                    if (cve.get('cvss_score', 0) > existing.get('cvss_score', 0) or
                        cve.get('source') == 'nvd'):  # Prefer NVD data
                        seen_cves[cve_id] = cve
        
        return list(seen_cves.values())
    
    def _rate_limit(self):
        """Implement rate limiting between requests"""
        current_time = time.time()
        time_since_last = current_time - self.last_request_time
        
        if time_since_last < self.request_delay:
            sleep_time = self.request_delay - time_since_last
            time.sleep(sleep_time)
        
        self.last_request_time = time.time()
    
    def get_cve_details(self, cve_id: str) -> Optional[Dict[str, Any]]:
        """Get detailed information about a specific CVE"""
        self.logger.info(f"Getting details for CVE {cve_id}")
        
        # Try NVD first
        cve_details = self._get_nvd_cve_details(cve_id)
        
        if not cve_details and self.cve_sources.get('vulners', {}).get('enabled', False):
            # Fallback to Vulners
            cve_details = self._get_vulners_cve_details(cve_id)
        
        return cve_details
    
    def _get_nvd_cve_details(self, cve_id: str) -> Optional[Dict[str, Any]]:
        """Get CVE details from NVD"""
        try:
            self._rate_limit()
            
            url = f"https://services.nvd.nist.gov/rest/json/cves/2.0"
            params = {'cveId': cve_id}
            
            headers = {}
            api_key = self.cve_sources.get('nvd', {}).get('api_key', '')
            if api_key:
                headers['apiKey'] = api_key
            
            response = self.session.get(url, params=params, headers=headers, timeout=30)
            
            if response.status_code == 200:
                data = response.json()
                vulnerabilities = data.get('vulnerabilities', [])
                
                if vulnerabilities:
                    return self._parse_nvd_cve(vulnerabilities[0], {'name': 'unknown', 'version': ''})
            
            return None
            
        except Exception as e:
            self.logger.error(f"Error getting NVD details for {cve_id}: {e}")
            return None
    
    def _get_vulners_cve_details(self, cve_id: str) -> Optional[Dict[str, Any]]:
        """Get CVE details from Vulners"""
        try:
            self._rate_limit()
            
            api_key = self.cve_sources.get('vulners', {}).get('api_key', '')
            if not api_key:
                return None
            
            url = f"https://vulners.com/api/v3/search/id/"
            params = {
                'apikey': api_key,
                'id': cve_id
            }
            
            response = self.session.get(url, params=params, timeout=30)
            
            if response.status_code == 200:
                data = response.json()
                
                if data.get('result') == 'OK':
                    documents = data.get('data', {}).get('documents', {})
                    if cve_id in documents:
                        return self._parse_vulners_cve({'_source': documents[cve_id]}, {'name': 'unknown', 'version': ''})
            
            return None
            
        except Exception as e:
            self.logger.error(f"Error getting Vulners details for {cve_id}: {e}")
            return None