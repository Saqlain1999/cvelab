export interface FingerprintingCommand {
  type: 'curl' | 'nmap' | 'nuclei';
  command: string;
  description: string;
  expectedOutput?: string;
  indicators: string[];
  confidence: 'high' | 'medium' | 'low';
}

export interface FingerprintingResult {
  commands: FingerprintingCommand[];
  detectionStrategy: string;
  ports: number[];
  protocols: string[];
  categories: string[];
  confidence: number;
  recommendations: string[];
}

export interface VulnerabilityIndicators {
  httpHeaders: string[];
  banners: string[];
  errorMessages: string[];
  pathDisclosure: string[];
  versionStrings: string[];
  serviceNames: string[];
}

export class FingerprintingService {
  private technologyProfiles: Map<string, any>;

  constructor() {
    this.technologyProfiles = this.initializeTechnologyProfiles();
  }

  /**
   * Generate fingerprinting commands and strategies for a CVE
   */
  generateFingerprint(cve: any, discoveryData?: any): FingerprintingResult {
    const category = this.categorizeVulnerability(cve);
    const technology = this.extractTechnology(cve, discoveryData);
    
    const profile = this.technologyProfiles.get(category) || this.technologyProfiles.get('default');
    const commands = this.generateCommands(cve, category, technology, profile);
    
    return {
      commands,
      detectionStrategy: this.buildDetectionStrategy(category, technology),
      ports: this.getRelevantPorts(category, technology),
      protocols: this.getRelevantProtocols(category, technology),
      categories: [category],
      confidence: this.calculateConfidence(cve, commands.length),
      recommendations: this.generateRecommendations(category, technology, cve)
    };
  }

  /**
   * Check if a CVE is fingerprintable with curl/nmap
   */
  isFingerprintable(cve: any): { isFingerprintable: boolean; methods: string[]; confidence: number } {
    const category = this.categorizeVulnerability(cve);
    const methods = [];
    let confidence = 0;

    // Check for network-based vulnerabilities
    if (cve.attackVector === 'Network') {
      confidence += 30;
      
      // Web application vulnerabilities
      if (['Web Application', 'CMS', 'Web Server'].includes(category)) {
        methods.push('curl', 'nuclei');
        confidence += 40;
      }
      
      // Network service vulnerabilities
      if (['Network Service', 'Database', 'SSH', 'FTP', 'DNS'].includes(category)) {
        methods.push('nmap', 'curl');
        confidence += 35;
      }

      // Check for common fingerprintable technologies
      const fingerprintableTech = [
        'apache', 'nginx', 'tomcat', 'iis', 'wordpress', 'joomla', 'drupal',
        'mysql', 'postgresql', 'mongodb', 'redis', 'openssh', 'proftp', 'bind',
        'squid', 'jenkins', 'gitlab', 'confluence', 'jira'
      ];

      const description = (cve.description || '').toLowerCase();
      const hasKnownTech = fingerprintableTech.some(tech => description.includes(tech));
      if (hasKnownTech) {
        confidence += 25;
      }

      // Boost confidence for common web ports and protocols
      if (description.includes('http') || description.includes('web') || description.includes('port 80') || description.includes('port 443')) {
        confidence += 20;
      }
    }

    return {
      isFingerprintable: confidence > 50 && methods.length > 0,
      methods,
      confidence: Math.min(confidence, 100)
    };
  }

  /**
   * Generate specific curl commands for web vulnerabilities
   */
  generateCurlCommands(cve: any, target = 'TARGET_IP'): FingerprintingCommand[] {
    const commands: FingerprintingCommand[] = [];
    const category = this.categorizeVulnerability(cve);
    const description = (cve.description || '').toLowerCase();

    // Basic HTTP detection
    commands.push({
      type: 'curl',
      command: `curl -I http://${target}`,
      description: 'Check HTTP headers for server identification',
      indicators: ['Server:', 'X-Powered-By:', 'X-Generator:'],
      confidence: 'high'
    });

    commands.push({
      type: 'curl',
      command: `curl -I https://${target}`,
      description: 'Check HTTPS headers for server identification',
      indicators: ['Server:', 'X-Powered-By:', 'X-Generator:'],
      confidence: 'high'
    });

    // Technology-specific commands
    if (category === 'CMS' || description.includes('wordpress')) {
      commands.push({
        type: 'curl',
        command: `curl -s http://${target}/wp-admin/admin-ajax.php`,
        description: 'WordPress AJAX endpoint detection',
        indicators: ['wordpress', 'wp-admin', '{"success"'],
        confidence: 'high'
      });

      commands.push({
        type: 'curl',
        command: `curl -s http://${target}/wp-json/wp/v2/users`,
        description: 'WordPress REST API user enumeration',
        indicators: ['wordpress', 'rest_route', 'wp-json'],
        confidence: 'medium'
      });
    }

    if (category === 'CMS' || description.includes('joomla')) {
      commands.push({
        type: 'curl',
        command: `curl -s http://${target}/administrator/`,
        description: 'Joomla administrator panel detection',
        indicators: ['joomla', 'administrator', 'com_login'],
        confidence: 'high'
      });
    }

    if (category === 'CMS' || description.includes('drupal')) {
      commands.push({
        type: 'curl',
        command: `curl -s http://${target}/CHANGELOG.txt`,
        description: 'Drupal version detection via changelog',
        indicators: ['drupal', 'CHANGELOG', 'VERSION'],
        confidence: 'medium'
      });
    }

    // Apache-specific detection
    if (description.includes('apache')) {
      commands.push({
        type: 'curl',
        command: `curl -s http://${target}/server-status`,
        description: 'Apache server status page',
        indicators: ['Apache Server Status', 'Server Version:', 'apache'],
        confidence: 'medium'
      });

      commands.push({
        type: 'curl',
        command: `curl -s http://${target}/server-info`,
        description: 'Apache server info page',
        indicators: ['Apache Server Information', 'Server Settings', 'apache'],
        confidence: 'medium'
      });
    }

    // Nginx-specific detection
    if (description.includes('nginx')) {
      commands.push({
        type: 'curl',
        command: `curl -s http://${target}/nginx_status`,
        description: 'Nginx status page detection',
        indicators: ['nginx', 'Active connections', 'server accepts'],
        confidence: 'medium'
      });
    }

    // Common error pages for version disclosure
    commands.push({
      type: 'curl',
      command: `curl -s http://${target}/nonexistent-page-404`,
      description: 'Trigger 404 error for server identification',
      indicators: ['404', 'Not Found', 'Server:', 'nginx', 'apache'],
      confidence: 'medium'
    });

    return commands;
  }

  /**
   * Generate nmap commands for network service detection
   */
  generateNmapCommands(cve: any, target = 'TARGET_IP'): FingerprintingCommand[] {
    const commands: FingerprintingCommand[] = [];
    const category = this.categorizeVulnerability(cve);
    const description = (cve.description || '').toLowerCase();

    // Basic service detection
    commands.push({
      type: 'nmap',
      command: `nmap -sV -p 1-1000 ${target}`,
      description: 'Service version detection on common ports',
      indicators: ['open', 'version', 'service'],
      confidence: 'high'
    });

    // Technology-specific port scans
    if (category === 'Web Server' || category === 'Web Application' || category === 'CMS') {
      commands.push({
        type: 'nmap',
        command: `nmap -sV -p 80,443,8080,8443 ${target}`,
        description: 'Web service detection on HTTP/HTTPS ports',
        indicators: ['http', 'https', 'nginx', 'apache', 'iis'],
        confidence: 'high'
      });
    }

    if (category === 'Database' || description.includes('mysql') || description.includes('postgresql')) {
      commands.push({
        type: 'nmap',
        command: `nmap -sV -p 3306,5432,1433,1521,27017 ${target}`,
        description: 'Database service detection',
        indicators: ['mysql', 'postgresql', 'mssql', 'oracle', 'mongodb'],
        confidence: 'high'
      });
    }

    if (category === 'SSH' || description.includes('ssh') || description.includes('openssh')) {
      commands.push({
        type: 'nmap',
        command: `nmap -sV -p 22 ${target}`,
        description: 'SSH service version detection',
        indicators: ['ssh', 'openssh', 'version'],
        confidence: 'high'
      });
    }

    if (category === 'FTP' || description.includes('ftp')) {
      commands.push({
        type: 'nmap',
        command: `nmap -sV -p 21 ${target}`,
        description: 'FTP service detection',
        indicators: ['ftp', 'vsftpd', 'proftp', 'version'],
        confidence: 'high'
      });
    }

    if (category === 'DNS' || description.includes('bind') || description.includes('dns')) {
      commands.push({
        type: 'nmap',
        command: `nmap -sU -sV -p 53 ${target}`,
        description: 'DNS service detection',
        indicators: ['domain', 'bind', 'dns', 'version'],
        confidence: 'high'
      });
    }

    // Script-based detection
    commands.push({
      type: 'nmap',
      command: `nmap -sC -sV -p 80,443 ${target}`,
      description: 'HTTP script scanning for detailed fingerprinting',
      indicators: ['http-title', 'http-server-header', 'ssl-cert'],
      confidence: 'medium'
    });

    return commands;
  }

  /**
   * Generate Nuclei template commands for vulnerability testing
   */
  generateNucleiCommands(cve: any, target = 'TARGET_IP'): FingerprintingCommand[] {
    const commands: FingerprintingCommand[] = [];
    const cveId = cve.cveId || cve.id;

    if (cveId) {
      commands.push({
        type: 'nuclei',
        command: `nuclei -u http://${target} -t cves/${cveId.toLowerCase()}.yaml`,
        description: `Nuclei template for ${cveId}`,
        indicators: ['CRITICAL', 'HIGH', 'MEDIUM', 'vulnerable'],
        confidence: 'high'
      });

      commands.push({
        type: 'nuclei',
        command: `nuclei -u https://${target} -t cves/${cveId.toLowerCase()}.yaml`,
        description: `Nuclei template for ${cveId} (HTTPS)`,
        indicators: ['CRITICAL', 'HIGH', 'MEDIUM', 'vulnerable'],
        confidence: 'high'
      });
    }

    // Technology-specific templates
    const category = this.categorizeVulnerability(cve);
    const technologyTemplates: Record<string, string[]> = {
      'CMS': ['wordpress', 'joomla', 'drupal'],
      'Web Server': ['apache', 'nginx', 'iis'],
      'Database': ['mysql', 'postgresql', 'mongodb'],
      'Network Service': ['ssh', 'ftp', 'dns']
    };

    const templates = technologyTemplates[category] || [];
    templates.forEach(template => {
      commands.push({
        type: 'nuclei',
        command: `nuclei -u http://${target} -t technologies/${template}/`,
        description: `${template} technology detection`,
        indicators: [template, 'version', 'technology'],
        confidence: 'medium'
      });
    });

    return commands;
  }

  /**
   * Categorize vulnerability based on CVE data
   */
  private categorizeVulnerability(cve: any): string {
    const description = (cve.description || '').toLowerCase();
    const category = cve.category || '';

    // Web-based categories
    if (description.includes('wordpress') || description.includes('wp-') || category.includes('WordPress')) {
      return 'CMS';
    }
    if (description.includes('joomla') || description.includes('drupal') || description.includes('magento')) {
      return 'CMS';
    }
    if (description.includes('apache') || description.includes('nginx') || description.includes('iis') || description.includes('tomcat')) {
      return 'Web Server';
    }
    if (description.includes('http') || description.includes('web') || category.includes('Web')) {
      return 'Web Application';
    }

    // Network services
    if (description.includes('ssh') || description.includes('openssh') || description.includes('port 22')) {
      return 'SSH';
    }
    if (description.includes('ftp') || description.includes('proftp') || description.includes('vsftpd')) {
      return 'FTP';
    }
    if (description.includes('dns') || description.includes('bind') || description.includes('port 53')) {
      return 'DNS';
    }
    if (description.includes('proxy') || description.includes('squid') || description.includes('haproxy')) {
      return 'Proxy';
    }

    // Databases
    if (description.includes('mysql') || description.includes('mariadb') || description.includes('port 3306')) {
      return 'Database';
    }
    if (description.includes('postgresql') || description.includes('postgres') || description.includes('port 5432')) {
      return 'Database';
    }
    if (description.includes('mongodb') || description.includes('mongo') || description.includes('port 27017')) {
      return 'Database';
    }
    if (description.includes('redis') || description.includes('port 6379')) {
      return 'Database';
    }

    // Default categories
    if (cve.attackVector === 'Network') {
      return 'Network Service';
    }

    return 'Unknown';
  }

  /**
   * Extract technology information from CVE and discovery data
   */
  private extractTechnology(cve: any, discoveryData?: any): string {
    const description = (cve.description || '').toLowerCase();
    
    // Extract from CVE description
    const technologies = [
      'apache', 'nginx', 'iis', 'tomcat', 'jetty',
      'wordpress', 'joomla', 'drupal', 'magento',
      'mysql', 'postgresql', 'mongodb', 'redis',
      'openssh', 'proftp', 'vsftpd', 'bind',
      'jenkins', 'gitlab', 'confluence', 'jira'
    ];

    for (const tech of technologies) {
      if (description.includes(tech)) {
        return tech;
      }
    }

    // Extract from discovery data if available
    if (discoveryData && discoveryData.sources) {
      for (const source of discoveryData.sources) {
        const sourceText = (source.title + ' ' + source.description).toLowerCase();
        for (const tech of technologies) {
          if (sourceText.includes(tech)) {
            return tech;
          }
        }
      }
    }

    return 'unknown';
  }

  /**
   * Initialize technology profiles for fingerprinting
   */
  private initializeTechnologyProfiles(): Map<string, any> {
    const profiles = new Map();

    profiles.set('Web Server', {
      ports: [80, 443, 8080, 8443],
      protocols: ['http', 'https'],
      headers: ['Server', 'X-Powered-By'],
      paths: ['/server-status', '/server-info', '/nginx_status']
    });

    profiles.set('CMS', {
      ports: [80, 443],
      protocols: ['http', 'https'],
      headers: ['X-Generator', 'X-Powered-By'],
      paths: ['/wp-admin/', '/administrator/', '/CHANGELOG.txt', '/readme.html']
    });

    profiles.set('Database', {
      ports: [3306, 5432, 1433, 1521, 27017, 6379],
      protocols: ['mysql', 'postgresql', 'mssql', 'oracle', 'mongodb', 'redis'],
      banners: ['mysql', 'postgresql', 'microsoft sql server', 'oracle', 'mongodb', 'redis']
    });

    profiles.set('SSH', {
      ports: [22],
      protocols: ['ssh'],
      banners: ['ssh', 'openssh']
    });

    profiles.set('FTP', {
      ports: [21],
      protocols: ['ftp'],
      banners: ['ftp', 'vsftpd', 'proftp']
    });

    profiles.set('DNS', {
      ports: [53],
      protocols: ['dns'],
      banners: ['bind', 'dns']
    });

    profiles.set('default', {
      ports: [80, 443, 22, 21, 25, 53, 110, 143, 993, 995],
      protocols: ['tcp', 'udp'],
      headers: ['Server', 'X-Powered-By'],
      paths: ['/']
    });

    return profiles;
  }

  /**
   * Generate commands based on category and technology
   */
  private generateCommands(cve: any, category: string, technology: string, profile: any): FingerprintingCommand[] {
    const commands: FingerprintingCommand[] = [];

    // Add curl commands for web-based services
    if (['Web Server', 'Web Application', 'CMS'].includes(category)) {
      commands.push(...this.generateCurlCommands(cve));
    }

    // Add nmap commands for network services
    if (cve.attackVector === 'Network') {
      commands.push(...this.generateNmapCommands(cve));
    }

    // Add nuclei commands for known CVEs
    commands.push(...this.generateNucleiCommands(cve));

    return commands;
  }

  /**
   * Build detection strategy description
   */
  private buildDetectionStrategy(category: string, technology: string): string {
    const strategies: Record<string, string> = {
      'Web Server': 'Check HTTP headers, server status pages, and error responses for version disclosure',
      'CMS': 'Enumerate CMS-specific paths, admin panels, and version files',
      'Database': 'Perform service detection on database ports and check for version banners',
      'SSH': 'Check SSH banner for version information and supported algorithms',
      'FTP': 'Connect to FTP service and check banner for version disclosure',
      'DNS': 'Query DNS service version using version.bind CHAOS TXT record',
      'Network Service': 'Perform service version detection and banner grabbing',
      'default': 'Use nmap service detection and HTTP fingerprinting'
    };

    return strategies[category] || strategies['default'];
  }

  /**
   * Get relevant ports for the vulnerability category
   */
  private getRelevantPorts(category: string, technology: string): number[] {
    const portMap: Record<string, number[]> = {
      'Web Server': [80, 443, 8080, 8443],
      'Web Application': [80, 443, 8080, 8443],
      'CMS': [80, 443],
      'Database': [3306, 5432, 1433, 1521, 27017, 6379],
      'SSH': [22],
      'FTP': [21],
      'DNS': [53],
      'Proxy': [3128, 8080, 8888]
    };

    return portMap[category] || [80, 443, 22, 21, 25, 53];
  }

  /**
   * Get relevant protocols for the vulnerability category
   */
  private getRelevantProtocols(category: string, technology: string): string[] {
    const protocolMap: Record<string, string[]> = {
      'Web Server': ['http', 'https'],
      'Web Application': ['http', 'https'],
      'CMS': ['http', 'https'],
      'Database': ['tcp'],
      'SSH': ['ssh'],
      'FTP': ['ftp'],
      'DNS': ['dns', 'udp'],
      'Proxy': ['http', 'https']
    };

    return protocolMap[category] || ['tcp', 'http'];
  }

  /**
   * Calculate fingerprinting confidence
   */
  private calculateConfidence(cve: any, commandCount: number): number {
    let confidence = 0;

    // Base confidence from command availability
    confidence += Math.min(commandCount * 10, 50);

    // Boost for network vulnerabilities
    if (cve.attackVector === 'Network') {
      confidence += 20;
    }

    // Boost for well-known technologies
    const description = (cve.description || '').toLowerCase();
    const wellKnownTech = ['apache', 'nginx', 'wordpress', 'mysql', 'openssh'];
    if (wellKnownTech.some(tech => description.includes(tech))) {
      confidence += 20;
    }

    // Boost for high severity
    if (['CRITICAL', 'HIGH'].includes(cve.severity)) {
      confidence += 10;
    }

    return Math.min(confidence, 100);
  }

  /**
   * Generate recommendations for fingerprinting
   */
  private generateRecommendations(category: string, technology: string, cve: any): string[] {
    const recommendations: string[] = [];

    recommendations.push('Start with nmap service detection to identify open ports and services');
    
    if (['Web Server', 'Web Application', 'CMS'].includes(category)) {
      recommendations.push('Use curl to check HTTP headers for server identification');
      recommendations.push('Look for version disclosure in error pages and default pages');
    }

    if (category === 'CMS') {
      recommendations.push('Check for CMS-specific paths and admin panels');
      recommendations.push('Look for version files like CHANGELOG.txt or readme.html');
    }

    if (cve.cveId) {
      recommendations.push(`Search for Nuclei templates specific to ${cve.cveId}`);
    }

    recommendations.push('Combine multiple detection methods for higher confidence');
    recommendations.push('Document all identified versions and indicators for vulnerability assessment');

    return recommendations;
  }
}

export const fingerprintingService = new FingerprintingService();