import { advancedScoringService } from "./advancedScoringService";

interface NistCveResponse {
  vulnerabilities: Array<{
    cve: {
      id: string;
      descriptions: Array<{
        lang: string;
        value: string;
      }>;
      published: string;
      lastModified: string;
      metrics?: {
        cvssMetricV31?: Array<{
          cvssData: {
            baseScore: number;
            vectorString: string;
            baseSeverity: string;
          };
        }>;
      };
      configurations?: Array<{
        nodes: Array<{
          cpeMatch: Array<{
            criteria: string;
            vulnerable: boolean;
            versionStartIncluding?: string;
            versionEndExcluding?: string;
          }>;
        }>;
      }>;
    };
  }>;
  totalResults: number;
}

interface CveTargetingOptions {
  timeframeYears?: number;
  severities?: ('LOW' | 'MEDIUM' | 'HIGH' | 'CRITICAL')[];
  attackVector?: ('NETWORK' | 'ADJACENT_NETWORK' | 'LOCAL' | 'PHYSICAL')[];
  attackComplexity?: ('LOW' | 'HIGH')[];
  userInteraction?: ('NONE' | 'REQUIRED')[];
  keywords?: string[];
  cpeNames?: string[];
  excludeAuthenticated?: boolean;
  onlyLabSuitable?: boolean;
  targetedCweIds?: string[];
}

export class CveService {
  private readonly BASE_URL = 'https://services.nvd.nist.gov/rest/json/cves/2.0';
  
  // Lab-suitable technologies and their CPE patterns
  private readonly LAB_SUITABLE_CPE_PATTERNS = [
    // Web Servers
    'cpe:2.3:a:apache:http_server',
    'cpe:2.3:a:nginx:nginx',
    'cpe:2.3:a:microsoft:internet_information_services',
    'cpe:2.3:a:apache:tomcat',
    
    // CMS Systems
    'cpe:2.3:a:wordpress:wordpress',
    'cpe:2.3:a:joomla:joomla\!',
    'cpe:2.3:a:drupal:drupal',
    'cpe:2.3:a:magento:magento',
    
    // Databases
    'cpe:2.3:a:mysql:mysql',
    'cpe:2.3:a:postgresql:postgresql',
    'cpe:2.3:a:mongodb:mongodb',
    'cpe:2.3:a:redis:redis',
    
    // Network Services
    'cpe:2.3:a:openbsd:openssh',
    'cpe:2.3:a:proftpd:proftpd',
    'cpe:2.3:a:isc:bind',
    'cpe:2.3:a:squid-cache:squid',
    
    // Web Frameworks
    'cpe:2.3:a:laravel:laravel',
    'cpe:2.3:a:nodejs:node.js',
    'cpe:2.3:a:django:django'
  ];
  
  // CWE IDs for remote exploitation vulnerabilities
  private readonly TARGET_CWE_IDS = [
    'CWE-79',   // Cross-site Scripting (XSS)
    'CWE-89',   // SQL Injection
    'CWE-78',   // OS Command Injection
    'CWE-94',   // Code Injection
    'CWE-502',  // Deserialization of Untrusted Data
    'CWE-22',   // Path Traversal
    'CWE-918',  // Server-Side Request Forgery (SSRF)
    'CWE-1336', // Template Injection
    'CWE-611',  // XML External Entity (XXE)
    'CWE-352',  // Cross-Site Request Forgery (CSRF)
    'CWE-434',  // Unrestricted Upload of File with Dangerous Type
    'CWE-287',  // Improper Authentication
    'CWE-269'   // Improper Privilege Management
  ];
  
  async fetchCvesFromNist(options: CveTargetingOptions = {}): Promise<any[]> {
    const {
      timeframeYears = 3,
      severities = ['HIGH', 'CRITICAL'],
      attackVector = ['NETWORK'],
      attackComplexity = ['LOW'],
      userInteraction = ['NONE'],
      keywords = [],
      cpeNames = [],
      excludeAuthenticated = true,
      onlyLabSuitable = true,
      targetedCweIds = this.TARGET_CWE_IDS
    } = options;
    const startDate = new Date();
    startDate.setFullYear(startDate.getFullYear() - timeframeYears);
    startDate.setHours(0, 0, 0, 0);
    
    const endDate = new Date();
    endDate.setHours(23, 59, 59, 999);
    
    // Build targeted search parameters
    const params = new URLSearchParams({
      pubStartDate: startDate.toISOString(),
      pubEndDate: endDate.toISOString(),
      resultsPerPage: '2000'
    });
    
    // Add CVSS severity filtering
    if (severities.length > 0) {
      params.append('cvssV3Severity', severities.join(','));
    }
    
    // Add attack vector filtering
    if (attackVector.length > 0) {
      const vectorCodes = attackVector.map(v => {
        switch (v) {
          case 'NETWORK': return 'N';
          case 'ADJACENT_NETWORK': return 'A';
          case 'LOCAL': return 'L';
          case 'PHYSICAL': return 'P';
          default: return 'N';
        }
      }).join(',');
      params.append('cvssV3Vector', `AV:${vectorCodes}`);
    }
    
    // Add CPE name filtering for lab-suitable technologies
    const targetCpeNames = cpeNames.length > 0 ? cpeNames : this.LAB_SUITABLE_CPE_PATTERNS;
    if (targetCpeNames.length > 0) {
      // NVD API supports CPE name matching
      params.append('cpeName', targetCpeNames.slice(0, 5).join(' OR '));
    }
    
    // Add keyword filtering for lab-suitable vulnerabilities
    const labKeywords = keywords.length > 0 ? keywords : [
      'remote code execution', 'sql injection', 'cross-site scripting', 
      'path traversal', 'deserialization', 'template injection',
      'server-side request forgery', 'xml external entity'
    ];
    if (labKeywords.length > 0) {
      params.append('keywordSearch', labKeywords.slice(0, 3).join(' OR '));
    }
    
    // Add CWE ID filtering
    if (targetedCweIds.length > 0) {
      params.append('cweId', targetedCweIds.slice(0, 5).join(','));
    }

    try {
      const response = await fetch(`${this.BASE_URL}?${params}`, {
        headers: {
          'Accept': 'application/json',
          'User-Agent': 'CVE-Lab-Hunter/1.0'
        }
      });

      if (!response.ok) {
        throw new Error(`NIST API error: ${response.status} ${response.statusText}`);
      }

      const data: NistCveResponse = await response.json();
      let vulnerabilities = this.transformNistData(data.vulnerabilities);
      
      // Apply additional client-side filtering for lab suitability
      if (onlyLabSuitable) {
        vulnerabilities = this.filterForLabSuitability(vulnerabilities, {
          excludeAuthenticated,
          attackVector,
          attackComplexity,
          userInteraction
        });
      }
      
      console.log(`Filtered to ${vulnerabilities.length} lab-suitable CVEs from ${data.totalResults} total`);
      return vulnerabilities;
    } catch (error) {
      console.error('Error fetching CVEs from NIST:', error);
      throw error;
    }
  }

  private transformNistData(vulnerabilities: any[]): any[] {
    return vulnerabilities.map(vuln => {
      const cve = vuln.cve;
      const metrics = cve.metrics?.cvssMetricV31?.[0];
      
      // Extract technology/product information
      const technology = this.extractTechnology(cve);
      const category = this.categorizeVulnerability(cve);
      
      return {
        cveId: cve.id,
        description: cve.descriptions.find((d: any) => d.lang === 'en')?.value || '',
        publishedDate: new Date(cve.published),
        lastModifiedDate: new Date(cve.lastModified),
        cvssScore: metrics?.cvssData?.baseScore || null,
        cvssVector: metrics?.cvssData?.vectorString || null,
        severity: metrics?.cvssData?.baseSeverity || 'UNKNOWN',
        affectedProduct: technology.product,
        affectedVersions: technology.versions,
        attackVector: this.extractAttackVector(metrics?.cvssData?.vectorString),
        technology: technology.product,
        category: category,
        hasPublicPoc: false, // Will be determined by GitHub/ExploitDB search
        isDockerDeployable: false, // Will be determined by analysis
        isCurlTestable: false, // Will be determined by analysis
        pocUrls: [],
        dockerInfo: null,
        fingerprintInfo: null,
        exploitabilityScore: this.calculateExploitabilityScore(metrics),
        labSuitabilityScore: 0 // Will be calculated after PoC analysis
      };
    });
  }

  private extractTechnology(cve: any): { product: string; versions: string[] } {
    let product = 'Unknown';
    let versions: string[] = [];

    if (cve.configurations) {
      for (const config of cve.configurations) {
        for (const node of config.nodes) {
          for (const match of node.cpeMatch) {
            if (match.vulnerable) {
              const cpe = match.criteria.split(':');
              if (cpe.length >= 5) {
                product = `${cpe[3]} ${cpe[4]}`.replace(/_/g, ' ');
                if (match.versionStartIncluding || match.versionEndExcluding) {
                  versions.push(`${match.versionStartIncluding || ''} - ${match.versionEndExcluding || ''}`);
                }
              }
            }
          }
        }
      }
    }

    return { product, versions };
  }

  private categorizeVulnerability(cve: any): string {
    const description = cve.descriptions.find((d: any) => d.lang === 'en')?.value.toLowerCase() || '';
    
    // Enhanced categorization with lab suitability in mind
    
    // CMS Systems (highly lab-suitable)
    if (description.includes('wordpress') || description.includes('drupal') || description.includes('joomla') ||
        description.includes('magento') || description.includes('phpbb') || description.includes('mediawiki')) {
      return 'CMS';
    }
    
    // Web Servers (very lab-suitable)
    if (description.includes('apache') || description.includes('nginx') || description.includes('iis') ||
        description.includes('tomcat') || description.includes('jetty') || description.includes('lighttpd')) {
      return 'Web Server';
    }
    
    // Network Services (good for network-based labs)
    if (description.includes('ssh') || description.includes('ftp') || description.includes('smtp') ||
        description.includes('dns') || description.includes('bind') || description.includes('postfix') ||
        description.includes('sendmail') || description.includes('exim') || description.includes('dovecot')) {
      return 'Network Service';
    }
    
    // Databases (good for injection-based labs)
    if (description.includes('mysql') || description.includes('postgresql') || description.includes('mongodb') ||
        description.includes('redis') || description.includes('mariadb') || description.includes('sqlite')) {
      return 'Database';
    }
    
    // Container & DevOps (modern lab environments)
    if (description.includes('docker') || description.includes('kubernetes') || description.includes('jenkins') ||
        description.includes('gitlab') || description.includes('nexus') || description.includes('artifactory')) {
      return 'Container';
    }
    
    // Network Security (proxy, firewall, gateway)
    if (description.includes('firewall') || description.includes('proxy') || description.includes('gateway') ||
        description.includes('squid') || description.includes('haproxy') || description.includes('pfsense')) {
      return 'Network Security';
    }
    
    // Web Frameworks (good for code injection labs)
    if (description.includes('django') || description.includes('flask') || description.includes('rails') ||
        description.includes('laravel') || description.includes('symfony') || description.includes('spring') ||
        description.includes('express') || description.includes('node.js')) {
      return 'Web Framework';
    }
    
    // Collaboration Tools (often network accessible)
    if (description.includes('confluence') || description.includes('jira') || description.includes('redmine') ||
        description.includes('grafana') || description.includes('kibana') || description.includes('splunk')) {
      return 'Collaboration';
    }
    
    return 'Other';
  }

  private extractAttackVector(vectorString?: string): string {
    if (!vectorString) return 'Unknown';
    
    const match = vectorString.match(/AV:([A-Z])/);
    if (match) {
      switch (match[1]) {
        case 'N': return 'Network';
        case 'A': return 'Adjacent Network';
        case 'L': return 'Local';
        case 'P': return 'Physical';
        default: return 'Unknown';
      }
    }
    
    return 'Unknown';
  }

  private calculateExploitabilityScore(metrics: any): number {
    if (!metrics) return 0;
    
    const vector = metrics.cvssData.vectorString;
    if (!vector) return 0;
    
    let score = 0;
    
    // Attack Vector (higher score for network attacks)
    if (vector.includes('AV:N')) score += 4;
    else if (vector.includes('AV:A')) score += 3;
    else if (vector.includes('AV:L')) score += 2;
    else if (vector.includes('AV:P')) score += 1;
    
    // Attack Complexity (higher score for low complexity)
    if (vector.includes('AC:L')) score += 3;
    else if (vector.includes('AC:H')) score += 1;
    
    // Privileges Required (higher score for no privileges)
    if (vector.includes('PR:N')) score += 3;
    else if (vector.includes('PR:L')) score += 2;
    else if (vector.includes('PR:H')) score += 1;
    
    // User Interaction (higher score for no interaction)
    if (vector.includes('UI:N')) score += 2;
    else if (vector.includes('UI:R')) score += 1;
    
    return Math.min(score / 12 * 10, 10); // Normalize to 0-10 scale
  }

  isLabSuitable(cve: any): boolean {
    // CVE is suitable for lab if:
    // 1. CVSS score >= 7.0 (high/critical)
    // 2. Network attack vector
    // 3. Affects common/deployable technologies
    // 4. Not requiring complex setup
    
    if (!cve.cvssScore || cve.cvssScore < 7.0) return false;
    if (cve.attackVector !== 'Network') return false;
    
    const labFriendlyTechnologies = [
      'apache', 'nginx', 'wordpress', 'drupal', 'joomla', 'mysql', 'postgresql',
      'openssh', 'docker', 'jenkins', 'gitlab', 'nexus', 'confluence', 'tomcat'
    ];
    
    const product = cve.affectedProduct?.toLowerCase() || '';
    return labFriendlyTechnologies.some(tech => product.includes(tech));
  }

  calculateAdvancedLabScore(cve: any): { score: number; breakdown: any } {
    // Auto-generate advanced scoring factors from CVE data
    const factors = advancedScoringService.generateFactorsFromCve(cve);
    
    // Calculate advanced score with detailed breakdown
    return advancedScoringService.calculateAdvancedScore(
      cve,
      factors.educational,
      factors.deployment,
      factors.technical,
      factors.practical
    );
  }

  calculateBasicLabScore(cve: any): number {
    let score = 0;

    // CVSS score weight (40%)
    if (cve.cvssScore) {
      score += (cve.cvssScore / 10) * 4;
    }

    // PoC availability (25%)
    if (cve.hasPublicPoc) {
      score += 2.5;
    }

    // Docker deployability (20%)
    if (cve.isDockerDeployable) {
      score += 2;
    }

    // Network testability (15%)
    if (cve.isCurlTestable) {
      score += 1.5;
    }

    return Math.min(score, 10);
  }

  /**
   * Enhanced filtering for lab suitability - applies client-side filters
   * that can't be done at the NVD API level
   */
  private filterForLabSuitability(vulnerabilities: any[], options: {
    excludeAuthenticated?: boolean;
    attackVector?: string[];
    attackComplexity?: string[];
    userInteraction?: string[];
  }): any[] {
    return vulnerabilities.filter(vuln => {
      // Basic lab suitability checks
      if (!vuln.cvssScore || vuln.cvssScore < 7.0) {
        return false;
      }
      
      // Filter by attack vector
      if (options.attackVector && !options.attackVector.includes(vuln.attackVector?.toUpperCase())) {
        return false;
      }
      
      // Check CVSS vector for complexity and user interaction
      if (vuln.cvssVector) {
        // Attack Complexity filtering
        if (options.attackComplexity?.includes('LOW') && !vuln.cvssVector.includes('AC:L')) {
          return false;
        }
        if (options.attackComplexity?.includes('HIGH') && !vuln.cvssVector.includes('AC:H')) {
          return false;
        }
        
        // User Interaction filtering
        if (options.userInteraction?.includes('NONE') && !vuln.cvssVector.includes('UI:N')) {
          return false;
        }
        if (options.userInteraction?.includes('REQUIRED') && !vuln.cvssVector.includes('UI:R')) {
          return false;
        }
      }
      
      // Exclude authenticated vulnerabilities if requested
      if (options.excludeAuthenticated) {
        const description = vuln.description?.toLowerCase() || '';
        const excludePatterns = [
          'requires authentication',
          'authenticated user',
          'valid credentials',
          'login required',
          'administrative access',
          'admin privileges',
          'physical access',
          'local access only',
          'must be logged in',
          'privilege escalation'
        ];
        
        if (excludePatterns.some(pattern => description.includes(pattern))) {
          return false;
        }
        
        // Also check CVSS vector for privilege requirements
        if (vuln.cvssVector && vuln.cvssVector.includes('PR:H')) {
          return false; // High privileges required
        }
      }
      
      // Check if technology is lab-deployable
      const product = vuln.affectedProduct?.toLowerCase() || '';
      const labSuitableTech = this.isLabSuitableTechnology(product);
      
      return labSuitableTech;
    });
  }
  
  /**
   * Check if a technology/product is suitable for lab deployment
   */
  private isLabSuitableTechnology(product: string): boolean {
    const labSuitableKeywords = [
      // Web Servers
      'apache', 'nginx', 'iis', 'tomcat', 'jetty', 'lighttpd',
      
      // CMS & Web Apps
      'wordpress', 'drupal', 'joomla', 'magento', 'phpbb', 'mediawiki',
      
      // Databases
      'mysql', 'postgresql', 'mongodb', 'redis', 'mariadb', 'sqlite',
      
      // Network Services
      'openssh', 'ssh', 'ftp', 'proftpd', 'vsftpd', 'bind', 'dns',
      'squid', 'proxy', 'postfix', 'sendmail', 'exim',
      
      // Web Frameworks & Platforms
      'node.js', 'nodejs', 'express', 'django', 'flask', 'rails',
      'laravel', 'codeigniter', 'symfony', 'spring',
      
      // Container & DevOps
      'docker', 'kubernetes', 'jenkins', 'gitlab', 'nexus',
      'sonarqube', 'artifactory',
      
      // Security & Monitoring
      'grafana', 'kibana', 'elasticsearch', 'logstash',
      'splunk', 'nagios', 'zabbix',
      
      // Collaboration
      'confluence', 'jira', 'redmine', 'trac'
    ];
    
    return labSuitableKeywords.some(keyword => product.includes(keyword));
  }
}
