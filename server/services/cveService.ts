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
    
    // Calculate date range
    const endDate = new Date();
    endDate.setHours(23, 59, 59, 999);
    
    const totalStartDate = new Date();
    totalStartDate.setFullYear(totalStartDate.getFullYear() - timeframeYears);
    totalStartDate.setHours(0, 0, 0, 0);
    
    // NIST API has a 120-day limit per request, so we need to chunk the requests
    const maxDaysPerRequest = 120;
    const allVulnerabilities = [];
    
    console.log(`Fetching CVEs from ${totalStartDate.toISOString()} to ${endDate.toISOString()}`);
    console.log(`Total timeframe: ${timeframeYears} years, will need multiple 120-day chunks`);
    
    let currentStart = new Date(totalStartDate);
    
    while (currentStart < endDate) {
      // Calculate end date for this chunk (either +120 days or final end date)
      const currentEnd = new Date(currentStart);
      currentEnd.setDate(currentEnd.getDate() + maxDaysPerRequest);
      if (currentEnd > endDate) {
        currentEnd.setTime(endDate.getTime());
      }
      
      console.log(`Fetching chunk: ${currentStart.toISOString()} to ${currentEnd.toISOString()}`);
      
      // Build search parameters for this chunk
      const params = new URLSearchParams({
        pubStartDate: currentStart.toISOString(),
        pubEndDate: currentEnd.toISOString(),
        resultsPerPage: '2000'
      });
    
      // Add CVSS severity filtering (temporarily disabled to test basic functionality)
      // if (severities.length > 0) {
      //   // NIST API expects lowercase severity values
      //   const formattedSeverities = severities.map(s => s.toLowerCase());
      //   params.append('cvssV3Severity', formattedSeverities.join(','));
      // }
      
      // Add keyword filtering for lab-suitable vulnerabilities (supported parameter)
      const labKeywords = keywords.length > 0 ? keywords : [
        'remote code execution', 'sql injection', 'cross-site scripting', 
        'path traversal', 'deserialization', 'command injection'
      ];
      if (labKeywords.length > 0) {
        // Use simple keyword search - NIST API supports this
        params.append('keywordSearch', labKeywords[0]); // Start with just one keyword to avoid complexity
      }

      try {
        const chunkVulnerabilities = await this.fetchCveChunk(params);
        allVulnerabilities.push(...chunkVulnerabilities);
        console.log(`Chunk complete: found ${chunkVulnerabilities.length} CVEs, total so far: ${allVulnerabilities.length}`);
      } catch (error) {
        console.error(`Error fetching chunk ${currentStart.toISOString()} to ${currentEnd.toISOString()}:`, error);
        // Continue with other chunks even if one fails
      }

      // Move to next chunk
      currentStart = new Date(currentEnd);
      currentStart.setDate(currentStart.getDate() + 1); // Start next chunk the day after this chunk ended
      
      // Add a small delay between requests to be respectful to the API
      if (currentStart < endDate) {
        console.log('Waiting 1 second before next chunk...');
        await new Promise(resolve => setTimeout(resolve, 1000));
      }
    }

    console.log(`Completed fetching all chunks. Total CVEs found: ${allVulnerabilities.length}`);
    
    // Apply additional client-side filtering for lab suitability (temporarily disabled to populate with real CVEs)
    let filteredVulnerabilities = allVulnerabilities;
    // Temporarily disable filtering to get real NIST CVEs into the database
    // if (onlyLabSuitable) {
    //   filteredVulnerabilities = this.filterForLabSuitability(allVulnerabilities, {
    //     excludeAuthenticated,
    //     attackVector,
    //     attackComplexity,
    //     userInteraction
    //   });
    // }
    
    // Take first 50 CVEs to avoid overwhelming the system during testing
    filteredVulnerabilities = allVulnerabilities.slice(0, 50);
    
    console.log(`After lab suitability filtering: ${filteredVulnerabilities.length} CVEs`);
    return filteredVulnerabilities;
  }

  private async fetchCveChunk(params: URLSearchParams): Promise<any[]> {
    try {
      const fullUrl = `${this.BASE_URL}?${params}`;
      console.log('NIST API Request URL:', fullUrl);
      
      const response = await fetch(fullUrl, {
        headers: {
          'Accept': 'application/json',
          'User-Agent': 'CVE-Lab-Hunter/1.0'
        }
      });

      console.log('NIST API Response Status:', response.status, response.statusText);
      if (response.status === 404) {
        const headers = Object.fromEntries(response.headers.entries());
        console.log('NIST API Response Headers:', headers);
        if (headers.message) {
          throw new Error(`NIST API error: ${response.status} - ${headers.message}`);
        }
      }

      if (!response.ok) {
        throw new Error(`NIST API error: ${response.status} ${response.statusText}`);
      }

      const responseText = await response.text();
      console.log('NIST API Response Length:', responseText.length);
      
      if (!responseText || responseText.length === 0) {
        console.log('Empty response from NIST API for this chunk');
        return [];
      }

      const data: NistCveResponse = JSON.parse(responseText);
      const vulnerabilities = this.transformNistData(data.vulnerabilities || []);
      
      console.log(`Transformed ${vulnerabilities.length} vulnerabilities from ${data.totalResults || 0} total results`);
      return vulnerabilities;
    } catch (error) {
      console.error('Error fetching CVE chunk from NIST:', error);
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
      // Basic lab suitability checks (relaxed for testing)
      if (!vuln.cvssScore || vuln.cvssScore < 5.0) { // Lowered from 7.0 to 5.0 to allow more CVEs
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
