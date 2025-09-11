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

export class CveService {
  private readonly BASE_URL = 'https://services.nvd.nist.gov/rest/json/cves/2.0';
  
  async fetchCvesFromNist(timeframeYears: number = 3): Promise<any[]> {
    const startDate = new Date();
    startDate.setFullYear(startDate.getFullYear() - timeframeYears);
    startDate.setHours(0, 0, 0, 0);
    
    const endDate = new Date();
    endDate.setHours(23, 59, 59, 999);
    
    const params = new URLSearchParams({
      pubStartDate: startDate.toISOString(),
      pubEndDate: endDate.toISOString(),
      resultsPerPage: '2000'
    });

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
      return this.transformNistData(data.vulnerabilities);
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
    
    if (description.includes('wordpress') || description.includes('drupal') || description.includes('joomla')) {
      return 'CMS';
    }
    if (description.includes('apache') || description.includes('nginx') || description.includes('iis')) {
      return 'Web Server';
    }
    if (description.includes('ssh') || description.includes('ftp') || description.includes('smtp')) {
      return 'Network Service';
    }
    if (description.includes('mysql') || description.includes('postgresql') || description.includes('mongodb')) {
      return 'Database';
    }
    if (description.includes('docker') || description.includes('kubernetes')) {
      return 'Container';
    }
    if (description.includes('firewall') || description.includes('proxy') || description.includes('gateway')) {
      return 'Network Security';
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
}
