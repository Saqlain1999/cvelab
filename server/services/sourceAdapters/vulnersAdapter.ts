import { BaseSourceAdapter } from './baseSourceAdapter';
import { RawCveData, CveDiscoveryOptions } from '../multiSourceCveDiscoveryService';

/**
 * Vulners Adapter - Integrates with vulners.com API
 * Large vulnerability database with free API access and good coverage
 */
export class VulnersAdapter extends BaseSourceAdapter {
  readonly sourceName = 'vulners';
  readonly displayName = 'Vulners';
  readonly baseUrl = 'https://vulners.com/api/v3';
  readonly reliabilityScore = 0.80; // Good reliability and coverage

  constructor() {
    super();
    // Vulners API configuration
    this.config.maxResultsPerPage = 100;
    this.rateLimitState.maxRequests = 100; // Generous free tier
  }

  public supportsHistoricalData(): boolean {
    return true; // Excellent historical coverage
  }

  public supportsRealTimeUpdates(): boolean {
    return true; // Updated regularly
  }

  public getMaxTimeframeYears(): number {
    return 20; // Good historical coverage
  }

  public async discoverCves(options: CveDiscoveryOptions): Promise<RawCveData[]> {
    console.log(`Vulners: Starting discovery with ${options.timeframeYears} year timeframe`);
    
    const allCves: RawCveData[] = [];
    
    try {
      // Vulners search by timeframe
      const cves = await this.searchByTimeframe(options);
      allCves.push(...cves);

      // Additional searches by technology if specified
      if (options.technologies && options.technologies.length > 0) {
        for (const technology of options.technologies.slice(0, 5)) {
          try {
            const techCves = await this.searchByTechnology(technology, options);
            allCves.push(...techCves);
            await this.delay(1000); // Respect rate limits
          } catch (error) {
            console.warn(`Vulners: Failed to search for technology ${technology}:`, error);
          }
        }
      }

      // Search by severity if specified
      if (options.severities && options.severities.length > 0) {
        for (const severity of options.severities) {
          try {
            const severityCves = await this.searchBySeverity(severity, options);
            allCves.push(...severityCves);
            await this.delay(1000);
          } catch (error) {
            console.warn(`Vulners: Failed to search for severity ${severity}:`, error);
          }
        }
      }

      console.log(`Vulners: Discovered ${allCves.length} CVEs`);
      return this.deduplicateResults(allCves);

    } catch (error) {
      console.error('Vulners: Discovery failed:', error);
      return [];
    }
  }

  public async getCveDetails(cveId: string): Promise<RawCveData | null> {
    try {
      console.log(`Vulners: Fetching details for ${cveId}`);
      
      const searchUrl = `${this.baseUrl}/search/id/`;
      const requestBody = {
        id: cveId,
        fields: ['id', 'title', 'description', 'published', 'modified', 'cvss', 'references', 'affectedPackage']
      };

      const response = await this.makeReliableRequest(searchUrl, {
        method: 'POST',
        headers: {
          'Content-Type': 'application/json'
        },
        body: JSON.stringify(requestBody)
      });

      if (!response.ok) {
        throw new Error(`Vulners API error: ${response.status} ${response.statusText}`);
      }

      const data = await response.json();
      
      if (data.result === 'OK' && data.data.documents && data.data.documents.length > 0) {
        return this.transformVulnersDocument(data.data.documents[0]);
      }

      return null;

    } catch (error) {
      console.error(`Vulners: Failed to get details for ${cveId}:`, error);
      return null;
    }
  }

  protected async performHealthCheck(): Promise<boolean> {
    try {
      const response = await this.makeReliableRequest(`${this.baseUrl}/archive/collection/`);
      const data = await response.json();
      return data.result === 'OK';
    } catch (error) {
      return false;
    }
  }

  private async searchByTimeframe(options: CveDiscoveryOptions): Promise<RawCveData[]> {
    try {
      const endDate = new Date();
      const startDate = new Date();
      startDate.setFullYear(startDate.getFullYear() - options.timeframeYears);

      const searchUrl = `${this.baseUrl}/search/lucene/`;
      const query = `type:cve AND published:[${this.formatDateForLucene(startDate)} TO ${this.formatDateForLucene(endDate)}]`;
      
      const requestBody = {
        query: query,
        size: options.maxResultsPerSource || 1000,
        sort: 'published',
        order: 'desc',
        fields: ['id', 'title', 'description', 'published', 'modified', 'cvss', 'references']
      };

      console.log(`Vulners: Searching with query: ${query}`);

      const response = await this.makeReliableRequest(searchUrl, {
        method: 'POST',
        headers: {
          'Content-Type': 'application/json'
        },
        body: JSON.stringify(requestBody)
      });

      if (!response.ok) {
        throw new Error(`Vulners API error: ${response.status} ${response.statusText}`);
      }

      const data = await response.json();
      
      if (data.result === 'OK' && data.data.search) {
        console.log(`Vulners: Found ${data.data.search.length} CVEs in timeframe search`);
        return data.data.search.map((doc: any) => this.transformVulnersDocument(doc));
      }

      return [];

    } catch (error) {
      console.error('Vulners: Timeframe search failed:', error);
      return [];
    }
  }

  private async searchByTechnology(technology: string, options: CveDiscoveryOptions): Promise<RawCveData[]> {
    try {
      const searchUrl = `${this.baseUrl}/search/lucene/`;
      const query = `type:cve AND (title:${technology} OR description:${technology} OR affectedPackage.packageName:${technology})`;
      
      const requestBody = {
        query: query,
        size: 100, // Limit technology-specific searches
        sort: 'published',
        order: 'desc',
        fields: ['id', 'title', 'description', 'published', 'modified', 'cvss', 'references', 'affectedPackage']
      };

      const response = await this.makeReliableRequest(searchUrl, {
        method: 'POST',
        headers: {
          'Content-Type': 'application/json'
        },
        body: JSON.stringify(requestBody)
      });

      if (!response.ok) {
        throw new Error(`Vulners API error: ${response.status} ${response.statusText}`);
      }

      const data = await response.json();
      
      if (data.result === 'OK' && data.data.search) {
        console.log(`Vulners: Found ${data.data.search.length} CVEs for technology ${technology}`);
        return data.data.search.map((doc: any) => this.transformVulnersDocument(doc));
      }

      return [];

    } catch (error) {
      console.error(`Vulners: Technology search failed for ${technology}:`, error);
      return [];
    }
  }

  private async searchBySeverity(severity: string, options: CveDiscoveryOptions): Promise<RawCveData[]> {
    try {
      const searchUrl = `${this.baseUrl}/search/lucene/`;
      
      // Map severity to CVSS score ranges
      const severityRanges: Record<string, string> = {
        'CRITICAL': '[9.0 TO 10.0]',
        'HIGH': '[7.0 TO 8.9]',
        'MEDIUM': '[4.0 TO 6.9]',
        'LOW': '[0.1 TO 3.9]'
      };

      const scoreRange = severityRanges[severity.toUpperCase()];
      if (!scoreRange) {
        console.warn(`Vulners: Unknown severity level: ${severity}`);
        return [];
      }

      const query = `type:cve AND cvss.score:${scoreRange}`;
      
      const requestBody = {
        query: query,
        size: 200, // Limit severity searches
        sort: 'published',
        order: 'desc',
        fields: ['id', 'title', 'description', 'published', 'modified', 'cvss', 'references']
      };

      const response = await this.makeReliableRequest(searchUrl, {
        method: 'POST',
        headers: {
          'Content-Type': 'application/json'
        },
        body: JSON.stringify(requestBody)
      });

      if (!response.ok) {
        throw new Error(`Vulners API error: ${response.status} ${response.statusText}`);
      }

      const data = await response.json();
      
      if (data.result === 'OK' && data.data.search) {
        console.log(`Vulners: Found ${data.data.search.length} CVEs for severity ${severity}`);
        return data.data.search.map((doc: any) => this.transformVulnersDocument(doc));
      }

      return [];

    } catch (error) {
      console.error(`Vulners: Severity search failed for ${severity}:`, error);
      return [];
    }
  }

  private transformVulnersDocument(doc: any): RawCveData {
    // Extract CVE ID from document
    const cveId = doc.id || doc._id || 'UNKNOWN';
    
    // Parse CVSS information
    let cvssScore: number | null = null;
    let cvssVector: string | null = null;
    let severity = 'UNKNOWN';

    if (doc.cvss) {
      if (typeof doc.cvss === 'object') {
        cvssScore = this.parseCvssScore(doc.cvss.score || doc.cvss.baseScore);
        cvssVector = doc.cvss.vector || doc.cvss.vectorString || null;
        severity = this.deriveSeverityFromScore(cvssScore);
      } else if (typeof doc.cvss === 'number') {
        cvssScore = this.parseCvssScore(doc.cvss);
        severity = this.deriveSeverityFromScore(cvssScore);
      }
    }

    // Extract affected products
    const affectedProducts: string[] = [];
    if (doc.affectedPackage) {
      if (Array.isArray(doc.affectedPackage)) {
        for (const pkg of doc.affectedPackage) {
          if (pkg.packageName) {
            affectedProducts.push(pkg.packageName);
          }
        }
      } else if (doc.affectedPackage.packageName) {
        affectedProducts.push(doc.affectedPackage.packageName);
      }
    }

    // Extract references
    const references: string[] = [];
    if (doc.references) {
      if (Array.isArray(doc.references)) {
        references.push(...doc.references);
      } else if (typeof doc.references === 'string') {
        references.push(doc.references);
      }
    }

    const cve: RawCveData = {
      cveId: cveId,
      source: this.sourceName,
      sourceUrl: `https://vulners.com/cve/${cveId}`,
      description: this.cleanDescription(doc.description || doc.title || 'No description available'),
      publishedDate: this.parseDate(doc.published),
      lastModifiedDate: this.parseDate(doc.modified || doc.published),
      cvssScore: cvssScore,
      cvssVector: cvssVector,
      severity: severity,
      affectedProducts: affectedProducts.length > 0 ? affectedProducts : undefined,
      references: references.length > 0 ? references : undefined,
      sourceMetadata: {
        vulnersId: doc._id || doc.id,
        vulnersType: doc.type,
        vulnersTitle: doc.title,
        extractionDate: new Date().toISOString(),
        hasDetailedCvss: !!doc.cvss,
        affectedPackageCount: Array.isArray(doc.affectedPackage) ? doc.affectedPackage.length : (doc.affectedPackage ? 1 : 0)
      },
      rawData: {
        vulnersDocument: doc
      }
    };

    return cve;
  }

  private formatDateForLucene(date: Date): string {
    return date.toISOString().split('T')[0] + 'T00:00:00Z';
  }

  private deriveSeverityFromScore(score: number | null): string {
    if (!score) return 'UNKNOWN';
    
    if (score >= 9.0) return 'CRITICAL';
    if (score >= 7.0) return 'HIGH';
    if (score >= 4.0) return 'MEDIUM';
    return 'LOW';
  }

  private deduplicateResults(cves: RawCveData[]): RawCveData[] {
    const seen = new Set<string>();
    const deduplicated: RawCveData[] = [];
    
    for (const cve of cves) {
      if (!seen.has(cve.cveId)) {
        seen.add(cve.cveId);
        deduplicated.push(cve);
      }
    }
    
    return deduplicated;
  }

  private delay(ms: number): Promise<void> {
    return new Promise(resolve => setTimeout(resolve, ms));
  }
}