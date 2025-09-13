import { BaseSourceAdapter } from './baseSourceAdapter';
import { RawCveData, CveDiscoveryOptions } from '../multiSourceCveDiscoveryService';

/**
 * CVE Details Adapter - Integrates with cvedetails.com
 * Free, comprehensive CVE database with detailed statistics and historical data
 */
export class CveDetailsAdapter extends BaseSourceAdapter {
  readonly sourceName = 'cvedetails';
  readonly displayName = 'CVE Details';
  readonly baseUrl = 'https://www.cvedetails.com';
  readonly reliabilityScore = 0.85; // High reliability for well-established database

  constructor() {
    super();
    // CVE Details specific configuration
    this.config.maxResultsPerPage = 50;
    this.rateLimitState.maxRequests = 30; // Conservative rate limiting for scraping
  }

  public supportsHistoricalData(): boolean {
    return true; // Excellent historical coverage
  }

  public supportsRealTimeUpdates(): boolean {
    return false; // Updated daily/weekly
  }

  public getMaxTimeframeYears(): number {
    return 25; // Covers CVEs back to 1999
  }

  public async discoverCves(options: CveDiscoveryOptions): Promise<RawCveData[]> {
    console.log(`CVE Details: Starting discovery with ${options.timeframeYears} year timeframe`);
    
    const allCves: RawCveData[] = [];
    
    try {
      // CVE Details uses a structured approach - search by year and severity
      const currentYear = new Date().getFullYear();
      const startYear = currentYear - options.timeframeYears;
      
      for (let year = startYear; year <= currentYear; year++) {
        console.log(`CVE Details: Fetching CVEs for year ${year}`);
        
        try {
          const yearCves = await this.fetchCvesForYear(year, options);
          allCves.push(...yearCves);
          
          // Respect rate limits between year requests
          if (year < currentYear) {
            await this.delay(2000); // 2 second delay between years
          }
        } catch (error) {
          console.warn(`CVE Details: Failed to fetch CVEs for year ${year}:`, error);
          continue; // Continue with other years
        }
      }

      // Also try searching by specific technologies if provided
      if (options.technologies && options.technologies.length > 0) {
        for (const technology of options.technologies.slice(0, 3)) { // Limit to prevent overloading
          try {
            const techCves = await this.searchByTechnology(technology, options);
            allCves.push(...techCves);
            await this.delay(2000);
          } catch (error) {
            console.warn(`CVE Details: Failed to search for technology ${technology}:`, error);
          }
        }
      }

      console.log(`CVE Details: Discovered ${allCves.length} CVEs`);
      return this.deduplicateResults(allCves);

    } catch (error) {
      console.error('CVE Details: Discovery failed:', error);
      return [];
    }
  }

  public async getCveDetails(cveId: string): Promise<RawCveData | null> {
    try {
      // Extract CVE number from ID (e.g., CVE-2024-12345 -> 12345)
      const cveMatch = cveId.match(/CVE-(\d{4})-(\d+)/);
      if (!cveMatch) {
        console.warn(`CVE Details: Invalid CVE ID format: ${cveId}`);
        return null;
      }

      const [, year, number] = cveMatch;
      const detailUrl = `${this.baseUrl}/cve/${cveId}/`;
      
      console.log(`CVE Details: Fetching details for ${cveId}`);
      
      const response = await this.makeReliableRequest(detailUrl);
      const html = await response.text();
      
      return this.parseCveDetailPage(html, cveId);

    } catch (error) {
      console.error(`CVE Details: Failed to get details for ${cveId}:`, error);
      return null;
    }
  }

  protected async performHealthCheck(): Promise<boolean> {
    try {
      const response = await this.makeReliableRequest(`${this.baseUrl}/browse-by-date.php`);
      return response.status === 200;
    } catch (error) {
      return false;
    }
  }

  private async fetchCvesForYear(year: number, options: CveDiscoveryOptions): Promise<RawCveData[]> {
    const cves: RawCveData[] = [];
    
    // CVE Details year browsing URL
    const yearUrl = `${this.baseUrl}/vulnerability-list/year-${year}/vulnerabilities.html`;
    
    try {
      const response = await this.makeReliableRequest(yearUrl);
      const html = await response.text();
      
      const yearCves = this.parseYearListPage(html, year);
      
      // Filter by severity if specified
      if (options.severities && options.severities.length > 0) {
        const filteredCves = yearCves.filter(cve => 
          options.severities!.includes(cve.severity)
        );
        cves.push(...filteredCves);
      } else {
        cves.push(...yearCves);
      }

      // Limit results per year to prevent overloading
      const maxPerYear = Math.floor((options.maxResultsPerSource || 500) / options.timeframeYears);
      return cves.slice(0, maxPerYear);

    } catch (error) {
      console.error(`CVE Details: Failed to fetch year ${year}:`, error);
      return [];
    }
  }

  private async searchByTechnology(technology: string, options: CveDiscoveryOptions): Promise<RawCveData[]> {
    try {
      // CVE Details vendor search
      const searchUrl = `${this.baseUrl}/vendor-search.php?search=${encodeURIComponent(technology)}`;
      
      const response = await this.makeReliableRequest(searchUrl);
      const html = await response.text();
      
      return this.parseSearchResults(html, technology);

    } catch (error) {
      console.error(`CVE Details: Technology search failed for ${technology}:`, error);
      return [];
    }
  }

  private parseYearListPage(html: string, year: number): RawCveData[] {
    const cves: RawCveData[] = [];
    
    try {
      // CVE Details uses table structure for CVE listings
      // This is a simplified parser - in production you'd want a more robust HTML parser
      const cvePattern = /(CVE-\d{4}-\d+)/g;
      const matches = html.match(cvePattern);
      
      if (matches) {
        for (const cveId of matches) {
          // Basic CVE structure for year listing
          // More details would be fetched via getCveDetails if needed
          const cve: RawCveData = {
            cveId: cveId,
            source: this.sourceName,
            sourceUrl: `${this.baseUrl}/cve/${cveId}/`,
            description: 'Description available via detail fetch', // Would need detail fetch for full description
            publishedDate: new Date(year, 0, 1), // Approximate date, would need detail fetch for exact
            lastModifiedDate: new Date(year, 0, 1),
            severity: 'UNKNOWN', // Would need detail fetch for severity
            sourceMetadata: {
              yearListExtracted: true,
              needsDetailFetch: true,
              extractionDate: new Date().toISOString()
            },
            rawData: {
              extractedFromYearList: true
            }
          };
          
          cves.push(cve);
        }
      }

    } catch (error) {
      console.error('CVE Details: Failed to parse year list page:', error);
    }
    
    return cves.slice(0, 100); // Limit to prevent overloading
  }

  private parseSearchResults(html: string, technology: string): RawCveData[] {
    const cves: RawCveData[] = [];
    
    try {
      // Parse vendor/technology search results
      const cvePattern = /(CVE-\d{4}-\d+)/g;
      const matches = html.match(cvePattern);
      
      if (matches) {
        for (const cveId of matches) {
          const cve: RawCveData = {
            cveId: cveId,
            source: this.sourceName,
            sourceUrl: `${this.baseUrl}/cve/${cveId}/`,
            description: `CVE affecting ${technology}`,
            publishedDate: new Date(),
            lastModifiedDate: new Date(),
            severity: 'UNKNOWN',
            affectedProducts: [technology],
            sourceMetadata: {
              searchTechnology: technology,
              needsDetailFetch: true,
              extractionDate: new Date().toISOString()
            },
            rawData: {
              searchMethod: 'technology',
              searchTerm: technology
            }
          };
          
          cves.push(cve);
        }
      }

    } catch (error) {
      console.error('CVE Details: Failed to parse search results:', error);
    }
    
    return cves.slice(0, 50); // Limit technology search results
  }

  private parseCveDetailPage(html: string, cveId: string): RawCveData | null {
    try {
      // Parse individual CVE detail page
      // This would extract detailed information from the CVE Details page structure
      
      const cve: RawCveData = {
        cveId: cveId,
        source: this.sourceName,
        sourceUrl: `${this.baseUrl}/cve/${cveId}/`,
        description: this.extractDescription(html) || 'No description available',
        publishedDate: this.extractPublishedDate(html) || new Date(),
        lastModifiedDate: this.extractLastModifiedDate(html) || new Date(),
        cvssScore: this.extractCvssScore(html),
        severity: this.extractSeverity(html) || 'UNKNOWN',
        affectedProducts: this.extractAffectedProducts(html),
        references: this.extractReferences(html),
        sourceMetadata: {
          detailPageParsed: true,
          extractionDate: new Date().toISOString(),
          hasDetailedInfo: true
        },
        rawData: {
          detailPageExtracted: true
        }
      };
      
      return cve;

    } catch (error) {
      console.error(`CVE Details: Failed to parse detail page for ${cveId}:`, error);
      return null;
    }
  }

  // HTML parsing helper methods (simplified implementations)
  private extractDescription(html: string): string | null {
    // Look for description in CVE Details page structure
    const descPattern = /<div[^>]*class="[^"]*description[^"]*"[^>]*>(.*?)<\/div>/is;
    const match = html.match(descPattern);
    return match ? this.cleanDescription(match[1]) : null;
  }

  private extractPublishedDate(html: string): Date | null {
    // Look for published date in various formats
    const datePatterns = [
      /Published[:\s]*(\d{4}-\d{2}-\d{2})/i,
      /Date[:\s]*(\d{4}-\d{2}-\d{2})/i
    ];
    
    for (const pattern of datePatterns) {
      const match = html.match(pattern);
      if (match) {
        return this.parseDate(match[1]);
      }
    }
    
    return null;
  }

  private extractLastModifiedDate(html: string): Date | null {
    const modPattern = /Modified[:\s]*(\d{4}-\d{2}-\d{2})/i;
    const match = html.match(modPattern);
    return match ? this.parseDate(match[1]) : null;
  }

  private extractCvssScore(html: string): number | null {
    const cvssPattern = /CVSS[:\s]*(\d+\.?\d*)/i;
    const match = html.match(cvssPattern);
    return match ? this.parseCvssScore(match[1]) : null;
  }

  private extractSeverity(html: string): string | null {
    const severityPattern = /Severity[:\s]*(critical|high|medium|low)/i;
    const match = html.match(severityPattern);
    return match ? this.normalizeSeverity(match[1]) : null;
  }

  private extractAffectedProducts(html: string): string[] {
    const products: string[] = [];
    
    // Look for product names in various sections
    const productPatterns = [
      /Product[:\s]*([^<\n]+)/gi,
      /Vendor[:\s]*([^<\n]+)/gi
    ];
    
    for (const pattern of productPatterns) {
      const matches = html.matchAll(pattern);
      for (const match of matches) {
        const product = match[1].trim();
        if (product && product.length > 2) {
          products.push(product);
        }
      }
    }
    
    return [...new Set(products)]; // Remove duplicates
  }

  private extractReferences(html: string): string[] {
    const references: string[] = [];
    
    // Look for reference URLs
    const urlPattern = /https?:\/\/[^\s<>"]+/g;
    const matches = html.match(urlPattern);
    
    if (matches) {
      for (const url of matches) {
        if (!url.includes('cvedetails.com')) { // Exclude self-references
          references.push(url);
        }
      }
    }
    
    return [...new Set(references)]; // Remove duplicates
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