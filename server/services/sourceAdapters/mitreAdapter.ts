import { BaseSourceAdapter } from './baseSourceAdapter';
import { RawCveData, CveDiscoveryOptions } from '../multiSourceCveDiscoveryService';

/**
 * MITRE CVE Adapter - Integrates with cve.mitre.org
 * Official CVE source with authoritative data and JSON feeds
 */
export class MitreAdapter extends BaseSourceAdapter {
  readonly sourceName = 'mitre';
  readonly displayName = 'MITRE CVE';
  readonly baseUrl = 'https://cve.mitre.org';
  readonly reliabilityScore = 0.95; // Highest reliability as official source

  private readonly cveListBaseUrl = 'https://cve.mitre.org/data/downloads';
  private readonly cveApiBaseUrl = 'https://services.nvd.nist.gov/rest/json/cves/2.0'; // Fallback to NVD for API access

  constructor() {
    super();
    // MITRE specific configuration
    this.config.maxResultsPerPage = 2000; // Large batches for JSON downloads
    this.rateLimitState.maxRequests = 20; // Conservative for official source
  }

  public supportsHistoricalData(): boolean {
    return true; // Complete historical coverage since CVE inception
  }

  public supportsRealTimeUpdates(): boolean {
    return true; // Updated regularly
  }

  public getMaxTimeframeYears(): number {
    return 30; // Covers all CVEs since program started
  }

  public async discoverCves(options: CveDiscoveryOptions): Promise<RawCveData[]> {
    console.log(`MITRE: Starting discovery with ${options.timeframeYears} year timeframe`);
    
    const allCves: RawCveData[] = [];
    
    try {
      // MITRE approach: Use year-based JSON feeds
      const currentYear = new Date().getFullYear();
      const startYear = currentYear - options.timeframeYears;
      
      for (let year = startYear; year <= currentYear; year++) {
        console.log(`MITRE: Fetching CVEs for year ${year}`);
        
        try {
          const yearCves = await this.fetchCvesForYear(year, options);
          allCves.push(...yearCves);
          
          // Small delay between year requests
          if (year < currentYear) {
            await this.delay(1000);
          }
        } catch (error) {
          console.warn(`MITRE: Failed to fetch CVEs for year ${year}:`, error);
          continue;
        }
      }

      console.log(`MITRE: Discovered ${allCves.length} CVEs`);
      return this.filterAndLimitResults(allCves, options);

    } catch (error) {
      console.error('MITRE: Discovery failed:', error);
      return [];
    }
  }

  public async getCveDetails(cveId: string): Promise<RawCveData | null> {
    try {
      console.log(`MITRE: Fetching details for ${cveId}`);
      
      // Try MITRE's direct CVE entry first
      const mitreUrl = `${this.baseUrl}/cgi-bin/cvename.cgi?name=${cveId}`;
      
      try {
        const response = await this.makeReliableRequest(mitreUrl);
        const html = await response.text();
        
        if (html.includes('ERROR') || html.includes('not found')) {
          throw new Error('CVE not found in MITRE');
        }
        
        return this.parseMitreCvePage(html, cveId);
        
      } catch (error) {
        console.warn(`MITRE: Direct lookup failed for ${cveId}, trying NVD fallback:`, error);
        
        // Fallback to NVD API for structured data
        return await this.getCveDetailsFromNvd(cveId);
      }

    } catch (error) {
      console.error(`MITRE: Failed to get details for ${cveId}:`, error);
      return null;
    }
  }

  protected async performHealthCheck(): Promise<boolean> {
    try {
      const response = await this.makeReliableRequest(`${this.baseUrl}/`);
      return response.status === 200 && response.url.includes('mitre.org');
    } catch (error) {
      return false;
    }
  }

  private async fetchCvesForYear(year: number, options: CveDiscoveryOptions): Promise<RawCveData[]> {
    try {
      // Try different MITRE year feed formats
      const feedUrls = [
        `${this.cveListBaseUrl}/allitems-cvrf-year-${year}.xml`,
        `https://cve.mitre.org/data/refs/refmap/source-${year}.html`,
        `https://cve.mitre.org/cgi-bin/cvekey.cgi?keyword=${year}`
      ];

      for (const feedUrl of feedUrls) {
        try {
          console.log(`MITRE: Trying year feed: ${feedUrl}`);
          
          const response = await this.makeReliableRequest(feedUrl);
          
          if (!response.ok) {
            continue; // Try next feed format
          }
          
          const content = await response.text();
          
          if (feedUrl.includes('.xml')) {
            return this.parseXmlFeed(content, year);
          } else {
            return this.parseHtmlFeed(content, year);
          }
          
        } catch (error) {
          console.warn(`MITRE: Failed to fetch from ${feedUrl}:`, error);
          continue;
        }
      }

      // If all MITRE feeds fail, fallback to NVD for the year
      console.log(`MITRE: All feeds failed for ${year}, using NVD fallback`);
      return await this.fetchYearFromNvdFallback(year, options);

    } catch (error) {
      console.error(`MITRE: Failed to fetch year ${year}:`, error);
      return [];
    }
  }

  private async fetchYearFromNvdFallback(year: number, options: CveDiscoveryOptions): Promise<RawCveData[]> {
    try {
      const startDate = new Date(year, 0, 1);
      const endDate = new Date(year, 11, 31);
      
      const params = new URLSearchParams({
        pubStartDate: startDate.toISOString(),
        pubEndDate: endDate.toISOString(),
        resultsPerPage: '2000'
      });

      const nvdUrl = `${this.cveApiBaseUrl}?${params}`;
      
      const response = await this.makeReliableRequest(nvdUrl);
      
      if (!response.ok) {
        throw new Error(`NVD API error: ${response.status}`);
      }

      const data = await response.json();
      
      if (data.vulnerabilities) {
        console.log(`MITRE (NVD fallback): Found ${data.vulnerabilities.length} CVEs for year ${year}`);
        return data.vulnerabilities.map((vuln: any) => this.transformNvdVulnerability(vuln.cve));
      }

      return [];

    } catch (error) {
      console.error(`MITRE: NVD fallback failed for year ${year}:`, error);
      return [];
    }
  }

  private parseXmlFeed(xmlContent: string, year: number): RawCveData[] {
    const cves: RawCveData[] = [];
    
    try {
      // Simple XML parsing for CVE IDs and basic info
      const cvePattern = /<vuln:CVE-ID>([^<]+)<\/vuln:CVE-ID>/g;
      const descPattern = /<vuln:Summary>([^<]+)<\/vuln:Summary>/g;
      
      let cveMatch;
      const cveIds: string[] = [];
      while ((cveMatch = cvePattern.exec(xmlContent)) !== null) {
        cveIds.push(cveMatch[1]);
      }
      
      let descMatch;
      const descriptions: string[] = [];
      while ((descMatch = descPattern.exec(xmlContent)) !== null) {
        descriptions.push(descMatch[1]);
      }
      
      // Combine CVE IDs with descriptions
      for (let i = 0; i < cveIds.length; i++) {
        const cveId = cveIds[i];
        const description = descriptions[i] || 'No description available';
        
        const cve: RawCveData = {
          cveId: cveId,
          source: this.sourceName,
          sourceUrl: `${this.baseUrl}/cgi-bin/cvename.cgi?name=${cveId}`,
          description: this.cleanDescription(description),
          publishedDate: new Date(year, 0, 1), // Approximate, would need detail fetch for exact
          lastModifiedDate: new Date(year, 0, 1),
          severity: 'UNKNOWN', // Would need additional lookup
          sourceMetadata: {
            extractedFromXmlFeed: true,
            feedYear: year,
            needsDetailFetch: true,
            extractionDate: new Date().toISOString()
          },
          rawData: {
            feedType: 'xml',
            feedYear: year
          }
        };
        
        cves.push(cve);
      }

    } catch (error) {
      console.error('MITRE: Failed to parse XML feed:', error);
    }
    
    return cves;
  }

  private parseHtmlFeed(htmlContent: string, year: number): RawCveData[] {
    const cves: RawCveData[] = [];
    
    try {
      // Extract CVE IDs from HTML content
      const cvePattern = /(CVE-\d{4}-\d+)/g;
      const matches = htmlContent.match(cvePattern);
      
      if (matches) {
        const uniqueCveIds = [...new Set(matches)];
        
        for (const cveId of uniqueCveIds) {
          const cve: RawCveData = {
            cveId: cveId,
            source: this.sourceName,
            sourceUrl: `${this.baseUrl}/cgi-bin/cvename.cgi?name=${cveId}`,
            description: 'Description available via detail fetch',
            publishedDate: new Date(year, 0, 1),
            lastModifiedDate: new Date(year, 0, 1),
            severity: 'UNKNOWN',
            sourceMetadata: {
              extractedFromHtmlFeed: true,
              feedYear: year,
              needsDetailFetch: true,
              extractionDate: new Date().toISOString()
            },
            rawData: {
              feedType: 'html',
              feedYear: year
            }
          };
          
          cves.push(cve);
        }
      }

    } catch (error) {
      console.error('MITRE: Failed to parse HTML feed:', error);
    }
    
    return cves;
  }

  private transformNvdVulnerability(cve: any): RawCveData {
    const metrics = cve.metrics?.cvssMetricV31?.[0] || cve.metrics?.cvssMetricV3?.[0] || cve.metrics?.cvssMetricV2?.[0];
    
    return {
      cveId: cve.id,
      source: this.sourceName,
      sourceUrl: `${this.baseUrl}/cgi-bin/cvename.cgi?name=${cve.id}`,
      description: this.cleanDescription(cve.descriptions?.find((d: any) => d.lang === 'en')?.value || 'No description available'),
      publishedDate: this.parseDate(cve.published),
      lastModifiedDate: this.parseDate(cve.lastModified),
      cvssScore: this.parseCvssScore(metrics?.cvssData?.baseScore),
      cvssVector: metrics?.cvssData?.vectorString || null,
      severity: this.normalizeSeverity(metrics?.cvssData?.baseSeverity) || 'UNKNOWN',
      references: cve.references?.map((ref: any) => ref.url) || [],
      sourceMetadata: {
        nvdFallback: true,
        mitreAuthoritative: true,
        hasNvdMetrics: !!metrics,
        extractionDate: new Date().toISOString()
      },
      rawData: {
        nvdVulnerability: cve,
        source: 'mitre_via_nvd'
      }
    };
  }

  private parseMitreCvePage(html: string, cveId: string): RawCveData | null {
    try {
      // Parse MITRE CVE page
      const description = this.extractDescriptionFromMitre(html);
      const publishedDate = this.extractDateFromMitre(html);
      const references = this.extractReferencesFromMitre(html);
      
      const cve: RawCveData = {
        cveId: cveId,
        source: this.sourceName,
        sourceUrl: `${this.baseUrl}/cgi-bin/cvename.cgi?name=${cveId}`,
        description: description || 'No description available',
        publishedDate: publishedDate || new Date(),
        lastModifiedDate: publishedDate || new Date(),
        severity: 'UNKNOWN', // MITRE doesn't always provide severity
        references: references,
        sourceMetadata: {
          mitreDirectLookup: true,
          authoritative: true,
          extractionDate: new Date().toISOString()
        },
        rawData: {
          mitreHtmlPage: true
        }
      };
      
      return cve;

    } catch (error) {
      console.error(`MITRE: Failed to parse CVE page for ${cveId}:`, error);
      return null;
    }
  }

  private async getCveDetailsFromNvd(cveId: string): Promise<RawCveData | null> {
    try {
      const params = new URLSearchParams({
        cveId: cveId
      });

      const nvdUrl = `${this.cveApiBaseUrl}?${params}`;
      
      const response = await this.makeReliableRequest(nvdUrl);
      
      if (!response.ok) {
        throw new Error(`NVD API error: ${response.status}`);
      }

      const data = await response.json();
      
      if (data.vulnerabilities && data.vulnerabilities.length > 0) {
        return this.transformNvdVulnerability(data.vulnerabilities[0].cve);
      }

      return null;

    } catch (error) {
      console.error(`MITRE: NVD detail lookup failed for ${cveId}:`, error);
      return null;
    }
  }

  // MITRE HTML parsing helpers
  private extractDescriptionFromMitre(html: string): string | null {
    const patterns = [
      /<td[^>]*>\s*Description\s*<\/td>\s*<td[^>]*>(.*?)<\/td>/is,
      /<th[^>]*>\s*Description\s*<\/th>\s*<td[^>]*>(.*?)<\/td>/is,
      /<b>\s*Description\s*<\/b>[^<]*<[^>]*>(.*?)<\/[^>]*>/is
    ];
    
    for (const pattern of patterns) {
      const match = html.match(pattern);
      if (match) {
        return this.cleanDescription(match[1].replace(/<[^>]*>/g, ' '));
      }
    }
    
    return null;
  }

  private extractDateFromMitre(html: string): Date | null {
    const patterns = [
      /Date\s*:\s*(\d{4}-\d{2}-\d{2})/i,
      /Published\s*:\s*(\d{4}-\d{2}-\d{2})/i,
      /(\d{4}-\d{2}-\d{2})/
    ];
    
    for (const pattern of patterns) {
      const match = html.match(pattern);
      if (match) {
        return this.parseDate(match[1]);
      }
    }
    
    return null;
  }

  private extractReferencesFromMitre(html: string): string[] {
    const references: string[] = [];
    
    // Look for reference URLs
    const urlPattern = /https?:\/\/[^\s<>"']+/g;
    const matches = html.match(urlPattern);
    
    if (matches) {
      for (const url of matches) {
        if (!url.includes('mitre.org') && !url.includes('cve.mitre.org')) {
          references.push(url);
        }
      }
    }
    
    return [...new Set(references)]; // Remove duplicates
  }

  private filterAndLimitResults(cves: RawCveData[], options: CveDiscoveryOptions): RawCveData[] {
    let filtered = cves;
    
    // Filter by severity if specified
    if (options.severities && options.severities.length > 0) {
      filtered = filtered.filter(cve => 
        options.severities!.includes(cve.severity) || cve.severity === 'UNKNOWN'
      );
    }
    
    // Filter by keywords if specified
    if (options.keywords && options.keywords.length > 0) {
      filtered = filtered.filter(cve => {
        const searchText = `${cve.description} ${cve.cveId}`.toLowerCase();
        return options.keywords!.some(keyword => 
          searchText.includes(keyword.toLowerCase())
        );
      });
    }
    
    // Limit results
    const maxResults = options.maxResultsPerSource || 1000;
    return filtered.slice(0, maxResults);
  }

  private delay(ms: number): Promise<void> {
    return new Promise(resolve => setTimeout(resolve, ms));
  }
}