// Multi-Source CVE Discovery Adapters
// This module exports all available CVE source adapters

// Import all source adapters
import { BaseSourceAdapter } from './baseSourceAdapter';
import { NistAdapter } from './nistAdapter';
import { CveDetailsAdapter } from './cveDetailsAdapter';
import { VulnersAdapter } from './vulnersAdapter';
import { MitreAdapter } from './mitreAdapter';
import { CirclAdapter } from './circlAdapter';
import { ExploitDbAdapter } from './exploitDbAdapter';

// Re-export for external use
export { BaseSourceAdapter } from './baseSourceAdapter';
export { NistAdapter } from './nistAdapter';
export { CveDetailsAdapter } from './cveDetailsAdapter';
export { VulnersAdapter } from './vulnersAdapter';
export { MitreAdapter } from './mitreAdapter';
export { CirclAdapter } from './circlAdapter';
export { ExploitDbAdapter } from './exploitDbAdapter';

// Re-export types from the main service
export type { 
  CveSourceAdapter, 
  RawCveData, 
  CveDiscoveryOptions,
  RateLimitStatus 
} from '../multiSourceCveDiscoveryService';

/**
 * Factory function to create all available source adapters
 * This is used by the MultiSourceCveDiscoveryService to initialize all adapters
 * Ordered by reliability and working status for prioritization
 */
export function createAllSourceAdapters() {
  return [
    new NistAdapter(),         // PRIMARY: NIST NVD - most reliable official source
    new MitreAdapter(),        // SECONDARY: MITRE with NVD fallback
    new VulnersAdapter(),      // TERTIARY: Good API performance
    new CirclAdapter(),        // QUATERNARY: Alternative API
    // Temporarily disabled failing sources to focus on working ones
    // new CveDetailsAdapter(),   // DISABLED: 403 errors blocking requests  
    // new ExploitDbAdapter()     // DISABLED: 404 errors on API endpoints
  ];
}

/**
 * Get adapter by source name
 */
export function getAdapterByName(sourceName: string) {
  const adapters = createAllSourceAdapters();
  return adapters.find(adapter => adapter.sourceName === sourceName);
}

/**
 * Get adapter configuration for management UI
 */
export function getAdapterConfigurations() {
  const adapters = createAllSourceAdapters();
  
  return adapters.map(adapter => ({
    sourceName: adapter.sourceName,
    displayName: adapter.displayName,
    baseUrl: adapter.baseUrl,
    reliabilityScore: adapter.reliabilityScore,
    isEnabled: adapter.isEnabled,
    supportsHistoricalData: adapter.supportsHistoricalData(),
    supportsRealTimeUpdates: adapter.supportsRealTimeUpdates(),
    maxTimeframeYears: adapter.getMaxTimeframeYears(),
    capabilities: {
      historical: adapter.supportsHistoricalData(),
      realTime: adapter.supportsRealTimeUpdates(),
      maxYears: adapter.getMaxTimeframeYears()
    }
  }));
}

/**
 * Source adapter metadata for documentation and monitoring
 */
export const SOURCE_ADAPTER_METADATA = {
  mitre: {
    description: 'Official MITRE CVE source with authoritative data',
    strengths: ['Authoritative', 'Complete historical coverage', 'Official source'],
    limitations: ['Limited API', 'Basic metadata', 'Slower updates'],
    recommendedUse: 'Primary source for authoritative CVE data'
  },
  vulners: {
    description: 'Large vulnerability database with comprehensive API',
    strengths: ['Fast API', 'Rich metadata', 'Good search capabilities'],
    limitations: ['Rate limits', 'Some paid features', 'Secondary source'],
    recommendedUse: 'Enhanced metadata and fast searching'
  },
  cvedetails: {
    description: 'Comprehensive CVE database with detailed statistics',
    strengths: ['Detailed statistics', 'Excellent historical data', 'Product mappings'],
    limitations: ['Web scraping required', 'Rate limits', 'Structure changes'],
    recommendedUse: 'Historical analysis and product-specific searches'
  },
  circl: {
    description: 'Alternative CVE search API with good performance',
    strengths: ['Fast API', 'Good coverage', 'Free access'],
    limitations: ['Smaller community', 'Less metadata', 'Newer platform'],
    recommendedUse: 'Backup source and alternative perspective'
  },
  exploitdb: {
    description: 'Focus on exploitable CVEs with public proof-of-concepts',
    strengths: ['Exploitable focus', 'PoC availability', 'Practical relevance'],
    limitations: ['Limited to exploitable CVEs', 'Smaller dataset', 'Specialized use'],
    recommendedUse: 'Lab-suitable and exploitable vulnerability discovery'
  }
} as const;