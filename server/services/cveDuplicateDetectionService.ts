import { type Cve, type InsertCve } from "@shared/schema";

/**
 * CVE Duplicate Detection and Merging Service
 * Handles intelligent detection and merging of duplicate CVE entries
 */
export class CveDuplicateDetectionService {
  
  /**
   * Check if a CVE already exists and merge new information
   */
  static async checkAndMergeCve(newCve: any, existingCves: Cve[]): Promise<{ 
    isDuplicate: boolean;
    mergedCve?: any;
    changes?: string[];
  }> {
    const existing = existingCves.find(cve => cve.cveId === newCve.cveId);
    
    if (!existing) {
      return { isDuplicate: false };
    }
    
    // Merge information from new CVE data
    const changes: string[] = [];
    const mergedCve = { ...existing };
    
    // Merge PoC URLs
    if (newCve.pocUrls && newCve.pocUrls.length > 0) {
      const existingUrls = new Set(existing.pocUrls || []);
      const newUrls = newCve.pocUrls.filter((url: string) => !existingUrls.has(url));
      
      if (newUrls.length > 0) {
        mergedCve.pocUrls = [...(existing.pocUrls || []), ...newUrls];
        mergedCve.hasPublicPoc = true;
        changes.push(`Added ${newUrls.length} new PoC URLs`);
      }
    }
    
    // Update Docker deployment info if new information is available
    if (newCve.dockerInfo && !existing.dockerInfo) {
      mergedCve.dockerInfo = newCve.dockerInfo;
      mergedCve.isDockerDeployable = true;
      changes.push('Added Docker deployment information');
    } else if (newCve.dockerInfo && existing.dockerInfo) {
      // Merge Docker info intelligently
      const existingDockerInfo = existing.dockerInfo as any;
      const newDockerInfo = newCve.dockerInfo;
      
      mergedCve.dockerInfo = {
        ...existingDockerInfo,
        ...newDockerInfo,
        // Keep the most detailed setup instructions
        setupInstructions: newDockerInfo.setupInstructions || existingDockerInfo.setupInstructions,
        // Use the simpler deployment complexity if available
        deploymentComplexity: newDockerInfo.deploymentComplexity === 'simple' ? 
          'simple' : existingDockerInfo.deploymentComplexity
      };
      changes.push('Updated Docker deployment information');
    }
    
    // Update fingerprinting info if new information is available
    if (newCve.fingerprintInfo && !existing.fingerprintInfo) {
      mergedCve.fingerprintInfo = newCve.fingerprintInfo;
      mergedCve.isCurlTestable = true;
      changes.push('Added fingerprinting information');
    } else if (newCve.fingerprintInfo && existing.fingerprintInfo) {
      // Merge fingerprinting info
      const existingFingerprintInfo = existing.fingerprintInfo as any;
      const newFingerprintInfo = newCve.fingerprintInfo;
      
      mergedCve.fingerprintInfo = {
        ...existingFingerprintInfo,
        ...newFingerprintInfo,
        // Merge unique commands
        commands: this.mergeUniqueCommands(
          existingFingerprintInfo.commands || [],
          newFingerprintInfo.commands || []
        ),
        // Use higher confidence
        confidence: Math.max(
          existingFingerprintInfo.confidence || 0,
          newFingerprintInfo.confidence || 0
        )
      };
      changes.push('Updated fingerprinting information');
    }
    
    // Update discovery metadata with new sources
    if (newCve.discoveryMetadata) {
      const existingMetadata = existing.discoveryMetadata as any || { sources: [], lastEnhanced: null };
      const newSources = newCve.discoveryMetadata.sources || [];
      
      // Merge unique sources based on URL
      const existingSourceUrls = new Set(
        (existingMetadata.sources || []).map((s: any) => s.url)
      );
      const uniqueNewSources = newSources.filter((s: any) => !existingSourceUrls.has(s.url));
      
      if (uniqueNewSources.length > 0) {
        mergedCve.discoveryMetadata = {
          ...existingMetadata,
          sources: [...(existingMetadata.sources || []), ...uniqueNewSources],
          lastEnhanced: new Date(),
          totalSources: (existingMetadata.sources || []).length + uniqueNewSources.length,
          sourceBreakdown: this.calculateSourceBreakdown([
            ...(existingMetadata.sources || []),
            ...uniqueNewSources
          ])
        };
        changes.push(`Added ${uniqueNewSources.length} new discovery sources`);
      }
    }
    
    // Update lab suitability score if higher
    if (newCve.labSuitabilityScore && 
        (!existing.labSuitabilityScore || newCve.labSuitabilityScore > existing.labSuitabilityScore)) {
      mergedCve.labSuitabilityScore = newCve.labSuitabilityScore;
      mergedCve.exploitabilityScore = newCve.exploitabilityScore;
      mergedCve.scoringBreakdown = newCve.scoringBreakdown;
      changes.push('Updated lab suitability scoring');
    }
    
    // Update CVSS information if newer or more complete
    if (newCve.cvssScore && (!existing.cvssScore || newCve.cvssScore !== existing.cvssScore)) {
      if (newCve.lastModifiedDate && existing.lastModifiedDate && 
          new Date(newCve.lastModifiedDate) > new Date(existing.lastModifiedDate)) {
        mergedCve.cvssScore = newCve.cvssScore;
        mergedCve.cvssVector = newCve.cvssVector;
        mergedCve.severity = newCve.severity;
        mergedCve.lastModifiedDate = newCve.lastModifiedDate;
        changes.push('Updated CVSS scoring information');
      }
    }
    
    // Update affected versions if more comprehensive
    if (newCve.affectedVersions && newCve.affectedVersions.length > 0) {
      const existingVersions = new Set(existing.affectedVersions || []);
      const newVersions = newCve.affectedVersions.filter((v: string) => !existingVersions.has(v));
      
      if (newVersions.length > 0) {
        mergedCve.affectedVersions = [...(existing.affectedVersions || []), ...newVersions];
        changes.push(`Added ${newVersions.length} new affected versions`);
      }
    }
    
    // Update the modification timestamp if changes were made
    if (changes.length > 0) {
      mergedCve.updatedAt = new Date();
    }
    
    return {
      isDuplicate: true,
      mergedCve,
      changes
    };
  }
  
  /**
   * Merge unique fingerprinting commands
   */
  private static mergeUniqueCommands(existing: any[], newCommands: any[]): any[] {
    const existingCommandTexts = new Set(existing.map(cmd => cmd.command));
    const uniqueNewCommands = newCommands.filter(cmd => !existingCommandTexts.has(cmd.command));
    return [...existing, ...uniqueNewCommands];
  }
  
  /**
   * Calculate source breakdown for discovery metadata
   */
  private static calculateSourceBreakdown(sources: any[]): Record<string, number> {
    const breakdown: Record<string, number> = {};
    for (const source of sources) {
      const type = source.type || 'unknown';
      breakdown[type] = (breakdown[type] || 0) + 1;
    }
    return breakdown;
  }
  
  /**
   * Generate a summary of changes for logging
   */
  static generateChangesSummary(changes: string[]): string {
    if (changes.length === 0) return 'No changes detected';
    
    return `Updated CVE with ${changes.length} enhancement(s): ${changes.join(', ')}`;
  }
  
  /**
   * Check if a CVE should be considered for update based on age and completeness
   */
  static shouldUpdateCve(existing: Cve): boolean {
    const threeDaysAgo = new Date();
    threeDaysAgo.setDate(threeDaysAgo.getDate() - 3);
    
    // Update if CVE is recent or missing key information
    const lastUpdate = existing.updatedAt || existing.createdAt;
    const lastUpdateDate = lastUpdate ? new Date(lastUpdate) : new Date(0); // Use epoch if no date
    
    return (
      lastUpdateDate < threeDaysAgo ||
      !existing.hasPublicPoc ||
      !existing.dockerInfo ||
      !existing.fingerprintInfo ||
      (existing.discoveryMetadata as any)?.sources?.length < 3
    );
  }
}

export default CveDuplicateDetectionService;