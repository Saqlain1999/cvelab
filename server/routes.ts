import type { Express } from "express";
import { createServer, type Server } from "http";
import { storage } from "./storage";
import { insertCveSchema, insertCveScanSchema, advancedScoringConfigSchema, cveStatusUpdateSchema, cveBulkStatusUpdateSchema } from "@shared/schema";
import { CveService } from "./services/cveService";
import { GitHubService } from "./services/githubService";
import { GoogleSheetsService } from "./services/googleSheetsService";
import { advancedScoringService } from "./services/advancedScoringService";
import { multiSourceDiscoveryService } from "./services/multiSourceDiscoveryService";
import { dockerDeploymentService } from "./services/dockerDeploymentService";
import { fingerprintingService } from "./services/fingerprintingService";
import { CveDuplicateDetectionService } from "./services/cveDuplicateDetectionService";

export async function registerRoutes(app: Express): Promise<Server> {
  const cveService = new CveService();
  const githubService = new GitHubService();
  const googleSheetsService = new GoogleSheetsService();

  // CVE endpoints
  app.get("/api/cves", async (req, res) => {
    try {
      const filters = {
        severity: req.query.severity ? String(req.query.severity).split(',') : undefined,
        technology: req.query.technology ? String(req.query.technology).split(',') : undefined,
        hasPublicPoc: req.query.hasPublicPoc ? req.query.hasPublicPoc === 'true' : undefined,
        isDockerDeployable: req.query.isDockerDeployable ? req.query.isDockerDeployable === 'true' : undefined,
        isCurlTestable: req.query.isCurlTestable ? req.query.isCurlTestable === 'true' : undefined,
        minCvssScore: req.query.minCvssScore ? Number(req.query.minCvssScore) : undefined,
        maxCvssScore: req.query.maxCvssScore ? Number(req.query.maxCvssScore) : undefined,
        search: req.query.search ? String(req.query.search) : undefined,
        status: req.query.status ? String(req.query.status).split(',') : undefined,
        listCategory: req.query.listCategory ? String(req.query.listCategory).split(',') : undefined,
        isPriority: req.query.isPriority ? req.query.isPriority === 'true' : undefined,
        hideDone: req.query.hideDone ? req.query.hideDone === 'true' : undefined,
        limit: req.query.limit ? Number(req.query.limit) : 50,
        offset: req.query.offset ? Number(req.query.offset) : 0
      };

      const cves = await storage.getCves(filters);
      res.json(cves);
    } catch (error) {
      console.error('Error fetching CVEs:', error);
      res.status(500).json({ message: 'Failed to fetch CVEs' });
    }
  });

  // CVE List Management endpoints (must come before /api/cves/:id)
  app.get("/api/cves/lists", async (req, res) => {
    try {
      const lists = await storage.getCveLists();
      res.json(lists);
    } catch (error) {
      console.error('Error fetching CVE lists:', error);
      res.status(500).json({ message: 'Failed to fetch CVE lists' });
    }
  });

  app.get("/api/cves/status-stats", async (req, res) => {
    try {
      const stats = await storage.getCveStatusStats();
      res.json(stats);
    } catch (error) {
      console.error('Error fetching status stats:', error);
      res.status(500).json({ message: 'Failed to fetch status statistics' });
    }
  });

  app.get("/api/cves/priority", async (req, res) => {
    try {
      const priorityCves = await storage.getPriorityCves();
      res.json(priorityCves);
    } catch (error) {
      console.error('Error fetching priority CVEs:', error);
      res.status(500).json({ message: 'Failed to fetch priority CVEs' });
    }
  });

  app.patch("/api/cves/bulk-status", async (req, res) => {
    try {
      const bulkUpdate = cveBulkStatusUpdateSchema.parse(req.body);
      const updatedCves = await storage.updateCveStatusBulk(bulkUpdate.cveIds, bulkUpdate.updates);
      
      res.json({ 
        updatedCount: updatedCves.length,
        updatedCves: updatedCves
      });
    } catch (error) {
      console.error('Error bulk updating CVE status:', error);
      if (error instanceof Error && error.name === 'ZodError') {
        return res.status(400).json({ message: 'Invalid request data', details: error.message });
      }
      res.status(500).json({ message: 'Failed to bulk update CVE status' });
    }
  });

  app.patch("/api/cves/:id/status", async (req, res) => {
    try {
      const statusUpdate = cveStatusUpdateSchema.parse(req.body);
      const updatedCve = await storage.updateCveStatus(req.params.id, statusUpdate);
      
      if (!updatedCve) {
        return res.status(404).json({ message: 'CVE not found' });
      }
      
      res.json(updatedCve);
    } catch (error) {
      console.error('Error updating CVE status:', error);
      if (error instanceof Error && error.name === 'ZodError') {
        return res.status(400).json({ message: 'Invalid request data', details: error.message });
      }
      res.status(500).json({ message: 'Failed to update CVE status' });
    }
  });

  app.get("/api/cves/:id", async (req, res) => {
    try {
      const cve = await storage.getCve(req.params.id);
      if (!cve) {
        return res.status(404).json({ message: 'CVE not found' });
      }
      res.json(cve);
    } catch (error) {
      console.error('Error fetching CVE:', error);
      res.status(500).json({ message: 'Failed to fetch CVE' });
    }
  });

  app.get("/api/stats", async (req, res) => {
    try {
      const stats = await storage.getCveStats();
      res.json(stats);
    } catch (error) {
      console.error('Error fetching stats:', error);
      res.status(500).json({ message: 'Failed to fetch stats' });
    }
  });

  // ============================================================================
  // Multi-Source CVE Discovery API Endpoints
  // ============================================================================

  /**
   * Get multi-source discovery capabilities and source information
   */
  app.get("/api/discovery/sources", async (req, res) => {
    try {
      const capabilities = cveService.getMultiSourceCapabilities();
      res.json(capabilities);
    } catch (error) {
      console.error('Error fetching multi-source capabilities:', error);
      res.status(500).json({ message: 'Failed to fetch source capabilities' });
    }
  });

  /**
   * Get source reliability report and rankings
   */
  app.get("/api/discovery/reliability", async (req, res) => {
    try {
      const reliabilityReport = cveService.getSourceReliabilityReport();
      res.json(reliabilityReport);
    } catch (error) {
      console.error('Error fetching reliability report:', error);
      res.status(500).json({ message: 'Failed to fetch reliability report' });
    }
  });

  /**
   * Refresh source reliability scores (admin endpoint)
   */
  app.post("/api/discovery/reliability/refresh", async (req, res) => {
    try {
      await cveService.refreshSourceReliabilityScores();
      const updatedReport = cveService.getSourceReliabilityReport();
      res.json({ 
        message: 'Reliability scores refreshed successfully',
        report: updatedReport 
      });
    } catch (error) {
      console.error('Error refreshing reliability scores:', error);
      res.status(500).json({ message: 'Failed to refresh reliability scores' });
    }
  });

  /**
   * Get enhanced CVE statistics with source attribution
   */
  app.get("/api/stats/multi-source", async (req, res) => {
    try {
      const baseStats = await storage.getCveStats();
      const reliabilityReport = cveService.getSourceReliabilityReport();
      const capabilities = cveService.getMultiSourceCapabilities();
      
      const enhancedStats = {
        ...baseStats,
        multiSourceMetrics: {
          availableSources: capabilities.availableSources,
          healthySources: reliabilityReport.summary.healthySources,
          averageReliability: reliabilityReport.summary.averageReliability,
          sourcesNeedingAttention: reliabilityReport.summary.sourcesNeedingAttention,
          topSources: reliabilityReport.sourceRankings.slice(0, 5).map(source => ({
            name: source.displayName,
            reliability: source.finalReliabilityScore,
            successRate: source.successRate,
            cvesProvided: source.totalCvesProvided
          }))
        },
        lastUpdated: new Date()
      };
      
      res.json(enhancedStats);
    } catch (error) {
      console.error('Error fetching enhanced multi-source stats:', error);
      res.status(500).json({ message: 'Failed to fetch enhanced statistics' });
    }
  });

  /**
   * Get CVEs with detailed source attribution
   */
  app.get("/api/cves/with-sources", async (req, res) => {
    try {
      const filters = {
        // Standard filters
        severity: req.query.severity ? String(req.query.severity).split(',') : undefined,
        technology: req.query.technology ? String(req.query.technology).split(',') : undefined,
        hasPublicPoc: req.query.hasPublicPoc ? req.query.hasPublicPoc === 'true' : undefined,
        isDockerDeployable: req.query.isDockerDeployable ? req.query.isDockerDeployable === 'true' : undefined,
        search: req.query.search ? String(req.query.search) : undefined,
        
        // Multi-source specific filters
        sources: req.query.sources ? String(req.query.sources).split(',') : undefined,
        primarySource: req.query.primarySource ? String(req.query.primarySource) : undefined,
        minReliabilityScore: req.query.minReliabilityScore ? Number(req.query.minReliabilityScore) : undefined,
        hasConflicts: req.query.hasConflicts ? req.query.hasConflicts === 'true' : undefined,
        minSourceCount: req.query.minSourceCount ? Number(req.query.minSourceCount) : undefined,
        
        limit: req.query.limit ? Number(req.query.limit) : 50,
        offset: req.query.offset ? Number(req.query.offset) : 0
      };

      const cves = await storage.getCves(filters);
      
      // Enhance with source attribution data
      const enhancedCves = cves.map(cve => ({
        ...cve,
        sourceAttribution: {
          sources: cve.sources || ['nist'], // Default to NIST for legacy data
          primarySource: cve.primarySource || 'nist',
          reliability: cve.sourceReliabilityScore || 0.95,
          hasConflicts: !!(cve.sourceConflicts && cve.sourceConflicts.length > 0),
          validationStatus: cve.crossSourceValidation?.validationStatus || 'single_source',
          deduplicationFingerprint: cve.deduplicationFingerprint
        }
      }));
      
      res.json(enhancedCves);
    } catch (error) {
      console.error('Error fetching CVEs with source attribution:', error);
      res.status(500).json({ message: 'Failed to fetch CVEs with source attribution' });
    }
  });

  /**
   * Trigger a test multi-source discovery for a specific CVE ID
   */
  app.post("/api/discovery/test/:cveId", async (req, res) => {
    try {
      const { cveId } = req.params;
      const { sources } = req.body;
      
      if (!cveId || !cveId.match(/^CVE-\d{4}-\d+$/)) {
        return res.status(400).json({ message: 'Invalid CVE ID format' });
      }

      console.log(`Testing multi-source discovery for ${cveId}`);
      
      // This would trigger a test discovery - for now, return mock data
      const testResult = {
        cveId,
        requestedSources: sources || ['all'],
        discoveryTimestamp: new Date(),
        message: 'Multi-source discovery test initiated',
        note: 'This is a test endpoint - full implementation would trigger actual discovery'
      };
      
      res.json(testResult);
    } catch (error) {
      console.error('Error testing multi-source discovery:', error);
      res.status(500).json({ message: 'Failed to test multi-source discovery' });
    }
  });

  /**
   * Get source conflict resolution details for specific CVEs
   */
  app.get("/api/cves/:id/conflicts", async (req, res) => {
    try {
      const cve = await storage.getCve(req.params.id);
      if (!cve) {
        return res.status(404).json({ message: 'CVE not found' });
      }

      const conflicts = {
        cveId: cve.cveId,
        hasConflicts: !!(cve.sourceConflicts && cve.sourceConflicts.length > 0),
        conflicts: cve.sourceConflicts || [],
        crossSourceValidation: cve.crossSourceValidation || {
          totalSources: 1,
          consistentFields: [],
          conflictingFields: [],
          confidence: 0.8,
          validationStatus: 'single_source'
        },
        resolution: {
          primarySource: cve.primarySource || 'nist',
          reliabilityScore: cve.sourceReliabilityScore || 0.95,
          resolutionMethod: 'reliability_weighted'
        }
      };

      res.json(conflicts);
    } catch (error) {
      console.error('Error fetching CVE conflicts:', error);
      res.status(500).json({ message: 'Failed to fetch CVE conflict information' });
    }
  });

  // Fingerprinting endpoints
  app.get("/api/cves/:id/fingerprint", async (req, res) => {
    try {
      const cve = await storage.getCve(req.params.id);
      if (!cve) {
        return res.status(404).json({ message: 'CVE not found' });
      }

      const fingerprintResult = fingerprintingService.generateFingerprint(cve, cve.discoveryMetadata);
      res.json(fingerprintResult);
    } catch (error) {
      console.error('Error generating fingerprint:', error);
      res.status(500).json({ message: 'Failed to generate fingerprint' });
    }
  });

  app.get("/api/cves/:id/fingerprintable", async (req, res) => {
    try {
      const cve = await storage.getCve(req.params.id);
      if (!cve) {
        return res.status(404).json({ message: 'CVE not found' });
      }

      const fingerprintableResult = fingerprintingService.isFingerprintable(cve);
      res.json(fingerprintableResult);
    } catch (error) {
      console.error('Error checking fingerprintability:', error);
      res.status(500).json({ message: 'Failed to check fingerprintability' });
    }
  });

  app.get("/api/cves/:id/commands/:type", async (req, res) => {
    try {
      const { id, type } = req.params;
      const { target = 'TARGET_IP' } = req.query;

      const cve = await storage.getCve(id);
      if (!cve) {
        return res.status(404).json({ message: 'CVE not found' });
      }

      let commands;
      switch (type) {
        case 'curl':
          commands = fingerprintingService.generateCurlCommands(cve, String(target));
          break;
        case 'nmap':
          commands = fingerprintingService.generateNmapCommands(cve, String(target));
          break;
        case 'nuclei':
          commands = fingerprintingService.generateNucleiCommands(cve, String(target));
          break;
        default:
          return res.status(400).json({ message: 'Invalid command type. Use curl, nmap, or nuclei' });
      }

      res.json({ commands, type, target });
    } catch (error) {
      console.error(`Error generating ${req.params.type} commands:`, error);
      res.status(500).json({ message: `Failed to generate ${req.params.type} commands` });
    }
  });

  // CVE scan endpoints
  app.post("/api/scans", async (req, res) => {
    try {
      const scanData = insertCveScanSchema.parse(req.body);
      const scan = await storage.createCveScan(scanData);
      
      // Start background scan process
      performCveScan(scan.id, scanData.timeframeYears || 3);
      
      res.json(scan);
    } catch (error) {
      console.error('Error starting CVE scan:', error);
      res.status(500).json({ message: 'Failed to start CVE scan' });
    }
  });

  app.get("/api/scans", async (req, res) => {
    try {
      const scans = await storage.getCveScans();
      res.json(scans);
    } catch (error) {
      console.error('Error fetching scans:', error);
      res.status(500).json({ message: 'Failed to fetch scans' });
    }
  });

  app.get("/api/scans/:id", async (req, res) => {
    try {
      const scan = await storage.getCveScan(req.params.id);
      if (!scan) {
        return res.status(404).json({ message: 'Scan not found' });
      }
      res.json(scan);
    } catch (error) {
      console.error('Error fetching scan:', error);
      res.status(500).json({ message: 'Failed to fetch scan' });
    }
  });

  // Export endpoints
  app.post("/api/export/sheets", async (req, res) => {
    try {
      const { spreadsheetId, sheetName = 'CVE Results', filters } = req.body;
      
      if (!spreadsheetId) {
        return res.status(400).json({ message: 'Spreadsheet ID is required' });
      }

      const cves = await storage.getCves(filters);
      const success = await googleSheetsService.exportToSheets(spreadsheetId, sheetName, cves);
      
      res.json({ success, message: `Exported ${cves.length} CVEs to Google Sheets` });
    } catch (error) {
      console.error('Error exporting to Google Sheets:', error);
      const errorMessage = error instanceof Error ? error.message : 'Unknown error';
      res.status(500).json({ message: 'Failed to export to Google Sheets', error: errorMessage });
    }
  });

  app.post("/api/export/sheets/create", async (req, res) => {
    try {
      const { title = `CVE Lab Results - ${new Date().toLocaleDateString()}` } = req.body;
      const spreadsheetId = await googleSheetsService.createSpreadsheet(title);
      res.json({ spreadsheetId, url: `https://docs.google.com/spreadsheets/d/${spreadsheetId}` });
    } catch (error) {
      console.error('Error creating Google Sheet:', error);
      const errorMessage = error instanceof Error ? error.message : 'Unknown error';
      res.status(500).json({ message: 'Failed to create Google Sheet', error: errorMessage });
    }
  });

  // Background scan function
  async function performCveScan(scanId: string, timeframeYears: number) {
    try {
      await storage.updateCveScan(scanId, { 
        status: 'running', 
        currentPhase: 'initializing'
      });

      // Fetch CVEs from NIST with enhanced targeting for lab-suitable vulnerabilities
      console.log(`Starting targeted CVE scan for ${timeframeYears} years...`);
      await storage.updateCveScan(scanId, { currentPhase: 'fetching' });
      
      // Enhanced CVE discovery using multi-source approach
      const discoveredCves = await cveService.fetchCvesFromAllSources({
        timeframeYears,
        severities: ['HIGH', 'CRITICAL'],
        attackVector: ['NETWORK'],
        attackComplexity: ['LOW'],
        userInteraction: ['NONE', 'REQUIRED'], // Allow both for wider coverage
        excludeAuthenticated: true,
        onlyLabSuitable: true,
        keywords: [
          'remote code execution', 'sql injection', 'cross-site scripting',
          'path traversal', 'deserialization', 'template injection',
          'server-side request forgery', 'xml external entity', 'file upload'
        ]
      });
      console.log(`Multi-source discovery completed: ${discoveredCves.length} lab-suitable CVEs from multiple platforms`);
      
      await storage.updateCveScan(scanId, { currentPhase: 'enriching' });
      
      // Enhanced tracking variables
      let totalFound = 0;
      let labDeployable = 0;
      let withPoc = 0;
      let criticalSeverity = 0;
      let fingerprintingCompleted = 0;
      let dockerAnalysisCompleted = 0;
      let multiSourceDiscoveryCompleted = 0;
      let totalSourcesDiscovered = 0;
      let enrichmentFailures = 0;
      
      // Detailed enrichment metrics
      const enrichmentMetrics = {
        sourceBreakdown: {} as Record<string, number>,
        avgSourcesPerCve: 0,
        fingerprintingSuccessRate: 0,
        dockerAnalysisSuccessRate: 0,
        topTechnologies: {} as Record<string, number>,
        avgLabSuitabilityScore: 0,
        enrichmentErrors: [] as Array<{cveId: string; phase: string; error: string}>
      };

      // Process each CVE
      for (const cveData of discoveredCves) {
        // Initialize Docker capability flags for this CVE
        let hasActualDockerCapability = false;
        let hasDockerHubContainers = false;
        
        try {
          // Check if CVE is lab suitable
          if (!cveService.isLabSuitable(cveData)) {
            continue;
          }

          totalFound++;

          // Enhanced multi-source PoC discovery
          console.log(`Discovering comprehensive sources for ${cveData.cveId}...`);
          try {
            const discoveryResults = await multiSourceDiscoveryService.discoverAllSources(
              cveData.cveId,
              { 
                query: `${cveData.cveId} poc exploit vulnerability`,
                maxResults: 20,
                includeDockerInfo: true
              }
            );

            multiSourceDiscoveryCompleted++;
            
            if (discoveryResults.sources.length > 0) {
              withPoc++;
              cveData.hasPublicPoc = true;
              
              // Track sources discovered
              totalSourcesDiscovered += discoveryResults.totalSources;
              
              // Update source breakdown metrics
              Object.keys(discoveryResults.sourceBreakdown).forEach(sourceType => {
                enrichmentMetrics.sourceBreakdown[sourceType] = 
                  (enrichmentMetrics.sourceBreakdown[sourceType] || 0) + discoveryResults.sourceBreakdown[sourceType];
              });
              
              // Collect URLs from all sources (GitHub, Medium, DockerHub, YouTube, etc.)
              cveData.pocUrls = discoveryResults.sources.map(source => source.url);
              
              // Precise Docker deployability based on actual deployment capabilities
              hasActualDockerCapability = discoveryResults.dockerInfo.some(info => 
                (info.hasDockerfile || info.hasCompose) && info.deploymentComplexity !== 'complex'
              );
              hasDockerHubContainers = discoveryResults.sources.some(source => 
                source.type === 'dockerhub'
              );
              
              // Only mark as deployable if there are actual Docker deployment capabilities
              cveData.isDockerDeployable = hasActualDockerCapability || hasDockerHubContainers;
              if (cveData.isDockerDeployable) {
                labDeployable++;
              }

              // Store comprehensive discovery metadata
              cveData.discoveryMetadata = {
                totalSources: discoveryResults.totalSources,
                sourceBreakdown: discoveryResults.sourceBreakdown,
                dockerInfo: discoveryResults.dockerInfo,
                topSources: discoveryResults.sources.slice(0, 5).map(source => ({
                  type: source.type,
                  title: source.title,
                  url: source.url,
                  relevanceScore: source.relevanceScore
                })),
                lastEnhanced: new Date()
              };

              console.log(`Found ${discoveryResults.totalSources} sources across ${Object.keys(discoveryResults.sourceBreakdown).length} platforms for ${cveData.cveId}`);
            } else {
              console.log(`No PoC sources found for ${cveData.cveId}`);
            }
          } catch (error) {
            console.warn(`Multi-source discovery failed for ${cveData.cveId}:`, error);
            enrichmentFailures++;
            enrichmentMetrics.enrichmentErrors.push({
              cveId: cveData.cveId,
              phase: 'discovery',
              error: error instanceof Error ? error.message : 'Unknown error'
            });
          }

          // Determine if curl/nmap testable (network services)
          cveData.isCurlTestable = cveData.attackVector === 'Network' && 
            ['Web Server', 'Network Service', 'CMS'].includes(cveData.category);

          // Generate comprehensive fingerprinting data
          try {
            console.log(`Generating fingerprinting data for ${cveData.cveId}...`);
            const fingerprintResult = fingerprintingService.generateFingerprint(cveData, cveData.discoveryMetadata);
            cveData.fingerprintInfo = {
              commands: fingerprintResult.commands,
              detectionStrategy: fingerprintResult.detectionStrategy,
              ports: fingerprintResult.ports,
              protocols: fingerprintResult.protocols,
              confidence: fingerprintResult.confidence,
              recommendations: fingerprintResult.recommendations,
              lastGenerated: new Date()
            };
            
            fingerprintingCompleted++;
            
            // Update testability based on fingerprinting analysis
            if (fingerprintResult.commands.length > 0) {
              cveData.isCurlTestable = fingerprintResult.commands.some(cmd => cmd.type === 'curl');
            }
            
            console.log(`Generated ${fingerprintResult.commands.length} fingerprinting commands for ${cveData.cveId}`);
          } catch (error) {
            console.warn(`Failed to generate fingerprinting data for ${cveData.cveId}:`, error);
            enrichmentFailures++;
            enrichmentMetrics.enrichmentErrors.push({
              cveId: cveData.cveId,
              phase: 'fingerprinting',
              error: error instanceof Error ? error.message : 'Unknown error'
            });
            cveData.fingerprintInfo = { error: 'Failed to generate fingerprinting data', lastGenerated: new Date() };
          }

          // Analyze Docker deployment possibilities in depth
          try {
            console.log(`Analyzing Docker deployment for ${cveData.cveId}...`);
            const deploymentAnalysis = await dockerDeploymentService.analyzeDeploymentPossibilities(cveData);
            
            dockerAnalysisCompleted++;
            
            if (deploymentAnalysis.isDeployable && deploymentAnalysis.recommendedTemplate) {
              // Generate automated deployment if possible
              const automatedDeployment = await dockerDeploymentService.generateAutomatedDeployment(cveData);
              
              cveData.dockerInfo = {
                isDeployable: deploymentAnalysis.isDeployable,
                recommendedTemplate: deploymentAnalysis.recommendedTemplate,
                alternativeOptions: deploymentAnalysis.alternativeOptions,
                deploymentChallenges: deploymentAnalysis.deploymentChallenges,
                mitigationSuggestions: deploymentAnalysis.mitigationSuggestions,
                communityResources: deploymentAnalysis.communityResources.slice(0, 3), // Limit for storage
                automatedDeployment: automatedDeployment ? {
                  deploymentScript: automatedDeployment.deploymentScript,
                  testingScript: automatedDeployment.testingScript,
                  cleanupScript: automatedDeployment.cleanupScript,
                  estimatedTime: automatedDeployment.deploymentTime,
                  resourceRequirements: automatedDeployment.resourceRequirements
                } : null,
                lastAnalyzed: new Date()
              };
              
              // Update deployability flags based on comprehensive analysis
              cveData.isDockerDeployable = deploymentAnalysis.isDeployable;
              if (cveData.isDockerDeployable && !hasActualDockerCapability && !hasDockerHubContainers) {
                labDeployable++; // Increment if not already counted
              }
              
              console.log(`Docker deployment analysis completed for ${cveData.cveId}: ${deploymentAnalysis.isDeployable ? 'Deployable' : 'Not deployable'}`);
            } else {
              cveData.dockerInfo = {
                isDeployable: false,
                deploymentChallenges: deploymentAnalysis.deploymentChallenges,
                reason: 'No suitable deployment template found',
                lastAnalyzed: new Date()
              };
              console.log(`CVE ${cveData.cveId} is not suitable for Docker deployment`);
            }
          } catch (error) {
            console.warn(`Failed to analyze Docker deployment for ${cveData.cveId}:`, error);
            enrichmentFailures++;
            enrichmentMetrics.enrichmentErrors.push({
              cveId: cveData.cveId,
              phase: 'docker-analysis',
              error: error instanceof Error ? error.message : 'Unknown error'
            });
            cveData.dockerInfo = { 
              isDeployable: false, 
              error: 'Failed to analyze Docker deployment',
              lastAnalyzed: new Date()
            };
          }

          // Calculate advanced lab suitability score AFTER all enrichment data is available
          const advancedScore = cveService.calculateAdvancedLabScore(cveData);
          cveData.labSuitabilityScore = advancedScore.score;
          cveData.scoringBreakdown = advancedScore.breakdown;

          // Track technology metrics
          if (cveData.technology) {
            enrichmentMetrics.topTechnologies[cveData.technology] = 
              (enrichmentMetrics.topTechnologies[cveData.technology] || 0) + 1;
          }

          if (cveData.severity === 'CRITICAL') {
            criticalSeverity++;
          }

          // Save or update CVE with intelligent duplicate detection
          const result = await storage.createOrUpdateCve(cveData);
          
          if (!result.isNew && result.changes && result.changes.length > 0) {
            console.log(`Updated existing CVE ${cveData.cveId}: ${CveDuplicateDetectionService.generateChangesSummary(result.changes)}`);
          } else if (result.isNew) {
            console.log(`Created new CVE ${cveData.cveId} with lab suitability score: ${cveData.labSuitabilityScore}`);
          }

          // Add small delay to avoid overwhelming APIs
          await new Promise(resolve => setTimeout(resolve, 100));
        } catch (error) {
          console.error(`Error processing CVE ${cveData.cveId}:`, error);
          enrichmentFailures++;
          enrichmentMetrics.enrichmentErrors.push({
            cveId: cveData.cveId,
            phase: 'general',
            error: error instanceof Error ? error.message : 'Unknown error'
          });
        }
      }

      // Calculate final enrichment metrics
      await storage.updateCveScan(scanId, { currentPhase: 'finalizing' });
      
      enrichmentMetrics.avgSourcesPerCve = totalFound > 0 ? totalSourcesDiscovered / totalFound : 0;
      enrichmentMetrics.fingerprintingSuccessRate = totalFound > 0 ? (fingerprintingCompleted / totalFound) * 100 : 0;
      enrichmentMetrics.dockerAnalysisSuccessRate = totalFound > 0 ? (dockerAnalysisCompleted / totalFound) * 100 : 0;
      enrichmentMetrics.avgLabSuitabilityScore = 0; // Will be calculated if needed
      
      // Limit error log size for storage
      if (enrichmentMetrics.enrichmentErrors.length > 50) {
        enrichmentMetrics.enrichmentErrors = enrichmentMetrics.enrichmentErrors.slice(0, 50);
      }

      // Update scan with comprehensive results
      await storage.updateCveScan(scanId, {
        status: 'completed',
        currentPhase: 'completed',
        totalFound,
        labDeployable,
        withPoc,
        criticalSeverity,
        fingerprintingCompleted,
        dockerAnalysisCompleted,
        multiSourceDiscoveryCompleted,
        totalSourcesDiscovered,
        enrichmentFailures,
        enrichmentMetrics
      });

      console.log(`CVE scan completed successfully!`);
      console.log(`📊 Results: ${totalFound} total, ${labDeployable} deployable, ${withPoc} with PoC, ${criticalSeverity} critical`);
      console.log(`🔍 Enrichment: ${multiSourceDiscoveryCompleted} discovered, ${fingerprintingCompleted} fingerprinted, ${dockerAnalysisCompleted} analyzed`);
      console.log(`📈 Sources: ${totalSourcesDiscovered} total sources discovered across all platforms`);
      console.log(`⚠️  Failures: ${enrichmentFailures} enrichment failures occurred`);
      console.log(`✅ Success rates: Discovery ${((multiSourceDiscoveryCompleted / totalFound) * 100).toFixed(1)}%, Fingerprinting ${enrichmentMetrics.fingerprintingSuccessRate.toFixed(1)}%, Docker ${enrichmentMetrics.dockerAnalysisSuccessRate.toFixed(1)}%`);
    } catch (error) {
      console.error('CVE scan failed:', error);
      const errorMessage = error instanceof Error ? error.message : 'Unknown error';
      await storage.updateCveScan(scanId, {
        status: 'failed',
        errorMessage
      });
    }
  }

  // Advanced Scoring Configuration API
  app.get("/api/scoring/config", async (req, res) => {
    try {
      const config = advancedScoringService.getConfig();
      res.json(config);
    } catch (error) {
      console.error('Error fetching scoring config:', error);
      res.status(500).json({ message: 'Failed to fetch scoring configuration' });
    }
  });

  app.post("/api/scoring/config", async (req, res) => {
    try {
      const validatedConfig = advancedScoringConfigSchema.parse(req.body);
      advancedScoringService.updateConfig(validatedConfig);
      const updatedConfig = advancedScoringService.getConfig();
      res.json(updatedConfig);
    } catch (error) {
      console.error('Error updating scoring config:', error);
      if (error instanceof Error && error.name === 'ZodError') {
        res.status(400).json({ message: 'Invalid configuration format', details: error.message });
      } else {
        res.status(500).json({ message: 'Failed to update scoring configuration' });
      }
    }
  });

  // CVE Advanced Scoring API
  app.get("/api/cves/:id/scoring", async (req, res) => {
    try {
      const cve = await storage.getCve(req.params.id);
      if (!cve) {
        return res.status(404).json({ message: 'CVE not found' });
      }

      const advancedScore = cveService.calculateAdvancedLabScore(cve);
      const basicScore = cveService.calculateBasicLabScore(cve);

      res.json({
        cveId: cve.cveId,
        advancedScore: advancedScore.score,
        basicScore,
        breakdown: advancedScore.breakdown,
        comparison: {
          improvement: Math.round((advancedScore.score - basicScore) * 10) / 10,
          percentChange: basicScore > 0 ? Math.round(((advancedScore.score - basicScore) / basicScore) * 100) : 0
        }
      });
    } catch (error) {
      console.error('Error calculating CVE scores:', error);
      res.status(500).json({ message: 'Failed to calculate CVE scores' });
    }
  });

  // Multi-Source Discovery API
  app.post("/api/cves/:id/sources", async (req, res) => {
    try {
      const cveId = req.params.id;
      const options = {
        query: req.body.query || cveId,
        maxResults: req.body.maxResults || 20,
        includeDockerInfo: req.body.includeDockerInfo || true,
        includeVideoTranscripts: req.body.includeVideoTranscripts || false
      };

      const discoveryResults = await multiSourceDiscoveryService.discoverAllSources(cveId, options);
      
      res.json({
        cveId,
        ...discoveryResults,
        searchTime: Date.now() - Date.now() // Placeholder for actual timing
      });
    } catch (error) {
      console.error('Error discovering sources for CVE:', error);
      res.status(500).json({ message: 'Failed to discover sources for CVE' });
    }
  });

  app.get("/api/cves/:id/sources", async (req, res) => {
    try {
      const cveId = req.params.id;
      const options = {
        query: cveId,
        maxResults: parseInt(req.query.maxResults as string) || 20,
        includeDockerInfo: req.query.includeDockerInfo === 'true',
        includeVideoTranscripts: req.query.includeVideoTranscripts === 'true'
      };

      const discoveryResults = await multiSourceDiscoveryService.discoverAllSources(cveId, options);
      
      res.json({
        cveId,
        ...discoveryResults
      });
    } catch (error) {
      console.error('Error discovering sources for CVE:', error);
      res.status(500).json({ message: 'Failed to discover sources for CVE' });
    }
  });

  // Docker Deployment Automation API
  app.get("/api/deployment/templates", async (req, res) => {
    try {
      const category = req.query.category as string;
      
      if (category) {
        const templates = await dockerDeploymentService.getTemplatesForCategory(category as any);
        res.json(templates);
      } else {
        const templates = await dockerDeploymentService.getAvailableTemplates();
        res.json(templates);
      }
    } catch (error) {
      console.error('Error fetching deployment templates:', error);
      res.status(500).json({ message: 'Failed to fetch deployment templates' });
    }
  });

  app.get("/api/deployment/templates/:templateId", async (req, res) => {
    try {
      const template = await dockerDeploymentService.getTemplate(req.params.templateId);
      if (!template) {
        return res.status(404).json({ message: 'Template not found' });
      }
      res.json(template);
    } catch (error) {
      console.error('Error fetching deployment template:', error);
      res.status(500).json({ message: 'Failed to fetch deployment template' });
    }
  });

  app.post("/api/cves/:id/deployment/analyze", async (req, res) => {
    try {
      const cve = await storage.getCve(req.params.id);
      if (!cve) {
        return res.status(404).json({ message: 'CVE not found' });
      }

      const analysis = await dockerDeploymentService.analyzeDeploymentPossibilities(cve);
      
      res.json({
        cveId: cve.cveId,
        ...analysis,
        analysisTime: new Date().toISOString()
      });
    } catch (error) {
      console.error('Error analyzing deployment possibilities for CVE:', error);
      res.status(500).json({ message: 'Failed to analyze deployment possibilities' });
    }
  });

  app.post("/api/cves/:id/deployment/generate", async (req, res) => {
    try {
      const cve = await storage.getCve(req.params.id);
      if (!cve) {
        return res.status(404).json({ message: 'CVE not found' });
      }

      const deployment = await dockerDeploymentService.generateAutomatedDeployment(cve);
      
      if (!deployment) {
        return res.status(404).json({ 
          message: 'No suitable deployment template found for this CVE',
          cveId: cve.cveId,
          reason: 'CVE may not be suitable for automated Docker deployment'
        });
      }

      res.json(deployment);
    } catch (error) {
      console.error('Error generating automated deployment for CVE:', error);
      res.status(500).json({ message: 'Failed to generate automated deployment' });
    }
  });

  app.get("/api/cves/:id/deployment", async (req, res) => {
    try {
      const cve = await storage.getCve(req.params.id);
      if (!cve) {
        return res.status(404).json({ message: 'CVE not found' });
      }

      const deploymentPackage = await dockerDeploymentService.generateDeploymentPackage(cve);
      
      res.json({
        cveId: cve.cveId,
        ...deploymentPackage,
        generatedAt: new Date().toISOString()
      });
    } catch (error) {
      console.error('Error generating deployment package for CVE:', error);
      res.status(500).json({ message: 'Failed to generate deployment package' });
    }
  });

  app.post("/api/cves/:id/deployment/scripts", async (req, res) => {
    try {
      const cve = await storage.getCve(req.params.id);
      if (!cve) {
        return res.status(404).json({ message: 'CVE not found' });
      }

      const { scriptType = 'all' } = req.body;
      const deployment = await dockerDeploymentService.generateAutomatedDeployment(cve);
      
      if (!deployment) {
        return res.status(404).json({ 
          message: 'No deployment available for this CVE',
          cveId: cve.cveId
        });
      }

      const scripts = {
        deployment: scriptType === 'all' || scriptType === 'deployment' ? deployment.deploymentScript : null,
        testing: scriptType === 'all' || scriptType === 'testing' ? deployment.testingScript : null,
        cleanup: scriptType === 'all' || scriptType === 'cleanup' ? deployment.cleanupScript : null
      };

      res.json({
        cveId: cve.cveId,
        scripts,
        instructions: deployment.customInstructions,
        resourceRequirements: deployment.resourceRequirements
      });
    } catch (error) {
      console.error('Error generating deployment scripts for CVE:', error);
      res.status(500).json({ message: 'Failed to generate deployment scripts' });
    }
  });

  // Docker deployment analytics endpoint
  app.get("/api/deployment/analytics", async (req, res) => {
    try {
      const cves = await storage.getCves();
      const analytics = {
        totalCves: cves.length,
        deployableCves: 0,
        templateUsage: {} as Record<string, number>,
        complexityDistribution: {
          simple: 0,
          moderate: 0,
          complex: 0
        },
        categoryDeployability: {} as Record<string, { total: number; deployable: number }>,
        averageSetupTime: '0 minutes',
        topDeployableCves: [] as any[]
      };

      const deployableAnalysis = [];

      for (const cve of cves) {
        try {
          const analysis = await dockerDeploymentService.analyzeDeploymentPossibilities(cve);
          
          if (analysis.isDeployable && analysis.recommendedTemplate) {
            analytics.deployableCves++;
            
            // Track template usage
            const templateId = analysis.recommendedTemplate.id;
            analytics.templateUsage[templateId] = (analytics.templateUsage[templateId] || 0) + 1;
            
            // Track complexity
            const complexity = analysis.recommendedTemplate.complexity;
            analytics.complexityDistribution[complexity]++;
            
            deployableAnalysis.push({
              cveId: cve.cveId,
              category: cve.category,
              severity: cve.severity,
              cvssScore: cve.cvssScore,
              template: analysis.recommendedTemplate.name,
              complexity,
              estimatedTime: analysis.recommendedTemplate.estimatedSetupTime
            });
          }

          // Track by category
          const category = cve.category || 'Unknown';
          if (!analytics.categoryDeployability[category]) {
            analytics.categoryDeployability[category] = { total: 0, deployable: 0 };
          }
          analytics.categoryDeployability[category].total++;
          if (analysis.isDeployable) {
            analytics.categoryDeployability[category].deployable++;
          }
        } catch (error) {
          console.warn(`Failed to analyze deployment for CVE ${cve.cveId}:`, error);
        }
      }

      // Calculate average setup time (simplified)
      const timeEstimates = deployableAnalysis.map(d => {
        const timeStr = d.estimatedTime;
        const match = timeStr.match(/(\d+)-?(\d+)?/);
        return match ? parseInt(match[1]) : 10;
      });
      const avgTime = timeEstimates.length > 0 
        ? Math.round(timeEstimates.reduce((a, b) => a + b, 0) / timeEstimates.length)
        : 0;
      analytics.averageSetupTime = `${avgTime} minutes`;

      // Top deployable CVEs by CVSS score
      analytics.topDeployableCves = deployableAnalysis
        .filter(d => d.cvssScore)
        .sort((a, b) => (b.cvssScore || 0) - (a.cvssScore || 0))
        .slice(0, 10)
        .map(d => ({
          cveId: d.cveId,
          cvssScore: d.cvssScore,
          template: d.template,
          estimatedTime: d.estimatedTime
        }));

      res.json(analytics);
    } catch (error) {
      console.error('Error generating deployment analytics:', error);
      res.status(500).json({ message: 'Failed to generate deployment analytics' });
    }
  });

  // Batch scoring comparison for dashboard analytics
  app.get("/api/scoring/analytics", async (req, res) => {
    try {
      const cves = await storage.getCves();
      const analytics = {
        totalCves: cves.length,
        scoringComparison: {
          averageAdvanced: 0,
          averageBasic: 0,
          improvement: 0
        },
        distributionByCategory: {} as any,
        topScoredCves: [] as any[]
      };

      let totalAdvanced = 0;
      let totalBasic = 0;
      const scoredCves = [];

      for (const cve of cves) {
        const advancedScore = cveService.calculateAdvancedLabScore(cve);
        const basicScore = cveService.calculateBasicLabScore(cve);
        
        totalAdvanced += advancedScore.score;
        totalBasic += basicScore;

        scoredCves.push({
          cveId: cve.cveId,
          category: cve.category,
          advancedScore: advancedScore.score,
          basicScore,
          improvement: advancedScore.score - basicScore
        });

        // Track by category
        if (cve.category && !analytics.distributionByCategory[cve.category]) {
          analytics.distributionByCategory[cve.category] = { count: 0, avgAdvanced: 0, avgBasic: 0 };
        }
        if (cve.category) {
          analytics.distributionByCategory[cve.category].count++;
        }
      }

      analytics.scoringComparison.averageAdvanced = Math.round((totalAdvanced / cves.length) * 10) / 10;
      analytics.scoringComparison.averageBasic = Math.round((totalBasic / cves.length) * 10) / 10;
      analytics.scoringComparison.improvement = Math.round((analytics.scoringComparison.averageAdvanced - analytics.scoringComparison.averageBasic) * 10) / 10;

      // Calculate category averages
      for (const category in analytics.distributionByCategory) {
        const categoryData = analytics.distributionByCategory[category];
        const categoryCves = scoredCves.filter(c => c.category === category);
        categoryData.avgAdvanced = Math.round((categoryCves.reduce((sum, c) => sum + c.advancedScore, 0) / categoryCves.length) * 10) / 10;
        categoryData.avgBasic = Math.round((categoryCves.reduce((sum, c) => sum + c.basicScore, 0) / categoryCves.length) * 10) / 10;
      }

      // Top scored CVEs
      analytics.topScoredCves = scoredCves
        .sort((a, b) => b.advancedScore - a.advancedScore)
        .slice(0, 10)
        .map(c => ({ cveId: c.cveId, score: c.advancedScore, improvement: c.improvement }));

      res.json(analytics);
    } catch (error) {
      console.error('Error generating scoring analytics:', error);
      res.status(500).json({ message: 'Failed to generate scoring analytics' });
    }
  });

  // CVE Enrichment and Duplicate Detection API
  app.post("/api/cves/:id/enrich", async (req, res) => {
    try {
      const cve = await storage.getCve(req.params.id);
      if (!cve) {
        return res.status(404).json({ message: 'CVE not found' });
      }

      const enrichmentStart = Date.now();
      
      // Comprehensive enrichment combining all discovery capabilities
      const [sourcesResult, deploymentAnalysis, scoringResult] = await Promise.allSettled([
        multiSourceDiscoveryService.discoverAllSources(cve.cveId, {
          query: cve.cveId,
          maxResults: 50,
          includeDockerInfo: true,
          includeVideoTranscripts: false
        }),
        dockerDeploymentService.analyzeDeploymentPossibilities(cve),
        Promise.resolve({
          advanced: cveService.calculateAdvancedLabScore(cve),
          basic: cveService.calculateBasicLabScore(cve)
        })
      ]);

      // Process results and update CVE
      let enrichedCve = { ...cve };
      const enrichmentLog = [];

      // Update sources and POC information
      if (sourcesResult.status === 'fulfilled') {
        const sources = sourcesResult.value;
        enrichmentLog.push(`Found ${sources.totalSources} sources across ${Object.keys(sources.sourceBreakdown).length} platforms`);
        
        // Update POC availability
        if (sources.sources.length > 0 && !enrichedCve.hasPublicPoc) {
          enrichedCve.hasPublicPoc = true;
          enrichmentLog.push('Updated POC availability to true');
        }
        
        // Update POC URLs
        const newPocUrls = sources.sources.map(s => s.url);
        enrichedCve.pocUrls = [...(enrichedCve.pocUrls || []), ...newPocUrls];
        
        // Update discovery metadata
        enrichedCve.discoveryMetadata = {
          lastEnriched: new Date().toISOString(),
          sourcesFound: sources.totalSources,
          sourceBreakdown: sources.sourceBreakdown,
          topSources: sources.sources.slice(0, 5)
        };
      }

      // Update deployment information
      if (deploymentAnalysis.status === 'fulfilled') {
        const deployment = deploymentAnalysis.value;
        enrichmentLog.push(`Analyzed deployment possibilities: ${deployment.alternativeOptions?.length || 0} options found`);
        
        // Update Docker deployability
        if (deployment.isDeployable && deployment.recommendedTemplate && !enrichedCve.isDockerDeployable) {
          enrichedCve.isDockerDeployable = true;
          enrichmentLog.push('Updated Docker deployability to true');
        }
        
        // Update fingerprinting capabilities based on deployment analysis
        if (deployment.isDeployable && !enrichedCve.isCurlTestable) {
          enrichedCve.isCurlTestable = true;
          enrichmentLog.push('Updated curl testability to true');
        }
        
        // Update Docker info with template information
        if (deployment.recommendedTemplate) {
          enrichedCve.dockerInfo = {
            available: true,
            templateId: deployment.recommendedTemplate.id,
            complexity: deployment.recommendedTemplate.complexity
          } as any;
        }
      }

      // Update scores
      if (scoringResult.status === 'fulfilled') {
        const scores = scoringResult.value;
        enrichedCve.labSuitabilityScore = scores.advanced.score;
        enrichedCve.exploitabilityScore = scores.basic;
        enrichedCve.scoringBreakdown = scores.advanced.breakdown;
        enrichmentLog.push(`Updated lab suitability score to ${scores.advanced.score}`);
      }

      // Save enriched CVE - only pass the fields that need updating
      const updates: any = {};
      if (enrichedCve.hasPublicPoc !== cve.hasPublicPoc) updates.hasPublicPoc = enrichedCve.hasPublicPoc;
      if (enrichedCve.isDockerDeployable !== cve.isDockerDeployable) updates.isDockerDeployable = enrichedCve.isDockerDeployable;
      if (enrichedCve.isCurlTestable !== cve.isCurlTestable) updates.isCurlTestable = enrichedCve.isCurlTestable;
      if (enrichedCve.pocUrls) updates.pocUrls = enrichedCve.pocUrls;
      if (enrichedCve.dockerInfo) updates.dockerInfo = enrichedCve.dockerInfo;
      if (enrichedCve.labSuitabilityScore) updates.labSuitabilityScore = enrichedCve.labSuitabilityScore;
      if (enrichedCve.exploitabilityScore) updates.exploitabilityScore = enrichedCve.exploitabilityScore;
      if (enrichedCve.scoringBreakdown) updates.scoringBreakdown = enrichedCve.scoringBreakdown;
      if (enrichedCve.discoveryMetadata) updates.discoveryMetadata = enrichedCve.discoveryMetadata;

      const updatedCve = await storage.updateCve(cve.id, updates);
      
      const enrichmentTime = Date.now() - enrichmentStart;
      
      res.json({
        cveId: cve.cveId,
        enrichmentTime,
        updatedFields: enrichmentLog,
        enrichedCve: updatedCve,
        summary: {
          sourcesFound: sourcesResult.status === 'fulfilled' ? sourcesResult.value.totalSources : 0,
          deploymentOptionsFound: deploymentAnalysis.status === 'fulfilled' ? deploymentAnalysis.value.alternativeOptions?.length || 0 : 0,
          pocAvailable: enrichedCve.hasPublicPoc,
          dockerDeployable: enrichedCve.isDockerDeployable,
          curlTestable: enrichedCve.isCurlTestable,
          labSuitabilityScore: enrichedCve.labSuitabilityScore
        }
      });
    } catch (error) {
      console.error('Error enriching CVE:', error);
      res.status(500).json({ message: 'Failed to enrich CVE' });
    }
  });

  // Bulk CVE enrichment API
  app.post("/api/cves/enrich/bulk", async (req, res) => {
    try {
      const { cveIds, maxConcurrent = 3 } = req.body;
      
      if (!cveIds || !Array.isArray(cveIds)) {
        return res.status(400).json({ message: 'cveIds array is required' });
      }

      const enrichmentResults: any[] = [];
      const errors: any[] = [];

      // Process CVEs in batches to avoid rate limiting
      for (let i = 0; i < cveIds.length; i += maxConcurrent) {
        const batch = cveIds.slice(i, i + maxConcurrent);
        
        const batchPromises = batch.map(async (cveId) => {
          try {
            const cve = await storage.getCve(cveId);
            if (!cve) {
              errors.push({ cveId, error: 'CVE not found' });
              return null;
            }

            // Simplified enrichment for bulk processing
            const sources = await multiSourceDiscoveryService.discoverAllSources(cve.cveId, {
              query: cve.cveId,
              maxResults: 20,
              includeDockerInfo: true
            });

            let updated = false;
            const updates: any = {};

            if (sources.sources.length > 0 && !cve.hasPublicPoc) {
              updates.hasPublicPoc = true;
              updates.pocUrls = [...(cve.pocUrls || []), ...sources.sources.map(s => s.url)];
              updated = true;
            }

            if (sources.dockerInfo.length > 0 && !cve.isDockerDeployable) {
              updates.isDockerDeployable = true;
              updated = true;
            }

            if (updated) {
              updates.discoveryMetadata = {
                lastEnriched: new Date().toISOString(),
                sourcesFound: sources.totalSources,
                sourceBreakdown: sources.sourceBreakdown
              };
              
              await storage.updateCve(cve.id, updates);
              return { cveId: cve.cveId, updated: true, sourcesFound: sources.totalSources };
            } else {
              return { cveId: cve.cveId, updated: false, sourcesFound: sources.totalSources };
            }
          } catch (error) {
            errors.push({ cveId, error: error instanceof Error ? error.message : 'Unknown error' });
            return null;
          }
        });

        const batchResults = await Promise.allSettled(batchPromises);
        batchResults.forEach(result => {
          if (result.status === 'fulfilled' && result.value) {
            enrichmentResults.push(result.value);
          }
        });

        // Add delay between batches to respect rate limits
        if (i + maxConcurrent < cveIds.length) {
          await new Promise(resolve => setTimeout(resolve, 2000));
        }
      }

      res.json({
        totalProcessed: cveIds.length,
        successful: enrichmentResults.length,
        errors: errors.length,
        results: enrichmentResults,
        errorList: errors
      });
    } catch (error) {
      console.error('Error in bulk CVE enrichment:', error);
      res.status(500).json({ message: 'Failed to perform bulk CVE enrichment' });
    }
  });

  // Duplicate detection API
  app.get("/api/cves/duplicates", async (req, res) => {
    try {
      const allCves = await storage.getCves();
      const duplicateGroups = [];
      const processed = new Set();

      for (const cve of allCves) {
        if (processed.has(cve.id)) continue;

        const potentialDuplicates = allCves.filter(other => 
          other.id !== cve.id && 
          !processed.has(other.id) &&
          (
            other.cveId === cve.cveId || // Same CVE ID
            (other.description === cve.description && other.description.length > 50) || // Same description
            (other.affectedProduct === cve.affectedProduct && 
             other.cvssScore === cve.cvssScore && 
             Math.abs(new Date(other.publishedDate).getTime() - new Date(cve.publishedDate).getTime()) < 86400000) // Same product, score, and within 24 hours
          )
        );

        if (potentialDuplicates.length > 0) {
          const group = [cve, ...potentialDuplicates];
          duplicateGroups.push({
            groupId: `dup_${Date.now()}_${Math.random().toString(36).substr(2, 9)}`,
            cves: group.map(c => ({
              id: c.id,
              cveId: c.cveId,
              description: c.description.substring(0, 100) + '...',
              publishedDate: c.publishedDate,
              cvssScore: c.cvssScore,
              hasPublicPoc: c.hasPublicPoc,
              isDockerDeployable: c.isDockerDeployable,
              sourcesCount: c.pocUrls?.length || 0
            })),
            duplicateReason: potentialDuplicates[0].cveId === cve.cveId ? 'Same CVE ID' : 
                            potentialDuplicates[0].description === cve.description ? 'Same description' : 'Similar metadata'
          });

          // Mark all as processed
          group.forEach(c => processed.add(c.id));
        } else {
          processed.add(cve.id);
        }
      }

      res.json({
        totalCves: allCves.length,
        duplicateGroups: duplicateGroups.length,
        groups: duplicateGroups
      });
    } catch (error) {
      console.error('Error detecting duplicates:', error);
      res.status(500).json({ message: 'Failed to detect duplicates' });
    }
  });

  // Merge duplicate CVEs API
  app.post("/api/cves/duplicates/merge", async (req, res) => {
    try {
      const { primaryCveId, duplicateCveIds, mergeStrategy = 'union' } = req.body;
      
      if (!primaryCveId || !duplicateCveIds || !Array.isArray(duplicateCveIds)) {
        return res.status(400).json({ message: 'primaryCveId and duplicateCveIds array are required' });
      }

      const primaryCve = await storage.getCve(primaryCveId);
      if (!primaryCve) {
        return res.status(404).json({ message: 'Primary CVE not found' });
      }

      const duplicateCves = await storage.getCveByIds(duplicateCveIds);
      const mergedData: any = { ...primaryCve };
      const mergeLog = [];

      // Merge POC URLs
      const allPocUrls = new Set([...(primaryCve.pocUrls || [])]);
      duplicateCves.forEach(dup => {
        dup.pocUrls?.forEach(url => allPocUrls.add(url));
      });
      mergedData.pocUrls = Array.from(allPocUrls);
      mergeLog.push(`Merged POC URLs: ${mergedData.pocUrls.length} total`);

      // Merge boolean flags (use OR logic)
      if (!mergedData.hasPublicPoc) {
        mergedData.hasPublicPoc = duplicateCves.some(dup => dup.hasPublicPoc);
        if (mergedData.hasPublicPoc) mergeLog.push('Updated hasPublicPoc to true');
      }

      if (!mergedData.isDockerDeployable) {
        mergedData.isDockerDeployable = duplicateCves.some(dup => dup.isDockerDeployable);
        if (mergedData.isDockerDeployable) mergeLog.push('Updated isDockerDeployable to true');
      }

      if (!mergedData.isCurlTestable) {
        mergedData.isCurlTestable = duplicateCves.some(dup => dup.isCurlTestable);
        if (mergedData.isCurlTestable) mergeLog.push('Updated isCurlTestable to true');
      }

      // Merge scoring (use highest scores)
      const allScores = [primaryCve, ...duplicateCves]
        .map(cve => ({
          exploitability: cve.exploitabilityScore || 0,
          labSuitability: cve.labSuitabilityScore || 0
        }));
      
      mergedData.exploitabilityScore = Math.max(...allScores.map(s => s.exploitability));
      mergedData.labSuitabilityScore = Math.max(...allScores.map(s => s.labSuitability));
      mergeLog.push(`Updated scores: exploitability=${mergedData.exploitabilityScore}, labSuitability=${mergedData.labSuitabilityScore}`);

      // Merge discovery metadata
      const allMetadata = [primaryCve, ...duplicateCves]
        .map(cve => cve.discoveryMetadata)
        .filter(Boolean);
      
      if (allMetadata.length > 0) {
        mergedData.discoveryMetadata = {
          lastMerged: new Date().toISOString(),
          mergedFrom: duplicateCveIds,
          combinedSources: allMetadata.reduce((total, meta: any) => total + (meta.sourcesFound || 0), 0),
          mergeStrategy
        };
        mergeLog.push('Updated discovery metadata with merge information');
      }

      // Update the primary CVE
      const updatedCve = await storage.updateCve(primaryCveId, mergedData);

      // Delete duplicate CVEs
      for (const dupId of duplicateCveIds) {
        await storage.deleteCve(dupId);
      }
      mergeLog.push(`Deleted ${duplicateCveIds.length} duplicate CVEs`);

      res.json({
        primaryCveId,
        mergedCve: updatedCve,
        mergeLog,
        duplicatesRemoved: duplicateCveIds.length,
        summary: {
          totalPocUrls: mergedData.pocUrls?.length || 0,
          hasPublicPoc: mergedData.hasPublicPoc,
          isDockerDeployable: mergedData.isDockerDeployable,
          isCurlTestable: mergedData.isCurlTestable,
          finalScores: {
            exploitability: mergedData.exploitabilityScore,
            labSuitability: mergedData.labSuitabilityScore
          }
        }
      });
    } catch (error) {
      console.error('Error merging duplicate CVEs:', error);
      res.status(500).json({ message: 'Failed to merge duplicate CVEs' });
    }
  });

  const httpServer = createServer(app);
  return httpServer;
}
