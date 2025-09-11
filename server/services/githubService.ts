import { 
  SearchResult, 
  SearchSource, 
  PocContextType, 
  DeploymentInfo,
  SourceSearchOptions,
  CveRelevanceInfo,
  SearchResultMetadata 
} from '../types/multiSourceTypes';

interface GitHubSearchResponse {
  total_count: number;
  items: Array<{
    name: string;
    full_name: string;
    description: string;
    html_url: string;
    stargazers_count: number;
    updated_at: string;
    language: string;
    fork: boolean;
    forks_count: number;
    watchers_count: number;
    size: number;
  }>;
}

interface GitHubContentResponse {
  name: string;
  path: string;
  sha: string;
  type: string;
  download_url: string;
}

interface GitHubRateLimit {
  remaining: number;
  reset: number;
  used: number;
  limit: number;
}

export class GitHubService {
  private readonly BASE_URL = 'https://api.github.com';
  private readonly API_KEY = process.env.GITHUB_API_KEY || process.env.GITHUB_TOKEN || '';
  private lastRateLimit: GitHubRateLimit | null = null;

  async searchPoCs(cveId: string, options?: SourceSearchOptions): Promise<SearchResult[]> {
    const maxResults = options?.maxResults || 10;
    const queries = this.buildSearchQueries(cveId);
    const allResults: any[] = [];

    for (const query of queries) {
      try {
        if (await this.isRateLimited()) {
          console.warn('GitHub API rate limited, skipping remaining queries');
          break;
        }

        const results = await this.searchRepositories(query);
        const pocResults = results.filter(repo => this.isPocRepository(repo, cveId));
        allResults.push(...pocResults);
      } catch (error) {
        console.error(`Error searching GitHub for ${query}:`, error);
      }
    }

    const uniqueResults = this.deduplicateResults(allResults);
    const rankedResults = this.rankResults(uniqueResults, cveId);
    
    // Convert to unified format
    return await Promise.all(
      rankedResults.slice(0, maxResults).map(repo => this.convertToSearchResult(repo, cveId))
    );
  }

  private buildSearchQueries(cveId: string): string[] {
    return [
      `${cveId} poc proof-of-concept`,
      `${cveId} exploit demonstration`,
      `${cveId} vulnerability reproduction`,
      `"${cveId}" docker vulnerable`,
      `"${cveId}" lab setup`,
      `${cveId} pentest toolkit`,
      `${cveId} security research`,
      `"${cveId}" CTF challenge`
    ];
  }

  private async searchRepositories(query: string): Promise<any[]> {
    const params = new URLSearchParams({
      q: query,
      sort: 'updated',
      order: 'desc',
      per_page: '30'
    });

    const headers: Record<string, string> = {
      'Accept': 'application/vnd.github.v3+json',
      'User-Agent': 'CVE-Lab-Hunter/1.0',
      'X-GitHub-Api-Version': '2022-11-28'
    };

    if (this.API_KEY) {
      headers['Authorization'] = `token ${this.API_KEY}`;
    }

    try {
      const response = await fetch(`${this.BASE_URL}/search/repositories?${params}`, {
        headers
      });

      // Update rate limit info
      const rateLimitRemaining = response.headers.get('X-RateLimit-Remaining');
      const rateLimitReset = response.headers.get('X-RateLimit-Reset');
      if (rateLimitRemaining && rateLimitReset) {
        this.lastRateLimit = {
          remaining: parseInt(rateLimitRemaining),
          reset: parseInt(rateLimitReset),
          used: 0,
          limit: parseInt(response.headers.get('X-RateLimit-Limit') || '60')
        };
      }

      if (!response.ok) {
        if (response.status === 403) {
          console.warn('GitHub API rate limit exceeded');
          return [];
        }
        throw new Error(`GitHub API error: ${response.status} ${response.statusText}`);
      }

      const data: GitHubSearchResponse = await response.json();
      return data.items || [];
    } catch (error) {
      console.error('Error searching GitHub repositories:', error);
      return [];
    }
  }

  private isPocRepository(repo: any, cveId: string): boolean {
    const name = repo.name.toLowerCase();
    const description = (repo.description || '').toLowerCase();
    const cveIdLower = cveId.toLowerCase();

    // Must contain CVE ID
    if (!name.includes(cveIdLower) && !description.includes(cveIdLower)) {
      return false;
    }

    // Enhanced PoC/exploit indicators
    const pocIndicators = [
      'poc', 'exploit', 'vulnerability', 'cve', 'proof', 'concept',
      'demo', 'reproduction', 'pentest', 'security', 'lab', 'ctf',
      'research', 'analysis', 'writeup'
    ];
    
    const hasIndicator = pocIndicators.some(indicator => 
      name.includes(indicator) || description.includes(indicator)
    );

    // Filter out obvious non-PoC repos
    const blacklistedTerms = ['mirror', 'backup', 'archive', 'docs-only', 'reference'];
    const isBlacklisted = blacklistedTerms.some(term => 
      name.includes(term) || description.includes(term)
    );

    return hasIndicator && !isBlacklisted && !repo.fork;
  }

  private deduplicateResults(results: any[]): any[] {
    const seen = new Set<string>();
    return results.filter(repo => {
      if (seen.has(repo.full_name)) {
        return false;
      }
      seen.add(repo.full_name);
      return true;
    });
  }

  private rankResults(results: any[], cveId: string): any[] {
    return results
      .map(repo => ({
        ...repo,
        relevanceScore: this.calculateRelevanceScore(repo, cveId)
      }))
      .sort((a, b) => b.relevanceScore - a.relevanceScore);
  }

  private calculateRelevanceScore(repo: any, cveId: string): number {
    let score = 0;
    
    const name = repo.name.toLowerCase();
    const description = (repo.description || '').toLowerCase();
    const cveIdLower = cveId.toLowerCase();

    // CVE ID matching (highest weight)
    if (name === cveIdLower) score += 15;
    else if (name.includes(cveIdLower)) score += 10;
    if (description.includes(cveIdLower)) score += 5;
    
    // Context type scoring
    if (name.includes('poc') || description.includes('poc')) score += 8;
    if (name.includes('exploit') || description.includes('exploit')) score += 7;
    if (name.includes('demo') || description.includes('demo')) score += 6;
    if (name.includes('lab') || description.includes('lab')) score += 5;
    
    // Educational value indicators
    if (description.includes('tutorial') || description.includes('guide')) score += 4;
    if (description.includes('research') || description.includes('analysis')) score += 3;
    
    // Quality indicators
    score += Math.log10(repo.stargazers_count + 1) * 2;
    score += Math.log10(repo.forks_count + 1);
    
    // Recent activity bonus
    const lastUpdate = new Date(repo.updated_at);
    const monthsOld = (Date.now() - lastUpdate.getTime()) / (1000 * 60 * 60 * 24 * 30);
    if (monthsOld < 12) score += Math.max(3 - monthsOld / 4, 0);
    
    // Language bonus for common languages
    const preferredLanguages = ['python', 'bash', 'shell', 'dockerfile'];
    if (preferredLanguages.includes(repo.language?.toLowerCase())) score += 2;
    
    return score;
  }

  async checkDockerDeployability(repoUrl: string): Promise<boolean> {
    try {
      const owner = repoUrl.split('/')[3];
      const repo = repoUrl.split('/')[4];
      
      const files = ['Dockerfile', 'docker-compose.yml', 'docker-compose.yaml', 'Dockerfile.vulnerable'];
      
      for (const file of files) {
        const response = await fetch(`${this.BASE_URL}/repos/${owner}/${repo}/contents/${file}`, {
          headers: {
            'Accept': 'application/vnd.github.v3+json',
            'User-Agent': 'CVE-Lab-Hunter/1.0',
            ...(this.API_KEY && { 'Authorization': `token ${this.API_KEY}` })
          }
        });
        
        if (response.ok) {
          return true;
        }
      }
      
      return false;
    } catch (error) {
      console.error('Error checking Docker deployability:', error);
      return false;
    }
  }

  async analyzeDeploymentInfo(repoUrl: string): Promise<DeploymentInfo> {
    const deploymentInfo: DeploymentInfo = {
      hasDocker: false,
      hasVagrant: false,
      hasScript: false,
      complexity: 'moderate',
      requirements: [],
      dockerFiles: []
    };

    try {
      const owner = repoUrl.split('/')[3];
      const repo = repoUrl.split('/')[4];
      
      // Check for various deployment files
      const deploymentFiles = [
        'Dockerfile', 'docker-compose.yml', 'docker-compose.yaml',
        'Vagrantfile', 'setup.sh', 'install.sh', 'run.sh',
        'requirements.txt', 'package.json', 'Gemfile', 'pom.xml'
      ];

      const contentResponse = await fetch(`${this.BASE_URL}/repos/${owner}/${repo}/contents`, {
        headers: {
          'Accept': 'application/vnd.github.v3+json',
          'User-Agent': 'CVE-Lab-Hunter/1.0',
          ...(this.API_KEY && { 'Authorization': `token ${this.API_KEY}` })
        }
      });

      if (contentResponse.ok) {
        const contents: GitHubContentResponse[] = await contentResponse.json();
        const fileNames = contents.map(item => item.name.toLowerCase());
        
        // Docker analysis
        const dockerFiles = fileNames.filter(name => 
          name.includes('dockerfile') || name.includes('docker-compose')
        );
        deploymentInfo.hasDocker = dockerFiles.length > 0;
        deploymentInfo.dockerFiles = dockerFiles;
        
        // Other deployment methods
        deploymentInfo.hasVagrant = fileNames.includes('vagrantfile');
        deploymentInfo.hasScript = fileNames.some(name => 
          name.endsWith('.sh') || name.includes('setup') || name.includes('install')
        );
        
        // Requirements analysis
        if (fileNames.includes('requirements.txt')) deploymentInfo.requirements.push('Python');
        if (fileNames.includes('package.json')) deploymentInfo.requirements.push('Node.js');
        if (fileNames.includes('gemfile')) deploymentInfo.requirements.push('Ruby');
        if (fileNames.includes('pom.xml')) deploymentInfo.requirements.push('Java');
        
        // Complexity assessment
        const complexityIndicators = fileNames.filter(name => 
          name.includes('config') || name.includes('env') || name.includes('secret')
        ).length;
        
        if (deploymentInfo.hasDocker && complexityIndicators < 2) {
          deploymentInfo.complexity = 'simple';
        } else if (complexityIndicators > 5 || (!deploymentInfo.hasDocker && !deploymentInfo.hasScript)) {
          deploymentInfo.complexity = 'complex';
        }
      }
    } catch (error) {
      console.error('Error analyzing deployment info:', error);
    }

    return deploymentInfo;
  }

  private async convertToSearchResult(repo: any, cveId: string): Promise<SearchResult> {
    const deploymentInfo = await this.analyzeDeploymentInfo(repo.html_url);
    
    // Determine context type
    let contextType = PocContextType.PROOF_OF_CONCEPT;
    const name = repo.name.toLowerCase();
    const description = (repo.description || '').toLowerCase();
    
    if (name.includes('exploit') || description.includes('exploit')) {
      contextType = PocContextType.EXPLOIT;
    } else if (name.includes('demo') || description.includes('demo')) {
      contextType = PocContextType.DEMO;
    } else if (name.includes('tool') || description.includes('tool')) {
      contextType = PocContextType.TOOL;
    } else if (deploymentInfo.hasDocker && name.includes('lab')) {
      contextType = PocContextType.LAB_SETUP;
    }

    const metadata: SearchResultMetadata = {
      author: repo.full_name.split('/')[0],
      publishDate: new Date(repo.updated_at),
      language: repo.language,
      stars: repo.stargazers_count,
      tags: [contextType, repo.language?.toLowerCase()].filter(Boolean),
      sourceSpecific: {
        forks: repo.forks_count,
        watchers: repo.watchers_count,
        size: repo.size,
        isFork: repo.fork
      }
    };

    const cveRelevance: CveRelevanceInfo = {
      cveMatch: name.includes(cveId.toLowerCase()) ? 'exact' : 'partial',
      contextType,
      deploymentInfo,
      educational: description.includes('tutorial') || description.includes('guide') || description.includes('learn'),
      technical: contextType === PocContextType.EXPLOIT || contextType === PocContextType.TOOL
    };

    return {
      id: `github_${repo.full_name}`,
      title: `${repo.name}`,
      url: repo.html_url,
      description: repo.description || 'No description available',
      source: SearchSource.GITHUB,
      relevanceScore: repo.relevanceScore || 0,
      metadata,
      cveRelevance,
      createdAt: new Date(repo.updated_at),
      updatedAt: new Date(repo.updated_at)
    };
  }

  private async isRateLimited(): Promise<boolean> {
    if (!this.lastRateLimit) return false;
    
    const now = Math.floor(Date.now() / 1000);
    if (now > this.lastRateLimit.reset) {
      this.lastRateLimit = null;
      return false;
    }
    
    return this.lastRateLimit.remaining < 5; // Conservative buffer
  }

  // Legacy method for backward compatibility
  async searchPocsLegacy(cveId: string): Promise<any[]> {
    const results = await this.searchPoCs(cveId, { 
      query: `${cveId} poc exploit`, 
      maxResults: 5 
    });
    return results.map(result => ({
      name: result.title,
      full_name: result.id.replace('github_', ''),
      html_url: result.url,
      description: result.description,
      stargazers_count: result.metadata.stars || 0,
      updated_at: result.updatedAt?.toISOString(),
      relevanceScore: result.relevanceScore
    }));
  }
}