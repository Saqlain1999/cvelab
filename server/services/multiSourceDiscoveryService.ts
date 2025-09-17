import { GitHubService } from './githubService';
import { storage } from '../storage';
import { rateLimit } from './rateLimiter';

export interface PocSource {
  type: 'github' | 'gitlab' | 'dockerhub' | 'exploitdb' | 'security_blog' | 'sec_rss';
  title: string;
  url: string;
  description: string;
  author?: string;
  publishedDate?: Date;
  relevanceScore: number;
  tags?: string[];
  metadata?: any;
}

export interface SourceSearchOptions {
  query: string;
  maxResults?: number;
  includeDockerInfo?: boolean;
  includeVideoTranscripts?: boolean;
}

export interface DockerDeploymentInfo {
  hasDockerfile: boolean;
  hasCompose: boolean;
  setupInstructions?: string;
  deploymentComplexity: 'simple' | 'moderate' | 'complex';
  prerequisites: string[];
  estimatedSetupTime: string;
}

export class MultiSourceDiscoveryService {
  private githubService: GitHubService;
  private cacheTimeout = 1000 * 60 * 30; // 30 minutes
  private cache = new Map<string, { data: any; timestamp: number }>();
  
  // Production reliability configuration
  private readonly CONFIG = {
    maxRetries: 3,
    baseDelay: 1000, // 1 second
    maxDelay: 10000, // 10 seconds
    timeout: 15000, // 15 seconds
    userAgent: 'Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/120.0.0.0 Safari/537.36',
    circuitBreakerThreshold: 5, // failures before circuit opens
    circuitBreakerResetTime: 60000 // 1 minute
  };
  
  // Circuit breaker state for each service
  private circuitBreakers = new Map<string, {
    failures: number;
    lastFailure: number;
    isOpen: boolean;
  }>();

  constructor() {
    this.githubService = new GitHubService(storage);
  }

  /**
   * Production-ready HTTP request with retry logic, timeout, and circuit breaker
   */
  private async makeReliableRequest(
    url: string, 
    options: RequestInit = {}, 
    serviceName: string
  ): Promise<Response | null> {
    // token-bucket limit before each attempt
    await rateLimit(serviceName);
    // Check circuit breaker
    if (this.isCircuitOpen(serviceName)) {
      console.warn(`Circuit breaker open for ${serviceName}, skipping request`);
      return null;
    }

    const requestOptions: RequestInit = {
      ...options,
      headers: {
        'User-Agent': this.CONFIG.userAgent,
        ...options.headers
      },
      signal: AbortSignal.timeout(this.CONFIG.timeout)
    };

    for (let attempt = 0; attempt <= this.CONFIG.maxRetries; attempt++) {
      try {
        console.debug(`${serviceName} request attempt ${attempt + 1}/${this.CONFIG.maxRetries + 1}: ${url}`);
        
        const response = await fetch(url, requestOptions);
        
        if (response.ok) {
          // Reset circuit breaker on success
          this.resetCircuitBreaker(serviceName);
          return response;
        } else if (response.status === 429) {
          // Rate limiting - wait longer
          const retryAfter = response.headers.get('retry-after');
          const waitTime = retryAfter ? parseInt(retryAfter) * 1000 : this.calculateBackoffDelay(attempt);
          console.warn(`${serviceName} rate limited, waiting ${waitTime}ms`);
          await this.delay(waitTime);
          continue;
        } else if (response.status >= 500) {
          // Server error - retry with backoff
          throw new Error(`Server error: ${response.status} ${response.statusText}`);
        } else {
          // Client error - don't retry
          console.warn(`${serviceName} client error: ${response.status} ${response.statusText}`);
          return response;
        }
      } catch (error) {
        const isLastAttempt = attempt === this.CONFIG.maxRetries;
        
        if (error instanceof Error && error.name === 'TimeoutError') {
          console.warn(`${serviceName} request timeout on attempt ${attempt + 1}`);
        } else if (error instanceof Error && error.name === 'AbortError') {
          console.warn(`${serviceName} request aborted on attempt ${attempt + 1}`);
        } else {
          console.warn(`${serviceName} request failed on attempt ${attempt + 1}:`, error);
        }

        if (isLastAttempt) {
          // Record failure for circuit breaker
          this.recordFailure(serviceName);
          console.error(`${serviceName} failed after ${this.CONFIG.maxRetries + 1} attempts`);
          return null;
        }

        // Wait before retry with exponential backoff
        const delayMs = this.calculateBackoffDelay(attempt);
        console.debug(`${serviceName} retrying in ${delayMs}ms...`);
        await this.delay(delayMs);
      }
    }

    return null;
  }

  /**
   * Calculate exponential backoff delay with jitter
   */
  private calculateBackoffDelay(attempt: number): number {
    const exponentialDelay = this.CONFIG.baseDelay * Math.pow(2, attempt);
    const cappedDelay = Math.min(exponentialDelay, this.CONFIG.maxDelay);
    // Add jitter (±25%) to prevent thundering herd
    const jitter = cappedDelay * 0.25 * (Math.random() - 0.5);
    return Math.round(cappedDelay + jitter);
  }

  /**
   * Simple delay utility
   */
  private delay(ms: number): Promise<void> {
    return new Promise(resolve => setTimeout(resolve, ms));
  }

  /**
   * Check if circuit breaker is open for a service
   */
  private isCircuitOpen(serviceName: string): boolean {
    const breaker = this.circuitBreakers.get(serviceName);
    if (!breaker) return false;

    if (breaker.isOpen) {
      const timeSinceLastFailure = Date.now() - breaker.lastFailure;
      if (timeSinceLastFailure > this.CONFIG.circuitBreakerResetTime) {
        // Reset circuit breaker
        this.resetCircuitBreaker(serviceName);
        return false;
      }
      return true;
    }

    return false;
  }

  /**
   * Record a failure for circuit breaker
   */
  private recordFailure(serviceName: string): void {
    const breaker = this.circuitBreakers.get(serviceName) || {
      failures: 0,
      lastFailure: 0,
      isOpen: false
    };

    breaker.failures++;
    breaker.lastFailure = Date.now();

    if (breaker.failures >= this.CONFIG.circuitBreakerThreshold) {
      breaker.isOpen = true;
      console.warn(`Circuit breaker opened for ${serviceName} after ${breaker.failures} failures`);
    }

    this.circuitBreakers.set(serviceName, breaker);
  }

  /**
   * Reset circuit breaker on successful request
   */
  private resetCircuitBreaker(serviceName: string): void {
    const breaker = this.circuitBreakers.get(serviceName);
    if (breaker) {
      breaker.failures = 0;
      breaker.isOpen = false;
      this.circuitBreakers.set(serviceName, breaker);
    }
  }

  async discoverAllSources(cveId: string, options: SourceSearchOptions = { query: cveId }): Promise<{ 
    sources: PocSource[]; 
    dockerInfo: DockerDeploymentInfo[]; 
    totalSources: number; 
    sourceBreakdown: Record<string, number>; 
    deploymentResources?: Array<{ type: string; title: string; url: string; confidence: number }>; 
  }> {
    const allSources: PocSource[] = [];
    const dockerInfo: DockerDeploymentInfo[] = [];
    const sourceBreakdown: Record<string, number> = {};

    // Search all sources in parallel for efficiency - FREE SOURCES ONLY
    const searchTasks = [
      this.searchGitHub(cveId, options),
      this.searchGitLab(cveId, options),
      this.searchDockerHub(cveId, options),
      this.searchExploitDB(cveId, options),
      this.searchSecurityBlogs(cveId, options),
      this.searchSecurityRSSFeeds(cveId, options)
    ];

    const results = await Promise.allSettled(searchTasks);

    // Process results and collect successful searches
    for (let i = 0; i < results.length; i++) {
      const result = results[i];
      if (result.status === 'fulfilled' && result.value.length > 0) {
        allSources.push(...result.value);
        const sourceType = ['github', 'gitlab', 'dockerhub', 'exploitdb', 'security_blog', 'sec_rss'][i];
        sourceBreakdown[sourceType] = result.value.length;
      }
    }

    // Get Docker deployment info for GitHub repos
    if (options.includeDockerInfo) {
      const githubSources = allSources.filter(s => s.type === 'github');
      for (const source of githubSources.slice(0, 5)) { // Limit to top 5 for performance
        try {
          const deployInfo = await this.analyzeDockerDeployment(source.url);
          if (deployInfo.hasDockerfile || deployInfo.hasCompose) {
            dockerInfo.push(deployInfo);
          }
        } catch (error) {
          console.warn(`Failed to analyze Docker deployment for ${source.url}:`, error);
        }
      }
    }

    // Sort all sources by relevance score
    allSources.sort((a, b) => b.relevanceScore - a.relevanceScore);

    // Try deployment resource discovery (ISO, trials, VM images, docs)
    let deploymentResources: Array<{ type: string; title: string; url: string; confidence: number }> | undefined;
    try {
      const { deploymentResourceService } = await import('./deploymentResourceService');
      const resources = await deploymentResourceService.discoverResources(cveId, { query: options.query, maxResults: 10 });
      deploymentResources = resources.map(r => ({ type: r.type, title: r.title, url: r.url, confidence: r.confidence }));
    } catch (e) {
      console.warn('Deployment resource discovery failed:', e);
    }

    return {
      sources: allSources.slice(0, options.maxResults || 50),
      dockerInfo,
      totalSources: allSources.length,
      sourceBreakdown,
      deploymentResources
    };
  }

  private async searchGitHub(cveId: string, options: SourceSearchOptions): Promise<PocSource[]> {
    try {
      const repos = await this.githubService.searchPoCs(options.query);
      
      return repos.map(repo => ({
        type: 'github' as const,
        title: repo.title,
        url: repo.url,
        description: repo.description || 'GitHub repository',
        author: repo.metadata.author,
        publishedDate: repo.metadata.publishDate || repo.updatedAt,
        relevanceScore: repo.relevanceScore,
        tags: ['poc', 'github', 'repository'],
        metadata: {
          stars: repo.metadata.stars,
          language: repo.metadata.language,
          lastUpdate: repo.updatedAt
        }
      }));
    } catch (error) {
      console.error('GitHub search failed:', error);
      return [];
    }
  }

  // GitLab search - completely free alternative to paid APIs
  private async searchGitLab(cveId: string, options: SourceSearchOptions): Promise<PocSource[]> {
    const cacheKey = `gitlab:${options.query}`;
    const cached = this.getCached(cacheKey);
    if (cached) return cached;

    try {
      // Enhanced search queries specifically for PoC discovery
      const searchQueries = [
        options.query,
        `${options.query} poc`,
        `${options.query} exploit`,
        `${options.query} vulnerability`,
        `${options.query} proof concept`,
        `${options.query} demo`,
        `${options.query} lab`,
        `${options.query} reproduce`,
        `${options.query} ctf`,          // New: CTF challenges
        `${options.query} tryhackme`,    // New: Popular lab platforms
        `${options.query} hackthebox`    // New: More lab terms
      ];

      const allRepos: PocSource[] = [];

      for (const query of searchQueries) {
        try {
          const url = `https://gitlab.com/api/v4/projects?search=${encodeURIComponent(query)}&order_by=star_count&sort=desc&per_page=20`;
          const response = await this.makeReliableRequest(url, {}, 'GitLab');

          if (response?.ok) {
            const projects = await response.json();
            const relevantRepos = projects
              ?.filter((project: any) => {
                const name = project.name?.toLowerCase() || '';
                const description = project.description?.toLowerCase() || '';
                const queryLower = options.query.toLowerCase();
                
                // More comprehensive filtering for PoC repositories
                return (
                  name.includes(queryLower) ||
                  description.includes(queryLower) ||
                  name.includes('cve') ||
                  name.includes('poc') ||
                  name.includes('exploit') ||
                  name.includes('vulnerability') ||
                  description.includes('poc') ||
                  description.includes('exploit') ||
                  description.includes('vulnerability')
                );
              })
              .map((project: any) => ({
                type: 'gitlab' as const,
                title: project.name,
                url: project.web_url,
                description: project.description || 'GitLab repository',
                author: project.namespace?.name,
                publishedDate: new Date(project.created_at),
                relevanceScore: this.calculateGitLabRelevance(project, options.query),
                tags: ['gitlab', 'repository', 'poc'],
                metadata: {
                  stars: project.star_count,
                  forks: project.forks_count,
                  lastActivity: project.last_activity_at,
                  visibility: project.visibility
                }
              })) || [];

            allRepos.push(...relevantRepos);
          } else if (response) {
            console.warn(`GitLab API returned ${response.status} for query "${query}"`);
          }
        } catch (error) {
          console.warn(`GitLab search failed for query "${query}":`, error);
        }
      }

      const uniqueRepos = this.deduplicateSources(allRepos);
      this.setCached(cacheKey, uniqueRepos);
      return uniqueRepos;

    } catch (error) {
      console.error('GitLab search failed:', error);
      return [];
    }
  }

  private async searchDockerHub(cveId: string, options: SourceSearchOptions): Promise<PocSource[]> {
    const cacheKey = `dockerhub:${options.query}`;
    const cached = this.getCached(cacheKey);
    if (cached) return cached;

    try {
      // Search DockerHub for CVE-related containers
      const searchQueries = [
        options.query,
        `${options.query}-poc`,
        `${options.query.replace('-', '')}poc`,  // New: No hyphen variant
        `vulnerability-${options.query}`,
        `${options.query}-lab`,                  // New: Lab containers
        `${options.query}-ctf`                   // New: CTF Docker images
      ];

      const allContainers: PocSource[] = [];

      for (const query of searchQueries) {
        try {
          const url = `https://hub.docker.com/v2/search/repositories/?query=${encodeURIComponent(query)}&page_size=25`;
          const response = await this.makeReliableRequest(url, {}, 'DockerHub');

          if (response?.ok) {
            const data = await response.json();
            const relevantContainers = data.results
              ?.filter((repo: any) => 
                repo.name?.toLowerCase().includes(options.query.toLowerCase()) ||
                repo.short_description?.toLowerCase().includes(options.query.toLowerCase())
              )
              .map((repo: any) => ({
                type: 'dockerhub' as const,
                title: repo.name,
                url: `https://hub.docker.com/r/${repo.namespace}/${repo.name}`,
                description: repo.short_description || 'Docker container',
                author: repo.namespace,
                publishedDate: new Date(repo.date_registered),
                relevanceScore: this.calculateDockerRelevance(repo, options.query),
                tags: ['docker', 'container', 'deployment'],
                metadata: {
                  stars: repo.star_count,
                  pulls: repo.pull_count,
                  automated: repo.is_automated,
                  official: repo.is_official
                }
              })) || [];

            allContainers.push(...relevantContainers);
          } else if (response) {
            console.warn(`DockerHub API returned ${response.status} for query "${query}"`);
          }
        } catch (error) {
          console.warn(`DockerHub search failed for query "${query}":`, error);
        }
      }

      const uniqueContainers = this.deduplicateSources(allContainers);
      this.setCached(cacheKey, uniqueContainers);
      return uniqueContainers;

    } catch (error) {
      console.error('DockerHub search failed:', error);
      return [];
    }
  }

  // Enhanced free security RSS feeds search
  private async searchSecurityRSSFeeds(cveId: string, options: SourceSearchOptions): Promise<PocSource[]> {
    const cacheKey = `sec_rss:${options.query}`;
    const cached = this.getCached(cacheKey);
    if (cached) return cached;

    try {
      // Curated list of reliable security RSS feeds
      const securityFeeds = [
        { name: 'The Hacker News', url: 'https://feeds.feedburner.com/TheHackersNews' },
        { name: 'SANS ISC', url: 'https://isc.sans.edu/rssfeed.xml' },
        { name: 'Krebs on Security', url: 'https://krebsonsecurity.com/feed/' },
        { name: 'Schneier on Security', url: 'https://www.schneier.com/feed/' },
        { name: 'BleepingComputer', url: 'https://www.bleepingcomputer.com/feed/' },
        // Removed: CVE Details (404), SecurityFocus (dead domain)
      ];

      const allBlogPosts: PocSource[] = [];

      for (const feed of securityFeeds) {
        try {
          const response = await this.makeReliableRequest(feed.url, {}, `RSS-${feed.name}`);
          
          if (response?.ok) {
            const rssText = await response.text();
            const posts = this.parseRSSForCVE(rssText, options.query, feed.name);
            allBlogPosts.push(...posts);
          } else if (response) {
            console.warn(`RSS feed ${feed.name} returned ${response.status}`);
          }
        } catch (error) {
          console.warn(`Failed to fetch ${feed.name} RSS:`, error);
        }
      }

      // Also search exploit-db RSS feed specifically
      try {
        const exploitDbRss = await fetch('https://www.exploit-db.com/rss.xml', {
          headers: { 'User-Agent': 'CVE-Lab-Hunter/1.0' }
        });
        if (exploitDbRss.ok) {
          const rssText = await exploitDbRss.text();
          const exploits = this.parseRSSForCVE(rssText, options.query, 'Exploit-DB RSS');
          allBlogPosts.push(...exploits);
        }
      } catch (error) {
        console.warn('Failed to fetch Exploit-DB RSS:', error);
      }

      this.setCached(cacheKey, allBlogPosts);
      return allBlogPosts;

    } catch (error) {
      console.error('Security RSS feeds search failed:', error);
      return [];
    }
  }

  private async searchExploitDB(cveId: string, options: SourceSearchOptions): Promise<PocSource[]> {
    const cacheKey = `exploitdb:${options.query}`;
    const cached = this.getCached(cacheKey);
    if (cached) return cached;

    try {
      // ExploitDB API often returns HTML instead of JSON, so we'll skip direct API
      // and rely on CSV data or RSS feed instead
      console.log('ExploitDB: Using RSS feed for CVE discovery (API endpoint unreliable)');
      
      const exploitDbRss = await this.makeReliableRequest(
        'https://www.exploit-db.com/rss.xml', 
        { headers: { 'User-Agent': 'CVE-Lab-Hunter/2.0' } },
        'ExploitDB-RSS'
      );
      
      if (exploitDbRss?.ok) {
        const rssText = await exploitDbRss.text();
        const exploits = this.parseRSSForCVE(rssText, options.query, 'ExploitDB');
        this.setCached(cacheKey, exploits);
        return exploits;
      }

      console.warn('ExploitDB RSS feed unavailable, skipping ExploitDB search');
      return [];
    } catch (error) {
      console.error('ExploitDB search failed:', error);
      return [];
    }
  }

  private async searchSecurityBlogs(cveId: string, options: SourceSearchOptions): Promise<PocSource[]> {
    const cacheKey = `secblogs:${options.query}`;
    const cached = this.getCached(cacheKey);
    if (cached) return cached;

    try {
      // Search major security blogs via RSS feeds and web scraping
      const securityFeeds = [
        { name: 'Krebs on Security', url: 'https://krebsonsecurity.com/feed/' },
        { name: 'Schneier on Security', url: 'https://www.schneier.com/feed/' },
        { name: 'SANS ISC', url: 'https://isc.sans.edu/rssfeed.xml' },
        { name: 'The Hacker News', url: 'https://feeds.feedburner.com/TheHackersNews' }
      ];

      const allBlogPosts: PocSource[] = [];

      for (const feed of securityFeeds) {
        try {
          const response = await fetch(feed.url);
          if (response.ok) {
            const rssText = await response.text();
            const posts = this.parseRSSForCVE(rssText, options.query, feed.name);
            allBlogPosts.push(...posts);
          }
        } catch (error) {
          console.warn(`Failed to fetch ${feed.name} RSS:`, error);
        }
      }

      this.setCached(cacheKey, allBlogPosts);
      return allBlogPosts;

    } catch (error) {
      console.error('Security blogs search failed:', error);
      return [];
    }
  }

  private async analyzeDockerDeployment(repoUrl: string): Promise<DockerDeploymentInfo> {
    try {
      const hasDockerfile = await this.githubService.checkDockerDeployability(repoUrl);
      
      // Additional checks for docker-compose
      const owner = repoUrl.split('/')[3];
      const repo = repoUrl.split('/')[4];
      
      let hasCompose = false;
      let setupInstructions = '';
      
      // Check for docker-compose files
      const composeFiles = ['docker-compose.yml', 'docker-compose.yaml'];
      for (const file of composeFiles) {
        try {
          const response = await fetch(
            `https://api.github.com/repos/${owner}/${repo}/contents/${file}`,
            {
              headers: {
                'Accept': 'application/vnd.github.v3+json',
                'User-Agent': 'CVE-Lab-Hunter/1.0'
              }
            }
          );
          if (response.ok) {
            hasCompose = true;
            break;
          }
        } catch (error) {
          // Continue checking other files
        }
      }

      // Analyze setup complexity
      let deploymentComplexity: 'simple' | 'moderate' | 'complex' = 'moderate';
      const prerequisites: string[] = ['Docker'];
      let estimatedSetupTime = '10-30 minutes';

      if (hasCompose) {
        deploymentComplexity = 'simple';
        estimatedSetupTime = '5-15 minutes';
        setupInstructions = 'Run `docker-compose up -d` to deploy the vulnerable environment.';
      } else if (hasDockerfile) {
        setupInstructions = 'Build and run with `docker build -t vuln-lab . && docker run -p 80:80 vuln-lab`';
      } else {
        deploymentComplexity = 'complex';
        estimatedSetupTime = '30+ minutes';
        prerequisites.push('Manual configuration required');
        setupInstructions = 'Manual setup required. See repository README for detailed instructions.';
      }

      return {
        hasDockerfile,
        hasCompose,
        setupInstructions,
        deploymentComplexity,
        prerequisites,
        estimatedSetupTime
      };

    } catch (error) {
      console.error('Failed to analyze Docker deployment:', error);
      return {
        hasDockerfile: false,
        hasCompose: false,
        deploymentComplexity: 'complex',
        prerequisites: ['Manual setup'],
        estimatedSetupTime: 'Unknown'
      };
    }
  }

  // Relevance calculation methods
  private calculateGitHubRelevance(repo: any, cveId: string): number {
    let score = 0;
    const name = repo.name?.toLowerCase() || '';
    const description = repo.description?.toLowerCase() || '';
    const cveIdLower = cveId.toLowerCase();

    if (name.includes(cveIdLower)) score += 10;
    if (description.includes(cveIdLower)) score += 5;
    if (name.includes('poc') || name.includes('exploit')) score += 8;
    if (description.includes('poc') || description.includes('exploit')) score += 4;
    score += Math.log10((repo.stargazers_count || 0) + 1);
    
    const lastUpdate = new Date(repo.updated_at);
    const oneYearAgo = new Date();
    oneYearAgo.setFullYear(oneYearAgo.getFullYear() - 1);
    if (lastUpdate > oneYearAgo) score += 2;

    return score;
  }

  private calculateMediumRelevance(article: any, cveId: string): number {
    let score = 0;
    const title = article.title?.toLowerCase() || '';
    const subtitle = article.subtitle?.toLowerCase() || '';
    const cveIdLower = cveId.toLowerCase();

    if (title.includes(cveIdLower)) score += 10;
    if (subtitle.includes(cveIdLower)) score += 5;
    score += Math.log10((article.clap_count || 0) + 1) * 0.5;
    
    // Boost for cybersecurity publications
    if (article.publication?.name?.toLowerCase().includes('security') || 
        article.publication?.name?.toLowerCase().includes('cyber')) {
      score += 3;
    }

    return score;
  }

  private calculateDockerRelevance(repo: any, cveId: string): number {
    let score = 0;
    const name = repo.name?.toLowerCase() || '';
    const description = repo.short_description?.toLowerCase() || '';
    const cveIdLower = cveId.toLowerCase();

    if (name.includes(cveIdLower)) score += 10;
    if (description.includes(cveIdLower)) score += 5;
    score += Math.log10((repo.star_count || 0) + 1);
    score += Math.log10((repo.pull_count || 0) + 1) * 0.1;
    
    if (repo.is_official) score += 5;
    if (repo.is_automated) score += 2;

    return score;
  }

  private calculateYouTubeRelevance(video: any, cveId: string): number {
    let score = 0;
    const title = video.snippet.title?.toLowerCase() || '';
    const description = video.snippet.description?.toLowerCase() || '';
    const cveIdLower = cveId.toLowerCase();

    if (title.includes(cveIdLower)) score += 10;
    if (description.includes(cveIdLower)) score += 5;
    
    // Boost for tutorial/demonstration keywords
    if (title.includes('tutorial') || title.includes('demo') || title.includes('walkthrough')) score += 3;
    if (description.includes('tutorial') || description.includes('demo') || description.includes('walkthrough')) score += 2;

    return score;
  }

  private calculateExploitDBRelevance(exploit: any, cveId: string): number {
    let score = 15; // Base score for being in ExploitDB
    const title = exploit.title?.toLowerCase() || '';
    const cveIdLower = cveId.toLowerCase();

    if (title.includes(cveIdLower)) score += 10;
    if (exploit.verified) score += 5;
    if (exploit.platform?.toLowerCase().includes('linux') || 
        exploit.platform?.toLowerCase().includes('windows')) score += 2;

    return score;
  }

  private calculateGitLabRelevance(project: any, cveId: string): number {
    let score = 0;
    const name = project.name?.toLowerCase() || '';
    const description = project.description?.toLowerCase() || '';
    const cveIdLower = cveId.toLowerCase();

    if (name.includes(cveIdLower)) score += 10;
    if (description.includes(cveIdLower)) score += 5;
    if (name.includes('poc') || name.includes('exploit')) score += 8;
    if (description.includes('poc') || description.includes('exploit')) score += 4;
    score += Math.log10((project.star_count || 0) + 1);
    
    const lastActivity = new Date(project.last_activity_at);
    const oneYearAgo = new Date();
    oneYearAgo.setFullYear(oneYearAgo.getFullYear() - 1);
    if (lastActivity > oneYearAgo) score += 2;

    // Boost for public repositories
    if (project.visibility === 'public') score += 1;

    return score;
  }

  private calculateSecurityBlogRelevance(post: any, cveId: string): number {
    let score = 0;
    const title = post.title?.toLowerCase() || '';
    const description = post.description?.toLowerCase() || '';
    const cveIdLower = cveId.toLowerCase();

    if (title.includes(cveIdLower)) score += 10;
    if (description.includes(cveIdLower)) score += 5;
    
    // Boost for analysis/poc keywords
    if (title.includes('analysis') || title.includes('poc') || title.includes('exploit')) score += 3;
    if (description.includes('analysis') || description.includes('poc') || description.includes('exploit')) score += 2;
    
    // Boost for recent posts
    if (post.publishedDate) {
      const postDate = new Date(post.publishedDate);
      const thirtyDaysAgo = new Date();
      thirtyDaysAgo.setDate(thirtyDaysAgo.getDate() - 30);
      if (postDate > thirtyDaysAgo) score += 3;
    }

    return score;
  }

  // Utility methods
  private deduplicateSources(sources: PocSource[]): PocSource[] {
    const seen = new Set<string>();
    return sources.filter(source => {
      const key = `${source.type}:${source.url}`;
      if (seen.has(key)) return false;
      seen.add(key);
      return true;
    });
  }

  private parseRSSForCVE(rssText: string, cveId: string, sourceName: string): PocSource[] {
    const posts: PocSource[] = [];
    const cveIdLower = cveId.toLowerCase();
    
    try {
      // Simple RSS parsing - look for CVE mentions in titles and descriptions
      const titleMatches = rssText.match(/<title[^>]*>(.*?)<\/title>/gi) || [];
      const linkMatches = rssText.match(/<link[^>]*>(.*?)<\/link>/gi) || [];
      const descMatches = rssText.match(/<description[^>]*>(.*?)<\/description>/gi) || [];
      
      for (let i = 0; i < titleMatches.length; i++) {
        const title = titleMatches[i]?.replace(/<[^>]*>/g, '') || '';
        const link = linkMatches[i]?.replace(/<[^>]*>/g, '') || '';
        const description = descMatches[i]?.replace(/<[^>]*>/g, '') || '';
        
        if (title.toLowerCase().includes(cveIdLower) || 
            description.toLowerCase().includes(cveIdLower)) {
          posts.push({
            type: 'security_blog',
            title: title.trim(),
            url: link.trim(),
            description: description.trim().substring(0, 200) + '...',
            author: sourceName,
            publishedDate: new Date(),
            relevanceScore: title.toLowerCase().includes(cveIdLower) ? 8 : 5,
            tags: ['blog', 'security', 'news'],
            metadata: { source: sourceName }
          });
        }
      }
    } catch (error) {
      console.warn(`RSS parsing failed for ${sourceName}:`, error);
    }
    
    return posts;
  }

  private getCached(key: string): any {
    const cached = this.cache.get(key);
    if (cached && (Date.now() - cached.timestamp) < this.cacheTimeout) {
      return cached.data;
    }
    return null;
  }

  private setCached(key: string, data: any): void {
    this.cache.set(key, { data, timestamp: Date.now() });
  }
}

export const multiSourceDiscoveryService = new MultiSourceDiscoveryService();