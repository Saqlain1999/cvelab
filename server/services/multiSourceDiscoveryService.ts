import { GitHubService } from './githubService';

export interface PocSource {
  type: 'github' | 'medium' | 'dockerhub' | 'youtube' | 'exploitdb' | 'security_blog';
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
  private rapidApiKey: string;
  private youtubeApiKey: string;
  private cacheTimeout = 1000 * 60 * 30; // 30 minutes
  private cache = new Map<string, { data: any; timestamp: number }>();

  constructor() {
    this.githubService = new GitHubService();
    this.rapidApiKey = process.env.RAPIDAPI_KEY || '';
    this.youtubeApiKey = process.env.YOUTUBE_API_KEY || process.env.GOOGLE_API_KEY || '';
  }

  async discoverAllSources(cveId: string, options: SourceSearchOptions = { query: cveId }): Promise<{
    sources: PocSource[];
    dockerInfo: DockerDeploymentInfo[];
    totalSources: number;
    sourceBreakdown: Record<string, number>;
  }> {
    const allSources: PocSource[] = [];
    const dockerInfo: DockerDeploymentInfo[] = [];
    const sourceBreakdown: Record<string, number> = {};

    // Search all sources in parallel for efficiency
    const searchTasks = [
      this.searchGitHub(cveId, options),
      this.searchMedium(cveId, options),
      this.searchDockerHub(cveId, options),
      this.searchYouTube(cveId, options),
      this.searchExploitDB(cveId, options),
      this.searchSecurityBlogs(cveId, options)
    ];

    const results = await Promise.allSettled(searchTasks);

    // Process results and collect successful searches
    for (let i = 0; i < results.length; i++) {
      const result = results[i];
      if (result.status === 'fulfilled' && result.value.length > 0) {
        allSources.push(...result.value);
        const sourceType = ['github', 'medium', 'dockerhub', 'youtube', 'exploitdb', 'security_blog'][i];
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

    return {
      sources: allSources.slice(0, options.maxResults || 50),
      dockerInfo,
      totalSources: allSources.length,
      sourceBreakdown
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

  private async searchMedium(cveId: string, options: SourceSearchOptions): Promise<PocSource[]> {
    if (!this.rapidApiKey) {
      console.warn('RapidAPI key not found, skipping Medium search');
      return [];
    }

    const cacheKey = `medium:${options.query}`;
    const cached = this.getCached(cacheKey);
    if (cached) return cached;

    try {
      // Search Medium articles using unofficial API
      const searchQueries = [
        options.query,
        `${options.query} vulnerability`,
        `${options.query} exploit`,
        `${options.query} proof of concept`
      ];

      const allArticles: PocSource[] = [];

      for (const query of searchQueries) {
        try {
          // Search by cybersecurity tag with CVE content
          const response = await fetch(
            `https://medium-api.p.rapidapi.com/tag/cybersecurity/articles?mode=hot&count=25`,
            {
              headers: {
                'X-RapidAPI-Key': this.rapidApiKey,
                'X-RapidAPI-Host': 'medium-api.p.rapidapi.com'
              }
            }
          );

          if (response.ok) {
            const data = await response.json();
            const relevantArticles = data.articles
              ?.filter((article: any) => 
                article.title?.toLowerCase().includes(options.query.toLowerCase()) ||
                article.subtitle?.toLowerCase().includes(options.query.toLowerCase())
              )
              .map((article: any) => ({
                type: 'medium' as const,
                title: article.title,
                url: article.url,
                description: article.subtitle || article.title,
                author: article.author?.name,
                publishedDate: new Date(article.published_at),
                relevanceScore: this.calculateMediumRelevance(article, options.query),
                tags: ['medium', 'article', 'analysis'],
                metadata: {
                  claps: article.clap_count,
                  readingTime: article.reading_time,
                  publication: article.publication?.name
                }
              })) || [];

            allArticles.push(...relevantArticles);
          }
        } catch (error) {
          console.warn(`Medium search failed for query "${query}":`, error);
        }
      }

      // Also search security-focused tags
      const securityTags = ['vulnerability', 'cybersecurity', 'infosec', 'hacking'];
      for (const tag of securityTags) {
        try {
          const response = await fetch(
            `https://medium-api.p.rapidapi.com/tag/${tag}/articles?mode=new&count=10`,
            {
              headers: {
                'X-RapidAPI-Key': this.rapidApiKey,
                'X-RapidAPI-Host': 'medium-api.p.rapidapi.com'
              }
            }
          );

          if (response.ok) {
            const data = await response.json();
            const relevantArticles = data.articles
              ?.filter((article: any) => 
                article.title?.toLowerCase().includes(options.query.toLowerCase()) ||
                article.subtitle?.toLowerCase().includes(options.query.toLowerCase())
              )
              .map((article: any) => ({
                type: 'medium' as const,
                title: article.title,
                url: article.url,
                description: article.subtitle || article.title,
                author: article.author?.name,
                publishedDate: new Date(article.published_at),
                relevanceScore: this.calculateMediumRelevance(article, options.query),
                tags: ['medium', 'article', tag],
                metadata: {
                  claps: article.clap_count,
                  readingTime: article.reading_time,
                  publication: article.publication?.name
                }
              })) || [];

            allArticles.push(...relevantArticles);
          }
        } catch (error) {
          // Continue with other tags
        }
      }

      const uniqueArticles = this.deduplicateSources(allArticles);
      this.setCached(cacheKey, uniqueArticles);
      return uniqueArticles;

    } catch (error) {
      console.error('Medium search failed:', error);
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
        `${options.query.replace('-', '')}`,
        `vulnerability-${options.query}`
      ];

      const allContainers: PocSource[] = [];

      for (const query of searchQueries) {
        try {
          const response = await fetch(
            `https://hub.docker.com/v2/search/repositories/?query=${encodeURIComponent(query)}&page_size=25`
          );

          if (response.ok) {
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

  private async searchYouTube(cveId: string, options: SourceSearchOptions): Promise<PocSource[]> {
    if (!this.youtubeApiKey) {
      console.warn('YouTube API key not found, skipping YouTube search');
      return [];
    }

    const cacheKey = `youtube:${cveId}`;
    const cached = this.getCached(cacheKey);
    if (cached) return cached;

    try {
      // Search YouTube for vulnerability demonstrations and tutorials
      const searchQueries = [
        `${cveId} demonstration`,
        `${cveId} tutorial`,
        `${cveId} exploit walkthrough`,
        `${cveId} vulnerability explained`,
        `${cveId} proof of concept`
      ];

      const allVideos: PocSource[] = [];

      for (const query of searchQueries) {
        try {
          const response = await fetch(
            `https://www.googleapis.com/youtube/v3/search?part=snippet&q=${encodeURIComponent(query)}&type=video&maxResults=10&key=${this.youtubeApiKey}`
          );

          if (response.ok) {
            const data = await response.json();
            const relevantVideos = data.items
              ?.filter((video: any) => 
                video.snippet.title?.toLowerCase().includes(cveId.toLowerCase()) ||
                video.snippet.description?.toLowerCase().includes(cveId.toLowerCase())
              )
              .map((video: any) => ({
                type: 'youtube' as const,
                title: video.snippet.title,
                url: `https://www.youtube.com/watch?v=${video.id.videoId}`,
                description: video.snippet.description,
                author: video.snippet.channelTitle,
                publishedDate: new Date(video.snippet.publishedAt),
                relevanceScore: this.calculateYouTubeRelevance(video, cveId),
                tags: ['youtube', 'video', 'tutorial'],
                metadata: {
                  channelId: video.snippet.channelId,
                  thumbnails: video.snippet.thumbnails,
                  videoId: video.id.videoId
                }
              })) || [];

            allVideos.push(...relevantVideos);
          }
        } catch (error) {
          console.warn(`YouTube search failed for query "${query}":`, error);
        }
      }

      const uniqueVideos = this.deduplicateSources(allVideos);
      this.setCached(cacheKey, uniqueVideos);
      return uniqueVideos;

    } catch (error) {
      console.error('YouTube search failed:', error);
      return [];
    }
  }

  private async searchExploitDB(cveId: string, options: SourceSearchOptions): Promise<PocSource[]> {
    const cacheKey = `exploitdb:${options.query}`;
    const cached = this.getCached(cacheKey);
    if (cached) return cached;

    try {
      // Search ExploitDB for public exploits
      const response = await fetch(
        `https://www.exploit-db.com/api/v1/search/${encodeURIComponent(options.query)}`
      );

      if (response.ok) {
        const data = await response.json();
        const exploits = data.data
          ?.map((exploit: any) => ({
            type: 'exploitdb' as const,
            title: exploit.title,
            url: `https://www.exploit-db.com/exploits/${exploit.id}`,
            description: exploit.description || exploit.title,
            author: exploit.author,
            publishedDate: new Date(exploit.date),
            relevanceScore: this.calculateExploitDBRelevance(exploit, options.query),
            tags: ['exploit', 'exploitdb', 'poc'],
            metadata: {
              platform: exploit.platform,
              type: exploit.type,
              verified: exploit.verified,
              exploitId: exploit.id
            }
          })) || [];

        this.setCached(cacheKey, exploits);
        return exploits;
      }

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