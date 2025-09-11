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
  }>;
}

export class GitHubService {
  private readonly BASE_URL = 'https://api.github.com';
  private readonly API_KEY = process.env.GITHUB_API_KEY || process.env.GITHUB_TOKEN || '';

  async searchPoCs(cveId: string): Promise<any[]> {
    const queries = [
      `${cveId} poc`,
      `${cveId} exploit`,
      `${cveId} vulnerability`,
      `"${cveId}" proof concept`
    ];

    const allResults: any[] = [];

    for (const query of queries) {
      try {
        const results = await this.searchRepositories(query);
        // Filter for likely PoC repositories
        const pocResults = results.filter(repo => this.isPocRepository(repo, cveId));
        allResults.push(...pocResults);
      } catch (error) {
        console.error(`Error searching GitHub for ${query}:`, error);
      }
    }

    // Remove duplicates and rank by relevance
    const uniqueResults = this.deduplicateResults(allResults);
    return this.rankResults(uniqueResults, cveId);
  }

  private async searchRepositories(query: string): Promise<any[]> {
    const params = new URLSearchParams({
      q: query,
      sort: 'stars',
      order: 'desc',
      per_page: '30'
    });

    const headers: Record<string, string> = {
      'Accept': 'application/vnd.github.v3+json',
      'User-Agent': 'CVE-Lab-Hunter/1.0'
    };

    if (this.API_KEY) {
      headers['Authorization'] = `token ${this.API_KEY}`;
    }

    try {
      const response = await fetch(`${this.BASE_URL}/search/repositories?${params}`, {
        headers
      });

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

    // Look for PoC/exploit indicators
    const pocIndicators = ['poc', 'exploit', 'vulnerability', 'cve', 'proof', 'concept'];
    const hasIndicator = pocIndicators.some(indicator => 
      name.includes(indicator) || description.includes(indicator)
    );

    return hasIndicator;
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
      .sort((a, b) => b.relevanceScore - a.relevanceScore)
      .slice(0, 5); // Top 5 most relevant
  }

  private calculateRelevanceScore(repo: any, cveId: string): number {
    let score = 0;
    
    const name = repo.name.toLowerCase();
    const description = (repo.description || '').toLowerCase();
    const cveIdLower = cveId.toLowerCase();

    // CVE ID in name (highest weight)
    if (name.includes(cveIdLower)) score += 10;
    
    // CVE ID in description
    if (description.includes(cveIdLower)) score += 5;
    
    // PoC indicators in name
    if (name.includes('poc') || name.includes('exploit')) score += 8;
    
    // PoC indicators in description
    if (description.includes('poc') || description.includes('exploit')) score += 4;
    
    // Star count (logarithmic scale)
    score += Math.log10(repo.stargazers_count + 1);
    
    // Recent activity (within last year)
    const lastUpdate = new Date(repo.updated_at);
    const oneYearAgo = new Date();
    oneYearAgo.setFullYear(oneYearAgo.getFullYear() - 1);
    if (lastUpdate > oneYearAgo) score += 2;
    
    return score;
  }

  async checkDockerDeployability(repoUrl: string): Promise<boolean> {
    // Check if repository contains Docker-related files
    try {
      const owner = repoUrl.split('/')[3];
      const repo = repoUrl.split('/')[4];
      
      const files = ['Dockerfile', 'docker-compose.yml', 'docker-compose.yaml'];
      
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
}
