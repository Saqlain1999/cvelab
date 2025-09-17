import { rateLimit } from './rateLimiter';

export interface WebSearchResult {
  title: string;
  url: string;
  snippet?: string;
  source: 'bing';
  confidence: number; // 0-1
}

export class SearchProviderService {
  private getBingKey(): string | undefined {
    return process.env.BING_API_KEY || process.env.bing_api_key || undefined;
  }

  async searchBingWeb(query: string, count = 10): Promise<WebSearchResult[]> {
    const key = this.getBingKey();
    if (!key) return [];

    await rateLimit('Bing');
    const params = new URLSearchParams({ q: query, count: String(Math.min(50, Math.max(1, count))) });
    const resp = await fetch(`https://api.bing.microsoft.com/v7.0/search?${params}`, {
      headers: {
        'Ocp-Apim-Subscription-Key': key,
        'User-Agent': 'CVE-Lab-Hunter/2.0'
      },
      signal: AbortSignal.timeout(12000)
    });
    if (!resp.ok) return [];
    const data = await resp.json();
    const webPages = data.webPages?.value || [];
    return webPages.map((item: any) => ({
      title: item.name,
      url: item.url,
      snippet: item.snippet,
      source: 'bing' as const,
      confidence: 0.5
    }));
  }
}

export const searchProviderService = new SearchProviderService();


