import type { IStorage } from '../storage';

interface GoogleSheetsRow {
  [key: string]: string | number | boolean;
}

export class GoogleSheetsService {
  private readonly SHEETS_BASE_URL = 'https://sheets.googleapis.com/v4/spreadsheets';
  private storage: IStorage;

  constructor(storage: IStorage) {
    this.storage = storage;
  }

  /**
   * Get Google API key from database configuration, fallback to environment variables
   */
  private async getApiKey(): Promise<string> {
    try {
      const config = await this.storage.getAppConfig();
      if (config?.googleApiKey) {
        return config.googleApiKey;
      }
    } catch (error) {
      console.warn('Failed to retrieve Google API key from database config:', error);
    }
    
    // Fallback to environment variables
    return process.env.GOOGLE_SHEETS_API_KEY || process.env.GOOGLE_API_KEY || '';
  }

  async exportToSheets(spreadsheetId: string, sheetName: string, data: any[]): Promise<boolean> {
    const apiKey = await this.getApiKey();
    if (!apiKey) {
      throw new Error('Google Sheets API key not configured in database or environment variables');
    }

    try {
      // Prepare data for sheets
      const headers = this.getHeaders();
      const rows = [headers, ...data.map(cve => this.transformCveToRow(cve))];

      // Clear existing data
      await this.clearSheet(spreadsheetId, sheetName);

      // Insert new data
      const encodedSheetName = encodeURIComponent(sheetName);
      const response = await fetch(
        `${this.SHEETS_BASE_URL}/${spreadsheetId}/values/${encodedSheetName}:append?valueInputOption=USER_ENTERED&key=${apiKey}`,
        {
          method: 'POST',
          headers: {
            'Content-Type': 'application/json',
          },
          body: JSON.stringify({
            values: rows
          })
        }
      );

      if (!response.ok) {
        throw new Error(`Google Sheets API error: ${response.status} ${response.statusText}`);
      }

      return true;
    } catch (error) {
      console.error('Error exporting to Google Sheets:', error);
      throw error;
    }
  }

  async createSpreadsheet(title: string): Promise<string> {
    const apiKey = await this.getApiKey();
    if (!apiKey) {
      throw new Error('Google Sheets API key not configured in database or environment variables');
    }

    try {
      const response = await fetch(`${this.SHEETS_BASE_URL}?key=${apiKey}`, {
        method: 'POST',
        headers: {
          'Content-Type': 'application/json',
        },
        body: JSON.stringify({
          properties: {
            title: title
          },
          sheets: [{
            properties: {
              title: 'CVE Results'
            }
          }]
        })
      });

      if (!response.ok) {
        throw new Error(`Google Sheets API error: ${response.status} ${response.statusText}`);
      }

      const result = await response.json();
      return result.spreadsheetId;
    } catch (error) {
      console.error('Error creating spreadsheet:', error);
      throw error;
    }
  }

  private async clearSheet(spreadsheetId: string, sheetName: string): Promise<void> {
    const apiKey = await this.getApiKey();
    const encodedSheetName = encodeURIComponent(sheetName);
    const response = await fetch(
      `${this.SHEETS_BASE_URL}/${spreadsheetId}/values/${encodedSheetName}:clear?key=${apiKey}`,
      {
        method: 'POST',
        headers: {
          'Content-Type': 'application/json',
        }
      }
    );

    if (!response.ok) {
      console.warn('Failed to clear sheet, continuing anyway');
    }
  }

  private getHeaders(): string[] {
    return [
      'CVE ID',
      'Severity',
      'CVSS Score',
      'Published Date',
      'Technology',
      'Category',
      'Description',
      'Has Public PoC',
      'Docker Deployable',
      'Curl/Nmap Testable',
      'PoC URLs',
      'Attack Vector',
      'Affected Versions',
      'Exploitability Score',
      'Lab Suitability Score'
    ];
  }

  private transformCveToRow(cve: any): (string | number | boolean)[] {
    return [
      cve.cveId,
      cve.severity,
      cve.cvssScore || 0,
      new Date(cve.publishedDate).toLocaleDateString(),
      cve.technology || '',
      cve.category || '',
      cve.description.substring(0, 500), // Truncate long descriptions
      cve.hasPublicPoc,
      cve.isDockerDeployable,
      cve.isCurlTestable,
      (cve.pocUrls || []).join(', '),
      cve.attackVector || '',
      (cve.affectedVersions || []).join(', '),
      cve.exploitabilityScore || 0,
      cve.labSuitabilityScore || 0
    ];
  }

  async validateSpreadsheetAccess(spreadsheetId: string): Promise<boolean> {
    const apiKey = await this.getApiKey();
    if (!apiKey) {
      return false;
    }

    try {
      const response = await fetch(
        `${this.SHEETS_BASE_URL}/${spreadsheetId}?key=${apiKey}`,
        {
          method: 'GET',
          headers: {
            'Accept': 'application/json',
          }
        }
      );

      return response.ok;
    } catch (error) {
      console.error('Error validating spreadsheet access:', error);
      return false;
    }
  }
}
