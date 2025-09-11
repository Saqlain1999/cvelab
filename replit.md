# CVE Lab Hunter

## Overview

CVE Lab Hunter is a vulnerability research platform designed for security professionals and researchers to discover, analyze, and deploy CVEs (Common Vulnerabilities and Exposures) in controlled lab environments. The application provides comprehensive CVE discovery, filtering, and lab deployment capabilities with integrations to external services for enhanced functionality.

The platform combines automated CVE scanning from NIST databases with GitHub-based proof-of-concept (PoC) discovery and Google Sheets export functionality. It focuses on identifying vulnerabilities that are suitable for laboratory testing and research purposes.

## User Preferences

Preferred communication style: Simple, everyday language.

## System Architecture

### Frontend Architecture
- **Framework**: React 18 with TypeScript using Vite as the build tool
- **UI Library**: Radix UI components with shadcn/ui styling system
- **Styling**: Tailwind CSS with custom CSS variables for theming (dark mode primary)
- **Routing**: Wouter for client-side routing
- **State Management**: TanStack Query (React Query) for server state management
- **Form Handling**: React Hook Form with Zod validation

### Backend Architecture
- **Server**: Express.js with TypeScript running on Node.js
- **API Pattern**: RESTful API design with JSON responses
- **Middleware**: Custom logging, error handling, and request processing
- **Development Server**: Vite middleware integration for hot module replacement
- **Build Process**: ESBuild for production bundling

### Data Storage Solutions
- **Database**: PostgreSQL with Drizzle ORM for type-safe database operations
- **Connection**: Neon Database serverless PostgreSQL hosting
- **Schema Management**: Drizzle migrations with dedicated migration files
- **Storage Layer**: Abstracted storage interface supporting both in-memory and database implementations

### Authentication and Authorization
- **Session Management**: PostgreSQL-backed sessions using connect-pg-simple
- **User Model**: Simple username/password authentication with UUID-based user identification
- **Security**: Password hashing and secure session cookies

### External Service Integrations

#### CVE Data Sources
- **NIST CVE Database**: Primary source for vulnerability data via REST API
- **Data Processing**: Automated CVE parsing with CVSS scoring and severity classification
- **Filtering**: Advanced filtering by severity, technology, CVSS scores, and exploit availability

#### GitHub Integration
- **PoC Discovery**: Automated search for proof-of-concept exploits and vulnerability demonstrations
- **Repository Analysis**: Ranking and filtering of GitHub repositories based on relevance and quality
- **API Integration**: GitHub API for repository metadata and search functionality

#### Google Sheets Integration
- **Export Functionality**: Direct export of filtered CVE data to Google Sheets
- **Spreadsheet Management**: Automated spreadsheet creation and data formatting
- **API Integration**: Google Sheets API v4 for data manipulation

### Key Features
- **CVE Discovery**: Configurable time-based scanning from NIST databases
- **Lab Suitability Analysis**: Automated scoring for Docker deployability and testing feasibility
- **Proof of Concept Integration**: GitHub-based PoC discovery and linking
- **Advanced Filtering**: Multi-dimensional filtering by severity, technology, and exploit characteristics
- **Export Capabilities**: CSV and Google Sheets export functionality
- **Real-time Updates**: Live data refreshing and scanning status monitoring

### Development Architecture
- **Monorepo Structure**: Shared schema and types between client and server
- **Hot Reload**: Vite-powered development with automatic server restart
- **Type Safety**: End-to-end TypeScript with shared interfaces and validation schemas
- **Code Organization**: Feature-based organization with service layer abstraction