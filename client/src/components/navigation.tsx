import { Link, useLocation } from "wouter";
import { ShieldCheck, Home, Search, Settings, Download, Server, Zap } from "lucide-react";

export function Navigation() {
  const [location] = useLocation();

  const navItems = [
    { path: "/", icon: Home, label: "Dashboard", active: location === "/" },
    { path: "/search", icon: Search, label: "CVE Search", active: location === "/search" },
    { path: "/config", icon: Settings, label: "Configuration", active: location === "/config" },
  ];

  return (
    <div className="w-64 bg-card border-r border-border flex flex-col" data-testid="navigation-sidebar">
      {/* Logo */}
      <div className="p-6 border-b border-border">
        <h1 className="text-xl font-bold text-primary flex items-center gap-2" data-testid="app-title">
          <ShieldCheck className="h-6 w-6" />
          CVE Lab Hunter
        </h1>
        <p className="text-sm text-muted-foreground mt-1">Vulnerability Research Platform</p>
      </div>
      
      {/* Navigation Menu */}
      <nav className="flex-1 p-4 space-y-2" data-testid="nav-menu">
        {navItems.map((item) => (
          <Link key={item.path} href={item.path}>
            <div
              className={`flex items-center gap-3 px-3 py-2 rounded-md transition-colors cursor-pointer ${
                item.active
                  ? "bg-primary text-primary-foreground"
                  : "text-muted-foreground hover:text-foreground hover:bg-muted"
              }`}
              data-testid={`nav-link-${item.label.toLowerCase().replace(' ', '-')}`}
            >
              <item.icon className="w-4 h-4" />
              {item.label}
            </div>
          </Link>
        ))}
        
      </nav>
      
      {/* Footer */}
      <div className="p-4 border-t border-border">
        <div className="flex items-center gap-2 text-sm text-muted-foreground" data-testid="connection-status">
          <div className="w-2 h-2 bg-green-500 rounded-full"></div>
          NIST NVD Connected
        </div>
      </div>
    </div>
  );
}
