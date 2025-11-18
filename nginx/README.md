# Nginx Configuration for CVE Lab Platform

## Overview

This directory contains the Nginx reverse proxy configuration for production deployments.

**Note:** Nginx is **optional** and only needed for:
- SSL/TLS termination
- Custom domain with HTTPS
- Load balancing (if scaling to multiple app instances)

**Dokploy users**: You don't need nginx! Dokploy handles SSL/TLS automatically.

---

## Directory Structure

```
nginx/
├── nginx.conf              # Main nginx configuration
├── conf.d/
│   └── cvelab.conf        # CVE Lab site configuration
├── ssl/                    # SSL certificates (add your own)
│   ├── fullchain.pem      # Full certificate chain
│   ├── privkey.pem        # Private key
│   └── chain.pem          # Intermediate certificates
└── logs/                   # Nginx access/error logs
```

---

## Setup SSL Certificates

### Option 1: Let's Encrypt (Recommended)

Using Certbot:

```bash
# Install certbot
sudo apt-get install certbot

# Generate certificate
sudo certbot certonly --standalone -d cvelab.yourdomain.com

# Copy certificates
sudo cp /etc/letsencrypt/live/cvelab.yourdomain.com/fullchain.pem nginx/ssl/
sudo cp /etc/letsencrypt/live/cvelab.yourdomain.com/privkey.pem nginx/ssl/
sudo cp /etc/letsencrypt/live/cvelab.yourdomain.com/chain.pem nginx/ssl/

# Set permissions
sudo chmod 644 nginx/ssl/fullchain.pem nginx/ssl/chain.pem
sudo chmod 600 nginx/ssl/privkey.pem
```

### Option 2: Self-Signed Certificate (Development Only)

```bash
# Generate self-signed certificate
openssl req -x509 -nodes -days 365 -newkey rsa:2048 \
  -keyout nginx/ssl/privkey.pem \
  -out nginx/ssl/fullchain.pem \
  -subj "/CN=cvelab.local"

# Copy for chain
cp nginx/ssl/fullchain.pem nginx/ssl/chain.pem
```

### Option 3: Existing Certificate

If you have SSL certificates from your provider:

```bash
# Copy your certificates
cp /path/to/your/certificate.crt nginx/ssl/fullchain.pem
cp /path/to/your/private.key nginx/ssl/privkey.pem
cp /path/to/your/ca-bundle.crt nginx/ssl/chain.pem
```

---

## Configuration

### Update Domain Name

Edit `nginx/conf.d/cvelab.conf`:

```nginx
server {
    listen 443 ssl http2;
    server_name cvelab.yourdomain.com;  # <- Change this
    ...
}
```

### Start Nginx

```bash
# Start with nginx profile
docker-compose --profile production up -d

# Or explicitly start nginx
docker-compose up -d nginx
```

### Verify Configuration

```bash
# Test nginx config
docker-compose exec nginx nginx -t

# Reload nginx
docker-compose exec nginx nginx -s reload

# View logs
docker-compose logs -f nginx
```

---

## SSL Security Test

After deployment, test your SSL configuration:

```bash
# Using SSL Labs (online)
# Visit: https://www.ssllabs.com/ssltest/analyze.html?d=cvelab.yourdomain.com

# Using testssl.sh (local)
docker run --rm -ti drwetter/testssl.sh cvelab.yourdomain.com
```

Target grade: **A or A+**

---

## Certificate Renewal

### Automatic Renewal (Let's Encrypt)

Create cron job:

```bash
# Edit crontab
crontab -e

# Add this line (runs daily at 2am)
0 2 * * * certbot renew --quiet --post-hook "cp /etc/letsencrypt/live/cvelab.yourdomain.com/*.pem /path/to/nginx/ssl/ && docker-compose exec nginx nginx -s reload"
```

### Manual Renewal

```bash
# Renew certificate
sudo certbot renew

# Copy new certificates
sudo cp /etc/letsencrypt/live/cvelab.yourdomain.com/fullchain.pem nginx/ssl/
sudo cp /etc/letsencrypt/live/cvelab.yourdomain.com/privkey.pem nginx/ssl/
sudo cp /etc/letsencrypt/live/cvelab.yourdomain.com/chain.pem nginx/ssl/

# Reload nginx
docker-compose exec nginx nginx -s reload
```

---

## Troubleshooting

### Certificate Errors

```bash
# Check certificate validity
openssl x509 -in nginx/ssl/fullchain.pem -text -noout

# Check certificate matches key
openssl x509 -noout -modulus -in nginx/ssl/fullchain.pem | openssl md5
openssl rsa -noout -modulus -in nginx/ssl/privkey.pem | openssl md5
# Should match!
```

### Nginx Won't Start

```bash
# Check config syntax
docker-compose exec nginx nginx -t

# View error log
docker-compose logs nginx

# Common issues:
# 1. Missing SSL certificates
# 2. Invalid domain name
# 3. Port 80/443 already in use
```

### Connection Issues

```bash
# Test HTTP redirect
curl -I http://cvelab.yourdomain.com
# Should return: 301 Moved Permanently

# Test HTTPS
curl -I https://cvelab.yourdomain.com
# Should return: 200 OK

# Test from outside
curl -I https://cvelab.yourdomain.com -H "Host: cvelab.yourdomain.com"
```

---

## Performance Tuning

For high traffic, adjust `nginx/nginx.conf`:

```nginx
events {
    worker_connections 4096;  # Increase from 1024
    use epoll;
}

http {
    # Increase buffer sizes
    proxy_buffer_size 8k;
    proxy_buffers 16 8k;

    # Connection pooling
    upstream cvelab_app {
        server app:5000;
        keepalive 32;
    }
}
```

---

## Without Nginx (Dokploy / Direct Deployment)

If you're using Dokploy or don't need nginx:

```bash
# Just use the app directly
docker-compose up -d app db redis

# App is available on port 5000
# Dokploy handles SSL/TLS automatically
```

---

## Security Notes

1. **Keep certificates secure**: chmod 600 privkey.pem
2. **Regular updates**: Keep nginx image updated
3. **Monitor logs**: Check for suspicious activity
4. **Rate limiting**: Consider adding rate limits for public APIs
5. **DDoS protection**: Use Cloudflare or similar for production

---

## Additional Resources

- [Mozilla SSL Configuration Generator](https://ssl-config.mozilla.org/)
- [Let's Encrypt Documentation](https://letsencrypt.org/docs/)
- [Nginx Documentation](https://nginx.org/en/docs/)
- [SSL Labs Test](https://www.ssllabs.com/ssltest/)
