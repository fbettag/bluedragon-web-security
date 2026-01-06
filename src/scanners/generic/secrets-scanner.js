/**
 * BlueDragon Web Security - Secrets Scanner
 * Detects exposed API keys, secrets, endpoints, and sensitive data in JavaScript
 * Ported from JSAnalyzer Burp Suite extension with enhancements
 */

import { SEVERITY } from '../../shared/constants.js';

/**
 * Secret detection patterns with metadata
 */
const SECRET_PATTERNS = [
  // AWS
  {
    pattern: /(A3T[A-Z0-9]|AKIA|AGPA|AIDA|AROA|AIPA|ANPA|ANVA|ASIA)[A-Z0-9]{16}/g,
    name: 'AWS Access Key',
    severity: SEVERITY.CRITICAL,
    validation: 'Check AWS CloudTrail for key usage'
  },
  {
    pattern: /(?<![A-Za-z0-9/+=])[A-Za-z0-9/+=]{40}(?![A-Za-z0-9/+=])/g,
    name: 'AWS Secret Key (Potential)',
    severity: SEVERITY.HIGH,
    context: 'aws|secret|key',
    validation: 'Verify in context of AWS configuration'
  },

  // Google
  {
    pattern: /AIza[0-9A-Za-z\-_]{35}/g,
    name: 'Google API Key',
    severity: SEVERITY.HIGH,
    validation: 'Test with Google APIs to verify scope'
  },
  {
    pattern: /[0-9]+-[0-9A-Za-z_]{32}\.apps\.googleusercontent\.com/g,
    name: 'Google OAuth Client ID',
    severity: SEVERITY.MEDIUM,
    validation: 'Check OAuth configuration'
  },

  // Stripe
  {
    pattern: /sk_live_[0-9a-zA-Z]{24,}/g,
    name: 'Stripe Live Secret Key',
    severity: SEVERITY.CRITICAL,
    validation: 'Immediate rotation required - production key'
  },
  {
    pattern: /sk_test_[0-9a-zA-Z]{24,}/g,
    name: 'Stripe Test Secret Key',
    severity: SEVERITY.MEDIUM,
    validation: 'Test environment key - still sensitive'
  },
  {
    pattern: /pk_live_[0-9a-zA-Z]{24,}/g,
    name: 'Stripe Live Publishable Key',
    severity: SEVERITY.LOW,
    validation: 'Public key - verify intended exposure'
  },
  {
    pattern: /rk_live_[0-9a-zA-Z]{24,}/g,
    name: 'Stripe Restricted Key',
    severity: SEVERITY.HIGH,
    validation: 'Check key permissions in Stripe dashboard'
  },

  // GitHub
  {
    pattern: /ghp_[0-9a-zA-Z]{36}/g,
    name: 'GitHub Personal Access Token',
    severity: SEVERITY.CRITICAL,
    validation: 'Check token scopes at github.com/settings/tokens'
  },
  {
    pattern: /gho_[0-9a-zA-Z]{36}/g,
    name: 'GitHub OAuth Token',
    severity: SEVERITY.CRITICAL,
    validation: 'OAuth token - check application permissions'
  },
  {
    pattern: /ghu_[0-9a-zA-Z]{36}/g,
    name: 'GitHub User-to-Server Token',
    severity: SEVERITY.CRITICAL,
    validation: 'GitHub App token - verify app permissions'
  },
  {
    pattern: /ghs_[0-9a-zA-Z]{36}/g,
    name: 'GitHub Server-to-Server Token',
    severity: SEVERITY.CRITICAL,
    validation: 'GitHub App installation token'
  },
  {
    pattern: /ghr_[0-9a-zA-Z]{36}/g,
    name: 'GitHub Refresh Token',
    severity: SEVERITY.CRITICAL,
    validation: 'Can generate new access tokens'
  },

  // GitLab
  {
    pattern: /glpat-[0-9a-zA-Z\-_]{20,}/g,
    name: 'GitLab Personal Access Token',
    severity: SEVERITY.CRITICAL,
    validation: 'Check token scopes in GitLab settings'
  },

  // Slack
  {
    pattern: /xox[baprs]-[0-9a-zA-Z\-]{10,48}/g,
    name: 'Slack Token',
    severity: SEVERITY.HIGH,
    validation: 'Test with Slack API - xoxb=bot, xoxp=user, xoxa=app'
  },
  {
    pattern: /https:\/\/hooks\.slack\.com\/services\/T[A-Z0-9]+\/B[A-Z0-9]+\/[a-zA-Z0-9]+/g,
    name: 'Slack Webhook URL',
    severity: SEVERITY.MEDIUM,
    validation: 'Can post messages to Slack channel'
  },

  // Discord
  {
    pattern: /https:\/\/discord(?:app)?\.com\/api\/webhooks\/[0-9]+\/[A-Za-z0-9_-]+/g,
    name: 'Discord Webhook URL',
    severity: SEVERITY.MEDIUM,
    validation: 'Can post messages to Discord channel'
  },
  {
    pattern: /[MN][A-Za-z\d]{23,}\.[\w-]{6}\.[\w-]{27}/g,
    name: 'Discord Bot Token',
    severity: SEVERITY.CRITICAL,
    validation: 'Full Discord bot access'
  },

  // JWT
  {
    pattern: /eyJ[A-Za-z0-9_-]{10,}\.eyJ[A-Za-z0-9_-]{10,}\.[A-Za-z0-9_-]+/g,
    name: 'JWT Token',
    severity: SEVERITY.MEDIUM,
    validation: 'Decode at jwt.io to check claims and expiration'
  },

  // Private Keys
  {
    pattern: /-----BEGIN\s+(?:RSA\s+)?PRIVATE\s+KEY-----/g,
    name: 'RSA Private Key',
    severity: SEVERITY.CRITICAL,
    validation: 'Private key exposure - immediate rotation needed'
  },
  {
    pattern: /-----BEGIN\s+(?:EC\s+)?PRIVATE\s+KEY-----/g,
    name: 'EC Private Key',
    severity: SEVERITY.CRITICAL,
    validation: 'Private key exposure - immediate rotation needed'
  },
  {
    pattern: /-----BEGIN\s+OPENSSH\s+PRIVATE\s+KEY-----/g,
    name: 'OpenSSH Private Key',
    severity: SEVERITY.CRITICAL,
    validation: 'SSH key exposure - immediate rotation needed'
  },
  {
    pattern: /-----BEGIN\s+PGP\s+PRIVATE\s+KEY\s+BLOCK-----/g,
    name: 'PGP Private Key',
    severity: SEVERITY.CRITICAL,
    validation: 'PGP key exposure - immediate rotation needed'
  },

  // Database Connection Strings
  {
    pattern: /mongodb(?:\+srv)?:\/\/[^\s"'<>]+/g,
    name: 'MongoDB Connection String',
    severity: SEVERITY.CRITICAL,
    validation: 'Database credentials exposed - check access'
  },
  {
    pattern: /postgres(?:ql)?:\/\/[^\s"'<>]+/g,
    name: 'PostgreSQL Connection String',
    severity: SEVERITY.CRITICAL,
    validation: 'Database credentials exposed - check access'
  },
  {
    pattern: /mysql:\/\/[^\s"'<>]+/g,
    name: 'MySQL Connection String',
    severity: SEVERITY.CRITICAL,
    validation: 'Database credentials exposed - check access'
  },
  {
    pattern: /redis:\/\/[^\s"'<>]+/g,
    name: 'Redis Connection String',
    severity: SEVERITY.HIGH,
    validation: 'Redis credentials exposed - check access'
  },
  {
    pattern: /amqp:\/\/[^\s"'<>]+/g,
    name: 'RabbitMQ Connection String',
    severity: SEVERITY.HIGH,
    validation: 'Message queue credentials exposed'
  },

  // Cloud Provider Tokens
  {
    pattern: /AccountKey=[A-Za-z0-9+/=]{86,}/g,
    name: 'Azure Storage Account Key',
    severity: SEVERITY.CRITICAL,
    validation: 'Azure storage full access key'
  },
  {
    pattern: /[a-zA-Z0-9_-]{24}\.[a-zA-Z0-9_-]{6}\.[a-zA-Z0-9_-]{25,}/g,
    name: 'Firebase Auth Token (Potential)',
    severity: SEVERITY.MEDIUM,
    context: 'firebase',
    validation: 'Verify Firebase project context'
  },

  // Twilio
  {
    pattern: /SK[0-9a-fA-F]{32}/g,
    name: 'Twilio API Key',
    severity: SEVERITY.HIGH,
    validation: 'Check Twilio console for key permissions'
  },
  {
    pattern: /AC[0-9a-fA-F]{32}/g,
    name: 'Twilio Account SID',
    severity: SEVERITY.MEDIUM,
    validation: 'Account identifier - check if Auth Token exposed'
  },

  // SendGrid
  {
    pattern: /SG\.[A-Za-z0-9_-]{22}\.[A-Za-z0-9_-]{43}/g,
    name: 'SendGrid API Key',
    severity: SEVERITY.HIGH,
    validation: 'Email sending capability - check permissions'
  },

  // Mailchimp
  {
    pattern: /[a-f0-9]{32}-us[0-9]{1,2}/g,
    name: 'Mailchimp API Key',
    severity: SEVERITY.HIGH,
    validation: 'Email marketing access'
  },

  // NPM
  {
    pattern: /npm_[A-Za-z0-9]{36}/g,
    name: 'NPM Access Token',
    severity: SEVERITY.HIGH,
    validation: 'Can publish packages to npm'
  },

  // PyPI
  {
    pattern: /pypi-AgEIcHlwaS5vcmc[A-Za-z0-9_-]{50,}/g,
    name: 'PyPI API Token',
    severity: SEVERITY.HIGH,
    validation: 'Can publish packages to PyPI'
  },

  // Heroku
  {
    pattern: /[0-9a-fA-F]{8}-[0-9a-fA-F]{4}-[0-9a-fA-F]{4}-[0-9a-fA-F]{4}-[0-9a-fA-F]{12}/g,
    name: 'Heroku API Key (Potential UUID)',
    severity: SEVERITY.LOW,
    context: 'heroku|api',
    validation: 'May be Heroku API key - verify context'
  },

  // Square
  {
    pattern: /sq0[a-z]{3}-[0-9A-Za-z\-_]{22,}/g,
    name: 'Square Access Token',
    severity: SEVERITY.HIGH,
    validation: 'Payment processing access'
  },

  // Shopify
  {
    pattern: /shpat_[a-fA-F0-9]{32}/g,
    name: 'Shopify Access Token',
    severity: SEVERITY.HIGH,
    validation: 'Shopify admin API access'
  },
  {
    pattern: /shpss_[a-fA-F0-9]{32}/g,
    name: 'Shopify Shared Secret',
    severity: SEVERITY.HIGH,
    validation: 'Shopify app shared secret'
  },

  // Algolia
  {
    pattern: /[a-zA-Z0-9]{32}/g,
    name: 'Algolia API Key (Potential)',
    severity: SEVERITY.LOW,
    context: 'algolia|search',
    validation: 'Verify Algolia context'
  },

  // Mapbox
  {
    pattern: /pk\.[a-zA-Z0-9]{60,}/g,
    name: 'Mapbox Public Token',
    severity: SEVERITY.LOW,
    validation: 'Public token - check usage restrictions'
  },
  {
    pattern: /sk\.[a-zA-Z0-9]{60,}/g,
    name: 'Mapbox Secret Token',
    severity: SEVERITY.HIGH,
    validation: 'Secret token - should not be in client code'
  },

  // Generic patterns
  {
    pattern: /api[_-]?key['":\s]*['"]?([a-zA-Z0-9_\-]{20,})['"]?/gi,
    name: 'Generic API Key',
    severity: SEVERITY.MEDIUM,
    validation: 'Verify key purpose and permissions'
  },
  {
    pattern: /api[_-]?secret['":\s]*['"]?([a-zA-Z0-9_\-]{20,})['"]?/gi,
    name: 'Generic API Secret',
    severity: SEVERITY.HIGH,
    validation: 'Verify secret purpose and permissions'
  },
  {
    pattern: /password['":\s]*['"]([^'"]{8,})['"]?/gi,
    name: 'Hardcoded Password',
    severity: SEVERITY.HIGH,
    validation: 'Credential exposure - verify if test/prod'
  },
  {
    pattern: /secret['":\s]*['"]([a-zA-Z0-9_\-]{16,})['"]?/gi,
    name: 'Generic Secret',
    severity: SEVERITY.MEDIUM,
    validation: 'Check context and purpose'
  }
];

/**
 * API endpoint patterns for discovery
 */
const ENDPOINT_PATTERNS = [
  { pattern: /["']((?:https?:)?\/\/[^"']+\/api\/[a-zA-Z0-9/_-]+)["']/gi, name: 'API Endpoint' },
  { pattern: /["'](\/api\/v?\d*\/[a-zA-Z0-9/_-]{2,})["']/gi, name: 'Versioned API Path' },
  { pattern: /["'](\/v\d+\/[a-zA-Z0-9/_-]{2,})["']/gi, name: 'Versioned Path' },
  { pattern: /["'](\/rest\/[a-zA-Z0-9/_-]{2,})["']/gi, name: 'REST Endpoint' },
  { pattern: /["'](\/graphql[a-zA-Z0-9/_-]*)["']/gi, name: 'GraphQL Endpoint' },
  { pattern: /["'](\/oauth[0-9]*\/[a-zA-Z0-9/_-]+)["']/gi, name: 'OAuth Endpoint' },
  { pattern: /["'](\/auth[a-zA-Z0-9/_-]*)["']/gi, name: 'Auth Endpoint' },
  { pattern: /["'](\/login[a-zA-Z0-9/_-]*)["']/gi, name: 'Login Endpoint' },
  { pattern: /["'](\/logout[a-zA-Z0-9/_-]*)["']/gi, name: 'Logout Endpoint' },
  { pattern: /["'](\/register[a-zA-Z0-9/_-]*)["']/gi, name: 'Register Endpoint' },
  { pattern: /["'](\/signup[a-zA-Z0-9/_-]*)["']/gi, name: 'Signup Endpoint' },
  { pattern: /["'](\/token[a-zA-Z0-9/_-]*)["']/gi, name: 'Token Endpoint' },
  { pattern: /["'](\/admin[a-zA-Z0-9/_-]*)["']/gi, name: 'Admin Endpoint' },
  { pattern: /["'](\/dashboard[a-zA-Z0-9/_-]*)["']/gi, name: 'Dashboard Endpoint' },
  { pattern: /["'](\/internal[a-zA-Z0-9/_-]*)["']/gi, name: 'Internal Endpoint' },
  { pattern: /["'](\/debug[a-zA-Z0-9/_-]*)["']/gi, name: 'Debug Endpoint' },
  { pattern: /["'](\/config[a-zA-Z0-9/_-]*)["']/gi, name: 'Config Endpoint' },
  { pattern: /["'](\/settings[a-zA-Z0-9/_-]*)["']/gi, name: 'Settings Endpoint' },
  { pattern: /["'](\/backup[a-zA-Z0-9/_-]*)["']/gi, name: 'Backup Endpoint' },
  { pattern: /["'](\/private[a-zA-Z0-9/_-]*)["']/gi, name: 'Private Endpoint' },
  { pattern: /["'](\/upload[a-zA-Z0-9/_-]*)["']/gi, name: 'Upload Endpoint' },
  { pattern: /["'](\/download[a-zA-Z0-9/_-]*)["']/gi, name: 'Download Endpoint' },
  { pattern: /["'](\/export[a-zA-Z0-9/_-]*)["']/gi, name: 'Export Endpoint' },
  { pattern: /["'](\/import[a-zA-Z0-9/_-]*)["']/gi, name: 'Import Endpoint' },
  { pattern: /["'](\/\.well-known\/[a-zA-Z0-9/_-]+)["']/gi, name: 'Well-Known Endpoint' },
  { pattern: /["'](\/\.git[a-zA-Z0-9/_-]*)["']/gi, name: 'Git Endpoint' },
  { pattern: /["'](\/idp\/[a-zA-Z0-9/_-]+)["']/gi, name: 'Identity Provider Endpoint' },
  { pattern: /["'](\/ws[s]?:\/\/[^"']+)["']/gi, name: 'WebSocket Endpoint' }
];

/**
 * Cloud storage URL patterns
 */
const CLOUD_STORAGE_PATTERNS = [
  {
    pattern: /https?:\/\/([a-zA-Z0-9.-]+)\.s3[a-zA-Z0-9.-]*\.amazonaws\.com[^\s"'<>]*/g,
    name: 'AWS S3 Bucket',
    severity: SEVERITY.MEDIUM,
    validation: 'Check bucket permissions and ACLs'
  },
  {
    pattern: /https?:\/\/s3[a-zA-Z0-9.-]*\.amazonaws\.com\/([a-zA-Z0-9._-]+)[^\s"'<>]*/g,
    name: 'AWS S3 Bucket (Path Style)',
    severity: SEVERITY.MEDIUM,
    validation: 'Check bucket permissions and ACLs'
  },
  {
    pattern: /https?:\/\/([a-zA-Z0-9.-]+)\.blob\.core\.windows\.net[^\s"'<>]*/g,
    name: 'Azure Blob Storage',
    severity: SEVERITY.MEDIUM,
    validation: 'Check container access level'
  },
  {
    pattern: /https?:\/\/storage\.googleapis\.com\/([a-zA-Z0-9._-]+)[^\s"'<>]*/g,
    name: 'Google Cloud Storage',
    severity: SEVERITY.MEDIUM,
    validation: 'Check bucket IAM permissions'
  },
  {
    pattern: /https?:\/\/([a-zA-Z0-9._-]+)\.storage\.googleapis\.com[^\s"'<>]*/g,
    name: 'Google Cloud Storage (Subdomain)',
    severity: SEVERITY.MEDIUM,
    validation: 'Check bucket IAM permissions'
  },
  {
    pattern: /https?:\/\/([a-zA-Z0-9._-]+)\.digitaloceanspaces\.com[^\s"'<>]*/g,
    name: 'DigitalOcean Spaces',
    severity: SEVERITY.MEDIUM,
    validation: 'Check space permissions'
  },
  {
    pattern: /https?:\/\/([a-zA-Z0-9._-]+)\.r2\.cloudflarestorage\.com[^\s"'<>]*/g,
    name: 'Cloudflare R2 Storage',
    severity: SEVERITY.MEDIUM,
    validation: 'Check bucket permissions'
  },
  {
    pattern: /https?:\/\/([a-zA-Z0-9._-]+)\.supabase\.co\/storage[^\s"'<>]*/g,
    name: 'Supabase Storage',
    severity: SEVERITY.MEDIUM,
    validation: 'Check storage bucket policies'
  }
];

/**
 * Sensitive file patterns
 */
const FILE_PATTERN = new RegExp(
  `["']([a-zA-Z0-9_/.\\-]+\\.(?:` +
  // Data files
  `sql|csv|xlsx|xls|json|xml|yaml|yml|` +
  // Config files
  `env|conf|config|cfg|ini|properties|` +
  // Backup files
  `bak|backup|old|orig|copy|swp|~|` +
  // Certificate/key files
  `key|pem|crt|cer|p12|pfx|jks|keystore|` +
  // Log files
  `log|logs|` +
  // Document files
  `doc|docx|pdf|` +
  // Archive files
  `zip|tar|gz|rar|7z|tgz|` +
  // Script files
  `sh|bash|bat|ps1|py|rb|pl|php|` +
  // Database files
  `db|sqlite|sqlite3|mdb` +
  `))["']`,
  'gi'
);

/**
 * Noise domains to filter out
 */
const NOISE_DOMAINS = [
  // XML namespaces
  'w3.org',
  'schemas.microsoft.com',
  'schemas.xmlsoap.org',
  'openxmlformats.org',
  'purl.org',
  'xmlns.com',

  // CDNs and common libs
  'cdnjs.cloudflare.com',
  'unpkg.com',
  'jsdelivr.net',
  'googleapis.com/ajax',

  // Build tools
  'webpack',
  'babel',
  'rollup',
  'parcel',
  'vite',

  // Placeholder domains
  'example.com',
  'example.org',
  'test.com',
  'localhost',
  '127.0.0.1',
  '0.0.0.0',

  // Common false positives
  'github.com/webpack',
  'github.com/babel',
  'npmjs.com',
  'npmjs.org'
];

/**
 * Noise file patterns
 */
const NOISE_FILE_PATTERNS = [
  /node_modules/i,
  /\.map$/i,
  /\.d\.ts$/i,
  /webpack/i,
  /babel/i,
  /polyfill/i,
  /vendor/i,
  /\.min\.(js|css)$/i,
  /^\/\//,  // Protocol-relative URLs
  /^\.\.?\//  // Relative paths
];

/**
 * Check if value is noise
 */
function isNoise(value, type) {
  const lowerValue = value.toLowerCase();

  // Check noise domains
  for (const domain of NOISE_DOMAINS) {
    if (lowerValue.includes(domain)) {
      return true;
    }
  }

  // Check noise file patterns
  if (type === 'file') {
    for (const pattern of NOISE_FILE_PATTERNS) {
      if (pattern.test(value)) {
        return true;
      }
    }
  }

  // Filter out very short matches that are likely false positives
  if (type === 'endpoint' && value.length < 5) {
    return true;
  }

  return false;
}

/**
 * Mask sensitive value for display
 */
function maskValue(value, showChars = 10) {
  if (value.length <= showChars * 2) {
    return value.substring(0, 4) + '***' + value.substring(value.length - 4);
  }
  return value.substring(0, showChars) + '...' + value.substring(value.length - 4);
}

/**
 * Extract secrets from content
 */
function extractSecrets(content, sourceUrl) {
  const findings = [];
  const seen = new Set();

  for (const { pattern, name, severity, validation, context } of SECRET_PATTERNS) {
    // Reset regex
    pattern.lastIndex = 0;

    let match;
    while ((match = pattern.exec(content)) !== null) {
      const value = match[1] || match[0];
      const key = `secret:${name}:${value}`;

      // Skip duplicates
      if (seen.has(key)) continue;

      // Skip if context required and not present
      if (context && !new RegExp(context, 'i').test(content.substring(Math.max(0, match.index - 100), match.index + 100))) {
        continue;
      }

      // Skip noise
      if (isNoise(value, 'secret')) continue;

      seen.add(key);

      findings.push({
        type: 'Secret',
        name: name,
        severity: severity,
        description: `${name} found in JavaScript source`,
        value: maskValue(value),
        rawValue: value,
        url: sourceUrl,
        validation: validation,
        location: `Character ${match.index}`
      });
    }
  }

  return findings;
}

/**
 * Extract API endpoints from content
 */
function extractEndpoints(content, sourceUrl, pageOrigin) {
  const findings = [];
  const seen = new Set();

  for (const { pattern, name } of ENDPOINT_PATTERNS) {
    // Reset regex
    pattern.lastIndex = 0;

    let match;
    while ((match = pattern.exec(content)) !== null) {
      const endpoint = match[1];
      const key = `endpoint:${endpoint}`;

      // Skip duplicates
      if (seen.has(key)) continue;

      // Skip noise
      if (isNoise(endpoint, 'endpoint')) continue;

      seen.add(key);

      // Determine if internal or external
      let fullUrl = endpoint;
      let isInternal = false;

      if (endpoint.startsWith('/')) {
        fullUrl = new URL(endpoint, pageOrigin).toString();
        isInternal = true;
      } else if (endpoint.startsWith('//')) {
        fullUrl = 'https:' + endpoint;
      }

      // Check if it's a potentially interesting endpoint
      const isInteresting = /admin|internal|debug|config|backup|private|token|auth/.test(endpoint.toLowerCase());

      findings.push({
        type: 'Endpoint',
        name: isInteresting ? `${name} (Interesting)` : name,
        severity: isInteresting ? SEVERITY.LOW : SEVERITY.INFO,
        description: `API endpoint discovered in JavaScript`,
        endpoint: endpoint,
        fullUrl: fullUrl,
        isInternal: isInternal,
        source: sourceUrl
      });
    }
  }

  return findings;
}

/**
 * Extract cloud storage URLs from content
 */
function extractCloudStorage(content, sourceUrl) {
  const findings = [];
  const seen = new Set();

  for (const { pattern, name, severity, validation } of CLOUD_STORAGE_PATTERNS) {
    // Reset regex
    pattern.lastIndex = 0;

    let match;
    while ((match = pattern.exec(content)) !== null) {
      const url = match[0];
      const bucketName = match[1];
      const key = `storage:${url}`;

      // Skip duplicates
      if (seen.has(key)) continue;

      // Skip noise
      if (isNoise(url, 'url')) continue;

      seen.add(key);

      findings.push({
        type: 'Cloud Storage',
        name: name,
        severity: severity,
        description: `${name} URL found - potential bucket enumeration/takeover target`,
        bucket: bucketName,
        url: url,
        validation: validation,
        source: sourceUrl,
        testVector: `Check public access: curl -I "${url}"`
      });
    }
  }

  return findings;
}

/**
 * Extract sensitive file references from content
 */
function extractFileReferences(content, sourceUrl) {
  const findings = [];
  const seen = new Set();

  // Reset regex
  FILE_PATTERN.lastIndex = 0;

  let match;
  while ((match = FILE_PATTERN.exec(content)) !== null) {
    const filePath = match[1];
    const key = `file:${filePath}`;

    // Skip duplicates
    if (seen.has(key)) continue;

    // Skip noise
    if (isNoise(filePath, 'file')) continue;

    seen.add(key);

    // Determine file type category
    const ext = filePath.split('.').pop().toLowerCase();
    let category = 'Other';
    let severity = SEVERITY.INFO;

    if (['sql', 'db', 'sqlite', 'sqlite3', 'mdb'].includes(ext)) {
      category = 'Database';
      severity = SEVERITY.MEDIUM;
    } else if (['env', 'conf', 'config', 'cfg', 'ini', 'properties'].includes(ext)) {
      category = 'Configuration';
      severity = SEVERITY.MEDIUM;
    } else if (['key', 'pem', 'crt', 'cer', 'p12', 'pfx', 'jks', 'keystore'].includes(ext)) {
      category = 'Certificate/Key';
      severity = SEVERITY.HIGH;
    } else if (['bak', 'backup', 'old', 'orig', 'copy', 'swp'].includes(ext)) {
      category = 'Backup';
      severity = SEVERITY.LOW;
    } else if (['sh', 'bash', 'bat', 'ps1', 'py', 'rb', 'pl', 'php'].includes(ext)) {
      category = 'Script';
      severity = SEVERITY.LOW;
    } else if (['log', 'logs'].includes(ext)) {
      category = 'Log';
      severity = SEVERITY.LOW;
    }

    findings.push({
      type: 'File Reference',
      name: `${category} File Reference`,
      severity: severity,
      description: `Reference to ${category.toLowerCase()} file found in JavaScript`,
      filePath: filePath,
      extension: ext,
      category: category,
      source: sourceUrl
    });
  }

  return findings;
}

/**
 * Main secrets scanner function
 */
export async function secretsScanner(context) {
  const { url, document: doc } = context;
  const results = [];
  const pageOrigin = new URL(url).origin;

  if (!doc) return results;

  try {
    // Get all script content
    const scripts = doc.querySelectorAll('script');
    const scriptContents = [];

    for (const script of scripts) {
      const src = script.getAttribute('src');

      if (src) {
        // External script - try to fetch if same origin
        try {
          const scriptUrl = new URL(src, url);
          if (scriptUrl.origin === pageOrigin) {
            const response = await fetch(scriptUrl.toString(), {
              signal: AbortSignal.timeout(5000)
            });
            if (response.ok) {
              const content = await response.text();
              scriptContents.push({ content, source: scriptUrl.toString() });
            }
          }
        } catch (e) {
          // Failed to fetch script
        }
      } else if (script.textContent) {
        // Inline script
        scriptContents.push({ content: script.textContent, source: url });
      }
    }

    // Also check data attributes and inline event handlers
    const body = doc.body?.innerHTML || '';
    scriptContents.push({ content: body, source: url + ' (DOM)' });

    // Scan all content
    for (const { content, source } of scriptContents) {
      // Extract secrets
      results.push(...extractSecrets(content, source));

      // Extract endpoints
      results.push(...extractEndpoints(content, source, pageOrigin));

      // Extract cloud storage URLs
      results.push(...extractCloudStorage(content, source));

      // Extract file references
      results.push(...extractFileReferences(content, source));
    }

    // Deduplicate by type + value/endpoint
    const deduped = [];
    const seen = new Set();

    for (const result of results) {
      const key = `${result.type}:${result.value || result.endpoint || result.url || result.filePath}`;
      if (!seen.has(key)) {
        seen.add(key);
        deduped.push(result);
      }
    }

    return deduped;

  } catch (error) {
    console.error('[BlueDragon] Secrets scanner error:', error);
    return results;
  }
}

export default {
  secretsScanner,
  SECRET_PATTERNS,
  ENDPOINT_PATTERNS,
  CLOUD_STORAGE_PATTERNS
};
