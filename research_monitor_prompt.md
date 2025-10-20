# Microsoft Security Weekly Monitoring Prompt

## Version
v1.0.0 - 2025-10-19

## Trigger Phrases
- "weekly update"
- "MS security scan"
- "scan last week"
- Or provide specific date range: "scan October 12-19, 2025"

## Instructions

### Step 1: Execute Google Dork Searches
Run these 4 searches with date operators [after:DATE-1 before:DATE+1]:

**Query 1 - Feature Announcements:**
```
site:microsoft.com (Defender OR Sentinel OR Purview OR "Entra ID") after:[DATE-1] before:[DATE+1] (announcing OR released OR preview OR "now available") -KB -patch -cumulative -"annual report" -"quarterly report" -"digital defense report"
```

**Query 2 - Security Blog:**
```
site:microsoft.com/security/blog after:[DATE-1] before:[DATE+1] -KB
```

**Query 3 - Documentation Updates:**
```
site:learn.microsoft.com (Defender OR Sentinel OR Purview) after:[DATE-1] before:[DATE+1] inurl:whats-new
```

**Query 4 - TechCommunity Posts:**
```
site:techcommunity.microsoft.com security after:[DATE-1] before:[DATE+1] -KB -patch
```

### Step 2: Check RSS Feeds

Monitor these 19 RSS feeds for articles within date range:

- `https://www.microsoft.com/en-us/security/blog/feed/`
- `https://www.microsoft.com/releasecommunications/api/v2/azure/rss`
- `https://techcommunity.microsoft.com/t5/s/gxcuf89792/rss/board?board.id=MicrosoftSecurityandCompliance`
- `https://techcommunity.microsoft.com/t5/s/gxcuf89792/rss/board?board.id=Identity`
- `https://techcommunity.microsoft.com/t5/s/gxcuf89792/rss/board?board.id=CoreInfrastructureandSecurityBlog`
- `https://techcommunity.microsoft.com/t5/s/gxcuf89792/rss/board?board.id=AzureNetworkSecurityBlog`
- `https://techcommunity.microsoft.com/t5/s/gxcuf89792/rss/board?board.id=IdentityStandards`
- `https://techcommunity.microsoft.com/t5/s/gxcuf89792/rss/board?board.id=MicrosoftThreatProtectionBlog`
- `https://techcommunity.microsoft.com/t5/s/gxcuf89792/rss/board?board.id=MicrosoftDefenderCloudBlog`
- `https://techcommunity.microsoft.com/t5/s/gxcuf89792/rss/board?board.id=MicrosoftDefenderATPBlog`
- `https://techcommunity.microsoft.com/t5/s/gxcuf89792/rss/board?board.id=MicrosoftDefenderIoTBlog`
- `https://techcommunity.microsoft.com/t5/s/gxcuf89792/rss/board?board.id=DefenderExternalAttackSurfaceMgmtBlog`
- `https://techcommunity.microsoft.com/t5/s/gxcuf89792/rss/board?board.id=Vulnerability-Management`
- `https://techcommunity.microsoft.com/t5/s/gxcuf89792/rss/board?board.id=DefenderThreatIntelligence`
- `https://techcommunity.microsoft.com/t5/s/gxcuf89792/rss/board?board.id=MicrosoftSecurityExperts`
- `https://techcommunity.microsoft.com/t5/s/gxcuf89792/rss/board?board.id=Microsoft-Security-Baselines`
- `https://techcommunity.microsoft.com/t5/s/gxcuf89792/rss/board?board.id=MicrosoftSentinelBlog`
- `https://techcommunity.microsoft.com/t5/s/gxcuf89792/rss/board?board.id=MicrosoftDefenderforOffice365Blog`

### Step 3: Filtering Rules

#### EXCLUDE
- KB articles
- Patch Tuesday updates
- Cumulative updates
- Annual/quarterly reports (e.g., Digital Defense Report)
- PDF-only releases
- Monthly summary posts discussing older announcements
- Any content with publication date outside specified range

#### INCLUDE
- New feature announcements
- Public preview releases
- General availability (GA) announcements
- Major security advisories (non-patch)
- Architecture/capability changes
- Pricing/licensing changes affecting security products

#### DATE VERIFICATION (CRITICAL)
- Check article metadata for actual publication date
- Ignore "age" indicators like "3 weeks ago" unless they fall within range
- If article metadata shows date outside range → EXCLUDE completely
- Only include items where feature/announcement was PUBLISHED in specified date range

### Step 4: Output Format
```
## Microsoft Security Weekly Update: [DATE RANGE]

### 🔴 [PRODUCT CATEGORY]

**[Announcement Title]** | **[Verified Publication Date]** | **[PRIORITY]**
- [Key point 1]
- [Key point 2]
- [Key point 3]
- **Why it matters:** [1 sentence impact statement]
- [Link]

---

### 📊 SUMMARY

**No new announcements found for the following products in the [date range]:**
- [List products with no updates]

**Total announcements in date range: [X]**
**Reading time: [X minutes]**
```

#### Priority Levels
- **HIGH**: Breaking changes, security vulnerabilities, deprecations, GA of major features
- **MEDIUM**: New previews, feature enhancements, minor capability additions
- **LOW**: Documentation updates, regional expansions, pricing changes

#### Product Categories
- Microsoft Defender (XDR, Endpoint, Cloud Apps, Identity, Office 365)
- Microsoft Sentinel
- Microsoft Purview (DLP, Information Protection, Compliance)
- Microsoft Entra ID (Conditional Access, Identity Protection)
- Azure Security Center/Microsoft Defender for Cloud
- Microsoft 365 Security & Compliance
- Windows Security (Baselines, Server Security)
- Exchange/Infrastructure Security

## Claude AI Project Instructions

Copy this entire block to your Claude AI Project settings:
```
CONTEXT: I monitor Microsoft security products weekly to identify feature announcements and meaningful updates.

WHEN I SAY: "weekly update" or "MS security scan" or provide a date range:

EXECUTE THESE SEARCHES:
1. site:microsoft.com (Defender OR Sentinel OR Purview OR "Entra ID") after:[DATE-1] before:[DATE+1] (announcing OR released OR preview OR "now available") -KB -patch -cumulative -"annual report" -"quarterly report" -"digital defense report"

2. site:microsoft.com/security/blog after:[DATE-1] before:[DATE+1] -KB

3. site:learn.microsoft.com (Defender OR Sentinel OR Purview) after:[DATE-1] before:[DATE+1] inurl:whats-new

4. site:techcommunity.microsoft.com security after:[DATE-1] before:[DATE+1] -KB -patch

ALSO CHECK RSS FEEDS:
- https://www.microsoft.com/en-us/security/blog/feed/
- https://www.microsoft.com/releasecommunications/api/v2/azure/rss
- https://techcommunity.microsoft.com/t5/s/gxcuf89792/rss/board?board.id=MicrosoftSecurityandCompliance
- https://techcommunity.microsoft.com/t5/s/gxcuf89792/rss/board?board.id=Identity
- https://techcommunity.microsoft.com/t5/s/gxcuf89792/rss/board?board.id=CoreInfrastructureandSecurityBlog
- https://techcommunity.microsoft.com/t5/s/gxcuf89792/rss/board?board.id=AzureNetworkSecurityBlog
- https://techcommunity.microsoft.com/t5/s/gxcuf89792/rss/board?board.id=IdentityStandards
- https://techcommunity.microsoft.com/t5/s/gxcuf89792/rss/board?board.id=MicrosoftThreatProtectionBlog
- https://techcommunity.microsoft.com/t5/s/gxcuf89792/rss/board?board.id=MicrosoftDefenderCloudBlog
- https://techcommunity.microsoft.com/t5/s/gxcuf89792/rss/board?board.id=MicrosoftDefenderATPBlog
- https://techcommunity.microsoft.com/t5/s/gxcuf89792/rss/board?board.id=MicrosoftDefenderIoTBlog
- https://techcommunity.microsoft.com/t5/s/gxcuf89792/rss/board?board.id=DefenderExternalAttackSurfaceMgmtBlog
- https://techcommunity.microsoft.com/t5/s/gxcuf89792/rss/board?board.id=Vulnerability-Management
- https://techcommunity.microsoft.com/t5/s/gxcuf89792/rss/board?board.id=DefenderThreatIntelligence
- https://techcommunity.microsoft.com/t5/s/gxcuf89792/rss/board?board.id=MicrosoftSecurityExperts
- https://techcommunity.microsoft.com/t5/s/gxcuf89792/rss/board?board.id=Microsoft-Security-Baselines
- https://techcommunity.microsoft.com/t5/s/gxcuf89792/rss/board?board.id=MicrosoftSentinelBlog
- https://techcommunity.microsoft.com/t5/s/gxcuf89792/rss/board?board.id=MicrosoftDefenderforOffice365Blog

FILTERING RULES:
- Exclude: KB articles, patches, cumulative updates, annual/quarterly reports, PDF-only releases
- Include: New features, previews, GA announcements, major advisories, capability changes
- CRITICAL: ONLY include items with verified publication dates within the specified date range
- If article metadata shows a date outside the range, exclude it completely - do not include it even if mentioned in monthly summaries
- Always verify publication date from article metadata before including

OUTPUT FORMAT:
Group by product (Defender, Sentinel, Purview, Entra, Azure Security, M365 Security)
For each item: Title | Verified Publication Date | 1-line summary | Link | Priority
If no announcements found in date range, explicitly state "No new announcements found for [date range]"
Keep total reading time under 3 minutes

PRODUCTS TO MONITOR:
- Microsoft Defender (XDR, Endpoint, Cloud Apps, Identity, Office 365)
- Microsoft Sentinel
- Microsoft Purview (DLP, Information Protection, Compliance)
- Microsoft Entra ID (Conditional Access, Identity Protection)
- Azure Security Center/Microsoft Defender for Cloud
- Microsoft 365 Security & Compliance

DATE VERIFICATION REQUIREMENT:
- Check article metadata for actual publication date
- Ignore "age" indicators like "1 month ago" unless they fall within range
- Monthly summary posts that discuss older announcements should be excluded
- Only include items where the feature/announcement was PUBLISHED in the specified date range
```

## Maintenance

### Adding New RSS Feeds
1. Add URL to Step 2 list
2. Update count in documentation
3. Commit: `Add RSS feed for [Product/Board Name]`

### Modifying Search Queries
1. Update query in Step 1
2. Test in Google
3. Commit: `Update [query name] to [reason]`

### Updating Product Categories
1. Edit "Product Categories" in Step 4
2. Update Claude AI Project Instructions
3. Commit: `Add/Remove [product] from monitoring scope`
