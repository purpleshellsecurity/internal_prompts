# Microsoft Security Weekly Monitoring System

## Purpose
Automated weekly monitoring of Microsoft security product announcements, filtering out patches, KB articles, and content outside specified date ranges.

## Trigger Phrases
- "weekly update"
- "MS security scan"
- "scan last week"
- Or provide specific date range: "scan October 12-19, 2025"

## Execution Process

### Step 1: Execute Google Dork Searches
Run these 4 searches with date operators [after:DATE-1 before:DATE+1]:

#### 1. Feature Announcements
```
site:microsoft.com (Defender OR Sentinel OR Purview OR "Entra ID") after:[DATE-1] before:[DATE+1] (announcing OR released OR preview OR "now available") -KB -patch -cumulative -"annual report" -"quarterly report" -"digital defense report"
```

#### 2. Security Blog
```
site:microsoft.com/security/blog after:[DATE-1] before:[DATE+1] -KB
```

#### 3. Documentation Updates
```
site:learn.microsoft.com (Defender OR Sentinel OR Purview) after:[DATE-1] before:[DATE+1] inurl:whats-new
```

#### 4. TechCommunity Posts
```
site:techcommunity.microsoft.com security after:[DATE-1] before:[DATE+1] -KB -patch
```

### Step 2: Check RSS Feeds
Monitor these 19 RSS feeds for articles within date range:

#### Primary Feeds
- https://www.microsoft.com/en-us/security/blog/feed/
- https://www.microsoft.com/releasecommunications/api/v2/azure/rss

#### TechCommunity Boards
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

### Step 3: Filtering Rules

#### EXCLUDE (Must filter out)
- KB articles
- Patch Tuesday updates
- Cumulative updates
- Annual/quarterly reports (e.g., Digital Defense Report)
- PDF-only releases
- Monthly summary posts discussing older announcements
- Any content with publication date outside specified range

#### INCLUDE (Must include)
- New feature announcements
- Public preview releases
- General availability (GA) announcements
- Major security advisories (non-patch)
- Architecture/capability changes
- Pricing/licensing changes affecting security products

#### CRITICAL DATE VERIFICATION
- Check article metadata for actual publication date
- Ignore "age" indicators like "3 weeks ago" unless they fall within range
- If article metadata shows date outside range → EXCLUDE completely
- Only include items where feature/announcement was PUBLISHED in specified date range

### Step 4: Output Format
```markdown
## Microsoft Security Weekly Update: [DATE RANGE]

[If no results found, state: "No new announcements found for [date range]"]

### 🔴 [PRODUCT CATEGORY]

**[Announcement Title]** | **[Verified Publication Date]** | **[PRIORITY]**
- [Key point 1]
- [Key point 2]
- [Key point 3]
- **Why it matters:** [1 sentence impact statement]
- [Link]

[Repeat for each announcement]

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

### Step 5: Quality Checks
- [ ] All dates verified from article metadata
- [ ] No KB articles included
- [ ] No patch-only content included
- [ ] No monthly summaries discussing old content
- [ ] All links tested and functional
- [ ] Priority levels assigned correctly
- [ ] Total reading time under 3 minutes (unless 10+ announcements)

---

## Maintenance Guide

### How to Update This Prompt

#### Adding New RSS Feeds
1. Obtain feed URL (TechCommunity format: `/t5/s/gxcuf89792/rss/board?board.id=[BOARDID]`)
2. Add to "Step 2: Check RSS Feeds" section
3. Update total count in documentation
4. Commit with message: `Add RSS feed for [Product/Board Name]`

#### Modifying Search Queries
1. Update relevant query in "Step 1" 
2. Test query in Google to verify results
3. Document reason for change in git commit
4. Commit with message: `Update [query name] to [reason]`

#### Adjusting Product Categories
1. Update "Product Categories" list under Step 4
2. Update "No new announcements" template in output format
3. Ensure all monitored products are covered
4. Commit with message: `Add/Remove [product] from monitoring scope`

#### Changing Date Range Logic
1. Modify date operators in Step 1 queries (currently DATE-1 and DATE+1)
2. Update filtering rules to match new logic
3. Test with historical date ranges
4. Commit with message: `Adjust date range logic to [new logic]`

#### Updating Filtering Rules
1. Add new exclusion/inclusion patterns to Step 3
2. Test against recent announcements to verify accuracy
3. Document examples of what should be caught
4. Commit with message: `Add filter for [pattern type]`

---

## Version History

### v1.0.0 - 2025-10-19
- Initial release
- 4 Google Dork searches
- 19 RSS feeds
- Strict date filtering
- Automated priority assignment

---

## Usage Examples

### Example 1: Weekly Monday Morning Update
```
Input: "weekly update"
Date Range Calculated: Last 7 days
Expected Output: All announcements from past week, grouped by product
```

### Example 2: Specific Date Range
```
Input: "MS security scan for October 12-19, 2025"
Date Range: 2025-10-12 to 2025-10-19
Expected Output: Only announcements published between these dates
```

### Example 3: Last Week Scan
```
Input: "scan last week"
Date Range Calculated: Previous calendar week (Monday-Sunday)
Expected Output: All announcements from previous week
```

---

## Troubleshooting

### Issue: Too many results
**Solution**: Verify date filtering is working correctly. Check that monthly summary posts are being excluded.

### Issue: Missing known announcements
**Solution**: 
1. Verify announcement was published in date range (not just discussed)
2. Check if announcement source is in RSS feed list
3. Verify Google Dork operators are current

### Issue: False positives (patches included)
**Solution**: Update exclusion filters in Step 3 to catch new patch naming patterns

### Issue: RSS feeds not accessible
**Solution**: Verify TechCommunity feed URLs haven't changed format. Microsoft occasionally updates their community platform structure.

---

## Contributing

To contribute improvements to this monitoring system:

1. Fork the repository
2. Create a feature branch (`git checkout -b feature/improvement-name`)
3. Make your changes
4. Test with at least 2 different date ranges
5. Update version history
6. Commit with descriptive message
7. Push to branch
8. Create Pull Request with:
   - Description of change
   - Reason for change
   - Test results
   - Example output

---

## License

This monitoring system documentation is provided as-is for internal security monitoring purposes.

---

## Contact

For questions or issues with this monitoring system, contact the Security Operations team.

---

## Appendix A: Claude AI Project Instructions

If using this with Claude AI Projects, add these instructions to your project:
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
- **CRITICAL: ONLY include items with verified publication dates within the specified date range**
- **If article metadata shows a date outside the range, exclude it completely - do not include it even if mentioned in monthly summaries**
- Always verify publication date from article metadata before including

OUTPUT FORMAT:
Group by product (Defender, Sentinel, Purview, Entra, Azure Security, M365 Security)
For each item: Title | **Verified Publication Date** | 1-line summary | Link | Priority
**If no announcements found in date range, explicitly state "No new announcements found for [date range]"**
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

---

## Appendix B: Alternative Search Methods

### Using Microsoft Graph API (Future Enhancement)
If direct API access becomes available, consider these endpoints:
- Microsoft 365 Message Center API
- Microsoft Learn API
- TechCommunity API (if available)

### Using Third-Party Aggregators
Consider supplementing with:
- RSS aggregator services (Feedly, Inoreader)
- Security news aggregators
- Microsoft MVP blogs

---

## Appendix C: Monitoring Gaps

### Known Limitations
1. Google search operators limited to 10 queries per minute
2. RSS feeds may have delays (up to 24 hours)
3. Some Microsoft announcements occur outside standard channels (Twitter, LinkedIn)
4. Private previews not publicly announced
5. Regional announcements may be missed

### Future Improvements
- [ ] Add Microsoft 365 Roadmap monitoring
- [ ] Include Azure Updates RSS feed filtering
- [ ] Monitor Microsoft MVP blog aggregator
- [ ] Add webhook integration for real-time alerts
- [ ] Create automated GitHub Actions workflow
