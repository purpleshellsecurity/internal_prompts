Master Prompt Iteration & Refinement Guide
Phase 1: Test-Driven Refinement
1.1 Create a Test Suite
Build a collection of test scenarios that cover your use cases:
Basic Tests

 Simple single resource (e.g., Storage Account)
 Multi-resource scenario (e.g., Web App + Database)
 Network infrastructure (e.g., VNet with subnets)

Intermediate Tests

 Hub-spoke topology
 Application with supporting services
 Cross-resource group deployment

Advanced Tests

 Complete landing zone
 Multi-region setup
 Complex security configurations

Edge Cases

 Ambiguous requirements
 Conflicting constraints
 Missing information scenarios

1.2 Run Test Scenarios
For each test:

Use your current master prompt
Ask a specific infrastructure question
Evaluate the response quality
Document what worked and what didn't

1.3 Evaluation Criteria
Rate each response on:

Correctness (1-5): Valid Bicep syntax, proper AVM usage
Completeness (1-5): All requirements addressed
Security (1-5): Best practices followed
Clarity (1-5): Code is readable and well-documented
Efficiency (1-5): Uses AVM modules, avoids redundancy

Phase 2: Iterative Improvement Cycle
2.1 The Feedback Loop
Test → Evaluate → Identify Gaps → Update Prompt → Repeat
2.2 Common Issues & Solutions
IssueSolutionAI doesn't check for AVM modulesAdd explicit instruction: "ALWAYS search for AVM modules first before writing custom code"Missing security configurationsAdd mandatory security checklist in promptInconsistent namingProvide explicit naming convention examplesWrong API versionsSpecify: "Use latest stable API versions"Missing parameter descriptionsMake @description() mandatory in examplesOver-complicated solutionsAdd: "Prefer simplicity; use minimal code to meet requirements"
2.3 Refinement Techniques
A. Add Specificity

Vague: "Follow best practices"
Specific: "Use managed identities, enable diagnostic settings, tag all resources with Environment, Owner, CostCenter"

B. Provide Examples

Instead of: "Use good naming"
Add: "Example: stg${environment}${appName}${uniqueString} for storage accounts"

C. Set Boundaries

Add: "Do NOT use deprecated features"
Add: "NEVER hardcode secrets in templates"
Add: "ALWAYS use parameter files for environment-specific values"

D. Create Decision Trees
IF deploying storage
  THEN check for avm/res/storage/storage-account
  IF AVM module exists
    THEN use module
  ELSE
    THEN write custom Bicep with security hardening
Phase 3: Version Control Your Prompt
3.1 Prompt Versioning Strategy
master-prompt-v1.0.md  → Initial version
master-prompt-v1.1.md  → Added security enhancements
master-prompt-v1.2.md  → Improved AVM module discovery
master-prompt-v2.0.md  → Major restructure
3.2 Track Changes
Keep a changelog:
markdown## v1.1 - 2025-01-15
### Added
- Explicit AVM module search requirement
- Security checklist expansion

### Changed
- Reorganized module design patterns

### Fixed
- Naming convention inconsistency
Phase 4: Measure & Optimize
4.1 Create Metrics
Track improvement over iterations:
Quality Metrics

% of responses using AVM modules
% of responses with complete security configs
% of responses with proper tagging
Average completeness score (1-5)

Efficiency Metrics

Lines of custom code vs AVM module usage
Number of follow-up questions needed
Time to production-ready code

4.2 A/B Testing
Test variations:

Version A: Current prompt
Version B: Modified section
Compare results on same test cases

Phase 5: Specialized Refinement
5.1 Domain-Specific Additions
Add sections for your specific needs:
For Data Platforms:
markdown### Data Platform Standards
- Use Azure Data Factory for ETL
- Implement Azure Purview for governance
- Configure Synapse Analytics with proper security
For Microservices:
markdown### Microservices Patterns
- Use AKS with Azure Service Mesh
- Implement API Management gateway
- Configure Application Insights for distributed tracing
5.2 Organization-Specific Rules
Add your company's standards:
markdown### [Company Name] Standards
- All resources must be in [region]
- Use [specific naming convention]
- Apply [specific tags]
- Deploy through [specific method]
Phase 6: Continuous Improvement
6.1 Regular Review Schedule

Weekly: Review recent test results
Monthly: Update based on new Azure features
Quarterly: Major revision based on accumulated feedback

6.2 Stay Current
Monitor and incorporate:

New AVM modules released
Azure service updates
Bicep language changes
Security advisories

6.3 Community Input

Share with team members
Gather feedback from actual usage
Document common questions
Build FAQ section

Phase 7: Advanced Optimization
7.1 Conditional Instructions
Add context-aware guidance:
markdownIF user mentions "production"
  THEN enforce strict security and HA requirements
ELSE IF user mentions "dev" or "test"
  THEN optimize for cost over redundancy
7.2 Progressive Disclosure
Structure from simple to complex:
markdown## Level 1: Core Requirements (Always Apply)
[Essential instructions]

## Level 2: Standard Practices (Apply When Relevant)
[Common scenarios]

## Level 3: Advanced Patterns (Apply For Complex Scenarios)
[Edge cases and complex patterns]
Practical Iteration Template
Iteration Log Entry
markdown## Test Date: [Date]
### Scenario: [Description]
### Prompt Version: v[X.X]

**Input Query:**
[Your test question]

**AI Response Quality:**
- Correctness: [1-5]
- Completeness: [1-5]
- Security: [1-5]
- Clarity: [1-5]
- Efficiency: [1-5]

**What Worked:**
- [Positive observations]

**What Didn't Work:**
- [Issues identified]

**Proposed Changes:**
- [ ] Change 1: [Description]
- [ ] Change 2: [Description]

**Next Test:**
[What to test next]
Quick Wins Checklist
Fastest improvements with highest impact:

Add explicit constraints - Turn suggestions into requirements
Include anti-patterns - Show what NOT to do
Provide code templates - Give copy-paste starting points
Add validation steps - Build in self-checking
Create response format - Structure the expected output
Include error handling - Guide through common mistakes
Add resource links - Point to official documentation
Set quality gates - Define minimum acceptable output

Resources for Iteration
Stay Updated:

Azure Updates: https://azure.microsoft.com/updates/
AVM Releases: https://github.com/Azure/bicep-registry-modules/releases
Bicep Changelog: https://github.com/Azure/bicep/releases

Community Resources:

Azure Bicep Discussions
Microsoft Q&A
Stack Overflow [azure-bicep] tag


Remember: Perfect is the enemy of good. Ship v1.0, test with real scenarios, then iterate based on actual usage patterns.
