# 🤝 Contributing to ChainGuard Protocol

We welcome contributions from security researchers, blockchain developers, and AI/ML engineers.

## How to Contribute

### 1. Adding Malware Signatures
Add to `config/signatures.yaml`:
```yaml
- id: "sig_YOUR_ID"
  name: "Malware Family Name"
  family: "family_name_lowercase"
  pattern: "hex_byte_pattern"
  severity: "CRITICAL"
  description: "What this signature detects"
  source: "Your name / organization"
```

### 2. Reporting False Positives
Open a GitHub issue with tag `false-positive` including:
- The address/tx hash flagged
- Evidence it's legitimate
- dApp/protocol it belongs to

### 3. Submitting Threat Intelligence
- Use the `/threat/report` API endpoint
- Include IPFS evidence hash
- Minimum 2 independent sources preferred

### 4. Code Contributions
1. Fork the repository
2. Create feature branch: `git checkout -b feature/agent-improvement`
3. All agent changes require corresponding tests
4. Smart contract changes require security review
5. Submit PR with detailed description

### 5. Bug Bounty
Critical security vulnerabilities in ChainGuard itself: report to sarthakdhaigude5337@gmail.com

## Code Standards
- Python: Black formatter, type hints required
- Solidity: Natspec comments, OpenZeppelin patterns
- React: TypeScript preferred, component tests required
- All PRs must pass CI/CD pipeline

## License
All contributions are MIT licensed.
