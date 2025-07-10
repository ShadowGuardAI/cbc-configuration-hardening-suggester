# cbc-Configuration-Hardening-Suggester
Analyzes a system configuration and suggests hardening measures based on industry best practices (e.g., CIS benchmarks). Outputs a list of recommended changes with justifications and severity levels. Uses a data file of known hardening rules. Uses `pyyaml` for configuration parsing. - Focused on Compares system configuration files (e.g., YAML, JSON, INI) against predefined security baselines (expressed as JSON Schemas).  Highlights deviations using 'deepdiff' and generates reports indicating areas of non-compliance.  Supports remediation recommendations based on baseline rules.

## Install
`git clone https://github.com/ShadowGuardAI/cbc-configuration-hardening-suggester`

## Usage
`./cbc-configuration-hardening-suggester [params]`

## Parameters
- `-h`: Show help message and exit
- `-v`: Enable verbose logging.

## License
Copyright (c) ShadowGuardAI
