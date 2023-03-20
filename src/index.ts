import { promises as fs } from 'fs';
import path from 'path';

import { SonarIssue, TryviReport, SemgrepReport } from './interfaces';

function convertSeverity(reportLevel: string): SonarIssue['severity'] {
  switch (reportLevel) {
    case 'HIGH':
      return 'BLOCKER';
    case 'LOW':
      return 'MINOR';
    case 'CRITICAL':
      return 'CRITICAL';
    case 'MEDIUM':
      return 'MAJOR';
    case 'ERROR':
      return 'BLOCKER';
    case 'WARNING':
      return 'MINOR';
    default:
      return 'INFO';
  }
}
export async function convertTryviReport(inputFile: string, outputFile: string):Promise<void> {
  const reportBlob = await fs.readFile(path.join(inputFile));
  const report: TryviReport | undefined = JSON.parse(reportBlob.toString() || '{}');
  const data: SonarIssue[] = [];
  for (const file of report?.Results || []) {
    // if exists
    for (const issue of file?.Misconfigurations || []) {
      data.push({
        engineId: 'Trivy',
        ruleId: issue.ID,
        primaryLocation: {
          filePath: file.Target,
          message: `${issue.ID} : ${issue.Message} => ${issue.Resolution} (${issue.PrimaryURL})`,
        },
        severity: convertSeverity(issue.Severity),
        type: 'VULNERABILITY',
      });
    }
    // if exists
    for (const issue of file?.Vulnerabilities || []) {
      data.push({
        engineId: 'Trivy',
        ruleId: issue.VulnerabilityID,
        primaryLocation: {
          filePath: file.Target,
          message: `${issue.VulnerabilityID} : ${issue.Title} \n ${issue.InstalledVersion} => ${issue.FixedVersion} \n ${issue.Description} (${issue.PrimaryURL})`,
        },
        severity: convertSeverity(issue.Severity),
        type: 'VULNERABILITY',
      });
    }
  }
  await fs.writeFile(path.join(outputFile), JSON.stringify({ issues: data }, null, 2), {
    flag: 'w',
  });
}

export async function convertSemgrepReport(inputFile: string, outputFile: string):Promise<void> {
  const reportBlob = await fs.readFile(path.join(inputFile));
  const report: SemgrepReport | undefined = JSON.parse(reportBlob.toString() || '{}');
  if (!report?.paths?.scanned?.length) {
    throw new Error('Empty report');
  }
  const data: SonarIssue[] = [];
  for (const issue of report?.results || []) {
    // if exists
    data.push({
      engineId: 'Semgrep',
      ruleId: issue.check_id,
      primaryLocation: {
        filePath: issue.path,
        message: `${issue.check_id} : ${issue.extra.message} => ${issue.extra.fix} (${issue.extra.metadata['source-rule-url']})`,
      },
      severity: convertSeverity(issue.extra.severity),
      type: 'VULNERABILITY',
    });
  }
  
  await fs.writeFile(path.join(outputFile), JSON.stringify({ issues: data }, null, 2), {
    flag: 'w',
  });
}
