import { promises as fs } from 'fs';
import path from 'path';

import { SonarIssue, TrivyReport, SemgrepReport } from './interfaces';

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

export async function convertReport(inputFile: string, outputFile: string):Promise<void> {
  const reportBlob = await fs.readFile(path.join(inputFile));
  const data: SonarIssue[] = [];
  
  console.log(inputFile);

  if (inputFile == 'trivy_report.json') {
    const report: TrivyReport | undefined = JSON.parse(reportBlob.toString() || '{}');
    if (!report?.Results?.length) {
      throw new Error('Empty report');
    }
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
  }

  else {
    const report: SemgrepReport | undefined = JSON.parse(reportBlob.toString() || '{}');
    if (!report?.results?.length) {
      throw new Error('Empty report');
    }
    const data: SonarIssue[] = [];
    for (const file of report?.results || []) {
      // if exists
      data.push({
        engineId: 'Semgrep',
        ruleId: file.check_id,
        primaryLocation: {
          filePath: file.path,
          message: `${file.check_id} : ${file.extra.message} => ${file.extra.fix} (${file.extra.metadata['source-rule-url']})`,
        },
        severity: convertSeverity(file.extra.severity),
        type: 'VULNERABILITY',
      });
    }
  }
  await fs.writeFile(path.join(outputFile), JSON.stringify({ issues: data }, null, 2), {
    flag: 'w',
  });
}
