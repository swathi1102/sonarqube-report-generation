#!/usr/bin/env node

import * as yargs from 'yargs';
import { convertTryviReport } from '../index';
import { convertSemgrepReport } from '../index';

const options: {
  output: string,
  file: string
} = <any>yargs
  .usage('Usage: -f <name>')
  .usage('Usage: -o <name>')
  .option('f', { alias: 'file', describe: 'Your trivy report', type: 'string', demandOption: true })
  .option('o', { alias: 'output', describe: 'Path to save sonarqube report', type: 'string', demandOption: true })
  .argv;

console.log('starting....');
console.log(options.file);

switch(options.file) {
  case "trivy-report.json":
    convertTryviReport(options.file, options.output).catch(e => {
      console.error(e);
      process.exit(1);
    }).then(() => {
      console.log('Done');
      process.exit(0);
    });
    break;
  case "semgrep-report.json":
    convertSemgrepReport(options.file, options.output).catch(e => {
      console.error(e);
      process.exit(1);
    }).then(() => {
      console.log('Done');
      process.exit(0);
    });
    break;
  default:
    console.log("Tool not supported!");
    break;
}
