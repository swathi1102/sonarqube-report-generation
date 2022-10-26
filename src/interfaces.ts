export interface SonarIssue {
  engineId: string;
  ruleId: string;
  primaryLocation: {
    message: string;
    filePath: string;
  };
  type: 'BUG' | 'VULNERABILITY' | 'CODE_SMELL';
  severity: 'BLOCKER' | 'CRITICAL' | 'MAJOR' | 'MINOR' | 'INFO';
}

export interface TrivyReport {
  SchemaVersion: number;
  ArtifactName: string;
  ArtifactType: string;
  Results: Array<{
    Target: string;
    Class: string;
    Type: string;
    MisconfSummary?: {
      Successes: number;
      Failures: number;
      Exceptions: number;
    };
    Vulnerabilities?: Array<{
      VulnerabilityID: string;
      PkgName: string;
      InstalledVersion: string;
      FixedVersion: string;

      SeveritySource: string;
      PrimaryURL: string;
      DataSource: {
        ID: string;
        Name: string;
        URL: string;
      };
      Title: string;
      Description: string;
      Severity: 'HIGH' | 'LOW' | 'MEDIUM' | 'CRITICAL';

      References?: string[];
      PublishedDate: string;
      LastModifiedDate: string;
    }>;
    Misconfigurations?: Array<{
      Type: string;
      ID: string;
      Title: string;
      Description: string;
      Message: string;
      Namespace: string;
      Query: string;
      Resolution: string;
      Severity: 'HIGH' | 'LOW' | 'MEDIUM' | 'CRITICAL';
      PrimaryURL: string;
      References?: string[];
    }>;
  }>;
}


export interface SemgrepReport {
  errors:  any[];
  paths:   Paths;
  results: Result[];
  version: string;
}

export interface Paths {
  _comment: string;
  scanned:  string[];
}

export interface Result {
  check_id: string;
  path:     string;
  start:    number;
  end:      number;
  extra:    Extra;
}

export interface ResultEnd {
  line: number;
  col:  number;
}

export interface Extra {
  message:  string;
  metavars: Metavars;
  metadata: Metadata;
  severity: 'INFO' | 'WARNING' | 'ERROR' ;
  fix?:     string;
  lines:    string;
}

export interface Metadata {
  cwe:                string;
  owasp:              string;
  "source-rule-url"?: string;
  references?:        string[];
}

export interface Metavars {
  $CIPHER?:   Cipher;
  $Y?:        Cookie;
  $X?:        Cookie;
  $RUNTIME?:  Cookie;
  $W?:        Cookie;
  $SQL?:      Cookie;
  $CTX?:      Cookie;
  $METHOD?:   Cipher;
  $COOKIE?:   Cookie;
  $RESPONSE?: Cookie;
  $RESP?:     Cookie;
}

export interface Cipher {
  start:            CIPHEREnd;
  end:              CIPHEREnd;
  abstract_content: string;
  unique_id:        CIPHERUniqueID;
}

export interface CIPHEREnd {
  line:   number;
  col:    number;
  offset: number;
}

export interface CIPHERUniqueID {
  type:   string;
  md5sum: string;
}

export interface Cookie {
  start:            CIPHEREnd;
  end:              CIPHEREnd;
  abstract_content: string;
  unique_id:        COOKIEUniqueID;
}

export interface COOKIEUniqueID {
  type:    string;
  value?:  string;
  kind?:   string;
  sid?:    number;
  md5sum?: string;
}

export enum Type {
  AST = "AST",
  ID = "id",
}

export enum Kind {
  Local = "Local",
  Param = "Param",
}