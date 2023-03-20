## Install

```bash
npm i sonarqube-report-generation -g
```


## Generate trivy report 

```bash
trivy fs --ignorefile .trivyignore  -f json -o trivy-report.json  .
trivy config --ignorefile .trivyignore  -f json -o trivy-report.json  .
trivy image --ignorefile .trivyignore  -f json -o trivy-report.json  my-docker-image
```


## Generate semgrep report 

```bash
semgrep ci --config <rules> -o semgrep-report.json --json
docker run -it --rm --init --volume "$(pwd)":/src --workdir /src --env "$RULES" returntocorp/semgrep semgrep ci -o semgrep-report.json --json
```

## Convert data to sonarqube generic issue format 

```bash 
sonarqube-report-generation -f trivy-report.json -o ./my-trivy-to-sonarqube-report.json
sonarqube-report-generation -f semgrep-report.json -o ./my-semgrep-to-sonarqube-report.json
```


## Run sonar-scaner witch additional params
```bash
 sonar-scanner 
      -Dsonar.projectKey=MyProject
      -Dsonar.host.url=my-host.com
      -Dsonar.login=${SONARQUBE_TOKEN}
      -Dsonar.sources=.
      -Dsonar.externalIssuesReportPaths=./my-trivy-to-sonarqube-report.json, ./my-semgrep-to-sonarqube-report.json

```



## NOTE: 
This project was forked and improved from https://github.com/Blynskyniki/trivy-to-sonarqube . 
